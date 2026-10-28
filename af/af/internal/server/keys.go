package server

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/florianoneto07/akma-free5gc/af/af/internal/aanf"
	"github.com/florianoneto07/akma-free5gc/af/af/internal/config"
	"github.com/florianoneto07/akma-free5gc/af/af/internal/logger"
	"github.com/florianoneto07/akma-free5gc/shared/akma/afid"
)

// KeyProvider obtains K_AF from the AAnF, directly (*aanf.Client) or
// through the NEF (*nef.Client).
type KeyProvider interface {
	ApplicationKey(ctx context.Context, id afid.AfID, aKid string) (aanf.Key, error)
}

// source names where a provider obtains K_AF, for the log.
func source(p KeyProvider) string {
	if s, ok := p.(interface{ Source() string }); ok {
		return s.Source()
	}
	return "the AAnF"
}

// ErrKafExpired reports a K_AF past its expiry under the reject policy.
var ErrKafExpired = errors.New("K_AF expired")

// keyCache holds the K_AF of each AF_ID and A-KID until its expiry: the
// "active context" of TS 33.535 cl. 6.2.1 step 2. The AF has one AF_ID per
// Ua* security protocol, so one K_AF per profile and cipher suite.
type keyCache struct {
	mu       sync.Mutex
	m        map[cacheKey]aanf.Key
	provider KeyProvider
	policy   config.KafExpiry
	timeout  time.Duration
}

type cacheKey struct {
	afID string // transport form
	aKid string
}

func newKeyCache(p KeyProvider, policy config.KafExpiry) *keyCache {
	return &keyCache{m: make(map[cacheKey]aanf.Key), provider: p, policy: policy, timeout: config.DefaultAanfTimeout}
}

// get returns a K_AF valid at now for id and aKid. A K_AF is never used at
// or after its expiry (TS 33.535 cl. 4.4.0). An expired one is requested
// again from the AAnF (policy refetch) or refused with ErrKafExpired (policy
// reject, TS 33.535 cl. 6.4.2).
func (c *keyCache) get(ctx context.Context, id afid.AfID, aKid string, now time.Time) (aanf.Key, error) {
	ck := cacheKey{afID: id.Transport(), aKid: aKid}
	c.mu.Lock()
	k, ok := c.m[ck]
	c.mu.Unlock()
	if ok && now.Before(k.Expiry) {
		return k, nil
	}
	if ok {
		if c.policy == config.KafExpiryReject {
			logger.UaLog.Infof("K_AF for A-KID %s expired at %s: access rejected (policy reject)",
				aKid, k.Expiry.UTC().Format(time.RFC3339))
			return aanf.Key{}, ErrKafExpired
		}
		logger.UaLog.Infof("K_AF for A-KID %s expired at %s: requesting it again from %s (policy refetch)",
			aKid, k.Expiry.UTC().Format(time.RFC3339), source(c.provider))
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	k, err := c.provider.ApplicationKey(ctx, id, aKid)
	if err != nil {
		c.forget(ck)
		return aanf.Key{}, err
	}
	if !now.Before(k.Expiry) {
		c.forget(ck)
		logger.ConsumerLog.Warnf("%s returned a K_AF for A-KID %s already expired at %s (clock offset?)",
			source(c.provider), aKid, k.Expiry.UTC().Format(time.RFC3339))
		return aanf.Key{}, aanf.ErrUnavailable
	}
	logger.ConsumerLog.Infof("K_AF for A-KID %s and AF_ID %s obtained from %s, expires %s", aKid, ck.afID,
		source(c.provider), k.Expiry.UTC().Format(time.RFC3339))
	logger.ConsumerLog.Debugf("K_AF for A-KID %s belongs to %s", aKid, k.Supi)
	c.mu.Lock()
	c.m[ck] = k
	c.mu.Unlock()
	return k, nil
}

func (c *keyCache) forget(ck cacheKey) {
	c.mu.Lock()
	delete(c.m, ck)
	c.mu.Unlock()
}
