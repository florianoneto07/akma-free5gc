package server

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/florianoneto07/akma-free5gc/af/af/internal/aanf"
	"github.com/florianoneto07/akma-free5gc/af/af/internal/config"
	"github.com/florianoneto07/akma-free5gc/af/af/internal/logger"
)

// KeyProvider obtains K_AF from the AAnF, directly (*aanf.Client) or
// through the NEF (*nef.Client).
type KeyProvider interface {
	ApplicationKey(ctx context.Context, aKid string) (aanf.Key, error)
}

// source names where a provider obtains K_AF, for the log.
func source(p KeyProvider) string {
	if s, ok := p.(interface{ Source() string }); ok {
		return s.Source()
	}
	return "the AAnF"
}

// errKafExpired reports a K_AF past its expiry under the reject policy.
var errKafExpired = errors.New("K_AF expired")

// keyCache holds the K_AF of each A-KID until its expiry: the "active
// context" of TS 33.535 cl. 6.2.1 step 2.
type keyCache struct {
	mu       sync.Mutex
	m        map[string]aanf.Key
	provider KeyProvider
	policy   config.KafExpiry
	timeout  time.Duration
}

func newKeyCache(p KeyProvider, policy config.KafExpiry) *keyCache {
	return &keyCache{m: make(map[string]aanf.Key), provider: p, policy: policy, timeout: config.DefaultAanfTimeout}
}

// get returns a K_AF valid at now for aKid. A K_AF is never used at or after
// its expiry (TS 33.535 cl. 4.4.0). An expired one is requested again from
// the AAnF (policy refetch) or refused with errKafExpired (policy reject,
// TS 33.535 cl. 6.4.2).
func (c *keyCache) get(ctx context.Context, aKid string, now time.Time) (aanf.Key, error) {
	c.mu.Lock()
	k, ok := c.m[aKid]
	c.mu.Unlock()
	if ok && now.Before(k.Expiry) {
		return k, nil
	}
	if ok {
		if c.policy == config.KafExpiryReject {
			logger.UaLog.Infof("K_AF for A-KID %s expired at %s: access rejected (policy reject)",
				aKid, k.Expiry.UTC().Format(time.RFC3339))
			return aanf.Key{}, errKafExpired
		}
		logger.UaLog.Infof("K_AF for A-KID %s expired at %s: requesting it again from %s (policy refetch)",
			aKid, k.Expiry.UTC().Format(time.RFC3339), source(c.provider))
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	k, err := c.provider.ApplicationKey(ctx, aKid)
	if err != nil {
		c.forget(aKid)
		return aanf.Key{}, err
	}
	if !now.Before(k.Expiry) {
		c.forget(aKid)
		logger.ConsumerLog.Warnf("%s returned a K_AF for A-KID %s already expired at %s (clock offset?)",
			source(c.provider), aKid, k.Expiry.UTC().Format(time.RFC3339))
		return aanf.Key{}, aanf.ErrUnavailable
	}
	logger.ConsumerLog.Infof("K_AF for A-KID %s obtained from %s, expires %s", aKid, source(c.provider),
		k.Expiry.UTC().Format(time.RFC3339))
	logger.ConsumerLog.Debugf("K_AF for A-KID %s belongs to %s", aKid, k.Supi)
	c.mu.Lock()
	c.m[aKid] = k
	c.mu.Unlock()
	return k, nil
}

func (c *keyCache) forget(aKid string) {
	c.mu.Lock()
	delete(c.m, aKid)
	c.mu.Unlock()
}
