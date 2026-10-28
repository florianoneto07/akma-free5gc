package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/florianoneto07/akma-free5gc/af/af/internal/aanf"
	"github.com/florianoneto07/akma-free5gc/af/af/internal/logger"
	"github.com/florianoneto07/akma-free5gc/af/akmatls"
	"github.com/florianoneto07/akma-free5gc/shared/akma/afid"
	"github.com/florianoneto07/akma-free5gc/shared/akma/akid"
	"github.com/florianoneto07/akma-free5gc/shared/akma/kdf"
)

// PSKSession is what a TLS or DTLS handshake with K_AF as PSK, or an OSCORE
// context from K_AF, established.
type PSKSession struct {
	AKid      string
	AfID      afid.AfID
	KafExpiry time.Time
}

// ErrPSKIdentity reports a PSK identity outside the AKMA name space. Like
// every error of PSKKey, it refuses the identity and the handshake fails:
// TLS carries no cause (TS 24.109 K.3).
var ErrPSKIdentity = errors.New("PSK identity is not 3GPP-AKMA;<A-KID>")

// PSKKey returns the K_AF of a PSK identity for the AF_ID id (TS 24.109
// K.3.2 e) and K.3.3 1) d); TS 33.222 cl. 5.4.0.1 step 4): the A-KID follows
// the prefix 3GPP-AKMA. remote is the address of the UE, for the log.
func (s *Server) PSKKey(ctx context.Context, id afid.AfID, identity, remote string) (PSKSession, kdf.Key, error) {
	aKid, err := akmatls.ParseIdentity(identity)
	if err == nil {
		_, err = akid.Parse(aKid, s.akid)
	}
	if err != nil {
		logger.UaLog.Warnf("PSK identity from %s is not 3GPP-AKMA;<A-KID>: handshake refused", remote)
		return PSKSession{}, kdf.Key{}, ErrPSKIdentity
	}
	sess, kaf, err := s.ApplicationKey(ctx, id, aKid, remote)
	if errors.Is(err, aanf.ErrKeyNotAvailable) {
		logger.UaLog.Infof("No K_AKMA at the AAnF for A-KID %s (AF_ID %s): handshake refused", aKid, id.Transport())
	}
	return sess, kaf, err
}

// ApplicationKey returns the K_AF of the A-KID aKid for the AF_ID id
// (TS 33.535 cl. 6.2.1 steps 2 and 9), from the cache or from the AAnF, and
// the session it gives. remote is the address of the UE, for the log.
func (s *Server) ApplicationKey(ctx context.Context, id afid.AfID, aKid, remote string) (PSKSession, kdf.Key, error) {
	key, err := s.keys.get(ctx, id, aKid, s.now())
	switch {
	case errors.Is(err, aanf.ErrKeyNotAvailable), errors.Is(err, ErrKafExpired):
		return PSKSession{}, kdf.Key{}, err
	case err != nil:
		logger.ConsumerLog.Errorf("K_AF for A-KID %s (UE at %s) not obtained: %v", aKid, remote, err)
		return PSKSession{}, kdf.Key{}, err
	}
	return PSKSession{AKid: aKid, AfID: id, KafExpiry: key.Expiry}, key.KAf, nil
}

type pskSessionKey struct{}

// WithPSKSession returns a context in which the PSK handler finds the
// session of its connection by calling get, after the handshake.
func WithPSKSession(ctx context.Context, get func() (PSKSession, bool)) context.Context {
	return context.WithValue(ctx, pskSessionKey{}, get)
}

// PSK returns the handler of the PSK profiles. The handshake authenticated
// the UE and the AF with K_AF, so a GET of the resource gets the
// Application Session Establishment Response (TS 33.535 cl. 6.2.1 step 9)
// without HTTP authentication.
func (s *Server) PSK() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.target(w, r) {
			return
		}
		get, _ := r.Context().Value(pskSessionKey{}).(func() (PSKSession, bool))
		var sess PSKSession
		ok := get != nil
		if ok {
			sess, ok = get()
		}
		if !ok {
			logger.UaLog.Errorf("Request from %s without a PSK session", r.RemoteAddr)
			writeError(w, http.StatusInternalServerError, CauseInvalidRequest)
			return
		}
		// The connection closes when K_AF expires; on a shifted clock
		// (clockOffset) it may outlive it here.
		if !s.now().Before(sess.KafExpiry) {
			logger.UaLog.Infof("K_AF for A-KID %s expired at %s: request rejected", sess.AKid,
				sess.KafExpiry.UTC().Format(time.RFC3339))
			w.Header().Set("Connection", "close")
			writeError(w, http.StatusForbidden, CauseKafExpired)
			return
		}
		rsp, _ := json.Marshal(SessionResponse{AKid: sess.AKid, KafExpiry: sess.KafExpiry.UTC()})
		logger.UaLog.Infof("UE with A-KID %s served over PSK TLS (AF_ID %s)", sess.AKid, sess.AfID.Transport())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(rsp)
	})
}

// String describes the session for the log.
func (p PSKSession) String() string {
	return fmt.Sprintf("A-KID %s, AF_ID %s", p.AKid, p.AfID.Transport())
}
