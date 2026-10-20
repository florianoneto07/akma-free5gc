// Package server is the Ua* server of the AF: HTTP Digest (RFC 7616) with
// the AKMA parameters of TS 33.535 B.1.2.2 and TS 24.109 K.2, without TLS.
package server

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/florianoneto07/akma-free5gc/af/af/internal/aanf"
	"github.com/florianoneto07/akma-free5gc/af/af/internal/config"
	"github.com/florianoneto07/akma-free5gc/af/af/internal/logger"
	"github.com/florianoneto07/akma-free5gc/af/uastar"
	"github.com/florianoneto07/akma-free5gc/shared/akma/akid"
)

// Causes of the error responses, sent in a JSON body.
const (
	CauseInvalidRequest      = "INVALID_REQUEST"
	CauseAkmaKeyNotAvailable = "AKMA_KEY_NOT_AVAILABLE"
	CauseKafExpired          = "KAF_EXPIRED"
	CauseNotFound            = "NOT_FOUND"
	CauseMethodNotAllowed    = "METHOD_NOT_ALLOWED"
	CauseMisdirectedRequest  = "MISDIRECTED_REQUEST"
	CauseAanfUnavailable     = "AANF_UNAVAILABLE"
)

// maxBodySize bounds the request body read for qop=auth-int.
const maxBodySize = 1 << 20

// SessionResponse is the body of a successful Application Session
// Establishment Response (TS 33.535 cl. 6.2.1 step 9). The SUPI is never
// sent to the UE.
type SessionResponse struct {
	AKid      string    `json:"aKid"`
	KafExpiry time.Time `json:"kafExpiry"`
}

// ErrorResponse is the body of an error without challenge.
type ErrorResponse struct {
	Cause string `json:"cause"`
}

// Server serves the protected resource of the AF.
type Server struct {
	s      *config.Settings
	nonces *nonceStore
	keys   *keyCache
	akid   akid.Options
	now    func() time.Time
}

// New returns the Ua* server for settings s, obtaining K_AF from p.
func New(s *config.Settings, p KeyProvider) *Server {
	return &Server{
		s:      s,
		nonces: newNonceStore(s.NonceLifetime),
		keys:   newKeyCache(p, s.KafExpiry),
		akid:   akid.DefaultOptions(),
		now:    func() time.Time { return time.Now().Add(s.ClockOffset) },
	}
}

// ServeHTTP checks the request in the numbered order below and stops at the
// first failure.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	now := s.now()
	remote := r.RemoteAddr

	// 1. Host: the FQDN used by the UE for the key derivation (TS 33.220
	// cl. 4.5.2 prerequisite (3)).
	if !strings.EqualFold(hostName(r.Host), s.s.FQDN) {
		logger.UaLog.Warnf("Request from %s for host %q, not %s", remote, r.Host, s.s.FQDN)
		writeError(w, http.StatusMisdirectedRequest, CauseMisdirectedRequest)
		return
	}
	if r.URL.Path != s.s.Path {
		writeError(w, http.StatusNotFound, CauseNotFound)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeError(w, http.StatusMethodNotAllowed, CauseMethodNotAllowed)
		return
	}

	// 2. No Digest credentials: the challenge, which is also the AKMA
	// initiation message (TS 33.535 cl. 6.5).
	authz := r.Header.Get("Authorization")
	creds, err := uastar.ParseCredentials(authz)
	if authz == "" || errors.Is(err, uastar.ErrNotDigest) {
		logger.UaLog.Infof("AKMA initiation: challenge sent to %s (product token %s: %v)",
			remote, uastar.ProductToken, uastar.HasProductToken(r.UserAgent()))
		s.challenge(w, now, false)
		return
	}

	// 3. Parameters of the supported profile.
	if err != nil {
		logger.UaLog.Warnf("Invalid Authorization from %s: %v", remote, err)
		writeError(w, http.StatusBadRequest, CauseInvalidRequest)
		return
	}
	if !strings.EqualFold(creds.Algorithm, uastar.Algorithm) || !slices.Contains(s.s.Qop, creds.Qop) {
		logger.UaLog.Warnf("Unsupported algorithm %q or qop %q from %s", creds.Algorithm, creds.Qop, remote)
		writeError(w, http.StatusBadRequest, CauseInvalidRequest)
		return
	}
	// 4. uri equal to the request target (RFC 7616 cl. 3.4.6).
	if creds.URI != r.RequestURI {
		logger.UaLog.Warnf("Digest uri %q differs from the request target %q (%s)", creds.URI, r.RequestURI, remote)
		writeError(w, http.StatusBadRequest, CauseInvalidRequest)
		return
	}
	// 5. realm (TS 24.109 K.2 d)).
	if creds.Realm != s.s.Realm {
		logger.UaLog.Warnf("Realm %q from %s is not %q", creds.Realm, remote, s.s.Realm)
		s.challenge(w, now, false)
		return
	}
	// 6 and 7. nonce, opaque, nc.
	nc, _ := uastar.ParseNC(creds.NC) // checked by ParseCredentials
	switch s.nonces.check(creds.Nonce, creds.Opaque, nc, now) {
	case nonceUnknown:
		logger.UaLog.Infof("Unknown nonce or opaque from %s: new challenge", remote)
		s.challenge(w, now, false)
		return
	case nonceStale:
		logger.UaLog.Infof("Stale nonce from %s: new challenge with stale=true", remote)
		s.challenge(w, now, true)
		return
	case nonceReplay:
		logger.UaLog.Warnf("Nonce count %s already used with this nonce (%s): possible replay", creds.NC, remote)
		s.challenge(w, now, false)
		return
	}
	// 8. The username is an A-KID.
	if _, err := akid.Parse(creds.Username, s.akid); err != nil {
		logger.UaLog.Warnf("Username from %s is not an A-KID", remote)
		writeError(w, http.StatusBadRequest, CauseInvalidRequest)
		return
	}
	aKid := creds.Username

	// 9. K_AF (TS 33.535 cl. 6.2.1 steps 2 and 9; B.1.2.2 step 6).
	key, err := s.keys.get(r.Context(), aKid, now)
	switch {
	case errors.Is(err, aanf.ErrKeyNotAvailable):
		logger.UaLog.Infof("No K_AKMA at the AAnF for A-KID %s: access rejected", aKid)
		writeError(w, http.StatusForbidden, CauseAkmaKeyNotAvailable)
		return
	case errors.Is(err, errKafExpired):
		writeError(w, http.StatusForbidden, CauseKafExpired)
		return
	case err != nil:
		logger.ConsumerLog.Errorf("K_AF for A-KID %s not obtained: %v", aKid, err)
		writeError(w, http.StatusServiceUnavailable, CauseAanfUnavailable)
		return
	}

	// 10. response.
	var body []byte
	if creds.Qop == uastar.QopAuthInt {
		if body, err = io.ReadAll(io.LimitReader(r.Body, maxBodySize)); err != nil {
			writeError(w, http.StatusBadRequest, CauseInvalidRequest)
			return
		}
	}
	in := uastar.Input{
		Username: aKid, Realm: s.s.Realm, Password: uastar.Password(key.KAf), Method: r.Method,
		URI: creds.URI, Nonce: creds.Nonce, NC: creds.NC, CNonce: creds.CNonce, Qop: creds.Qop,
	}
	if !uastar.Equal(in.Response(body), strings.ToLower(creds.Response)) {
		// RFC 7616 cl. 3.4: a login failure SHOULD be logged.
		logger.UaLog.Warnf("Digest response from %s does not match the K_AF of A-KID %s: authentication failed",
			remote, aKid)
		s.challenge(w, now, false)
		return
	}
	if !s.nonces.commit(creds.Nonce, nc) {
		logger.UaLog.Warnf("Nonce count %s already used with this nonce (%s): possible replay", creds.NC, remote)
		s.challenge(w, now, false)
		return
	}

	rsp, _ := json.Marshal(SessionResponse{AKid: aKid, KafExpiry: key.Expiry.UTC()})
	info := uastar.AuthInfo{RspAuth: in.RspAuth(rsp), Qop: creds.Qop, NC: creds.NC, CNonce: creds.CNonce}
	logger.UaLog.Infof("UE with A-KID %s authenticated (nc %s, qop %s)", aKid, creds.NC, creds.Qop)
	w.Header().Set("Authentication-Info", info.String())
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(rsp)
}

// challenge answers 401 with a new Digest challenge (RFC 7616 cl. 3.3;
// TS 33.535 B.1.2.2 step 3).
func (s *Server) challenge(w http.ResponseWriter, now time.Time, stale bool) {
	nonce, opaque := s.nonces.issue(now)
	c := uastar.Challenge{
		Realm: s.s.Realm, Qop: s.s.Qop, Algorithm: uastar.Algorithm, Nonce: nonce, Opaque: opaque,
		Stale: stale, Charset: uastar.Charset,
	}
	w.Header().Set("WWW-Authenticate", c.String())
	w.WriteHeader(http.StatusUnauthorized)
}

// writeError answers without a challenge, so without the realm of the AKMA
// challenge (TS 33.535 B.1.2.2 step 6).
func writeError(w http.ResponseWriter, status int, cause string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(ErrorResponse{Cause: cause})
}

// hostName returns the host of a Host header field value, without the port.
func hostName(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}
