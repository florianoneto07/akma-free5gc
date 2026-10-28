// Package uaclient is the UE side of the Ua* profiles: HTTP Digest keyed
// with K_AF inside TLS (TS 24.109 K.2) or, for tests, without it (package
// uastar), and TLS with K_AF as pre-shared key (TS 24.109 K.3, with
// wolfSSL). With Digest it accepts the AF only when the AF proves that it
// holds the same K_AF (rspauth).
package uaclient

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/florianoneto07/akma-free5gc/af/akmatls"
	"github.com/florianoneto07/akma-free5gc/af/uastar"
	"github.com/florianoneto07/akma-free5gc/shared/akma/afid"
	"github.com/florianoneto07/akma-free5gc/shared/akma/kdf"
)

// DefaultUserAgent carries the AKMA product token (TS 24.109 K.2 b) 1)).
const DefaultUserAgent = "akma-uaclient/0.1 " + uastar.ProductToken

var (
	// ErrChallenge reports a challenge that does not select AKMA for this AF
	// (TS 33.535 B.1.2.2 step 4; TS 24.109 K.2 d)) or is outside the
	// supported profile. The A-KID is not sent.
	ErrChallenge = errors.New("uaclient: challenge rejected")
	// ErrServerAuth reports a 200 response without a valid
	// Authentication-Info: the AF did not prove that it holds K_AF.
	ErrServerAuth = errors.New("uaclient: AF not authenticated")
)

// RejectedError reports that the AF refused the session.
type RejectedError struct {
	Status int    // HTTP status
	CoAP   string // or CoAP response code, such as "4.03"
	Cause  string
}

func (e *RejectedError) Error() string {
	code := fmt.Sprint(e.Status)
	if e.CoAP != "" {
		code = e.CoAP
	}
	if e.Cause != "" {
		return fmt.Sprintf("uaclient: AF answered %s %s", code, e.Cause)
	}
	return fmt.Sprintf("uaclient: AF answered %s", code)
}

// KeySource returns the A-KID and the K_AF of the AF_ID with the Ua*
// security protocol identifier id (TS 33.535 cl. 6.2.1 step 1), e.g. from
// the AKMA key service of the ME.
type KeySource func(ctx context.Context, id afid.UaStarID) (aKid string, kaf kdf.Key, err error)

// Config describes the AF and the AKMA material of the UE.
type Config struct {
	FQDN        string // FQDN of the AF, used for K_AF and sent in Host
	Connect     string // host:port to connect to
	Path        string
	RealmPrefix string // expected first part of the realm; default uastar.RealmPrefix
	// Keys gives the A-KID and K_AF once the Ua* identifier is known:
	// UaStarID without TLS; with TLS, 01 00 01 and the cipher suite of
	// the connection (TS 33.220 H.3). Without Keys, AKID and KAf.
	Keys     KeySource
	UaStarID afid.UaStarID
	AKID     string
	KAf      kdf.Key
	// TLS makes the session run over HTTPS (TS 24.109 K.2 a)); nil: HTTP,
	// the simplified Ua*.
	TLS *tls.Config
	// Reconnect opens a new connection for each request; with TLS, it
	// offers the session of the previous one.
	Reconnect bool
	Qop       string // default uastar.QopAuth
	UserAgent string // default DefaultUserAgent
	// LocalAddr is the source address of the connections, e.g. the address
	// of the PDU session (uesimtun0), so that the request goes through the
	// user plane. Empty: chosen by the system.
	LocalAddr string
	HTTP      *http.Client
}

// Result is a successful Application Session Establishment Response.
type Result struct {
	AKid      string    `json:"aKid"`
	KafExpiry time.Time `json:"kafExpiry"`
	NC        string    `json:"-"`
	// AfID is the AF_ID of the K_AF, in transport form.
	AfID string `json:"-"`
	// TLS state of the connection that carried the response, if any.
	TLSVersion  uint16 `json:"-"`
	CipherSuite uint16 `json:"-"`
	Resumed     bool   `json:"-"`
	// IDContext is the ID Context of the OSCORE context, set by a renewal
	// (RFC 8613 Appendix B.2).
	IDContext []byte `json:"-"`
}

// Session keeps the Digest state of one protection space: the challenge and
// the nonce count (RFC 7616 cl. 3.6), and the A-KID and K_AF of the
// AF_ID in use.
type Session struct {
	cfg       Config
	host      string
	scheme    string
	challenge *uastar.Challenge
	nc        uint32
	keyID     afid.UaStarID
	keyed     bool
	aKid      string
	kaf       kdf.Key
}

// NewSession returns a session with the AF of cfg.
func NewSession(cfg Config) (*Session, error) {
	if cfg.RealmPrefix == "" {
		cfg.RealmPrefix = uastar.RealmPrefix
	}
	if cfg.Qop == "" {
		cfg.Qop = uastar.QopAuth
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = DefaultUserAgent
	}
	if cfg.HTTP == nil {
		dialer, err := newDialer(cfg.LocalAddr)
		if err != nil {
			return nil, err
		}
		tr := &http.Transport{DialContext: dialer.DialContext, TLSClientConfig: cfg.TLS}
		cfg.HTTP = &http.Client{Timeout: 10 * time.Second, Transport: tr}
	}
	if !strings.HasPrefix(cfg.Path, "/") {
		return nil, fmt.Errorf("uaclient: path %q must start with /", cfg.Path)
	}
	_, port, err := net.SplitHostPort(cfg.Connect)
	if err != nil {
		return nil, fmt.Errorf("uaclient: connect: %w", err)
	}
	// Host carries the FQDN used for the key derivation (TS 33.220
	// cl. 4.5.2 prerequisite (3)), even when connecting to an address.
	scheme, defaultPort := "http", "80"
	if cfg.TLS != nil {
		scheme, defaultPort = "https", "443"
	}
	host := cfg.FQDN
	if port != defaultPort {
		host = net.JoinHostPort(cfg.FQDN, port)
	}
	return &Session{cfg: cfg, host: host, scheme: scheme}, nil
}

func newDialer(localAddr string) (*net.Dialer, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	if localAddr != "" {
		ip := net.ParseIP(localAddr)
		if ip == nil {
			return nil, fmt.Errorf("uaclient: local address %q is not an IP address", localAddr)
		}
		dialer.LocalAddr = &net.TCPAddr{IP: ip}
	}
	return dialer, nil
}

// Establish sends one Application Session Establishment Request (TS 33.535
// cl. 6.2.1 step 1). The first call obtains the challenge; later calls reuse
// it with an incremented nonce count, and adopt a new one once if the AF
// answers stale=true.
func (s *Session) Establish(ctx context.Context) (Result, error) {
	if s.challenge == nil {
		rsp, body, err := s.send(ctx, "")
		if err != nil {
			return Result{}, err
		}
		if rsp.StatusCode != http.StatusUnauthorized {
			return Result{}, rejected(rsp.StatusCode, body)
		}
		if err := s.adopt(rsp); err != nil {
			return Result{}, err
		}
		if err := s.key(ctx, rsp); err != nil {
			return Result{}, err
		}
	}
	for attempt := 0; ; attempt++ {
		s.nc++
		in := uastar.Input{
			Username: s.aKid, Realm: s.challenge.Realm, Password: uastar.Password(s.kaf),
			Method: http.MethodGet, URI: s.cfg.Path, Nonce: s.challenge.Nonce, NC: uastar.FormatNC(s.nc),
			CNonce: cnonce(), Qop: s.cfg.Qop,
		}
		creds := uastar.Credentials{
			Username: in.Username, Realm: in.Realm, URI: in.URI, Algorithm: uastar.Algorithm,
			Nonce: in.Nonce, NC: in.NC, CNonce: in.CNonce, Qop: in.Qop, Response: in.Response(nil),
			Opaque: s.challenge.Opaque,
		}
		rsp, body, err := s.send(ctx, creds.String())
		if err != nil {
			return Result{}, err
		}
		switch rsp.StatusCode {
		case http.StatusOK:
			r, err := verify(rsp, body, in)
			if err != nil {
				return Result{}, err
			}
			r.AfID = s.cfg.FQDN + "." + s.keyID.String()
			if rsp.TLS != nil {
				r.TLSVersion, r.CipherSuite, r.Resumed = rsp.TLS.Version, rsp.TLS.CipherSuite, rsp.TLS.DidResume
			}
			return r, nil
		case http.StatusUnauthorized:
			c, perr := uastar.ParseChallenge(rsp.Header.Get("WWW-Authenticate"))
			if perr == nil && c.Stale && attempt == 0 {
				if err := s.adopt(rsp); err != nil {
					return Result{}, err
				}
				continue
			}
			return Result{}, rejected(rsp.StatusCode, body)
		default:
			return Result{}, rejected(rsp.StatusCode, body)
		}
	}
}

// adopt checks a challenge (TS 33.535 B.1.2.2 step 4: realm with the
// expected prefix and the FQDN of the AF) and makes it the one of the
// session.
func (s *Session) adopt(rsp *http.Response) error {
	c, err := uastar.ParseChallenge(rsp.Header.Get("WWW-Authenticate"))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrChallenge, err)
	}
	if !strings.EqualFold(c.Algorithm, uastar.Algorithm) {
		return fmt.Errorf("%w: algorithm %s", ErrChallenge, c.Algorithm)
	}
	prefix, fqdn, ok := uastar.SplitRealm(c.Realm)
	if !ok || prefix != s.cfg.RealmPrefix {
		return fmt.Errorf("%w: realm %q does not select AKMA", ErrChallenge, c.Realm)
	}
	if !strings.EqualFold(fqdn, s.cfg.FQDN) {
		return fmt.Errorf("%w: realm %q is not of %s", ErrChallenge, c.Realm, s.cfg.FQDN)
	}
	if !slices.Contains(c.Qop, s.cfg.Qop) {
		return fmt.Errorf("%w: qop %s not offered", ErrChallenge, s.cfg.Qop)
	}
	s.challenge, s.nc = &c, 0
	return nil
}

// key obtains the A-KID and K_AF of the Ua* identifier of rsp, once the
// challenge has selected AKMA: the A-KID is sent only then (TS 33.535
// B.1.2.2 step 5). With TLS, the identifier carries the cipher suite of the
// connection (TS 33.220 H.3).
func (s *Session) key(ctx context.Context, rsp *http.Response) error {
	id := s.cfg.UaStarID
	if rsp.TLS != nil {
		id = akmatls.UaStarTLS(rsp.TLS.CipherSuite)
	}
	if s.keyed && id == s.keyID {
		return nil
	}
	if s.cfg.Keys == nil {
		s.aKid, s.kaf = s.cfg.AKID, s.cfg.KAf
	} else {
		aKid, kaf, err := s.cfg.Keys(ctx, id)
		if err != nil {
			return err
		}
		s.aKid, s.kaf = aKid, kaf
	}
	if s.aKid == "" {
		return errors.New("uaclient: no A-KID")
	}
	s.keyID, s.keyed = id, true
	return nil
}

func (s *Session) send(ctx context.Context, authorization string) (*http.Response, []byte, error) {
	if s.cfg.Reconnect {
		if t, ok := s.cfg.HTTP.Transport.(interface{ CloseIdleConnections() }); ok {
			t.CloseIdleConnections()
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.scheme+"://"+s.cfg.Connect+s.cfg.Path, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Host = s.host
	req.Header.Set("User-Agent", s.cfg.UserAgent)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	rsp, err := s.cfg.HTTP.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer rsp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(rsp.Body, 1<<20))
	return rsp, body, err
}

// verify checks the Authentication-Info of a 200 response: the AF proves
// that it holds K_AF (RFC 7616 cl. 3.5).
func verify(rsp *http.Response, body []byte, in uastar.Input) (Result, error) {
	info, err := uastar.ParseAuthInfo(rsp.Header.Get("Authentication-Info"))
	if err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrServerAuth, err)
	}
	if info.Qop != in.Qop || info.NC != in.NC || info.CNonce != in.CNonce {
		return Result{}, fmt.Errorf("%w: qop, nc or cnonce differ from the request", ErrServerAuth)
	}
	if !uastar.Equal(strings.ToLower(info.RspAuth), in.RspAuth(body)) {
		return Result{}, fmt.Errorf("%w: rspauth does not match", ErrServerAuth)
	}
	var r Result
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&r); err != nil {
		return Result{}, fmt.Errorf("uaclient: response body: %w", err)
	}
	r.NC = in.NC
	return r, nil
}

func rejected(status int, body []byte) error {
	var e struct {
		Cause string `json:"cause"`
	}
	_ = json.Unmarshal(body, &e)
	return &RejectedError{Status: status, Cause: e.Cause}
}

// cnonce returns 16 random octets in base64.
func cnonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}
