// Package uaclient is the UE side of the simplified Ua* protocol of package
// uastar: it establishes an application session with the AF using the A-KID
// and K_AF, and accepts the AF only when it proves that it holds the same
// K_AF (rspauth).
package uaclient

import (
	"bytes"
	"context"
	"crypto/rand"
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

	"github.com/florianoneto07/akma-free5gc/af/uastar"
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
	Status int
	Cause  string
}

func (e *RejectedError) Error() string {
	if e.Cause != "" {
		return fmt.Sprintf("uaclient: AF answered %d %s", e.Status, e.Cause)
	}
	return fmt.Sprintf("uaclient: AF answered %d", e.Status)
}

// Config describes the AF and the AKMA material of the UE.
type Config struct {
	FQDN        string // FQDN of the AF, used for K_AF and sent in Host
	Connect     string // host:port to connect to
	Path        string
	RealmPrefix string // expected first part of the realm; default uastar.RealmPrefix
	AKID        string
	KAf         kdf.Key
	Qop         string // default uastar.QopAuth
	UserAgent   string // default DefaultUserAgent
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
}

// Session keeps the Digest state of one protection space: the challenge and
// the nonce count (RFC 7616 cl. 3.6).
type Session struct {
	cfg       Config
	host      string
	challenge *uastar.Challenge
	nc        uint32
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
		dialer := &net.Dialer{Timeout: 10 * time.Second}
		if cfg.LocalAddr != "" {
			ip := net.ParseIP(cfg.LocalAddr)
			if ip == nil {
				return nil, fmt.Errorf("uaclient: local address %q is not an IP address", cfg.LocalAddr)
			}
			dialer.LocalAddr = &net.TCPAddr{IP: ip}
		}
		cfg.HTTP = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DialContext: dialer.DialContext}}
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
	host := cfg.FQDN
	if port != "80" {
		host = net.JoinHostPort(cfg.FQDN, port)
	}
	return &Session{cfg: cfg, host: host}, nil
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
	}
	for attempt := 0; ; attempt++ {
		s.nc++
		in := uastar.Input{
			Username: s.cfg.AKID, Realm: s.challenge.Realm, Password: uastar.Password(s.cfg.KAf),
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
			return verify(rsp, body, in)
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

func (s *Session) send(ctx context.Context, authorization string) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+s.cfg.Connect+s.cfg.Path, nil)
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
