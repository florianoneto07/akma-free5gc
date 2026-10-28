//go:build wolfssl

package uaclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/florianoneto07/akma-free5gc/af/akmatls"
	"github.com/florianoneto07/akma-free5gc/af/wolftls"
	"github.com/florianoneto07/akma-free5gc/shared/akma/afid"
)

// PSKBuilt is true: this client has the PSK profiles, and with wolfSSL it
// is licensed under the GNU General Public License v3.0.
const PSKBuilt = true

// PSKSession runs requests over TLS connections authenticated with K_AF.
type PSKSession struct {
	cfg    PSKConfig
	client *wolftls.Client
	http   *http.Client
	host   string
	afID   string

	mu      sync.Mutex
	conn    *wolftls.Conn    // last connection
	session *wolftls.Session // to resume on the next connection
}

// NewPSKSession returns a session with the AF of cfg.
func NewPSKSession(cfg PSKConfig) (*PSKSession, error) {
	if err := cfg.check(); err != nil {
		return nil, err
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = DefaultUserAgent
	}
	version := wolftls.VersionTLS13
	switch cfg.Profile {
	case akmatls.ProfilePSKTLS13:
	case akmatls.ProfilePSKTLS12:
		version = wolftls.VersionTLS12
	default:
		return nil, fmt.Errorf("uaclient: profile %q is not a PSK profile", cfg.Profile)
	}
	_, port, err := net.SplitHostPort(cfg.Connect)
	if err != nil {
		return nil, fmt.Errorf("uaclient: connect: %w", err)
	}
	s := &PSKSession{cfg: cfg, host: cfg.FQDN}
	if port != "443" {
		s.host = net.JoinHostPort(cfg.FQDN, port)
	}
	s.client, err = wolftls.NewClient(wolftls.ClientConfig{
		Version: version, ServerName: cfg.FQDN, OfferPSKKEOnly: cfg.OfferPSKKEOnly,
		Key: pskKey(cfg, afid.UaStarTLS13, func(id string) { s.afID = id }),
	})
	if err != nil {
		return nil, err
	}
	dialer, err := newDialer(cfg.LocalAddr)
	if err != nil {
		s.client.Close()
		return nil, err
	}
	s.http = &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			raw, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			s.mu.Lock()
			resume := s.session
			s.mu.Unlock()
			c := s.client.Client(raw, resume)
			if deadline, ok := ctx.Deadline(); ok {
				_ = c.SetDeadline(deadline)
			}
			if err := c.Handshake(); err != nil {
				c.Close()
				return nil, err
			}
			_ = c.SetDeadline(time.Time{})
			s.mu.Lock()
			s.conn = c
			s.mu.Unlock()
			return c, nil
		},
	}}
	return s, nil
}

// pskKey returns the Key function of a PSK client: in (D)TLS 1.3 the K_AF
// of the fixed identifier base, before the ClientHello; in (D)TLS 1.2 the
// K_AF of the identifier of the cipher suite chosen by the AF, after the
// ServerHello (TS 33.222 cl. 5.4.0.2 NOTE 0; TS 33.220 H.3). used gets the
// AF_ID of the K_AF.
func pskKey(cfg PSKConfig, base afid.UaStarID, used func(string)) func(string, uint16) (string, []byte, error) {
	return func(hint string, suite uint16) (string, []byte, error) {
		id := base
		if suite != akmaTLS13Suite {
			// TS 24.109 K.3.2 d): the hint names the AKMA name space.
			if hint != akmatls.IdentityHint {
				return "", nil, fmt.Errorf("%w: psk_identity_hint %q", ErrNotPSK, hint)
			}
			id = akmatls.UaStarTLS(suite)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		aKid, kaf, err := cfg.Keys(ctx, id)
		if err != nil {
			return "", nil, err
		}
		used(cfg.FQDN + "." + id.String())
		return akmatls.Identity(aKid), kaf[:], nil
	}
}

// akmaTLS13Suite is the suite wolftls gives the Key function of a (D)TLS 1.3
// client.
const akmaTLS13Suite = wolftls.TLS_AES_128_GCM_SHA256

// Establish sends one Application Session Establishment Request (TS 33.535
// cl. 6.2.1 step 1) inside the TLS session. The handshake authenticated
// both sides, so the request carries no HTTP authentication.
func (s *PSKSession) Establish(ctx context.Context) (Result, error) {
	if s.cfg.Reconnect {
		s.http.CloseIdleConnections()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+s.cfg.Connect+s.cfg.Path, nil)
	if err != nil {
		return Result{}, err
	}
	req.Host = s.host
	req.Header.Set("User-Agent", s.cfg.UserAgent)
	rsp, err := s.http.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer rsp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(rsp.Body, 1<<20))
	if err != nil {
		return Result{}, err
	}
	s.mu.Lock()
	conn := s.conn
	if sess := conn.Session(); sess != nil {
		s.session.Free()
		s.session = sess
	}
	s.mu.Unlock()
	if rsp.StatusCode != http.StatusOK {
		return Result{}, rejected(rsp.StatusCode, body)
	}
	var r Result
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&r); err != nil {
		return Result{}, fmt.Errorf("uaclient: response body: %w", err)
	}
	st := conn.State()
	r.AfID, r.TLSVersion, r.CipherSuite, r.Resumed = s.afID, st.Version, st.CipherSuite, st.Resumed
	return r, nil
}

// Close closes the connections and frees the TLS session.
func (s *PSKSession) Close() {
	s.http.CloseIdleConnections()
	s.mu.Lock()
	s.session.Free()
	s.session = nil
	s.mu.Unlock()
	s.client.Close()
}
