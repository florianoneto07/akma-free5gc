//go:build wolfssl

package uaclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/florianoneto07/akma-free5gc/af/akmatls"
	"github.com/florianoneto07/akma-free5gc/af/coap"
	"github.com/florianoneto07/akma-free5gc/af/wolftls"
)

// DTLSSession sends CoAP requests over DTLS associations authenticated
// with K_AF (TS 33.535 Annex C; RFC 7252).
type DTLSSession struct {
	cfg    PSKConfig
	client *wolftls.Client
	afID   string

	mu      sync.Mutex
	conn    *wolftls.Conn
	coap    *coap.Client
	session *wolftls.Session // to resume on the next association
}

// NewDTLSSession returns a session with the AF of cfg; cfg.Profile is
// akmatls.ProfilePSKDTLS13 or akmatls.ProfilePSKDTLS12.
func NewDTLSSession(cfg PSKConfig) (*DTLSSession, error) {
	if err := cfg.check(); err != nil {
		return nil, err
	}
	var version uint16
	switch cfg.Profile {
	case akmatls.ProfilePSKDTLS13:
		version = wolftls.VersionDTLS13
	case akmatls.ProfilePSKDTLS12:
		version = wolftls.VersionDTLS12
	default:
		return nil, fmt.Errorf("uaclient: profile %q is not a DTLS profile", cfg.Profile)
	}
	s := &DTLSSession{cfg: cfg}
	var err error
	s.client, err = wolftls.NewClient(wolftls.ClientConfig{
		Version: version, ServerName: cfg.FQDN, OfferPSKKEOnly: cfg.OfferPSKKEOnly,
		Key: pskKey(cfg, akmatls.UaStarDTLS13, func(id string) { s.afID = id }),
	})
	if err != nil {
		return nil, err
	}
	return s, nil
}

// associate opens a DTLS association, offering the session of the previous
// one. mu is held.
func (s *DTLSSession) associate(ctx context.Context) error {
	raddr, err := net.ResolveUDPAddr("udp", s.cfg.Connect)
	if err != nil {
		return fmt.Errorf("uaclient: connect: %w", err)
	}
	var laddr *net.UDPAddr
	if s.cfg.LocalAddr != "" {
		ip := net.ParseIP(s.cfg.LocalAddr)
		if ip == nil {
			return fmt.Errorf("uaclient: local address %q is not an IP address", s.cfg.LocalAddr)
		}
		laddr = &net.UDPAddr{IP: ip}
	}
	raw, err := net.DialUDP("udp", laddr, raddr)
	if err != nil {
		return err
	}
	c := s.client.Client(raw, s.session)
	deadline := time.Now().Add(15 * time.Second)
	if d, ok := ctx.Deadline(); ok {
		deadline = d
	}
	_ = c.SetDeadline(deadline)
	if err := c.Handshake(); err != nil {
		c.Close()
		return err
	}
	_ = c.SetDeadline(time.Time{})
	s.conn, s.coap = c, coap.NewClient(c)
	return nil
}

// Establish sends one Application Session Establishment Request (TS 33.535
// cl. 6.2.1 step 1): a CoAP GET of the resource, confirmable, inside the
// DTLS association. The handshake authenticated both sides.
func (s *DTLSSession) Establish(ctx context.Context) (Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil && s.cfg.Reconnect {
		s.closeLocked()
	}
	if s.conn == nil {
		if err := s.associate(ctx); err != nil {
			return Result{}, err
		}
	}
	req := &coap.Message{Code: coap.GET}
	req.Add(coap.OptionURIHost, []byte(s.cfg.FQDN))
	req.SetPath(s.cfg.Path)
	rsp, err := s.coap.Do(ctx, req)
	if err != nil && ended(err) {
		// The AF ended the association, as when K_AF expires (TS 33.535
		// cl. 6.4.2): a new one, resuming the session if the AF still
		// accepts its ticket.
		s.closeLocked()
		if err = s.associate(ctx); err == nil {
			rsp, err = s.coap.Do(ctx, req)
		}
	}
	if err != nil {
		return Result{}, err
	}
	if sess := s.conn.Session(); sess != nil {
		s.session.Free()
		s.session = sess
	}
	if rsp.Code != coap.Content {
		var e struct {
			Cause string `json:"cause"`
		}
		_ = json.Unmarshal(rsp.Payload, &e)
		return Result{}, &RejectedError{CoAP: rsp.Code.String(), Cause: e.Cause}
	}
	var r Result
	if err := json.NewDecoder(bytes.NewReader(rsp.Payload)).Decode(&r); err != nil {
		return Result{}, fmt.Errorf("uaclient: response payload: %w", err)
	}
	st := s.conn.State()
	r.AfID, r.TLSVersion, r.CipherSuite, r.Resumed = s.afID, st.Version, st.CipherSuite, st.Resumed
	return r, nil
}

// closeLocked ends the association, keeping its session. mu is held.
func (s *DTLSSession) closeLocked() {
	if sess := s.conn.Session(); sess != nil {
		s.session.Free()
		s.session = sess
	}
	s.conn.Close()
	s.conn, s.coap = nil, nil
}

// Close ends the association and frees the session.
func (s *DTLSSession) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		s.closeLocked()
	}
	s.session.Free()
	s.session = nil
	s.client.Close()
}

// ended reports an error of an association that the peer ended.
func ended(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed)
}
