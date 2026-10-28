package uaclient

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/florianoneto07/akma-free5gc/af/akmaoscore"
	"github.com/florianoneto07/akma-free5gc/af/akmatls"
	"github.com/florianoneto07/akma-free5gc/af/coap"
	"github.com/florianoneto07/akma-free5gc/af/oscore"
	"github.com/florianoneto07/akma-free5gc/shared/akma/akid"
)

// OSCORESession sends CoAP requests protected by OSCORE with a security
// context from K_AF (TS 33.535 Annex D), over UDP.
type OSCORESession struct {
	cfg PSKConfig

	mu     sync.Mutex
	conn   *net.UDPConn
	client *oscore.Client
	afID   string
}

// NewOSCORESession returns a session with the AF of cfg; cfg.Profile is
// akmatls.ProfileOSCORE. It needs no wolfSSL.
func NewOSCORESession(cfg PSKConfig) (*OSCORESession, error) {
	if err := cfg.check(); err != nil {
		return nil, err
	}
	if cfg.Profile != akmatls.ProfileOSCORE {
		return nil, fmt.Errorf("uaclient: profile %q is not %s", cfg.Profile, akmatls.ProfileOSCORE)
	}
	return &OSCORESession{cfg: cfg}, nil
}

// establish sends the Application Session Establishment Request, POST
// /akma (D.3.2 step 1), and derives the security context from K_AF and the
// two payloads (D.3.3). mu is held.
func (s *OSCORESession) establish(ctx context.Context) error {
	if s.conn == nil {
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
		if s.conn, err = net.DialUDP("udp", laddr, raddr); err != nil {
			return err
		}
	}
	// The ME derives K_AF for the AF_ID of OSCORE (TS 33.535 cl. 6.2.1
	// step 1).
	aKid, kaf, err := s.cfg.Keys(ctx, akmatls.UaStarOSCORE)
	if err != nil {
		return err
	}
	s.afID = s.cfg.FQDN + "." + akmatls.UaStarOSCORE.String()
	r := akmaoscore.Request{AKID: aKid, N1: make([]byte, akmaoscore.NonceSize),
		AFSID: make([]byte, akmaoscore.SenderIDSize)}
	if _, err := rand.Read(r.N1); err != nil {
		return err
	}
	if _, err := rand.Read(r.AFSID); err != nil {
		return err
	}
	payload, err := r.Marshal(akid.DefaultOptions())
	if err != nil {
		return fmt.Errorf("uaclient: A-KID: %w", err)
	}
	req := &coap.Message{Code: coap.POST, Payload: payload}
	req.Add(coap.OptionURIHost, []byte(s.cfg.FQDN))
	req.SetPath(akmaoscore.Path)
	req.Add(coap.OptionContentFormat, coap.EncodeUint(uint32(coap.FormatCBOR)))
	cc := coap.NewClient(s.conn)
	rsp, err := cc.Do(ctx, req)
	if err != nil {
		return err
	}
	if rsp.Code != coap.Created {
		return &RejectedError{CoAP: rsp.Code.String(), Cause: string(rsp.Payload)}
	}
	if f, ok := rsp.ContentFormat(); !ok || f != coap.FormatCBOR {
		return fmt.Errorf("uaclient: AKMA response not in CBOR")
	}
	a, err := akmaoscore.ParseResponse(rsp.Payload)
	if err != nil {
		return err
	}
	if bytes.Equal(a.UESID, r.AFSID) {
		return errors.New("uaclient: the AF chose a UE-SID equal to the AF-SID")
	}
	c, err := akmaoscore.Context(kaf, payload, rsp.Payload, r.AFSID, a.UESID, true)
	if err != nil {
		return err
	}
	s.client = oscore.NewClient(cc, c)
	return nil
}

// Establish sends GET of the session resource protected by OSCORE (D.3.2
// steps 5 and 6), after a POST /akma when there is no context yet or with
// Reconnect. With Renew, the request runs the protocol of RFC 8613 Appendix
// B.2 first, which gives the context a new ID Context (D.3.4).
func (s *OSCORESession) Establish(ctx context.Context) (Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.client == nil || s.cfg.Reconnect {
		if err := s.establish(ctx); err != nil {
			return Result{}, err
		}
	}
	req := &coap.Message{Code: coap.GET}
	req.Add(coap.OptionURIHost, []byte(s.cfg.FQDN))
	req.SetPath(s.cfg.Path)
	do := s.client.Do
	if s.cfg.Renew {
		do = s.client.Renew
	}
	rsp, err := do(ctx, req)
	var ue *oscore.UnprotectedError
	if errors.As(err, &ue) && ue.Code == coap.Unauthorized {
		// The AF has no context any more: its K_AF expired (TS 33.535
		// cl. 6.4.2) or it restarted. A new establishment, with a new N1
		// (D.3.4).
		if err = s.establish(ctx); err == nil {
			rsp, err = s.client.Do(ctx, req)
		}
	}
	if err != nil {
		return Result{}, err
	}
	if rsp.Code != coap.Content {
		var e struct {
			Cause string `json:"cause"`
		}
		_ = json.Unmarshal(rsp.Payload, &e)
		return Result{}, &RejectedError{CoAP: rsp.Code.String(), Cause: e.Cause}
	}
	var r Result
	if err := json.Unmarshal(rsp.Payload, &r); err != nil {
		return Result{}, fmt.Errorf("uaclient: response payload: %w", err)
	}
	r.AfID = s.afID
	r.IDContext = s.client.Context().IDContext()
	return r, nil
}

// Close closes the socket.
func (s *OSCORESession) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		s.conn.Close()
		s.conn, s.client = nil, nil
	}
}
