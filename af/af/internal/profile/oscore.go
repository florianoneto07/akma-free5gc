package profile

import (
	"net"
	"sync"
	"time"

	"github.com/florianoneto07/akma-free5gc/af/af/internal/config"
	"github.com/florianoneto07/akma-free5gc/af/af/internal/logger"
	"github.com/florianoneto07/akma-free5gc/af/af/internal/server"
	"github.com/florianoneto07/akma-free5gc/af/akmaoscore"
	"github.com/florianoneto07/akma-free5gc/af/coap"
	"github.com/florianoneto07/akma-free5gc/af/oscore"
)

// Bounds of the OSCORE contexts of the AF.
var oscoreLimits = oscore.Limits{
	MaxContexts: 4096,
	// The newest contexts of an A-KID.
	MaxPerGroup: 4,
	// A context with which no request was verified, and an R2 of RFC 8613
	// Appendix B.2 not used.
	PendingLifetime: 60 * time.Second,
}

// pruneInterval is how often expired and pending contexts are removed; a
// request with an expired one fails before that.
const pruneInterval = 10 * time.Second

// startOSCORE serves the OSCORE profile (TS 33.535 Annex D) on UDP: POST
// /akma establishes a security context from K_AF, and requests protected
// with it get the session resource. It returns the stop of the server.
func startOSCORE(p config.Profile, s *config.Settings, ua *server.Server) (func(), error) {
	addr, err := net.ResolveUDPAddr("udp", p.Listen)
	if err != nil {
		return nil, err
	}
	pc, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	store := oscore.NewServer(oscoreLimits, nil)
	store.Renewed = func(e *oscore.Entry, c *oscore.Context) {
		sess, _ := e.Data.(server.PSKSession)
		logger.UaLog.Infof("OSCORE context of %s with UE-SID %x renewed (RFC 8613 Appendix B.2), ID Context %x",
			sess, c.RecipientID(), c.IDContext())
	}
	cs := &coap.Server{Handle: func(m *coap.Message, from net.Addr) *coap.Message {
		return handleOSCORE(m, from.String(), s, ua, store)
	}}
	var wg sync.WaitGroup
	done := make(chan struct{})
	wg.Add(2)
	go func() {
		defer wg.Done()
		_ = cs.Serve(pc)
	}()
	go func() {
		defer wg.Done()
		t := time.NewTicker(pruneInterval)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				for _, e := range store.Prune() {
					logRemoved(e)
				}
			}
		}
	}()
	return func() {
		close(done)
		pc.Close()
		wg.Wait()
	}, nil
}

func handleOSCORE(m *coap.Message, remote string, s *config.Settings, ua *server.Server, store *oscore.Server) *coap.Message {
	if _, ok := m.Option(coap.OptionOSCORE); ok {
		rsp := store.Handle(m, func(in *coap.Message, e *oscore.Entry) *coap.Message {
			return ua.CoAP(in, e.Data.(server.PSKSession), remote, "OSCORE")
		})
		if _, protected := rsp.Option(coap.OptionOSCORE); !protected {
			logger.UaLog.Warnf("OSCORE request from %s refused: %s %s", remote, rsp.Code, rsp.Payload)
		}
		return rsp
	}
	switch m.Path() {
	case akmaoscore.Path:
		return ua.AKMA(m, store, remote)
	case s.Path:
		// The session resource only answers requests protected by OSCORE.
		logger.UaLog.Warnf("Request from %s for %s without OSCORE", remote, s.Path)
		return &coap.Message{Code: coap.Unauthorized, Payload: []byte(server.CauseOSCORERequired)}
	}
	return &coap.Message{Code: coap.NotFound, Payload: []byte(server.CauseNotFound)}
}

func logRemoved(e *oscore.Entry) {
	sess, _ := e.Data.(server.PSKSession)
	if time.Now().Before(e.Expiry) {
		logger.UaLog.Infof("OSCORE context of %s with UE-SID %x not used: removed", sess, e.Context.RecipientID())
		return
	}
	logger.UaLog.Infof("K_AF of %s expired: OSCORE context with UE-SID %x removed", sess, e.Context.RecipientID())
}
