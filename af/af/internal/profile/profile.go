// Package profile opens the Ua* servers of the AF, one per profile of the
// configuration (TS 33.535 Annexes B, C and D; TS 24.109 Annex K).
package profile

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/florianoneto07/akma-free5gc/af/af/internal/config"
	"github.com/florianoneto07/akma-free5gc/af/af/internal/logger"
	"github.com/florianoneto07/akma-free5gc/af/af/internal/server"
	"github.com/florianoneto07/akma-free5gc/af/akmatls"
)

// Running is a profile being served.
type Running struct {
	Profile config.Profile
	srv     *http.Server // nil on UDP
	l       net.Listener
	release func()
}

// Start opens the listener of p and serves it with ua.
func Start(p config.Profile, s *config.Settings, ua *server.Server) (*Running, error) {
	if akmatls.IsUDP(p.Type) {
		start := startDTLS
		if p.Type == akmatls.ProfileOSCORE {
			start = startOSCORE
		}
		stop, err := start(p, s, ua)
		if err != nil {
			return nil, err
		}
		return &Running{Profile: p, release: stop}, nil
	}
	l, err := net.Listen("tcp", p.Listen)
	if err != nil {
		return nil, err
	}
	r := &Running{Profile: p, l: l, release: func() {}}
	r.srv = &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
		ErrorLog:          log.New(logger.UaLog.WriterLevel(logrus.WarnLevel), "", 0),
		// HTTP/1.1 only: the Ua* protocol needs nothing else.
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
	}
	switch p.Type {
	case akmatls.ProfileDigestHTTP:
		r.srv.Handler = ua
	case akmatls.ProfileDigestTLS:
		cfg, err := k2Config(p, s.FQDN)
		if err != nil {
			l.Close()
			return nil, err
		}
		r.l = tls.NewListener(l, cfg)
		r.srv.Handler = ua.DigestTLS()
	case akmatls.ProfilePSKTLS13, akmatls.ProfilePSKTLS12:
		pl, connCtx, release, err := pskListener(p, s, ua, l)
		if err != nil {
			l.Close()
			return nil, err
		}
		r.l, r.srv.ConnContext, r.release = pl, connCtx, release
		r.srv.Handler = ua.PSK()
	default:
		l.Close()
		return nil, fmt.Errorf("profile type %q", p.Type)
	}
	go func() {
		if err := r.srv.Serve(r.l); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.MainLog.Errorf("Ua* server %s on %s: %v", p.Type, p.Listen, err)
		}
	}()
	return r, nil
}

// Shutdown stops the server.
func (r *Running) Shutdown(ctx context.Context) {
	if r.srv != nil {
		_ = r.srv.Shutdown(ctx)
	}
	r.release()
}

// k2Config loads the certificate of the AF and checks that it names the
// FQDN of the AF, which the UE checks (TS 33.222 cl. 5.3.1.3).
func k2Config(p config.Profile, fqdn string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(p.Certificate, p.Key)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", p.Type, err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("%s: %w", p.Type, err)
	}
	if err := leaf.VerifyHostname(fqdn); err != nil {
		return nil, fmt.Errorf("%s: certificate %s: %w", p.Type, p.Certificate, err)
	}
	return akmatls.ServerConfig(cert), nil
}
