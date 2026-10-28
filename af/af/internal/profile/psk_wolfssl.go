//go:build wolfssl

package profile

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/florianoneto07/akma-free5gc/af/af/internal/config"
	"github.com/florianoneto07/akma-free5gc/af/af/internal/logger"
	"github.com/florianoneto07/akma-free5gc/af/af/internal/server"
	"github.com/florianoneto07/akma-free5gc/af/akmatls"
	"github.com/florianoneto07/akma-free5gc/af/coap"
	"github.com/florianoneto07/akma-free5gc/af/wolftls"
	"github.com/florianoneto07/akma-free5gc/shared/akma/afid"
)

// Built is true: this AF has the PSK profiles, and with wolfSSL it is
// licensed under the GNU General Public License v3.0.
const Built = true

const (
	// handshakeTimeout bounds a DTLS handshake, retransmissions included.
	handshakeTimeout = 15 * time.Second
	// idleTimeout ends a DTLS association without requests: UDP has no
	// end of connection.
	idleTimeout = 5 * time.Minute
)

// pskServer returns the wolfSSL server of a PSK profile (TS 24.109 K.3.2 and
// K.3.3; TS 33.535 Annex C) and the name of its protocol, for the log.
func pskServer(p config.Profile, s *config.Settings, ua *server.Server) (*wolftls.Server, string, error) {
	var version uint16
	var name string
	protocol := afid.UaStarTLS13
	switch p.Type {
	case akmatls.ProfilePSKTLS13:
		version, name = wolftls.VersionTLS13, "TLS 1.3"
	case akmatls.ProfilePSKTLS12:
		version, name = wolftls.VersionTLS12, "TLS 1.2"
	case akmatls.ProfilePSKDTLS13:
		version, name, protocol = wolftls.VersionDTLS13, "DTLS 1.3", akmatls.UaStarDTLS13
	default:
		version, name = wolftls.VersionDTLS12, "DTLS 1.2"
	}
	ws, err := wolftls.NewServer(wolftls.ServerConfig{
		Version:         version,
		ServerName:      s.FQDN,
		IdentityHint:    akmatls.IdentityHint,
		SessionLifetime: akmatls.SessionLifetime,
		Key: func(req wolftls.KeyRequest) (wolftls.Key, error) {
			// (D)TLS 1.3: the fixed identifier, known to the UE before the
			// ClientHello; (D)TLS 1.2: the one of the selected cipher
			// suite (TS 33.222 cl. 5.4.0.2 NOTE 0; TS 33.220 H.3).
			id := afid.AfID{FQDN: s.FQDN, Protocol: protocol}
			if req.CipherSuite != 0 {
				id.Protocol = akmatls.UaStarTLS(req.CipherSuite)
			}
			ctx, cancel := context.WithTimeout(context.Background(), config.DefaultAanfTimeout+time.Second)
			defer cancel()
			sess, kaf, err := ua.PSKKey(ctx, id, req.Identity, req.RemoteAddr.String())
			if err != nil {
				return wolftls.Key{}, err
			}
			// Expiry on the clock of the process, not on a shifted one.
			return wolftls.Key{PSK: kaf[:], Expiry: sess.KafExpiry.Add(-s.ClockOffset), Peer: sess}, nil
		},
		Expired: func(c *wolftls.Conn) {
			if sess, ok := c.State().Peer.(server.PSKSession); ok {
				logger.UaLog.Infof("K_AF of %s expired: %s session with %s closed", sess, name, c.RemoteAddr())
			}
		},
	})
	return ws, name, err
}

// pskListener returns the listener of a PSK TLS profile, the ConnContext
// that gives the handler the session of its connection, and the release of
// the wolfSSL context.
func pskListener(p config.Profile, s *config.Settings, ua *server.Server, l net.Listener) (net.Listener,
	func(context.Context, net.Conn) context.Context, func(), error) {
	ws, name, err := pskServer(p, s, ua)
	if err != nil {
		return nil, nil, nil, err
	}
	connCtx := func(ctx context.Context, c net.Conn) context.Context {
		lc, ok := c.(*loggedConn)
		if !ok {
			return ctx
		}
		return server.WithPSKSession(ctx, func() (server.PSKSession, bool) {
			sess, ok := lc.State().Peer.(server.PSKSession)
			return sess, ok
		})
	}
	return &loggingListener{Listener: ws.Listener(l), name: name}, connCtx, ws.Close, nil
}

// startDTLS serves a PSK DTLS profile: CoAP requests on DTLS associations
// (TS 33.535 Annex C; RFC 7252). It returns the stop of the server.
func startDTLS(p config.Profile, s *config.Settings, ua *server.Server) (func(), error) {
	addr, err := net.ResolveUDPAddr("udp", p.Listen)
	if err != nil {
		return nil, err
	}
	pc, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	ws, name, err := pskServer(p, s, ua)
	if err != nil {
		pc.Close()
		return nil, err
	}
	l, err := ws.ListenDTLS(pc)
	if err != nil {
		pc.Close()
		ws.Close()
		return nil, err
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				serveCoAP(c.(*wolftls.Conn), name, ua)
			}()
		}
	}()
	return func() {
		l.Close()
		wg.Wait()
		ws.Close()
	}, nil
}

// serveCoAP runs the handshake of one association and answers its CoAP
// requests until it ends, idles out or its K_AF expires.
func serveCoAP(c *wolftls.Conn, name string, ua *server.Server) {
	defer c.Close()
	remote := c.RemoteAddr().String()
	_ = c.SetReadDeadline(time.Now().Add(handshakeTimeout))
	if err := c.Handshake(); err != nil {
		logger.UaLog.Warnf("%s PSK handshake with %s failed: %v", name, remote, err)
		return
	}
	st := c.State()
	sess, _ := st.Peer.(server.PSKSession)
	logger.UaLog.Infof("%s PSK handshake with %s: %s, cipher suite %04X, resumed %t", name, remote, sess,
		st.CipherSuite, st.Resumed)
	var r coap.Responder
	buf := make([]byte, 2048)
	for {
		_ = c.SetReadDeadline(time.Now().Add(idleTimeout))
		n, err := c.Read(buf)
		if err != nil {
			return
		}
		out := r.Answer(buf[:n], time.Now(), func(req *coap.Message) *coap.Message {
			return ua.CoAP(req, sess, remote, "PSK DTLS")
		})
		if out != nil {
			if _, err := c.Write(out); err != nil {
				return
			}
		}
	}
}

// loggingListener logs the outcome of each handshake, which net/http does
// not see on a connection that is not a *tls.Conn.
type loggingListener struct {
	net.Listener
	name string
}

func (l *loggingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &loggedConn{Conn: c.(*wolftls.Conn), name: l.name}, nil
}

type loggedConn struct {
	*wolftls.Conn
	name string
	once sync.Once
}

func (c *loggedConn) Read(p []byte) (int, error) {
	c.once.Do(func() {
		if err := c.Handshake(); err != nil {
			logger.UaLog.Warnf("%s PSK handshake with %s failed: %v", c.name, c.RemoteAddr(), err)
			return
		}
		st := c.State()
		sess, _ := st.Peer.(server.PSKSession)
		logger.UaLog.Infof("%s PSK handshake with %s: %s, cipher suite %04X, resumed %t", c.name, c.RemoteAddr(),
			sess, st.CipherSuite, st.Resumed)
	})
	return c.Conn.Read(p)
}
