//go:build wolfssl

// Copyright 2026 Floriano Neto.
// Licensed under the GNU General Public License v3.0 or later; see COPYING.

package wolftls

/*
#cgo CFLAGS: -I${SRCDIR}/../build/wolfssl/install/include
#cgo LDFLAGS: ${SRCDIR}/../build/wolfssl/install/lib/libwolfssl.a -lm -lpthread
#include "shim.h"
*/
import "C"

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
	"unsafe"
)

// TLS and DTLS versions, as wolfSSL_version gives them.
const (
	VersionTLS12  uint16 = 0x0303
	VersionTLS13  uint16 = 0x0304
	VersionDTLS12 uint16 = 0xFEFD
	VersionDTLS13 uint16 = 0xFEFC
)

// isDTLS reports whether v is a DTLS version.
func isDTLS(v uint16) bool { return v == VersionDTLS12 || v == VersionDTLS13 }

// is13 reports whether v is TLS 1.3 or DTLS 1.3.
func is13(v uint16) bool { return v == VersionTLS13 || v == VersionDTLS13 }

// Cipher suites negotiated with a PSK.
const (
	// TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 is mandatory with PSK in TLS 1.2
	// (TS 33.210 cl. 6.2.3; RFC 8442).
	TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 uint16 = 0xD001
	// TLS_AES_128_GCM_SHA256 goes with an external PSK in TLS 1.3, whose
	// hash defaults to SHA-256 (RFC 8446 cl. 4.2.11).
	TLS_AES_128_GCM_SHA256 uint16 = 0x1301
)

// Cipher lists in wolfSSL names. TLS 1.2 suites are ECDHE with AES-GCM only
// (TS 33.210 cl. 6.2.3); TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384,
// recommended there, is not in wolfSSL.
const (
	serverList12 = "ECDHE-PSK-AES128-GCM-SHA256"
	serverList13 = "TLS13-AES128-GCM-SHA256"
	// A TLS 1.2 client also offers suites without PSK (TS 33.222
	// cl. 5.4.0.1 step 1). It has no trusted certificate, so a server
	// that selects one of them fails the handshake.
	clientList12 = "ECDHE-PSK-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:" +
		"ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"
	clientList13 = "TLS13-AES128-GCM-SHA256:TLS13-AES256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256"
)

// groups are the key exchange groups: P-256 (mandatory), x25519 and P-384
// (TS 33.210 cl. 6.2.2 and 6.2.3).
var groups = [...]C.int{C.WOLFSSL_ECC_SECP256R1, C.WOLFSSL_ECC_X25519, C.WOLFSSL_ECC_SECP384R1}

// KeyRequest is what the server's Key function gets.
type KeyRequest struct {
	// Identity is the PSK identity sent by the client.
	Identity string
	// CipherSuite is the negotiated cipher suite in TLS 1.2, zero in
	// TLS 1.3.
	CipherSuite uint16
	// RemoteAddr is the address of the client.
	RemoteAddr net.Addr
}

// Key is what the server's Key function returns for a PSK identity.
type Key struct {
	// PSK is the external pre-shared key.
	PSK []byte
	// Expiry ends the use of the key: Conn closes at Expiry, and no
	// session ticket of the connection is accepted from then on. Zero: no
	// expiry.
	Expiry time.Time
	// Peer is given back in ConnState.Peer, also on a resumed connection.
	Peer any
}

// ServerConfig configures a Server.
type ServerConfig struct {
	// Version is VersionTLS12, VersionTLS13, VersionDTLS12 or
	// VersionDTLS13.
	Version uint16
	// ServerName is the name the client must send in server_name.
	ServerName string
	// IdentityHint is the psk_identity_hint of the ServerKeyExchange
	// (TLS 1.2).
	IdentityHint string
	// Key returns the PSK of an identity. An error refuses the identity
	// and fails the handshake; Conn.Handshake then returns an *Error that
	// wraps it. It runs during the handshake and must not call methods of
	// the connection.
	Key func(KeyRequest) (Key, error)
	// SessionLifetime bounds the session tickets; zero disables them and
	// with them resumption.
	SessionLifetime time.Duration
	// Expired, if set, is called when a connection reaches Key.Expiry,
	// before it is closed.
	Expired func(*Conn)
}

// ClientConfig configures a Client.
type ClientConfig struct {
	// Version is VersionTLS12, VersionTLS13, VersionDTLS12 or
	// VersionDTLS13.
	Version uint16
	// ServerName is sent in server_name.
	ServerName string
	// Key returns the PSK identity and the PSK. In (D)TLS 1.2 it is called
	// after the ServerHello, with the hint of the server and the
	// negotiated cipher suite; in (D)TLS 1.3 before the ClientHello, with
	// TLS_AES_128_GCM_SHA256.
	Key func(hint string, cipherSuite uint16) (identity string, psk []byte, err error)
	// OfferPSKKEOnly makes a TLS 1.3 ClientHello offer psk_ke and not
	// psk_dhe_ke, which TS 33.210 cl. 6.2.2 forbids. Test only.
	OfferPSKKEOnly bool
}

// Error is a failure reported by wolfSSL.
type Error struct {
	Op    string // handshake, read, write
	Code  int    // wolfSSL error code
	Text  string
	Cause error // error of a Key function, if one failed
}

func (e *Error) Error() string {
	msg := fmt.Sprintf("wolftls: %s: %s (%d)", e.Op, e.Text, e.Code)
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

func (e *Error) Unwrap() error { return e.Cause }

var initOnce sync.Once

func initLibrary() {
	initOnce.Do(func() { C.wolfSSL_Init() })
}

// Server makes server connections with one configuration.
type Server struct {
	cfg     ServerConfig
	ctx     *C.WOLFSSL_CTX
	tickets *ticketStore
	// cookieSecret keys the DTLS 1.2 cookies, which bind the
	// HelloVerifyRequest to the address of the client.
	cookieSecret []byte
}

// NewServer checks cfg and builds its wolfSSL context.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Key == nil {
		return nil, errors.New("wolftls: Key is required")
	}
	if cfg.ServerName == "" {
		return nil, errors.New("wolftls: ServerName is required")
	}
	initLibrary()
	var method *C.WOLFSSL_METHOD
	list := serverList12
	switch cfg.Version {
	case VersionTLS12:
		method = C.wolfTLSv1_2_server_method()
	case VersionTLS13:
		method, list = C.wolfTLSv1_3_server_method(), serverList13
	case VersionDTLS12:
		method = C.wolfDTLSv1_2_server_method()
	case VersionDTLS13:
		method, list = C.wolfDTLSv1_3_server_method(), serverList13
	default:
		return nil, fmt.Errorf("wolftls: version %#04x is not TLS or DTLS 1.2 or 1.3", cfg.Version)
	}
	ctx := C.wolfSSL_CTX_new(method)
	if ctx == nil {
		return nil, errors.New("wolftls: wolfSSL_CTX_new failed")
	}
	s := &Server{cfg: cfg, ctx: ctx}
	if isDTLS(cfg.Version) {
		s.cookieSecret = make([]byte, 32)
		if _, err := rand.Read(s.cookieSecret); err != nil {
			C.wolfSSL_CTX_free(ctx)
			return nil, err
		}
	}
	if err := s.setup(list); err != nil {
		C.wolfSSL_CTX_free(ctx)
		return nil, err
	}
	return s, nil
}

func (s *Server) setup(list string) error {
	tls13 := is13(s.cfg.Version)
	if err := setCommon(s.ctx, list); err != nil {
		return err
	}
	name := C.CString(s.cfg.ServerName)
	defer C.free(unsafe.Pointer(name))
	if C.wolfSSL_CTX_UseSNI(s.ctx, C.WOLFSSL_SNI_HOST_NAME, unsafe.Pointer(name), C.word16(len(s.cfg.ServerName))) != C.WOLFSSL_SUCCESS {
		return errors.New("wolftls: server name not set")
	}
	// A client that sends another name or none is refused.
	C.wolfSSL_CTX_SNI_SetOptions(s.ctx, C.WOLFSSL_SNI_HOST_NAME, C.WOLFSSL_SNI_ABORT_ON_ABSENCE)
	if tls13 {
		C.wolfSSL_CTX_only_dhe_psk(s.ctx)
	} else if s.cfg.IdentityHint != "" {
		hint := C.CString(s.cfg.IdentityHint)
		defer C.free(unsafe.Pointer(hint))
		if C.wolfSSL_CTX_use_psk_identity_hint(s.ctx, hint) != C.WOLFSSL_SUCCESS {
			return errors.New("wolftls: identity hint not set")
		}
	}
	tickets := 0
	if s.cfg.SessionLifetime > 0 {
		st, err := newTicketStore(s.cfg.SessionLifetime)
		if err != nil {
			return err
		}
		s.tickets, tickets = st, 1
		secs := C.int(s.cfg.SessionLifetime / time.Second)
		C.wolfSSL_CTX_set_TicketHint(s.ctx, secs)
		C.wolfSSL_CTX_set_timeout(s.ctx, C.uint(secs))
	}
	C.wolftls_setup_server(s.ctx, cBool(tls13), C.int(tickets), cBool(isDTLS(s.cfg.Version)))
	return nil
}

func cBool(b bool) C.int {
	if b {
		return 1
	}
	return 0
}

// Server returns a TLS server connection over raw. The handshake runs on
// the first Read or Write, or on Handshake. A DTLS server takes its
// connections from ListenDTLS.
func (s *Server) Server(raw net.Conn) *Conn {
	conn := newConn(raw, s.ctx, s, nil, false)
	if isDTLS(s.cfg.Version) {
		conn.setupErr = errors.New("wolftls: a DTLS server takes its connections from ListenDTLS")
	}
	return conn
}

// Listener returns a listener whose connections are server connections
// over those of l.
func (s *Server) Listener(l net.Listener) net.Listener {
	return &listener{Listener: l, s: s}
}

// Close releases the wolfSSL context. Open connections keep a reference
// to it.
func (s *Server) Close() {
	C.wolfSSL_CTX_free(s.ctx)
}

type listener struct {
	net.Listener
	s *Server
}

func (l *listener) Accept() (net.Conn, error) {
	raw, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return l.s.Server(raw), nil
}

// Client makes client connections with one configuration.
type Client struct {
	cfg ClientConfig
	ctx *C.WOLFSSL_CTX
}

// NewClient checks cfg and builds its wolfSSL context.
func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.Key == nil {
		return nil, errors.New("wolftls: Key is required")
	}
	if cfg.ServerName == "" {
		return nil, errors.New("wolftls: ServerName is required")
	}
	initLibrary()
	var method *C.WOLFSSL_METHOD
	list := clientList12
	switch cfg.Version {
	case VersionTLS12:
		method = C.wolfTLSv1_2_client_method()
	case VersionTLS13:
		method, list = C.wolfTLSv1_3_client_method(), clientList13
	case VersionDTLS12:
		method = C.wolfDTLSv1_2_client_method()
	case VersionDTLS13:
		method, list = C.wolfDTLSv1_3_client_method(), clientList13
	default:
		return nil, fmt.Errorf("wolftls: version %#04x is not TLS or DTLS 1.2 or 1.3", cfg.Version)
	}
	ctx := C.wolfSSL_CTX_new(method)
	if ctx == nil {
		return nil, errors.New("wolftls: wolfSSL_CTX_new failed")
	}
	if err := setCommon(ctx, list); err != nil {
		C.wolfSSL_CTX_free(ctx)
		return nil, err
	}
	// No certificate is trusted: the server is authenticated by the PSK.
	C.wolfSSL_CTX_set_verify(ctx, C.WOLFSSL_VERIFY_PEER, nil)
	tls13 := C.int(0)
	if is13(cfg.Version) {
		tls13 = 1
		if cfg.OfferPSKKEOnly {
			C.wolfSSL_CTX_no_dhe_psk(ctx)
		} else {
			C.wolfSSL_CTX_only_dhe_psk(ctx)
		}
	} else if C.wolfSSL_CTX_UseSessionTicket(ctx) != C.WOLFSSL_SUCCESS {
		C.wolfSSL_CTX_free(ctx)
		return nil, errors.New("wolftls: session tickets not enabled")
	}
	C.wolftls_setup_client(ctx, tls13)
	return &Client{cfg: cfg, ctx: ctx}, nil
}

// Client returns a client connection over raw: a stream for TLS, a
// connected UDP socket for DTLS. With resume, the handshake first offers
// that session (Conn.Session of an earlier connection).
func (c *Client) Client(raw net.Conn, resume *Session) *Conn {
	conn := newConn(raw, c.ctx, nil, c, isDTLS(c.cfg.Version))
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.ssl == nil {
		return conn
	}
	name := C.CString(c.cfg.ServerName)
	defer C.free(unsafe.Pointer(name))
	if C.wolfSSL_UseSNI(conn.ssl, C.WOLFSSL_SNI_HOST_NAME, unsafe.Pointer(name), C.word16(len(c.cfg.ServerName))) != C.WOLFSSL_SUCCESS {
		conn.setupErr = errors.New("wolftls: server name not set")
		return conn
	}
	if resume != nil && resume.s != nil && C.wolfSSL_set_session(conn.ssl, resume.s) != C.WOLFSSL_SUCCESS {
		conn.setupErr = errors.New("wolftls: session not set")
	}
	return conn
}

// Close releases the wolfSSL context. Open connections keep a reference
// to it.
func (c *Client) Close() {
	C.wolfSSL_CTX_free(c.ctx)
}

// Session is a client session that a later connection can resume.
type Session struct {
	s *C.WOLFSSL_SESSION
}

// Free releases the session.
func (s *Session) Free() {
	if s != nil && s.s != nil {
		C.wolfSSL_SESSION_free(s.s)
		s.s = nil
	}
}

func setCommon(ctx *C.WOLFSSL_CTX, list string) error {
	cl := C.CString(list)
	defer C.free(unsafe.Pointer(cl))
	if C.wolfSSL_CTX_set_cipher_list(ctx, cl) != C.WOLFSSL_SUCCESS {
		return fmt.Errorf("wolftls: cipher list %q not accepted", list)
	}
	g := groups
	if C.wolfSSL_CTX_set_groups(ctx, &g[0], C.int(len(g))) != C.WOLFSSL_SUCCESS {
		return errors.New("wolftls: groups not accepted")
	}
	return nil
}
