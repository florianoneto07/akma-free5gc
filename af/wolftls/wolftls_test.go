//go:build wolfssl

// Copyright 2026 Floriano Neto.
// Licensed under the GNU General Public License v3.0 or later; see COPYING.

package wolftls

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	serverName = "af1.akma.example"
	hint       = "3GPP-AKMA"
	identity   = "3GPP-AKMA;rid-test-akid@ba.akma.mnc093.mcc208.3gppnetwork.org"
)

var (
	psk      = bytes.Repeat([]byte{0x5a}, 32)
	otherPSK = bytes.Repeat([]byte{0xa5}, 32)
	errNoKey = errors.New("no K_AKMA for this A-KID")
)

// fixture is a server on a loopback listener.
type fixture struct {
	t        *testing.T
	srv      *Server
	l        net.Listener
	keyCalls atomic.Int32
	suites   chan uint16
	conns    chan *Conn
}

func newFixture(t *testing.T, version uint16, mod func(*ServerConfig)) *fixture {
	t.Helper()
	f := &fixture{t: t, suites: make(chan uint16, 8), conns: make(chan *Conn, 8)}
	cfg := ServerConfig{
		Version: version, ServerName: serverName, IdentityHint: hint, SessionLifetime: time.Hour,
		Key: func(req KeyRequest) (Key, error) {
			f.keyCalls.Add(1)
			f.suites <- req.CipherSuite
			if req.Identity != identity {
				return Key{}, errNoKey
			}
			return Key{PSK: psk, Expiry: time.Now().Add(time.Hour), Peer: "ue-1"}, nil
		},
	}
	if mod != nil {
		mod(&cfg)
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.srv, f.l = srv, srv.Listener(l)
	t.Cleanup(func() { f.l.Close(); srv.Close() })
	go f.serve()
	return f
}

// serve echoes one line per connection.
func (f *fixture) serve() {
	for {
		c, err := f.l.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			wc := c.(*Conn)
			_ = wc.SetDeadline(time.Now().Add(5 * time.Second))
			buf := make([]byte, 64)
			n, err := wc.Read(buf)
			f.conns <- wc
			if err != nil {
				return
			}
			_, _ = wc.Write(buf[:n])
			_, _ = wc.Read(buf) // until the client closes
		}()
	}
}

type clientOpts struct {
	version    uint16
	psk        []byte
	identity   string
	serverName string
	pskKEOnly  bool
	resume     *Session
}

// dial runs a client connection and one echo; it returns the connection,
// open, or the first error.
func (f *fixture) dial(o clientOpts) (*Conn, string, error) {
	f.t.Helper()
	if o.psk == nil {
		o.psk = psk
	}
	if o.identity == "" {
		o.identity = identity
	}
	if o.serverName == "" {
		o.serverName = serverName
	}
	var gotHint string
	cli, err := NewClient(ClientConfig{
		Version: o.version, ServerName: o.serverName, OfferPSKKEOnly: o.pskKEOnly,
		Key: func(h string, suite uint16) (string, []byte, error) {
			gotHint = h
			return o.identity, o.psk, nil
		},
	})
	if err != nil {
		f.t.Fatal(err)
	}
	defer cli.Close()
	raw, err := net.Dial("tcp", f.l.Addr().String())
	if err != nil {
		f.t.Fatal(err)
	}
	c := cli.Client(raw, o.resume)
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte("ping\n")); err != nil {
		c.Close()
		return nil, gotHint, err
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(c, buf); err != nil {
		c.Close()
		return nil, gotHint, err
	}
	if string(buf) != "ping\n" {
		f.t.Fatalf("echo %q", buf)
	}
	return c, gotHint, nil
}

func (f *fixture) serverConn() *Conn {
	select {
	case c := <-f.conns:
		return c
	case <-time.After(5 * time.Second):
		f.t.Fatal("no server connection")
		return nil
	}
}

func TestTLS13PSK(t *testing.T) {
	f := newFixture(t, VersionTLS13, nil)
	c, _, err := f.dial(clientOpts{version: VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	st := c.State()
	if st.Version != VersionTLS13 || st.CipherSuite != TLS_AES_128_GCM_SHA256 || st.Identity != identity {
		t.Fatalf("client state %+v", st)
	}
	sst := f.serverConn().State()
	if sst.Identity != identity || sst.Peer != "ue-1" || sst.Resumed {
		t.Fatalf("server state %+v", sst)
	}
}

func TestTLS12PSK(t *testing.T) {
	f := newFixture(t, VersionTLS12, nil)
	c, gotHint, err := f.dial(clientOpts{version: VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	st := c.State()
	if st.Version != VersionTLS12 || st.CipherSuite != TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 {
		t.Fatalf("client state %+v", st)
	}
	if gotHint != hint {
		t.Fatalf("hint %q", gotHint)
	}
	if s := <-f.suites; s != TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 {
		t.Fatalf("suite at the server key lookup %#04x", s)
	}
	if sst := f.serverConn().State(); sst.Identity != identity || sst.Peer != "ue-1" {
		t.Fatalf("server state %+v", sst)
	}
}

func TestWrongKeyFails(t *testing.T) {
	for _, v := range []uint16{VersionTLS12, VersionTLS13} {
		f := newFixture(t, v, nil)
		if _, _, err := f.dial(clientOpts{version: v, psk: otherPSK}); err == nil {
			t.Fatalf("%#04x: handshake with another key succeeded", v)
		}
	}
}

func TestUnknownIdentityRefused(t *testing.T) {
	for _, v := range []uint16{VersionTLS12, VersionTLS13} {
		f := newFixture(t, v, nil)
		if _, _, err := f.dial(clientOpts{version: v, identity: "3GPP-AKMA;unknown@x"}); err == nil {
			t.Fatalf("%#04x: unknown identity accepted", v)
		}
		c := f.serverConn()
		var werr *Error
		if err := c.Handshake(); !errors.Is(err, errNoKey) || !errors.As(err, &werr) {
			t.Fatalf("%#04x: server error %v does not carry the cause", v, err)
		}
	}
}

// TS 33.210 cl. 6.2.2: psk_ke shall not be supported.
func TestPSKKERefused(t *testing.T) {
	f := newFixture(t, VersionTLS13, nil)
	if _, _, err := f.dial(clientOpts{version: VersionTLS13, pskKEOnly: true}); err == nil {
		t.Fatal("a ClientHello with psk_ke only was accepted")
	}
}

func TestServerNameRequired(t *testing.T) {
	for _, v := range []uint16{VersionTLS12, VersionTLS13} {
		f := newFixture(t, v, nil)
		if _, _, err := f.dial(clientOpts{version: v, serverName: "af2.akma.example"}); err == nil {
			t.Fatalf("%#04x: another server name accepted", v)
		}
	}
}

func TestResumption(t *testing.T) {
	for _, v := range []uint16{VersionTLS12, VersionTLS13} {
		t.Run(fmt.Sprintf("%#04x", v), func(t *testing.T) {
			f := newFixture(t, v, nil)
			c, _, err := f.dial(clientOpts{version: v})
			if err != nil {
				t.Fatal(err)
			}
			sess := c.Session()
			c.Close()
			f.serverConn()
			if sess == nil {
				t.Fatal("no session")
			}
			defer sess.Free()
			c2, _, err := f.dial(clientOpts{version: v, resume: sess})
			if err != nil {
				t.Fatal(err)
			}
			defer c2.Close()
			if !c2.State().Resumed {
				t.Fatal("client did not resume")
			}
			sst := f.serverConn().State()
			if !sst.Resumed || sst.Identity != identity || sst.Peer != "ue-1" {
				t.Fatalf("server state %+v", sst)
			}
			if n := f.keyCalls.Load(); n != 1 {
				t.Fatalf("%d key lookups, want 1", n)
			}
		})
	}
}

// TS 33.535 cl. 6.4.2, TS 33.222 cl. 5.4.1.4: the session ends with the key,
// and its tickets with it.
func TestExpiry(t *testing.T) {
	for _, v := range []uint16{VersionTLS12, VersionTLS13} {
		t.Run(fmt.Sprintf("%#04x", v), func(t *testing.T) {
			var expired atomic.Bool
			f := newFixture(t, v, func(cfg *ServerConfig) {
				key := cfg.Key
				cfg.Key = func(req KeyRequest) (Key, error) {
					k, err := key(req)
					k.Expiry = time.Now().Add(1500 * time.Millisecond)
					return k, err
				}
				cfg.Expired = func(*Conn) { expired.Store(true) }
			})
			c, _, err := f.dial(clientOpts{version: v})
			if err != nil {
				t.Fatal(err)
			}
			sess := c.Session()
			defer sess.Free()
			f.serverConn()
			buf := make([]byte, 1)
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := c.Read(buf); err != io.EOF {
				t.Fatalf("read after the expiry: %v, want EOF (close_notify)", err)
			}
			c.Close()
			if !expired.Load() {
				t.Fatal("Expired not called")
			}
			c2, _, err := f.dial(clientOpts{version: v, resume: sess})
			if err != nil {
				t.Fatal(err)
			}
			defer c2.Close()
			if sst := f.serverConn().State(); sst.Resumed {
				t.Fatal("a ticket of an expired key was accepted")
			}
			if n := f.keyCalls.Load(); n != 2 {
				t.Fatalf("%d key lookups, want 2", n)
			}
		})
	}
}

// recorder keeps what a client sends and receives.
type recorder struct {
	net.Conn
	mu      sync.Mutex
	in, out bytes.Buffer
}

func (r *recorder) Read(p []byte) (int, error) {
	n, err := r.Conn.Read(p)
	r.mu.Lock()
	r.in.Write(p[:n])
	r.mu.Unlock()
	return n, err
}

func (r *recorder) Write(p []byte) (int, error) {
	r.mu.Lock()
	r.out.Write(p)
	r.mu.Unlock()
	return r.Conn.Write(p)
}

// hello returns the extensions of the first handshake message of a stream,
// and its cipher suites (ClientHello) or cipher suite (ServerHello).
func hello(t *testing.T, stream []byte) (map[uint16][]byte, []uint16) {
	t.Helper()
	if len(stream) < 5 || stream[0] != 22 {
		t.Fatalf("not a handshake record: % x", stream[:min(len(stream), 5)])
	}
	rec := stream[5 : 5+int(binary.BigEndian.Uint16(stream[3:5]))]
	typ, body := rec[0], rec[4:4+(int(rec[1])<<16|int(rec[2])<<8|int(rec[3]))]
	p := body[2+32:]
	p = p[1+int(p[0]):] // session id
	var suites []uint16
	if typ == 1 {
		n := int(binary.BigEndian.Uint16(p))
		for i := 0; i < n; i += 2 {
			suites = append(suites, binary.BigEndian.Uint16(p[2+i:]))
		}
		p = p[2+n:]
		p = p[1+int(p[0]):] // compression methods
	} else {
		suites = []uint16{binary.BigEndian.Uint16(p)}
		p = p[3:]
	}
	exts := map[uint16][]byte{}
	p = p[2:]
	for len(p) >= 4 {
		typ, n := binary.BigEndian.Uint16(p), int(binary.BigEndian.Uint16(p[2:]))
		exts[typ] = p[4 : 4+n]
		p = p[4+n:]
	}
	return exts, suites
}

const (
	extServerName      = 0
	extSupportedGroups = 10
	extEMS             = 23
	extEarlyData       = 42
	extPSKModes        = 45
	extRenegInfo       = 0xff01
)

// TS 33.210 cl. 6.2.3 and TS 24.109 K.3.2: the suites and extensions on the
// wire, TLS 1.2.
func TestTLS12Hello(t *testing.T) {
	f := newFixture(t, VersionTLS12, nil)
	rec := dialRecorded(t, f, VersionTLS12)
	ch, offered := hello(t, rec.out.Bytes())
	if !bytes.Contains(ch[extServerName], []byte(serverName)) {
		t.Error("ClientHello without the server name")
	}
	if _, ok := ch[extEMS]; !ok {
		t.Error("ClientHello without extended_master_secret")
	}
	if offered[0] != TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 || !slices.Contains(offered, 0xC02B) || !slices.Contains(offered, 0xC02F) {
		t.Errorf("ClientHello suites %04x: PSK first, then the suites without PSK", offered)
	}
	groups := ch[extSupportedGroups]
	if !bytes.Equal(groups, []byte{0, 6, 0, 23, 0, 29, 0, 24}) {
		t.Errorf("supported groups % x, want P-256, x25519, P-384", groups)
	}
	sh, chosen := hello(t, rec.in.Bytes())
	if chosen[0] != TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 {
		t.Errorf("ServerHello suite %04x", chosen[0])
	}
	for _, e := range []uint16{extEMS, extRenegInfo} {
		if _, ok := sh[e]; !ok {
			t.Errorf("ServerHello without extension %#04x", e)
		}
	}
}

// TS 33.210 cl. 6.2.2 and TS 24.109 K.3.3: psk_dhe_ke only, no early data.
func TestTLS13Hello(t *testing.T) {
	f := newFixture(t, VersionTLS13, nil)
	rec := dialRecorded(t, f, VersionTLS13)
	ch, _ := hello(t, rec.out.Bytes())
	if !bytes.Equal(ch[extPSKModes], []byte{1, 1}) {
		t.Errorf("psk_key_exchange_modes % x, want psk_dhe_ke only", ch[extPSKModes])
	}
	if _, ok := ch[extEarlyData]; ok {
		t.Error("ClientHello offers early data")
	}
	if !bytes.Contains(ch[41], []byte(identity)) {
		t.Error("pre_shared_key without the identity")
	}
	if !bytes.Contains(ch[extServerName], []byte(serverName)) {
		t.Error("ClientHello without the server name")
	}
}

func dialRecorded(t *testing.T, f *fixture, v uint16) *recorder {
	t.Helper()
	cli, err := NewClient(ClientConfig{Version: v, ServerName: serverName,
		Key: func(string, uint16) (string, []byte, error) { return identity, psk, nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	raw, err := net.Dial("tcp", f.l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	rec := &recorder{Conn: raw}
	c := cli.Client(rec, nil)
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if err := c.Handshake(); err != nil {
		t.Fatal(err)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return &recorder{in: *bytes.NewBuffer(slices.Clone(rec.in.Bytes())), out: *bytes.NewBuffer(slices.Clone(rec.out.Bytes()))}
}

// net/http reads in the background while a handler writes, and aborts that
// read with a past deadline: several requests on one connection.
func TestHTTP(t *testing.T) {
	for _, v := range []uint16{VersionTLS12, VersionTLS13} {
		t.Run(fmt.Sprintf("%#04x", v), func(t *testing.T) {
			srv, err := NewServer(ServerConfig{Version: v, ServerName: serverName, IdentityHint: hint,
				Key: func(KeyRequest) (Key, error) { return Key{PSK: psk}, nil }})
			if err != nil {
				t.Fatal(err)
			}
			defer srv.Close()
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			hs := &http.Server{
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					body, _ := io.ReadAll(r.Body)
					fmt.Fprintf(w, "%s %d", r.URL.Path, len(body))
				}),
				ConnContext: func(ctx context.Context, c net.Conn) context.Context { return ctx },
			}
			go hs.Serve(srv.Listener(l))
			defer hs.Close()

			cli, err := NewClient(ClientConfig{Version: v, ServerName: serverName,
				Key: func(string, uint16) (string, []byte, error) { return identity, psk, nil }})
			if err != nil {
				t.Fatal(err)
			}
			defer cli.Close()
			var dials atomic.Int32
			hc := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
				DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					dials.Add(1)
					raw, err := (&net.Dialer{}).DialContext(ctx, network, addr)
					if err != nil {
						return nil, err
					}
					c := cli.Client(raw, nil)
					if err := c.Handshake(); err != nil {
						c.Close()
						return nil, err
					}
					return c, nil
				},
			}}
			defer hc.CloseIdleConnections()
			for i := range 5 {
				body := strings.Repeat("x", i*20000)
				rsp, err := hc.Post("https://"+l.Addr().String()+"/p", "text/plain", strings.NewReader(body))
				if err != nil {
					t.Fatal(err)
				}
				got, _ := io.ReadAll(rsp.Body)
				rsp.Body.Close()
				if want := fmt.Sprintf("/p %d", len(body)); string(got) != want {
					t.Fatalf("response %q, want %q", got, want)
				}
			}
			if n := dials.Load(); n != 1 {
				t.Fatalf("%d connections, want 1", n)
			}
		})
	}
}

// An independent client: OpenSSL with an external PSK in TLS 1.3. OpenSSL
// 3.0 has no TLS 1.2 ECDHE_PSK with AES-GCM, so only TLS 1.3 is checked.
func TestOpenSSLClient(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not found")
	}
	srv, err := NewServer(ServerConfig{Version: VersionTLS13, ServerName: serverName,
		Key: func(req KeyRequest) (Key, error) {
			if req.Identity != identity {
				return Key{}, errNoKey
			}
			return Key{PSK: psk}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	states := make(chan ConnState, 1)
	go func() {
		raw, err := l.Accept()
		if err != nil {
			return
		}
		c := srv.Server(raw)
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		line, err := bufio.NewReader(c).ReadString('\n')
		states <- c.State()
		if err == nil {
			_, _ = c.Write([]byte("echo " + line))
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, openssl, "s_client", "-quiet", "-tls1_3", "-connect", l.Addr().String(),
		"-servername", serverName, "-psk_identity", identity, "-psk", hex.EncodeToString(psk))
	cmd.Stdin = strings.NewReader("ping\n")
	out, err := cmd.Output()
	if !strings.Contains(string(out), "echo ping") {
		t.Fatalf("openssl s_client: %v, output %q", err, out)
	}
	st := <-states
	if st.Identity != identity || st.CipherSuite != TLS_AES_128_GCM_SHA256 {
		t.Fatalf("server state %+v", st)
	}
}
