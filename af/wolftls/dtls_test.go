//go:build wolfssl

// Copyright 2026 Floriano Neto.
// Licensed under the GNU General Public License v3.0 or later; see COPYING.

package wolftls

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// dtlsFixture is a DTLS server on a loopback UDP socket.
type dtlsFixture struct {
	t        *testing.T
	l        net.Listener
	keyCalls atomic.Int32
	conns    chan *Conn
}

func newDTLSFixture(t *testing.T, version uint16, mod func(*ServerConfig)) *dtlsFixture {
	t.Helper()
	f := &dtlsFixture{t: t, conns: make(chan *Conn, 8)}
	cfg := ServerConfig{
		Version: version, ServerName: serverName, IdentityHint: hint, SessionLifetime: time.Hour,
		Key: func(req KeyRequest) (Key, error) {
			f.keyCalls.Add(1)
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
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	f.l, err = srv.ListenDTLS(pc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.l.Close(); srv.Close() })
	go func() {
		for {
			c, err := f.l.Accept()
			if err != nil {
				return
			}
			go f.echo(c.(*Conn))
		}
	}()
	return f
}

// echo answers each record with the same record until the client leaves.
func (f *dtlsFixture) echo(c *Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if err := c.Handshake(); err != nil {
		f.conns <- c
		return
	}
	f.conns <- c
	buf := make([]byte, 2048)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return
		}
		if _, err := c.Write(buf[:n]); err != nil {
			return
		}
	}
}

func (f *dtlsFixture) serverConn() *Conn {
	select {
	case c := <-f.conns:
		return c
	case <-time.After(5 * time.Second):
		f.t.Fatal("no server connection")
		return nil
	}
}

// dial runs a DTLS client over raw, or a new UDP socket, and one echo.
func (f *dtlsFixture) dial(o clientOpts, raw net.Conn) (*Conn, string, error) {
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
		Key: func(h string, _ uint16) (string, []byte, error) {
			gotHint = h
			return o.identity, o.psk, nil
		},
	})
	if err != nil {
		f.t.Fatal(err)
	}
	defer cli.Close()
	if raw == nil {
		if raw, err = net.DialUDP("udp", nil, f.l.Addr().(*net.UDPAddr)); err != nil {
			f.t.Fatal(err)
		}
	}
	c := cli.Client(raw, o.resume)
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte("ping")); err != nil {
		c.Close()
		return nil, gotHint, err
	}
	buf := make([]byte, 64)
	n, err := c.Read(buf)
	if err != nil {
		c.Close()
		return nil, gotHint, err
	}
	if string(buf[:n]) != "ping" {
		f.t.Fatalf("echo %q", buf[:n])
	}
	return c, gotHint, nil
}

func TestDTLS13PSK(t *testing.T) {
	f := newDTLSFixture(t, VersionDTLS13, nil)
	c, _, err := f.dial(clientOpts{version: VersionDTLS13}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if st := c.State(); st.Version != VersionDTLS13 || st.CipherSuite != TLS_AES_128_GCM_SHA256 {
		t.Fatalf("client state %+v", st)
	}
	if sst := f.serverConn().State(); sst.Identity != identity || sst.Peer != "ue-1" {
		t.Fatalf("server state %+v", sst)
	}
}

func TestDTLS12PSK(t *testing.T) {
	f := newDTLSFixture(t, VersionDTLS12, nil)
	c, gotHint, err := f.dial(clientOpts{version: VersionDTLS12}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if st := c.State(); st.Version != VersionDTLS12 || st.CipherSuite != TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 {
		t.Fatalf("client state %+v", st)
	}
	if gotHint != hint {
		t.Fatalf("hint %q", gotHint)
	}
	if sst := f.serverConn().State(); sst.Identity != identity {
		t.Fatalf("server state %+v", sst)
	}
}

// Each Write is one record and each Read returns one.
func TestDTLSRecords(t *testing.T) {
	f := newDTLSFixture(t, VersionDTLS13, nil)
	c, _, err := f.dial(clientOpts{version: VersionDTLS13}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	buf := make([]byte, 2048)
	for i := range 5 {
		msg := bytes.Repeat([]byte{byte('a' + i)}, 100*(i+1))
		if _, err := c.Write(msg); err != nil {
			t.Fatal(err)
		}
		n, err := c.Read(buf)
		if err != nil || !bytes.Equal(buf[:n], msg) {
			t.Fatalf("record %d: %d octets, %v", i, n, err)
		}
	}
}

func TestDTLSRefused(t *testing.T) {
	for _, v := range []uint16{VersionDTLS12, VersionDTLS13} {
		t.Run(fmt.Sprintf("%#04x", v), func(t *testing.T) {
			f := newDTLSFixture(t, v, nil)
			if _, _, err := f.dial(clientOpts{version: v, psk: otherPSK}, nil); err == nil {
				t.Error("another key accepted")
			}
			if _, _, err := f.dial(clientOpts{version: v, identity: "3GPP-AKMA;unknown@x"}, nil); err == nil {
				t.Error("unknown identity accepted")
			}
			if _, _, err := f.dial(clientOpts{version: v, serverName: "af2.akma.example"}, nil); err == nil {
				t.Error("another server name accepted")
			}
		})
	}
	f := newDTLSFixture(t, VersionDTLS13, nil)
	if _, _, err := f.dial(clientOpts{version: VersionDTLS13, pskKEOnly: true}, nil); err == nil {
		t.Error("psk_ke accepted (TS 33.210 cl. 6.2.2)")
	}
}

func TestDTLSResumption(t *testing.T) {
	for _, v := range []uint16{VersionDTLS12, VersionDTLS13} {
		t.Run(fmt.Sprintf("%#04x", v), func(t *testing.T) {
			f := newDTLSFixture(t, v, nil)
			c, _, err := f.dial(clientOpts{version: v}, nil)
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
			c2, _, err := f.dial(clientOpts{version: v, resume: sess}, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer c2.Close()
			if sst := f.serverConn().State(); !sst.Resumed || sst.Identity != identity || sst.Peer != "ue-1" {
				t.Fatalf("server state %+v", sst)
			}
			if n := f.keyCalls.Load(); n != 1 {
				t.Fatalf("%d key lookups, want 1", n)
			}
		})
	}
}

// TS 33.535 cl. 6.4.2: the association ends with the key (close_notify).
func TestDTLSExpiry(t *testing.T) {
	f := newDTLSFixture(t, VersionDTLS13, func(cfg *ServerConfig) {
		key := cfg.Key
		cfg.Key = func(req KeyRequest) (Key, error) {
			k, err := key(req)
			k.Expiry = time.Now().Add(1500 * time.Millisecond)
			return k, err
		}
	})
	c, _, err := f.dial(clientOpts{version: VersionDTLS13}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 16)); err != io.EOF {
		t.Fatalf("read after the expiry: %v, want EOF (close_notify)", err)
	}
}

// datagrams is a client socket that keeps what goes each way; with
// firstOnly, it sends only the first datagram and never reads.
type datagrams struct {
	net.Conn
	firstOnly bool
	mu        sync.Mutex
	sent      [][]byte
	got       [][]byte
	block     chan struct{}
}

func (d *datagrams) Write(p []byte) (int, error) {
	d.mu.Lock()
	first := len(d.sent) == 0
	d.sent = append(d.sent, append([]byte(nil), p...))
	d.mu.Unlock()
	if d.firstOnly && !first {
		return len(p), nil
	}
	return d.Conn.Write(p)
}

func (d *datagrams) Read(p []byte) (int, error) {
	if d.firstOnly {
		<-d.block
		return 0, net.ErrClosed
	}
	n, err := d.Conn.Read(p)
	d.mu.Lock()
	d.got = append(d.got, append([]byte(nil), p[:n]...))
	d.mu.Unlock()
	return n, err
}

func (d *datagrams) Close() error {
	if d.firstOnly {
		select {
		case <-d.block:
		default:
			close(d.block)
		}
	}
	return d.Conn.Close()
}

// dtlsHandshake returns the type and the body of the first handshake
// message of a datagram in a plaintext DTLS record.
func dtlsHandshake(t *testing.T, d []byte) (byte, []byte) {
	t.Helper()
	if len(d) < 13+12 || d[0] != 22 {
		t.Fatalf("not a plaintext handshake record: % x", d[:min(len(d), 16)])
	}
	rec := d[13 : 13+int(binary.BigEndian.Uint16(d[11:13]))]
	n := int(rec[9])<<16 | int(rec[10])<<8 | int(rec[11])
	return rec[0], rec[12 : 12+n]
}

// extensions of a DTLS ClientHello body or of a ServerHello body.
func dtlsExtensions(clientHello bool, body []byte) map[uint16][]byte {
	p := body[2+32:]
	p = p[1+int(p[0]):] // session id
	if clientHello {
		p = p[1+int(p[0]):] // legacy cookie
		p = p[2+int(binary.BigEndian.Uint16(p)):]
		p = p[1+int(p[0]):] // compression methods
	} else {
		p = p[3:] // cipher suite, compression method
	}
	exts := map[uint16][]byte{}
	p = p[2:]
	for len(p) >= 4 {
		typ, n := binary.BigEndian.Uint16(p), int(binary.BigEndian.Uint16(p[2:]))
		exts[typ] = p[4 : 4+n]
		p = p[4+n:]
	}
	return exts
}

const extCookie = 44

// RFC 9147 cl. 5.1: the server answers the first ClientHello with a
// HelloRetryRequest and a cookie; the second ClientHello carries it, with
// psk_dhe_ke only and the identity. RFC 6347 cl. 4.2.1: HelloVerifyRequest.
func TestDTLSCookieOnTheWire(t *testing.T) {
	for _, v := range []uint16{VersionDTLS12, VersionDTLS13} {
		t.Run(fmt.Sprintf("%#04x", v), func(t *testing.T) {
			f := newDTLSFixture(t, v, nil)
			raw, err := net.DialUDP("udp", nil, f.l.Addr().(*net.UDPAddr))
			if err != nil {
				t.Fatal(err)
			}
			d := &datagrams{Conn: raw}
			c, _, err := f.dial(clientOpts{version: v}, d)
			if err != nil {
				t.Fatal(err)
			}
			c.Close()
			d.mu.Lock()
			defer d.mu.Unlock()
			typ, body := dtlsHandshake(t, d.got[0])
			if v == VersionDTLS12 {
				if typ != 3 {
					t.Fatalf("first answer of the server: handshake type %d, want HelloVerifyRequest", typ)
				}
				return
			}
			if typ != 2 || len(dtlsExtensions(false, body)[extCookie]) == 0 {
				t.Fatalf("first answer of the server: type %d without a cookie, want HelloRetryRequest", typ)
			}
			_, ch2 := dtlsHandshake(t, d.sent[1])
			exts := dtlsExtensions(true, ch2)
			if len(exts[extCookie]) == 0 || !bytes.Equal(exts[extPSKModes], []byte{1, 1}) ||
				!bytes.Contains(exts[41], []byte(identity)) || !bytes.Contains(exts[extServerName], []byte(serverName)) {
				t.Fatalf("second ClientHello extensions %v", exts)
			}
		})
	}
}

// A ClientHello from an address that never answers the cookie makes the
// server ask for no key: a forged source address costs no AAnF request.
func TestDTLSNoKeyBeforeCookie(t *testing.T) {
	for _, v := range []uint16{VersionDTLS12, VersionDTLS13} {
		t.Run(fmt.Sprintf("%#04x", v), func(t *testing.T) {
			f := newDTLSFixture(t, v, nil)
			raw, err := net.DialUDP("udp", nil, f.l.Addr().(*net.UDPAddr))
			if err != nil {
				t.Fatal(err)
			}
			d := &datagrams{Conn: raw, firstOnly: true, block: make(chan struct{})}
			cli, err := NewClient(ClientConfig{Version: v, ServerName: serverName,
				Key: func(string, uint16) (string, []byte, error) { return identity, psk, nil }})
			if err != nil {
				t.Fatal(err)
			}
			defer cli.Close()
			c := cli.Client(d, nil)
			_ = c.SetDeadline(time.Now().Add(1500 * time.Millisecond))
			if err := c.Handshake(); err == nil {
				t.Fatal("handshake without answering the cookie")
			}
			c.Close()
			time.Sleep(200 * time.Millisecond)
			if n := f.keyCalls.Load(); n != 0 {
				t.Fatalf("%d key lookups before the cookie", n)
			}
		})
	}
}

// An independent client: OpenSSL with DTLS 1.3 (4.1 and later), given in
// OPENSSL_DTLS13, with an external PSK. OpenSSL 4.1 offers a post-quantum key
// share: with an identity of the size of an A-KID, its ClientHello passes
// 1700 octets, above what wolfSSL reads by default with an MTU of 1200. The
// server has the settings of the AF.
func TestOpenSSLDTLS13Client(t *testing.T) {
	openssl := os.Getenv("OPENSSL_DTLS13")
	if openssl == "" {
		t.Skip("OPENSSL_DTLS13 not set")
	}
	akid := "3GPP-AKMA;rid7.atidjP5j0bBNfT9o7j6lm58blvhRmyRmzpmKLC9wLZZb3Ac=@5gc.mnc410.mcc310.3gppnetwork.org"
	for _, id := range []string{identity, akid} {
		t.Run(fmt.Sprintf("identity of %d octets", len(id)), func(t *testing.T) {
			got := make(chan string, 1)
			srv, err := NewServer(ServerConfig{
				Version: VersionDTLS13, ServerName: serverName, IdentityHint: hint, SessionLifetime: time.Hour,
				Key: func(req KeyRequest) (Key, error) {
					got <- req.Identity
					return Key{PSK: psk}, nil
				}})
			if err != nil {
				t.Fatal(err)
			}
			defer srv.Close()
			pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			l, err := srv.ListenDTLS(pc)
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			go func() {
				c, err := l.Accept()
				if err != nil {
					return
				}
				wc := c.(*Conn)
				defer wc.Close()
				_ = wc.SetDeadline(time.Now().Add(5 * time.Second))
				buf := make([]byte, 64)
				if n, err := wc.Read(buf); err == nil {
					_, _ = wc.Write(buf[:n])
				}
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, openssl, "s_client", "-quiet", "-dtls1_3", "-connect", l.Addr().String(),
				"-servername", serverName, "-psk_identity", id, "-psk", hex.EncodeToString(psk))
			cmd.Stdin = strings.NewReader("ping")
			out, _ := cmd.Output()
			if !bytes.Contains(out, []byte("ping")) {
				t.Fatalf("openssl s_client: output %q", out)
			}
			if gotID := <-got; gotID != id {
				t.Fatalf("identity %q", gotID)
			}
		})
	}
}
