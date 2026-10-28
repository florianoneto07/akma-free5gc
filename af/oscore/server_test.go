package oscore

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/florianoneto07/akma-free5gc/af/coap"
)

var (
	ueParams = Params{MasterSecret: secret, MasterSalt: salt, SenderID: []byte("ue"), RecipientID: []byte("af")}
	afParams = Params{MasterSecret: secret, MasterSalt: salt, SenderID: []byte("af"), RecipientID: []byte("ue")}
)

type fixture struct {
	srv  *Server
	addr *net.UDPAddr
	mu   sync.Mutex
	t    time.Time // the clock of srv
}

func (f *fixture) now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.t
}

func (f *fixture) advance(d time.Duration) {
	f.mu.Lock()
	f.t = f.t.Add(d)
	f.mu.Unlock()
}

// serve starts a CoAP server on the loopback that hands the protected
// requests to an OSCORE server, which answers 2.05 with the path.
func serve(t *testing.T, l Limits) *fixture {
	t.Helper()
	f := &fixture{t: time.Now()}
	f.srv = NewServer(l, f.now)
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	cs := &coap.Server{Handle: func(m *coap.Message, _ net.Addr) *coap.Message {
		if _, ok := m.Option(coap.OptionOSCORE); !ok {
			return &coap.Message{Code: coap.Unauthorized}
		}
		return f.srv.Handle(m, func(in *coap.Message, e *Entry) *coap.Message {
			return &coap.Message{Code: coap.Content, Payload: []byte(e.Data.(string) + in.Path())}
		})
	}}
	go cs.Serve(pc)
	t.Cleanup(func() { pc.Close() })
	f.addr = pc.LocalAddr().(*net.UDPAddr)
	return f
}

var limits = Limits{MaxContexts: 16, MaxPerGroup: 2, PendingLifetime: time.Minute}

func (f *fixture) client(t *testing.T) (*Client, *net.UDPConn) {
	t.Helper()
	conn, err := net.DialUDP("udp", nil, f.addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return NewClient(coap.NewClient(conn), newContext(t, ueParams, 0)), conn
}

func get(path string) *coap.Message {
	m := &coap.Message{Code: coap.GET}
	m.Add(coap.OptionURIHost, []byte("af.example"))
	m.SetPath(path)
	return m
}

func short(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestClientServer(t *testing.T) {
	f := serve(t, limits)
	if err := f.srv.Add(&Entry{Context: newContext(t, afParams, 0), Group: "g", Expiry: f.now().Add(time.Hour),
		Data: "hello "}); err != nil {
		t.Fatal(err)
	}
	c, _ := f.client(t)
	for _, p := range []string{"/a", "/b"} {
		rsp, err := c.Do(short(t), get(p))
		if err != nil || rsp.Code != coap.Content || string(rsp.Payload) != "hello "+p {
			t.Fatalf("%s: %+v %v", p, rsp, err)
		}
	}

	// Appendix B.2: a new context with ID Context R2 || R3 on both sides.
	before := c.Context()
	rsp, err := c.Renew(short(t), get("/renewed"))
	if err != nil || string(rsp.Payload) != "hello /renewed" {
		t.Fatalf("renewal: %+v %v", rsp, err)
	}
	after := c.Context()
	if after == before || len(after.IDContext()) != 2*RenewalNonceSize {
		t.Fatalf("ID Context after the renewal: %x", after.IDContext())
	}
	f.srv.mu.Lock()
	srvCtx := f.srv.entries["ue"].Context
	f.srv.mu.Unlock()
	if string(srvCtx.IDContext()) != string(after.IDContext()) {
		t.Fatalf("server ID Context %x, client %x", srvCtx.IDContext(), after.IDContext())
	}
	// Later requests omit the 'kid context' (RFC 8613 cl. 5.1).
	if rsp, err := c.Do(short(t), get("/c")); err != nil || string(rsp.Payload) != "hello /c" {
		t.Fatalf("after the renewal: %+v %v", rsp, err)
	}
	// The old context no longer works.
	old := NewClient(coap.NewClient(dial(t, f.addr)), newContext(t, ueParams, 1000))
	var ue *UnprotectedError
	if _, err := old.Do(short(t), get("/d")); !errors.As(err, &ue) || ue.Code != coap.BadRequest {
		t.Fatalf("old context: %v", err)
	}
}

func dial(t *testing.T, addr *net.UDPAddr) *net.UDPConn {
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// A protected request sent again with another Message ID is refused by the
// replay window; the same datagram again gets the same response from the
// CoAP deduplication.
func TestReplayOverUDP(t *testing.T) {
	f := serve(t, limits)
	if err := f.srv.Add(&Entry{Context: newContext(t, afParams, 0), Expiry: f.now().Add(time.Hour), Data: ""}); err != nil {
		t.Fatal(err)
	}
	conn := dial(t, f.addr)
	out, _, err := newContext(t, ueParams, 0).ProtectRequest(get("/x"), nil)
	if err != nil {
		t.Fatal(err)
	}
	exchange := func(mid uint16) *coap.Message {
		out.Type, out.MessageID, out.Token = coap.Confirmable, mid, []byte{1}
		b, _ := out.Marshal()
		if _, err := conn.Write(b); err != nil {
			t.Fatal(err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 1500)
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		m, err := coap.Parse(buf[:n])
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	first := exchange(1)
	if _, ok := first.Option(coap.OptionOSCORE); !ok || first.Code != coap.Changed {
		t.Fatalf("first: %+v", first)
	}
	if again := exchange(1); string(again.Payload) != string(first.Payload) {
		t.Fatal("same Message ID: other response")
	}
	if replay := exchange(2); replay.Code != coap.Unauthorized || string(replay.Payload) != "Replay detected" {
		t.Fatalf("replay: %s %q", replay.Code, replay.Payload)
	}
}

func TestServerState(t *testing.T) {
	f := serve(t, limits)
	add := func(sender, recipient, group string, expiry time.Duration) error {
		p := afParams
		p.SenderID, p.RecipientID = []byte(sender), []byte(recipient)
		return f.srv.Add(&Entry{Context: newContext(t, p, 0), Group: group, Expiry: f.now().Add(expiry), Data: ""})
	}
	if err := add("af", "ue", "g", time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := add("af", "ue", "h", time.Hour); !errors.Is(err, ErrIDInUse) {
		t.Fatalf("Recipient ID twice: %v", err)
	}
	// MaxPerGroup 2: the third context of a group removes the oldest.
	f.advance(time.Second)
	_ = add("af", "u2", "g", time.Hour)
	f.advance(time.Second)
	_ = add("af", "u3", "g", time.Hour)
	if f.srv.InUse([]byte("ue")) || !f.srv.InUse([]byte("u2")) || !f.srv.InUse([]byte("u3")) {
		t.Fatal("group limit")
	}
	// Pending contexts go after PendingLifetime, expired ones at Expiry.
	_ = add("af", "u4", "x", 90*time.Second)
	f.advance(2 * time.Minute)
	if gone := f.srv.Prune(); len(gone) != 3 || f.srv.Len() != 0 {
		t.Fatalf("pruned %d, left %d", len(gone), f.srv.Len())
	}

	// An expired context is not found.
	if err := add("af", "ue", "g", time.Minute); err != nil {
		t.Fatal(err)
	}
	c, _ := f.client(t)
	if _, err := c.Do(short(t), get("/a")); err != nil {
		t.Fatal(err)
	}
	f.advance(time.Minute)
	var ue *UnprotectedError
	if _, err := c.Do(short(t), get("/a")); !errors.As(err, &ue) || ue.Code != coap.Unauthorized ||
		ue.Diagnostic != "Security context not found" {
		t.Fatalf("expired: %v", err)
	}

	full := NewServer(Limits{MaxContexts: 1, MaxPerGroup: 1, PendingLifetime: time.Minute}, nil)
	_ = full.Add(&Entry{Context: newContext(t, afParams, 0), Expiry: time.Now().Add(time.Hour)})
	p := afParams
	p.RecipientID = []byte("u2")
	if err := full.Add(&Entry{Context: newContext(t, p, 0), Group: "other", Expiry: time.Now().Add(time.Hour)}); !errors.Is(err, ErrFull) {
		t.Fatalf("full: %v", err)
	}
}
