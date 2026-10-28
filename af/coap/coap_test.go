package coap

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// The request of the DTLS profile, encoded by hand from RFC 7252 cl. 3:
// 44 (version 1, CON, token of 4), 01 (GET), 12 34 (message ID), the token,
// Uri-Host (delta 3, length 16 = 13 + 3: 3D 03), then Uri-Path (delta 8:
// 82 "ua"; delta 0: 02 "v1", 07 "session").
const requestHex = "4401123461626364" +
	"3d03" + "6166312e616b6d612e6578616d706c65" +
	"82" + "7561" + "02" + "7631" + "07" + "73657373696f6e"

func request() *Message {
	m := &Message{Type: Confirmable, Code: GET, MessageID: 0x1234, Token: []byte("abcd")}
	m.SetPath("/ua/v1/session")
	m.Add(OptionURIHost, []byte("af1.akma.example"))
	return m
}

func TestMarshalRequest(t *testing.T) {
	b, err := request().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(b); got != requestHex {
		t.Fatalf("encoding\n got %s\nwant %s", got, requestHex)
	}
}

func TestParseRequest(t *testing.T) {
	b, _ := hex.DecodeString(requestHex)
	m, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	host, _ := m.Option(OptionURIHost)
	if m.Type != Confirmable || m.Code != GET || m.MessageID != 0x1234 || string(m.Token) != "abcd" ||
		m.Path() != "/ua/v1/session" || string(host) != "af1.akma.example" || m.Payload != nil {
		t.Fatalf("message %+v", m)
	}
}

// A response with Content-Format and payload; long options (extended
// nibbles 13 and 14).
func TestRoundTrip(t *testing.T) {
	m := &Message{Type: Acknowledgement, Code: Content, MessageID: 7, Token: []byte{1, 2, 3, 4, 5, 6, 7, 8},
		Payload: []byte(`{"aKid":"x"}`)}
	m.Add(OptionContentFormat, EncodeUint(uint32(FormatJSON)))
	m.Add(OptionURIQuery, bytes.Repeat([]byte("q"), 20))
	m.Add(OptionProxyURI, bytes.Repeat([]byte("p"), 300))
	b, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(b, []byte{0x68, 0x45, 0, 7}) {
		t.Fatalf("header % x", b[:4])
	}
	got, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	cf, ok := got.ContentFormat()
	q, _ := got.Option(OptionURIQuery)
	p, _ := got.Option(OptionProxyURI)
	if !ok || cf != FormatJSON || len(q) != 20 || len(p) != 300 || string(got.Payload) != `{"aKid":"x"}` ||
		got.Code.String() != "2.05" {
		t.Fatalf("message %+v", got)
	}
}

func TestParseErrors(t *testing.T) {
	for name, h := range map[string]string{
		"short":                  "4401",
		"version 2":              "84011234",
		"token length 9":         "490112340102030405060708",
		"token cut short":        "4401123461",
		"marker without payload": "40011234ff",
		"reserved nibble":        "40011234f0",
		"option cut short":       "400112343461",
		"empty with token":       "4100123461",
	} {
		b, _ := hex.DecodeString(h)
		if _, err := Parse(b); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestUintAndCritical(t *testing.T) {
	if len(EncodeUint(0)) != 0 || !bytes.Equal(EncodeUint(50), []byte{50}) || !bytes.Equal(EncodeUint(300), []byte{1, 44}) ||
		DecodeUint([]byte{1, 44}) != 300 {
		t.Fatal("uint encoding")
	}
	m := request()
	if n, ok := m.UnknownCritical(OptionURIHost, OptionURIPath); ok {
		t.Fatalf("option %d reported", n)
	}
	m.Add(OptionURIQuery, []byte("a=b"))
	if n, ok := m.UnknownCritical(OptionURIHost, OptionURIPath); !ok || n != OptionURIQuery {
		t.Fatal("Uri-Query not reported")
	}
}

// server answers over UDP with a Responder; dropFirst drops the first
// answer, so that the client retransmits.
func server(t *testing.T, dropFirst bool) (*net.UDPConn, *atomic.Int32) {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	var handled atomic.Int32
	var r Responder
	go func() {
		buf := make([]byte, 2048)
		sent := 0
		for {
			n, addr, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			out := r.Answer(buf[:n], time.Now(), func(req *Message) *Message {
				handled.Add(1)
				rsp := &Message{Code: Content, Payload: []byte(req.Path())}
				rsp.Add(OptionContentFormat, EncodeUint(uint32(FormatText)))
				return rsp
			})
			sent++
			if out == nil || dropFirst && sent == 1 {
				continue
			}
			_, _ = pc.WriteToUDP(out, addr)
		}
	}()
	return pc, &handled
}

func dial(t *testing.T, pc *net.UDPConn) net.Conn {
	t.Helper()
	c, err := net.DialUDP("udp", nil, pc.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestExchange(t *testing.T) {
	pc, handled := server(t, false)
	cl := NewClient(dial(t, pc))
	for i := range 3 {
		req := &Message{Code: GET}
		req.SetPath("/ua/v1/session")
		rsp, err := cl.Do(context.Background(), req)
		if err != nil || rsp.Code != Content || string(rsp.Payload) != "/ua/v1/session" {
			t.Fatalf("request %d: %+v, %v", i, rsp, err)
		}
	}
	if handled.Load() != 3 {
		t.Fatalf("%d requests handled", handled.Load())
	}
}

// RFC 7252 cl. 4.2 and 4.5: the client retransmits; the server answers the
// duplicate with the same response and handles the request once.
func TestRetransmission(t *testing.T) {
	pc, handled := server(t, true)
	cl := NewClient(dial(t, pc))
	req := &Message{Code: GET}
	req.SetPath("/x")
	start := time.Now()
	rsp, err := cl.Do(context.Background(), req)
	if err != nil || string(rsp.Payload) != "/x" {
		t.Fatalf("%+v, %v", rsp, err)
	}
	if time.Since(start) < AckTimeout {
		t.Fatal("answered before a retransmission")
	}
	if handled.Load() != 1 {
		t.Fatalf("request handled %d times", handled.Load())
	}
}

func TestResponderPingAndMalformed(t *testing.T) {
	var r Responder
	ping, _ := (&Message{Type: Confirmable, MessageID: 9}).Marshal()
	out := r.Answer(ping, time.Now(), nil)
	if m, err := Parse(out); err != nil || m.Type != Reset || m.MessageID != 9 {
		t.Fatalf("ping: %+v, %v", m, err)
	}
	bad, _ := hex.DecodeString("40011234f0")
	if m, err := Parse(r.Answer(bad, time.Now(), nil)); err != nil || m.Type != Reset || m.MessageID != 0x1234 {
		t.Fatalf("malformed CON: %+v, %v", m, err)
	}
	ack, _ := (&Message{Type: Acknowledgement, MessageID: 3}).Marshal()
	if r.Answer(ack, time.Now(), nil) != nil {
		t.Fatal("answered an acknowledgement")
	}
}

// A retransmission that arrives while the server still handles the first
// copy gets the same response, and the handler runs once (RFC 7252
// cl. 4.5).
func TestServerRetransmission(t *testing.T) {
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	srv := &Server{Handle: func(req *Message, _ net.Addr) *Message {
		calls.Add(1)
		time.Sleep(300 * time.Millisecond)
		return &Message{Code: Content, Payload: []byte(req.Path())}
	}}
	go srv.Serve(pc)
	defer pc.Close()

	conn, err := net.DialUDP("udp", nil, pc.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	req := &Message{Type: Confirmable, Code: GET, MessageID: 7, Token: []byte{1, 2}}
	req.SetPath("/a/b")
	out, _ := req.Marshal()
	for range 3 {
		if _, err := conn.Write(out); err != nil {
			t.Fatal(err)
		}
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1500)
	for i := range 3 {
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("answer %d: %v", i, err)
		}
		rsp, err := Parse(buf[:n])
		if err != nil || rsp.Type != Acknowledgement || rsp.MessageID != 7 || string(rsp.Payload) != "/a/b" {
			t.Fatalf("answer %d: %+v %v", i, rsp, err)
		}
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("handler ran %d times", n)
	}

	c := NewClient(conn)
	get := &Message{Code: GET}
	get.SetPath("/c")
	rsp, err := c.Do(context.Background(), get)
	if err != nil || string(rsp.Payload) != "/c" {
		t.Fatalf("client: %+v %v", rsp, err)
	}
}
