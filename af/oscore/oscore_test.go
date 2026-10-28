package oscore

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/florianoneto07/akma-free5gc/af/coap"
)

// RFC 8613 Appendix C.1 to C.3: key derivation.
func TestKeyDerivation(t *testing.T) {
	secret := unhex("0102030405060708090a0b0c0d0e0f10")
	salt := unhex("9e7ca92223786340")
	for _, v := range []struct {
		name                        string
		p                           Params
		infoSender, infoRecipient   string
		infoIV                      string
		sender, recipient, iv       string
		senderNonce, recipientNonce string
	}{
		{"C.1.1 client", Params{MasterSecret: secret, MasterSalt: salt, SenderID: []byte{}, RecipientID: []byte{1}},
			"8540f60a634b657910", "854101f60a634b657910", "8540f60a6249560d",
			"f0910ed7295e6ad4b54fc793154302ff", "ffb14e093c94c9cac9471648b4f98710", "4622d4dd6d944168eefb54987c",
			"4622d4dd6d944168eefb54987c", "4722d4dd6d944169eefb54987c"},
		{"C.1.2 server", Params{MasterSecret: secret, MasterSalt: salt, SenderID: []byte{1}, RecipientID: []byte{}},
			"854101f60a634b657910", "8540f60a634b657910", "8540f60a6249560d",
			"ffb14e093c94c9cac9471648b4f98710", "f0910ed7295e6ad4b54fc793154302ff", "4622d4dd6d944168eefb54987c",
			"4722d4dd6d944169eefb54987c", "4622d4dd6d944168eefb54987c"},
		{"C.2.1 client", Params{MasterSecret: secret, SenderID: []byte{0}, RecipientID: []byte{1}},
			"854100f60a634b657910", "854101f60a634b657910", "8540f60a6249560d",
			"321b26943253c7ffb6003b0b64d74041", "e57b5635815177cd679ab4bcec9d7dda", "be35ae297d2dace910c52e99f9",
			"bf35ae297d2dace910c52e99f9", "bf35ae297d2dace810c52e99f9"},
		{"C.2.2 server", Params{MasterSecret: secret, SenderID: []byte{1}, RecipientID: []byte{0}},
			"854101f60a634b657910", "854100f60a634b657910", "8540f60a6249560d",
			"e57b5635815177cd679ab4bcec9d7dda", "321b26943253c7ffb6003b0b64d74041", "be35ae297d2dace910c52e99f9",
			"bf35ae297d2dace810c52e99f9", "bf35ae297d2dace910c52e99f9"},
		{"C.3.1 client", Params{MasterSecret: secret, MasterSalt: salt, SenderID: []byte{}, RecipientID: []byte{1},
			IDContext: unhex("37cbf3210017a2d3")},
			"85404837cbf3210017a2d30a634b657910", "8541014837cbf3210017a2d30a634b657910",
			"85404837cbf3210017a2d30a6249560d",
			"af2a1300a5e95788b356336eeecd2b92", "e39a0c7c77b43f03b4b39ab9a268699f", "2ca58fb85ff1b81c0b7181b85e",
			"2ca58fb85ff1b81c0b7181b85e", "2da58fb85ff1b81d0b7181b85e"},
		{"C.3.2 server", Params{MasterSecret: secret, MasterSalt: salt, SenderID: []byte{1}, RecipientID: []byte{},
			IDContext: unhex("37cbf3210017a2d3")},
			"8541014837cbf3210017a2d30a634b657910", "85404837cbf3210017a2d30a634b657910",
			"85404837cbf3210017a2d30a6249560d",
			"e39a0c7c77b43f03b4b39ab9a268699f", "af2a1300a5e95788b356336eeecd2b92", "2ca58fb85ff1b81c0b7181b85e",
			"2da58fb85ff1b81d0b7181b85e", "2ca58fb85ff1b81c0b7181b85e"},
	} {
		c, err := Derive(v.p)
		if err != nil {
			t.Fatalf("%s: %v", v.name, err)
		}
		for _, x := range []struct{ what, got, want string }{
			{"info sender", hex.EncodeToString(c.info(c.p.SenderID, "Key", 16)), v.infoSender},
			{"info recipient", hex.EncodeToString(c.info(c.p.RecipientID, "Key", 16)), v.infoRecipient},
			{"info IV", hex.EncodeToString(c.info([]byte{}, "IV", 13)), v.infoIV},
			{"Sender Key", hex.EncodeToString(c.senderKey), v.sender},
			{"Recipient Key", hex.EncodeToString(c.recipientKey), v.recipient},
			{"Common IV", hex.EncodeToString(c.commonIV), v.iv},
			{"sender nonce", hex.EncodeToString(c.nonce(c.p.SenderID, []byte{0})), v.senderNonce},
			{"recipient nonce", hex.EncodeToString(c.nonce(c.p.RecipientID, []byte{0})), v.recipientNonce},
		} {
			if x.got != x.want {
				t.Errorf("%s: %s %s, want %s", v.name, x.what, x.got, x.want)
			}
		}
	}
}

func parse(t *testing.T, s string) *coap.Message {
	t.Helper()
	m, err := coap.Parse(unhex(s))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func marshal(t *testing.T, m *coap.Message) string {
	t.Helper()
	b, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func newContext(t *testing.T, p Params, seq uint64) *Context {
	t.Helper()
	c, err := Derive(p)
	if err != nil {
		t.Fatal(err)
	}
	c.seq = seq
	return c
}

var (
	secret = unhex("0102030405060708090a0b0c0d0e0f10")
	salt   = unhex("9e7ca92223786340")
	c1     = Params{MasterSecret: secret, MasterSalt: salt, SenderID: []byte{}, RecipientID: []byte{1}}
	s1     = Params{MasterSecret: secret, MasterSalt: salt, SenderID: []byte{1}, RecipientID: []byte{}}
)

// RFC 8613 Appendix C.4 to C.6: protected requests, Sender Sequence Number
// 20.
func TestProtectRequest(t *testing.T) {
	idc := unhex("37cbf3210017a2d3")
	for _, v := range []struct {
		name       string
		p          Params
		kidContext []byte
		in, out    string
	}{
		{"C.4", c1, nil, "44015d1f00003974396c6f63616c686f737483747631",
			"44025d1f00003974396c6f63616c686f7374620914ff612f1092f1776f1c1668b3825e"},
		{"C.5", Params{MasterSecret: secret, SenderID: []byte{0}, RecipientID: []byte{1}}, nil,
			"440171c30000b932396c6f63616c686f737483747631",
			"440271c30000b932396c6f63616c686f737463091400ff4ed339a5a379b0b8bc731fffb0"},
		{"C.6", Params{MasterSecret: secret, MasterSalt: salt, SenderID: []byte{}, RecipientID: []byte{1}, IDContext: idc},
			idc, "44012f8eef9bbf7a396c6f63616c686f737483747631",
			"44022f8eef9bbf7a396c6f63616c686f73746b19140837cbf3210017a2d3ff72cd7273fd331ac45cffbe55c3"},
	} {
		out, _, err := newContext(t, v.p, 20).ProtectRequest(parse(t, v.in), v.kidContext)
		if err != nil {
			t.Fatalf("%s: %v", v.name, err)
		}
		if got := marshal(t, out); got != v.out {
			t.Errorf("%s: %s", v.name, got)
		}
	}
}

const (
	requestC4   = "44015d1f00003974396c6f63616c686f737483747631"
	protectedC4 = "44025d1f00003974396c6f63616c686f7374620914ff612f1092f1776f1c1668b3825e"
	responseC7  = "64455d1f00003974ff48656c6c6f20576f726c6421"
)

// RFC 8613 Appendix C.7 and C.8: the server verifies the request of C.4 and
// protects the response, without and with a Partial IV; the client
// verifies it.
func TestResponse(t *testing.T) {
	for _, v := range []struct {
		name string
		piv  bool
		out  string
	}{
		{"C.7", false, "64445d1f0000397490ffdbaad1e9a7e7b2a813d3c31524378303cdafae119106"},
		{"C.8", true, "64445d1f00003974920100ff4d4c13669384b67354b2b6175ff4b8658c666a6cf88e"},
	} {
		server := newContext(t, s1, 0)
		m := parse(t, protectedC4)
		opt, _, err := optionOf(m)
		if err != nil {
			t.Fatal(err)
		}
		in, r, err := server.VerifyRequest(m, opt)
		if err != nil {
			t.Fatalf("%s: %v", v.name, err)
		}
		if got := marshal(t, in); got != requestC4 {
			t.Errorf("%s: decrypted request %s", v.name, got)
		}
		out, err := server.ProtectResponse(r, parse(t, responseC7), v.piv, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := marshal(t, out); got != v.out {
			t.Errorf("%s: %s", v.name, got)
		}

		client := newContext(t, c1, 20)
		_, cr, err := client.ProtectRequest(parse(t, requestC4), nil)
		if err != nil {
			t.Fatal(err)
		}
		got, err := client.VerifyResponse(cr, parse(t, v.out))
		if err != nil {
			t.Fatalf("%s: client: %v", v.name, err)
		}
		if marshal(t, got) != responseC7 {
			t.Errorf("%s: client decrypted %s", v.name, marshal(t, got))
		}
	}
}

func TestReplayAndErrors(t *testing.T) {
	server := newContext(t, s1, 0)
	m := parse(t, protectedC4)
	opt, _, _ := optionOf(m)
	if _, _, err := server.VerifyRequest(m, opt); err != nil {
		t.Fatal(err)
	}
	if _, _, err := server.VerifyRequest(m, opt); !errors.Is(err, ErrReplay) {
		t.Fatalf("replayed request: %v", err)
	}

	other := newContext(t, Params{MasterSecret: unhex("ff02030405060708090a0b0c0d0e0f10"), MasterSalt: salt,
		SenderID: []byte{1}, RecipientID: []byte{}}, 0)
	if _, _, err := other.VerifyRequest(m, opt); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("other Master Secret: %v", err)
	}
	cut := parse(t, protectedC4)
	cut.Payload = cut.Payload[:len(cut.Payload)-1]
	if _, _, err := newContext(t, s1, 0).VerifyRequest(cut, opt); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("cut ciphertext: %v", err)
	}
	wrong := opt
	wrong.KID = []byte{9}
	if _, _, err := newContext(t, s1, 0).VerifyRequest(m, wrong); !errors.Is(err, ErrNoContext) {
		t.Fatalf("other kid: %v", err)
	}
	// An outer Class E option is discarded; an altered Class U option is
	// not protected (Uri-Host, cl. 4.1.3.2) and goes through.
	extra := parse(t, protectedC4)
	extra.Add(coap.OptionURIPath, []byte("outer"))
	in, _, err := newContext(t, s1, 0).VerifyRequest(extra, opt)
	if err != nil || in.Path() != "/tv1" {
		t.Fatalf("outer Uri-Path: %v %q", err, in.Path())
	}

	c := newContext(t, c1, MaxSequence)
	if _, _, err := c.ProtectRequest(parse(t, requestC4), nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.ProtectRequest(parse(t, requestC4), nil); !errors.Is(err, ErrSequenceExhausted) {
		t.Fatalf("after 2^40 - 1: %v", err)
	}
	if _, err := Derive(Params{MasterSecret: secret, SenderID: []byte{1}, RecipientID: []byte{1}}); err == nil {
		t.Fatal("Sender ID equal to the Recipient ID accepted")
	}
	if _, err := Derive(Params{MasterSecret: secret, SenderID: make([]byte, 8), RecipientID: []byte{}}); err == nil {
		t.Fatal("Sender ID of 8 octets accepted")
	}
}

func TestWindow(t *testing.T) {
	var w window
	for _, s := range []uint64{5, 3, 40, 39, 9, 41} {
		if w.seen(s) {
			t.Fatalf("%d seen before it came", s)
		}
		w.mark(s)
		if !w.seen(s) {
			t.Fatalf("%d not seen", s)
		}
	}
	for s, want := range map[uint64]bool{3: true, 5: true, 8: true, 9: true, 10: false, 38: false, 39: true, 42: false} {
		if got := w.seen(s); got != want {
			t.Errorf("seen(%d) = %v", s, got)
		}
	}
}

func TestOption(t *testing.T) {
	for _, v := range []struct {
		hex string
		o   Option
	}{
		{"", Option{}},
		{"0914", Option{PartialIV: []byte{0x14}, HasKID: true, KID: []byte{}}},
		{"091400", Option{PartialIV: []byte{0x14}, HasKID: true, KID: []byte{0}}},
		{"19140837cbf3210017a2d3", Option{PartialIV: []byte{0x14}, HasKID: true, KID: []byte{},
			HasKIDContext: true, KIDContext: unhex("37cbf3210017a2d3")}},
		{"0100", Option{PartialIV: []byte{0}}},
		{"1000", Option{HasKIDContext: true, KIDContext: []byte{}}},
	} {
		o, err := ParseOption(unhex(v.hex))
		if err != nil {
			t.Fatalf("%s: %v", v.hex, err)
		}
		if got := hex.EncodeToString(o.Marshal()); got != v.hex {
			t.Errorf("%s: marshalled as %s", v.hex, got)
		}
		if !bytes.Equal(o.PartialIV, v.o.PartialIV) || o.HasKID != v.o.HasKID || !bytes.Equal(o.KID, v.o.KID) ||
			o.HasKIDContext != v.o.HasKIDContext || !bytes.Equal(o.KIDContext, v.o.KIDContext) {
			t.Errorf("%s: %+v", v.hex, o)
		}
	}
	for _, bad := range []string{"00", "20", "06000000000000", "0201", "1001", "0114ff"} {
		if _, err := ParseOption(unhex(bad)); !errors.Is(err, ErrDecode) {
			t.Errorf("%s: %v", bad, err)
		}
	}
}
