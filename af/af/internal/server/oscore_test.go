package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/florianoneto07/akma-free5gc/af/af/internal/aanf"
	"github.com/florianoneto07/akma-free5gc/af/akmaoscore"
	"github.com/florianoneto07/akma-free5gc/af/cbor"
	"github.com/florianoneto07/akma-free5gc/af/coap"
	"github.com/florianoneto07/akma-free5gc/af/oscore"
	"github.com/florianoneto07/akma-free5gc/shared/akma/akid"
)

func akmaRequest(t *testing.T, aKid string, afSID []byte) *coap.Message {
	t.Helper()
	payload, err := akmaoscore.Request{AKID: aKid, N1: bytes.Repeat([]byte{1}, 16), AFSID: afSID}.Marshal(akid.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	m := &coap.Message{Type: coap.Confirmable, Code: coap.POST, Payload: payload}
	m.Add(coap.OptionURIHost, []byte(testFQDN))
	m.SetPath(akmaoscore.Path)
	m.Add(coap.OptionContentFormat, coap.EncodeUint(uint32(coap.FormatCBOR)))
	return m
}

// The OSCORE profile (TS 33.535 Annex D): POST /akma, then a GET protected
// with the context both sides derive from K_AF.
func TestOSCORE(t *testing.T) {
	af := newTestAF(t, nil)
	store := oscore.NewServer(oscore.Limits{MaxContexts: 8, MaxPerGroup: 4, PendingLifetime: time.Minute}, af.clock.now)
	req := akmaRequest(t, testAKid, []byte{0xaf})
	rsp := af.srv.AKMA(req, store, "ue")
	if cf, _ := rsp.ContentFormat(); rsp.Code != coap.Created || cf != coap.FormatCBOR {
		t.Fatalf("%s %q", rsp.Code, rsp.Payload)
	}
	if got := af.aanf.afIDs; len(got) != 1 || got[0] != testFQDN+".0100000008" {
		t.Fatalf("AF_ID asked: %v", got)
	}
	r, err := akmaoscore.ParseResponse(rsp.Payload)
	if err != nil || len(r.N2) != akmaoscore.NonceSize || len(r.UESID) != akmaoscore.SenderIDSize {
		t.Fatalf("%+v %v", r, err)
	}
	ue, err := akmaoscore.Context(testKaf, req.Payload, rsp.Payload, []byte{0xaf}, r.UESID, true)
	if err != nil {
		t.Fatal(err)
	}
	get := &coap.Message{Type: coap.Confirmable, Code: coap.GET}
	get.Add(coap.OptionURIHost, []byte(testFQDN))
	get.SetPath("/ua/v1/session")
	out, binding, err := ue.ProtectRequest(get, nil)
	if err != nil {
		t.Fatal(err)
	}
	protected := store.Handle(out, func(in *coap.Message, e *oscore.Entry) *coap.Message {
		return af.srv.CoAP(in, e.Data.(PSKSession), "ue", "OSCORE")
	})
	in, err := ue.VerifyResponse(binding, protected)
	if err != nil {
		t.Fatal(err)
	}
	var s SessionResponse
	if err := json.Unmarshal(in.Payload, &s); err != nil || in.Code != coap.Content || s.AKid != testAKid {
		t.Fatalf("%s %+v %v", in.Code, s, err)
	}
	// The context expires with K_AF.
	af.clock.advance(time.Hour)
	out, _, _ = ue.ProtectRequest(get, nil)
	if rsp := store.Handle(out, nil); rsp.Code != coap.Unauthorized {
		t.Fatalf("after the expiry: %s", rsp.Code)
	}
}

func TestOSCOREErrors(t *testing.T) {
	af := newTestAF(t, nil)
	store := oscore.NewServer(oscore.Limits{MaxContexts: 8, MaxPerGroup: 4, PendingLifetime: time.Minute}, af.clock.now)
	for name, tc := range map[string]struct {
		mod   func(*coap.Message)
		code  coap.Code
		cause string
	}{
		"other host": {func(m *coap.Message) { m.Options[0].Value = []byte("af2.akma.example") }, coap.NotFound,
			CauseMisdirectedRequest},
		"GET":               {func(m *coap.Message) { m.Code = coap.GET }, coap.MethodNotAllowed, CauseMethodNotAllowed},
		"JSON":              {func(m *coap.Message) { m.Options[len(m.Options)-1].Value = []byte{50} }, coap.UnsupportedFormat, CauseUnsupportedFormat},
		"no Content-Format": {func(m *coap.Message) { m.Options = m.Options[:len(m.Options)-1] }, coap.UnsupportedFormat, CauseUnsupportedFormat},
		"not CBOR":          {func(m *coap.Message) { m.Payload = []byte("{}") }, coap.BadRequest, CauseInvalidRequest},
		"unknown critical":  {func(m *coap.Message) { m.Add(coap.OptionURIQuery, []byte("a")) }, coap.BadOption, CauseInvalidRequest},
		"OSC-INP other alg": {func(m *coap.Message) {
			v, _ := cbor.Decode(m.Payload)
			v.A = append(v.A, cbor.BytesValue(cbor.MustEncode(cbor.MapValue(cbor.Pair{Key: cbor.IntValue(4), Value: cbor.IntValue(11)}))))
			m.Payload = cbor.MustEncode(v)
		}, coap.BadRequest, CauseOSCInputNotSupported},
	} {
		req := akmaRequest(t, testAKid, []byte{0xaf})
		tc.mod(req)
		if rsp := af.srv.AKMA(req, store, "ue"); rsp.Code != tc.code || string(rsp.Payload) != tc.cause {
			t.Errorf("%s: %s %q", name, rsp.Code, rsp.Payload)
		}
	}
	if n := af.aanf.callCount(); n != 0 {
		t.Fatalf("AAnF asked %d times for refused requests", n)
	}

	af.aanf.err = aanf.ErrKeyNotAvailable
	if rsp := af.srv.AKMA(akmaRequest(t, testAKid, []byte{0xaf}), store, "ue"); rsp.Code != coap.Forbidden ||
		string(rsp.Payload) != CauseAkmaKeyNotAvailable {
		t.Fatalf("no K_AKMA: %s %q", rsp.Code, rsp.Payload)
	}
	af.aanf.err = fmt.Errorf("%w: down", aanf.ErrUnavailable)
	if rsp := af.srv.AKMA(akmaRequest(t, testAKid, []byte{0xaf}), store, "ue"); rsp.Code != coap.ServiceUnavailable ||
		string(rsp.Payload) != CauseAanfUnavailable {
		t.Fatalf("AAnF down: %s %q", rsp.Code, rsp.Payload)
	}
	if store.Len() != 0 {
		t.Fatalf("%d contexts kept", store.Len())
	}
}
