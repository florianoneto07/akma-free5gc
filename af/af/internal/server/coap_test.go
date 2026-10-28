package server

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/florianoneto07/akma-free5gc/af/akmatls"
	"github.com/florianoneto07/akma-free5gc/af/coap"
	"github.com/florianoneto07/akma-free5gc/shared/akma/afid"
)

// The CoAP resource of the DTLS profiles (TS 33.535 Annex C; RFC 7252).
func TestCoAPHandler(t *testing.T) {
	af := newTestAF(t, nil)
	expiry := af.clock.now().Add(time.Hour)
	sess := PSKSession{AKid: testAKid, AfID: afid.AfID{FQDN: testFQDN, Protocol: akmatls.UaStarDTLS13}, KafExpiry: expiry}
	get := func(mod func(*coap.Message)) *coap.Message {
		req := &coap.Message{Type: coap.Confirmable, Code: coap.GET}
		req.Add(coap.OptionURIHost, []byte(testFQDN))
		req.SetPath("/ua/v1/session")
		if mod != nil {
			mod(req)
		}
		return af.srv.CoAP(req, sess, "ue", "PSK DTLS")
	}
	cause := func(m *coap.Message) string {
		var e ErrorResponse
		_ = json.Unmarshal(m.Payload, &e)
		return e.Cause
	}

	rsp := get(nil)
	var r SessionResponse
	cf, _ := rsp.ContentFormat()
	if err := json.Unmarshal(rsp.Payload, &r); err != nil || rsp.Code != coap.Content || cf != coap.FormatJSON ||
		r.AKid != testAKid || !r.KafExpiry.Equal(expiry) {
		t.Fatalf("response %s %+v, %v", rsp.Code, r, err)
	}
	// Without Uri-Host: its default is the address, named by the handshake.
	if rsp := get(func(m *coap.Message) { m.Options = m.Options[1:] }); rsp.Code != coap.Content {
		t.Fatalf("without Uri-Host: %s", rsp.Code)
	}
	for name, tc := range map[string]struct {
		mod   func(*coap.Message)
		code  coap.Code
		cause string
	}{
		"other host":       {func(m *coap.Message) { m.Options[0].Value = []byte("af2.akma.example") }, coap.NotFound, CauseMisdirectedRequest},
		"other path":       {func(m *coap.Message) { m.Options = m.Options[:1]; m.SetPath("/x") }, coap.NotFound, CauseNotFound},
		"POST":             {func(m *coap.Message) { m.Code = coap.POST }, coap.MethodNotAllowed, CauseMethodNotAllowed},
		"unknown critical": {func(m *coap.Message) { m.Add(coap.OptionURIQuery, []byte("a")) }, coap.BadOption, CauseInvalidRequest},
	} {
		if rsp := get(tc.mod); rsp.Code != tc.code || cause(rsp) != tc.cause {
			t.Errorf("%s: %s %s", name, rsp.Code, cause(rsp))
		}
	}
	af.clock.advance(2 * time.Hour)
	if rsp := get(nil); rsp.Code != coap.Forbidden || cause(rsp) != CauseKafExpired {
		t.Fatalf("after the expiry: %s %s", rsp.Code, cause(rsp))
	}
}
