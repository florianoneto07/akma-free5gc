package sbi

import (
	"net/http"
	"testing"
)

// Every answer of the AAnF carries Server and 3gpp-Sbi-NF-Peer-Info
// (TS 29.500 table 5.2.2.2-1 and cl. 5.2.3.2.21), with the NF instance of the
// consumer from its client certificate or, without TLS, from the header of
// the request.
func TestSbiHeaders(t *testing.T) {
	e := newEnv(t)
	self := e.app.ctx.NfId

	r := e.retrieve(afLocal, "rid0000.atidnotregistered@5gc.mnc093.mcc208.3gppnetwork.org")
	if r.status < http.StatusBadRequest {
		t.Fatalf("status = %d, want an error answer", r.status)
	}
	if got := r.header.Get("Server"); got != "AANF-"+self {
		t.Errorf("Server = %q", got)
	}
	if got, want := r.header.Get("3gpp-Sbi-NF-Peer-Info"), "srcinst="+self+"; dstinst="+afInstance; got != want {
		t.Errorf("3gpp-Sbi-NF-Peer-Info = %q, want %q", got, want)
	}

	// The SBI over http: the consumer from the header of the request.
	e.peer = nil
	r = e.do(http.MethodPost, prefix+"/retrieve-applicationkey", "application/json", nil,
		map[string]string{"3gpp-Sbi-NF-Peer-Info": "srcinst=" + afInstance})
	if got, want := r.header.Get("3gpp-Sbi-NF-Peer-Info"), "srcinst="+self+"; dstinst="+afInstance; got != want {
		t.Errorf("without TLS: 3gpp-Sbi-NF-Peer-Info = %q, want %q", got, want)
	}
	r = e.do(http.MethodGet, "/unknown", "", nil, nil)
	if got := r.header.Get("Server"); got != "AANF-"+self {
		t.Errorf("404 of an unknown path: Server = %q", got)
	}
	if got := r.header.Get("3gpp-Sbi-NF-Peer-Info"); got != "srcinst="+self {
		t.Errorf("unknown consumer: 3gpp-Sbi-NF-Peer-Info = %q", got)
	}
}
