package consumer

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	aanf_context "github.com/florianoneto07/akma-free5gc/free5gc/aanf/internal/context"
	"github.com/florianoneto07/akma-free5gc/free5gc/aanf/pkg/factory"
	"github.com/free5gc/openapi/models"
)

// hbRequest is a request received by hbNRF.
type hbRequest struct {
	method, path, contentType, ifMatch, userAgent, peerInfo, body string
}

// hbNRF answers the registration (PUT) with 201 and the heart-beat interval
// heartBeat, and the heart-beat (PATCH) with patchStatus, without OAuth2.
type hbNRF struct {
	mu          sync.Mutex
	heartBeat   int32
	patchStatus int
	requests    []hbRequest
}

func (n *hbNRF) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	n.mu.Lock()
	n.requests = append(n.requests, hbRequest{
		method: r.Method, path: r.URL.Path, contentType: r.Header.Get("Content-Type"),
		ifMatch: r.Header.Get("If-Match"), userAgent: r.Header.Get("User-Agent"),
		peerInfo: r.Header.Get("3gpp-Sbi-NF-Peer-Info"), body: string(body),
	})
	heartBeat, patchStatus := n.heartBeat, n.patchStatus
	n.mu.Unlock()
	switch r.Method {
	case http.MethodPut:
		var profile models.NrfNfManagementNfProfile
		_ = json.Unmarshal(body, &profile)
		profile.HeartBeatTimer = heartBeat
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Location", "http://"+r.Host+r.URL.Path)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(profile)
	case http.MethodPatch:
		if patchStatus == http.StatusNotFound {
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"status":404,"cause":"RESOURCE_NOT_FOUND"}`))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (n *hbNRF) received(method string) []hbRequest {
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []hbRequest
	for _, r := range n.requests {
		if r.method == method {
			out = append(out, r)
		}
	}
	return out
}

func newHeartBeatConsumer(t *testing.T, nrf *hbNRF) (*Consumer, *aanf_context.AANFContext) {
	t.Helper()
	ts := httptest.NewServer(h2c.NewHandler(nrf, &http2.Server{}))
	t.Cleanup(ts.Close)
	cfg := &factory.Config{
		Info: &factory.Info{Version: "1.0.0"},
		Configuration: &factory.Configuration{
			NfInstanceId: uuid.New().String(),
			Sbi: &factory.Sbi{
				Scheme: "http", RegisterIPv4: "192.168.16.130", BindingIPv4: "192.168.16.130", Port: 8010,
			},
			ServiceNameList: []string{"naanf-akma"},
			NrfUri:          ts.URL,
			PlmnSupportList: []models.PlmnId{{Mcc: "208", Mnc: "93"}},
			Akma:            &factory.Akma{},
		},
		Logger: &factory.Logger{Enable: true, Level: "info"},
	}
	ctx, err := aanf_context.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewConsumer(&fakeApp{ctx: ctx, cfg: cfg})
	if err != nil {
		t.Fatal(err)
	}
	return c, ctx
}

// F29: the registration proposes the heart-beat interval, and the
// interval of the answer of the NRF prevails (TS 29.510 table 6.1.6.2.2-1).
func TestRegisterHeartBeatTimer(t *testing.T) {
	nrf := &hbNRF{heartBeat: 5}
	c, ctx := newHeartBeatConsumer(t, nrf)
	if _, _, err := c.RegisterNFInstance(context.Background()); err != nil {
		t.Fatal(err)
	}
	puts := nrf.received(http.MethodPut)
	if len(puts) != 1 {
		t.Fatalf("registrations = %d", len(puts))
	}
	var profile models.NrfNfManagementNfProfile
	if err := json.Unmarshal([]byte(puts[0].body), &profile); err != nil {
		t.Fatal(err)
	}
	if profile.HeartBeatTimer != factory.AanfDefaultHeartBeatTimer {
		t.Errorf("heartBeatTimer proposed = %d, want %d", profile.HeartBeatTimer, factory.AanfDefaultHeartBeatTimer)
	}
	if got := ctx.HeartBeat(); got != 5*time.Second {
		t.Errorf("heart-beat interval = %s, want the NRF's 5s", got)
	}
}

// F29: the heart-beat is a PATCH that replaces nfStatus by
// REGISTERED, without If-Match (TS 29.510 cl. 5.2.2.3.2), with the
// User-Agent and 3gpp-Sbi-NF-Peer-Info of the AAnF (TS 29.500).
func TestSendHeartBeat(t *testing.T) {
	nrf := &hbNRF{heartBeat: 60}
	c, ctx := newHeartBeatConsumer(t, nrf)
	status, err := c.SendHeartBeat(context.Background())
	if err != nil || status != http.StatusNoContent {
		t.Fatalf("heart-beat: %d %v", status, err)
	}
	patches := nrf.received(http.MethodPatch)
	if len(patches) != 1 {
		t.Fatalf("PATCH requests = %d", len(patches))
	}
	p := patches[0]
	if p.path != "/nnrf-nfm/v1/nf-instances/"+ctx.NfId {
		t.Errorf("path = %s", p.path)
	}
	if p.contentType != "application/json-patch+json" {
		t.Errorf("Content-Type = %q", p.contentType)
	}
	if p.ifMatch != "" {
		t.Errorf("If-Match = %q, want none", p.ifMatch)
	}
	var items []models.PatchItem
	if err := json.Unmarshal([]byte(p.body), &items); err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Op != models.PatchOperation_REPLACE || items[0].Path != "/nfStatus" ||
		items[0].Value != string(models.NrfNfManagementNfStatus_REGISTERED) {
		t.Errorf("patch = %+v", items)
	}
	if p.userAgent != "AANF-"+ctx.NfId {
		t.Errorf("User-Agent = %q", p.userAgent)
	}
	if p.peerInfo != "srcinst="+ctx.NfId {
		t.Errorf("3gpp-Sbi-NF-Peer-Info = %q", p.peerInfo)
	}
}

// TS 29.510 cl. 5.2.2.3.2 does not say what to do with 404: the NRF no longer
// has the profile, so the AAnF registers again.
func TestRunHeartBeatRegistersAgain(t *testing.T) {
	nrf := &hbNRF{heartBeat: 1, patchStatus: http.StatusNotFound}
	c, ctx := newHeartBeatConsumer(t, nrf)
	ctx.SetHeartBeat(1)
	run, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		c.RunHeartBeat(run)
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for len(nrf.received(http.MethodPut)) == 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	<-done
	if len(nrf.received(http.MethodPatch)) == 0 {
		t.Fatal("no heart-beat")
	}
	if len(nrf.received(http.MethodPut)) == 0 {
		t.Fatal("no registration after the 404")
	}
}
