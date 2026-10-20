package consumer

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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

type fakeApp struct {
	ctx *aanf_context.AANFContext
	cfg *factory.Config
}

func (a *fakeApp) SetLogEnable(bool)                  {}
func (a *fakeApp) SetLogLevel(string)                 {}
func (a *fakeApp) SetReportCaller(bool)               {}
func (a *fakeApp) Start()                             {}
func (a *fakeApp) Terminate()                         {}
func (a *fakeApp) Context() *aanf_context.AANFContext { return a.ctx }
func (a *fakeApp) Config() *factory.Config            { return a.cfg }

// fakeNRF answers NFRegister like the NRF of free5GC: 201 with a Location
// header, or 200 for an update, echoing the profile with the "oauth2"
// custom information.
type fakeNRF struct {
	mu       sync.Mutex
	status   int
	requests []map[string]json.RawMessage
	paths    []string
	fails    int
}

func (n *fakeNRF) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.fails > 0 {
		n.fails--
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	body, _ := io.ReadAll(r.Body)
	var profile map[string]json.RawMessage
	_ = json.Unmarshal(body, &profile)
	n.requests = append(n.requests, profile)
	n.paths = append(n.paths, r.Method+" "+r.URL.Path)
	profile["customInfo"] = json.RawMessage(`{"oauth2":true}`)
	out, _ := json.Marshal(profile)
	w.Header().Set("Content-Type", "application/json")
	if n.status == http.StatusCreated {
		w.Header().Set("Location", "http://"+r.Host+r.URL.Path)
	}
	w.WriteHeader(n.status)
	_, _ = w.Write(out)
}

func newConsumer(t *testing.T, nrf *fakeNRF, rids []string) (*Consumer, *aanf_context.AANFContext) {
	t.Helper()
	ts := httptest.NewServer(h2c.NewHandler(nrf, &http2.Server{}))
	t.Cleanup(ts.Close)
	cfg := &factory.Config{
		Info: &factory.Info{Version: "1.0.0"},
		Configuration: &factory.Configuration{
			NfInstanceId: uuid.New().String(),
			Sbi: &factory.Sbi{
				Scheme: "http", RegisterIPv4: "192.168.16.130", BindingIPv4: "192.168.16.130", Port: 8000,
			},
			ServiceNameList:   []string{"naanf-akma"},
			NrfUri:            ts.URL,
			PlmnSupportList:   []models.PlmnId{{Mcc: "208", Mnc: "93"}},
			RoutingIndicators: rids,
			Akma:              &factory.Akma{},
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

func TestRegisterNFInstanceProfile(t *testing.T) {
	nrf := &fakeNRF{status: http.StatusCreated}
	c, ctx := newConsumer(t, nrf, []string{"0000", "012"})

	_, id, err := c.RegisterNFInstance(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if id != ctx.NfId {
		t.Errorf("NF instance ID = %s, want %s", id, ctx.NfId)
	}
	if !ctx.OAuth2Required {
		t.Error("OAuth2 setting of the NRF not applied")
	}
	if len(nrf.paths) != 1 || nrf.paths[0] != "PUT /nnrf-nfm/v1/nf-instances/"+ctx.NfId {
		t.Fatalf("requests = %v", nrf.paths)
	}
	p := nrf.requests[0]
	if string(p["nfType"]) != `"AANF"` || string(p["nfStatus"]) != `"REGISTERED"` {
		t.Errorf("nfType %s nfStatus %s", p["nfType"], p["nfStatus"])
	}
	// TS 29.510 table 6.1.6.2.73-1: Routing Indicators as strings, leading
	// zeros kept.
	if got := string(p["aanfInfoList"]); got != `{"1":{"routingIndicators":["0000","012"]}}` {
		t.Errorf("aanfInfoList = %s", got)
	}
	var services []models.NrfNfManagementNfService
	if err := json.Unmarshal(p["nfServices"], &services); err != nil || len(services) != 1 {
		t.Fatalf("nfServices = %s", p["nfServices"])
	}
	s := services[0]
	if s.ServiceName != models.ServiceName_NAANF_AKMA || s.Scheme != models.UriScheme_HTTP ||
		len(s.Versions) != 1 || s.Versions[0].ApiVersionInUri != "v1" || s.Versions[0].ApiFullVersion != "1.2.0" {
		t.Errorf("service = %+v", s)
	}
	if len(s.IpEndPoints) != 1 || s.IpEndPoints[0].Ipv4Address != "192.168.16.130" || s.IpEndPoints[0].Port != 8000 {
		t.Errorf("ipEndPoints = %+v", s.IpEndPoints)
	}
	allowed := map[models.NrfNfManagementNfType]bool{}
	for _, nt := range s.AllowedNfTypes {
		allowed[nt] = true
	}
	if len(allowed) != 3 || !allowed["AUSF"] || !allowed["NEF"] || !allowed["AF"] {
		t.Errorf("allowedNfTypes = %v", s.AllowedNfTypes)
	}
}

// Without Routing Indicators the AAnF serves any of them: no aanfInfoList.
func TestRegisterNFInstanceWithoutRIDs(t *testing.T) {
	nrf := &fakeNRF{status: http.StatusCreated}
	c, _ := newConsumer(t, nrf, nil)
	if _, _, err := c.RegisterNFInstance(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := nrf.requests[0]["aanfInfoList"]; ok {
		t.Error("aanfInfoList sent without Routing Indicators")
	}
}

// The OAuth2 setting is also taken from a 200 (profile update) answer.
func TestRegisterNFInstanceUpdate(t *testing.T) {
	nrf := &fakeNRF{status: http.StatusOK}
	c, ctx := newConsumer(t, nrf, nil)
	if _, _, err := c.RegisterNFInstance(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !ctx.OAuth2Required {
		t.Error("OAuth2 setting not applied on update")
	}
}

func TestRegisterNFInstanceRetries(t *testing.T) {
	registerRetryInterval = 10 * time.Millisecond
	nrf := &fakeNRF{status: http.StatusCreated, fails: 2}
	c, _ := newConsumer(t, nrf, nil)
	if _, _, err := c.RegisterNFInstance(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(nrf.requests) != 1 {
		t.Errorf("registrations = %d", len(nrf.requests))
	}
}

func TestRegisterNFInstanceCancelled(t *testing.T) {
	registerRetryInterval = 10 * time.Millisecond
	nrf := &fakeNRF{status: http.StatusCreated, fails: 1 << 30}
	c, _ := newConsumer(t, nrf, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, _, err := c.RegisterNFInstance(ctx)
	if err == nil || !strings.Contains(err.Error(), "Cancel") {
		t.Errorf("err = %v", err)
	}
}
