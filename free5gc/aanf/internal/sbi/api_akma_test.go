package sbi

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"golang.org/x/net/http2/hpack"

	aanf_context "github.com/florianoneto07/akma-free5gc/free5gc/aanf/internal/context"
	"github.com/florianoneto07/akma-free5gc/free5gc/aanf/internal/logger"
	"github.com/florianoneto07/akma-free5gc/free5gc/aanf/internal/sbi/consumer"
	"github.com/florianoneto07/akma-free5gc/free5gc/aanf/internal/sbi/processor"
	"github.com/florianoneto07/akma-free5gc/free5gc/aanf/pkg/factory"
	"github.com/florianoneto07/akma-free5gc/shared/akma/afid"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/openapi/oauth"
)

const (
	prefix   = "/naanf-akma/v1"
	afLocal  = "af1.akma.example.FF00000001" // authorized for afInstance
	afRemote = "af2.akma.example.FF00000001" // authorized for af2Instance only
	afNone   = "af3.akma.example.FF00000001" // not in the local policy

	aanfInstance = "b6f417f0-06fa-4c38-b291-33066f5a5fe7"
	afInstance   = "2170454b-4cfa-406a-a77c-2137042b54b4"
	af2Instance  = "e4b00d27-d8ed-473f-9f93-af78e87fc0ce"
	nefInstance  = "8e73ad07-906c-4952-93ac-cd32bbb076ed"
	ausfInstance = "5a6d7127-edf7-4edc-960c-e4105ff023d8"
)

// Vector "testbed-ue" of the oracle (shared/akma/testdata/vectors.json).
type vector struct {
	Name          string            `json:"name"`
	Supi          string            `json:"supi"`
	KAkma         string            `json:"k_akma"`
	AKID          map[string]string `json:"a_kid"`
	AfIDTransport string            `json:"af_id_transport"`
	KAf           string            `json:"k_af"`
	KAfBase64     string            `json:"k_af_base64"`
}

func loadVector(t *testing.T) vector {
	t.Helper()
	raw, err := os.ReadFile("../../../../shared/akma/testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Vectors []vector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	for _, v := range f.Vectors {
		if v.Name == "testbed-ue" {
			return v
		}
	}
	t.Fatal("vector testbed-ue not found")
	return vector{}
}

type fakeApp struct {
	ctx  *aanf_context.AANFContext
	cfg  *factory.Config
	proc *processor.Processor
	cons *consumer.Consumer
}

func (a *fakeApp) SetLogEnable(bool)                  {}
func (a *fakeApp) SetLogLevel(string)                 {}
func (a *fakeApp) SetReportCaller(bool)               {}
func (a *fakeApp) Start()                             {}
func (a *fakeApp) Terminate()                         {}
func (a *fakeApp) Context() *aanf_context.AANFContext { return a.ctx }
func (a *fakeApp) Config() *factory.Config            { return a.cfg }
func (a *fakeApp) Processor() *processor.Processor    { return a.proc }
func (a *fakeApp) Consumer() *consumer.Consumer       { return a.cons }

func testConfig() *factory.Config {
	return &factory.Config{
		Info: &factory.Info{Version: "1.0.0"},
		Configuration: &factory.Configuration{
			NfInstanceId: uuid.New().String(),
			Sbi: &factory.Sbi{
				Scheme: "http", RegisterIPv4: "127.0.0.1", BindingIPv4: "127.0.0.1", Port: 8000,
			},
			ServiceNameList:   []string{"naanf-akma"},
			NrfUri:            "http://127.0.0.10:8000",
			PlmnSupportList:   []models.PlmnId{{Mcc: "208", Mnc: "93"}},
			RoutingIndicators: []string{"0000"},
			Akma: &factory.Akma{
				KafLifetime: "1h",
				AuthorizedAfs: []factory.AuthorizedAf{
					{AfId: afLocal, NfInstanceIds: []string{afInstance}},
					{AfId: afRemote, NfInstanceIds: []string{af2Instance}},
				},
			},
		},
		Logger: &factory.Logger{Enable: true, Level: "info"},
	}
}

type env struct {
	t      *testing.T
	app    *fakeApp
	server *Server
	ts     *httptest.Server
	client *http.Client
	v      vector
	// peer is the TLS client of the requests, that the test server, in h2c,
	// gives to the handlers; nil is the SBI over http.
	peer *tls.ConnectionState
}

func newEnv(t *testing.T) *env {
	t.Helper()
	gin.SetMode(gin.TestMode)
	cfg := testConfig()
	ctx, err := aanf_context.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	app := &fakeApp{ctx: ctx, cfg: cfg}
	if app.proc, err = processor.NewProcessor(app); err != nil {
		t.Fatal(err)
	}
	if app.cons, err = consumer.NewConsumer(app); err != nil {
		t.Fatal(err)
	}
	s := &Server{ServerAanf: app}
	s.router = newRouter(s)
	// A route that panics, to observe the 500 answer.
	s.router.POST(prefix+"/panic-for-test", func(*gin.Context) { panic("test panic") })

	e := &env{t: t, app: app, server: s, v: loadVector(t), peer: peerOf(t, afInstance, "AF")}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.TLS = e.peer
		s.router.ServeHTTP(w, r)
	})
	ts := httptest.NewUnstartedServer(h2c.NewHandler(handler, &http2.Server{}))
	ts.Start()
	t.Cleanup(ts.Close)

	client := &http.Client{Transport: &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}}
	e.ts, e.client = ts, client
	return e
}

type response struct {
	status int
	header http.Header
	body   []byte
}

func (r response) problem(t *testing.T) models.ProblemDetails {
	t.Helper()
	if ct := r.header.Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("Content-Type = %q, want application/problem+json (body %s)", ct, r.body)
	}
	var pd models.ProblemDetails
	if err := json.Unmarshal(r.body, &pd); err != nil {
		t.Fatalf("ProblemDetails: %v", err)
	}
	if int(pd.Status) != r.status {
		t.Errorf("ProblemDetails.status = %d, HTTP status %d", pd.Status, r.status)
	}
	return pd
}

func (e *env) do(method, path, contentType string, body io.Reader, header map[string]string) response {
	e.t.Helper()
	req, err := http.NewRequest(method, e.ts.URL+path, body)
	if err != nil {
		e.t.Fatal(err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	rsp, err := e.client.Do(req)
	if err != nil {
		e.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer rsp.Body.Close()
	b, _ := io.ReadAll(rsp.Body)
	if rsp.ProtoMajor != 2 {
		e.t.Errorf("response over HTTP/%d, want HTTP/2", rsp.ProtoMajor)
	}
	// Never emitted: 204, since a K_AF is always derivable when K_AKMA is
	// present, and ROAMING_AKMA_SERVICE_DENIED, since the roaming status is
	// not subscribed.
	if path == prefix+"/retrieve-applicationkey" && rsp.StatusCode == http.StatusNoContent {
		e.t.Errorf("retrieve-applicationkey answered 204")
	}
	if bytes.Contains(b, []byte("ROAMING_AKMA_SERVICE_DENIED")) {
		e.t.Errorf("ROAMING_AKMA_SERVICE_DENIED emitted")
	}
	return response{rsp.StatusCode, rsp.Header, b}
}

func (e *env) postJSON(op string, v any, header map[string]string) response {
	e.t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		e.t.Fatal(err)
	}
	return e.do(http.MethodPost, prefix+op, "application/json", bytes.NewReader(b), header)
}

func (e *env) register(header map[string]string) response {
	return e.postJSON("/register-anchorkey", map[string]any{
		"supi": e.v.Supi, "aKId": e.v.AKID["base64"], "kAkma": e.v.KAkma,
	}, header)
}

func (e *env) retrieve(afID, aKId string) response {
	return e.postJSON("/retrieve-applicationkey", map[string]any{"afId": afID, "aKId": aKId}, nil)
}

func wantStatus(t *testing.T, r response, status int) {
	t.Helper()
	if r.status != status {
		t.Fatalf("status = %d, want %d (body %s)", r.status, status, r.body)
	}
}

func wantProblem(t *testing.T, r response, status int, cause string, params ...string) {
	t.Helper()
	wantStatus(t, r, status)
	pd := r.problem(t)
	if pd.Cause != cause {
		t.Errorf("cause = %q, want %q", pd.Cause, cause)
	}
	for _, p := range params {
		found := false
		for _, ip := range pd.InvalidParams {
			found = found || ip.Param == p
		}
		if !found {
			t.Errorf("invalidParams %+v lacks %s", pd.InvalidParams, p)
		}
	}
}

// --- Naanf_AKMA_AnchorKey_Register (TS 29.535 cl. 4.2.2.2.2) ---

func TestRegisterAnchorKey(t *testing.T) {
	e := newEnv(t)
	r := e.register(nil)
	wantStatus(t, r, http.StatusOK)
	if ct := r.header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	var info models.AkmaKeyInfo
	if err := json.Unmarshal(r.body, &info); err != nil {
		t.Fatal(err)
	}
	if info.Supi != e.v.Supi || info.AKId != e.v.AKID["base64"] || info.KAkma != e.v.KAkma || info.Gpsi != "" {
		t.Errorf("response AkmaKeyInfo = %+v", info)
	}
	if info.SuppFeat != "" {
		t.Errorf("suppFeat = %q without negotiation", info.SuppFeat)
	}
}

func TestRegisterFeatureNegotiation(t *testing.T) {
	e := newEnv(t)
	r := e.postJSON("/register-anchorkey", map[string]any{
		"supi": e.v.Supi, "aKId": e.v.AKID["base64"], "kAkma": e.v.KAkma, "suppFeat": "3",
	}, nil)
	wantStatus(t, r, http.StatusOK)
	var info models.AkmaKeyInfo
	_ = json.Unmarshal(r.body, &info)
	if info.SuppFeat != "0" {
		t.Errorf("suppFeat = %q, want 0 (no optional feature supported)", info.SuppFeat)
	}
}

func TestRegisterBadRequests(t *testing.T) {
	e := newEnv(t)
	v := e.v
	cases := []struct {
		name   string
		body   map[string]any
		cause  string
		params []string
	}{
		{"no supi nor gpsi", map[string]any{"aKId": v.AKID["base64"], "kAkma": v.KAkma},
			"MANDATORY_IE_MISSING", []string{"/supi"}},
		{"gpsi without AKMA_GPSI_Support", map[string]any{"gpsi": "msisdn-33612345678", "aKId": v.AKID["base64"], "kAkma": v.KAkma},
			"MANDATORY_IE_MISSING", []string{"/supi"}},
		{"supi and gpsi", map[string]any{"supi": v.Supi, "gpsi": "msisdn-33612345678", "aKId": v.AKID["base64"], "kAkma": v.KAkma},
			"OPTIONAL_IE_INCORRECT", []string{"/gpsi"}},
		{"no aKId", map[string]any{"supi": v.Supi, "kAkma": v.KAkma},
			"MANDATORY_IE_MISSING", []string{"/aKId"}},
		{"no kAkma", map[string]any{"supi": v.Supi, "aKId": v.AKID["base64"]},
			"MANDATORY_IE_MISSING", []string{"/kAkma"}},
		{"kAkma too short", map[string]any{"supi": v.Supi, "aKId": v.AKID["base64"], "kAkma": v.KAkma[:62]},
			"MANDATORY_IE_INCORRECT", []string{"/kAkma"}},
		{"kAkma not hex", map[string]any{"supi": v.Supi, "aKId": v.AKID["base64"], "kAkma": strings.Repeat("g", 64)},
			"MANDATORY_IE_INCORRECT", []string{"/kAkma"}},
		{"aKId not an NAI", map[string]any{"supi": v.Supi, "aKId": "rid0000.atidAAAA", "kAkma": v.KAkma},
			"MANDATORY_IE_INCORRECT", []string{"/aKId"}},
		{"aKId with RID of 5 digits", map[string]any{"supi": v.Supi, "aKId": strings.Replace(v.AKID["base64"], "rid0000", "rid00000", 1), "kAkma": v.KAkma},
			"MANDATORY_IE_INCORRECT", []string{"/aKId"}},
		{"suppFeat not hex", map[string]any{"supi": v.Supi, "aKId": v.AKID["base64"], "kAkma": v.KAkma, "suppFeat": "xyz"},
			"OPTIONAL_IE_INCORRECT", []string{"/suppFeat"}},
		{"kAkma of wrong JSON type", map[string]any{"supi": v.Supi, "aKId": v.AKID["base64"], "kAkma": 12},
			"INVALID_MSG_FORMAT", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			wantProblem(t, e.postJSON("/register-anchorkey", c.body, nil), http.StatusBadRequest, c.cause, c.params...)
		})
	}
	t.Run("body not JSON", func(t *testing.T) {
		r := e.do(http.MethodPost, prefix+"/register-anchorkey", "application/json", strings.NewReader("{"), nil)
		wantProblem(t, r, http.StatusBadRequest, "INVALID_MSG_FORMAT")
	})
	t.Run("empty body", func(t *testing.T) {
		r := e.do(http.MethodPost, prefix+"/register-anchorkey", "application/json", http.NoBody, nil)
		wantProblem(t, r, http.StatusBadRequest, "INVALID_MSG_FORMAT")
	})
}

// The "akid" label of the example of TS 29.522 table 5.14.5.4.2-1 is accepted.
func TestRegisterAcceptsAkidLabel(t *testing.T) {
	e := newEnv(t)
	alt := strings.Replace(e.v.AKID["base64"], ".atid", ".akid", 1)
	r := e.postJSON("/register-anchorkey", map[string]any{"supi": e.v.Supi, "aKId": alt, "kAkma": e.v.KAkma}, nil)
	wantStatus(t, r, http.StatusOK)
	// The same K_AKMA is found with the "atid" form.
	wantStatus(t, e.retrieve(afLocal, e.v.AKID["base64"]), http.StatusOK)
}

// --- Naanf_AKMA_ApplicationKey_Get (TS 29.535 cl. 4.2.2.3.2) ---

func TestRetrieveApplicationKey(t *testing.T) {
	e := newEnv(t)
	wantStatus(t, e.register(nil), http.StatusOK)

	r := e.retrieve(afLocal, e.v.AKID["base64"])
	wantStatus(t, r, http.StatusOK)
	var raw map[string]any
	if err := json.Unmarshal(r.body, &raw); err != nil {
		t.Fatal(err)
	}
	if raw["kaf"] != e.v.KAf {
		t.Errorf("kaf = %v, want the oracle vector %s", raw["kaf"], e.v.KAf)
	}
	if raw["supi"] != e.v.Supi {
		t.Errorf("supi = %v", raw["supi"])
	}
	if _, ok := raw["gpsi"]; ok {
		t.Error("gpsi present")
	}
	exp, _ := raw["expiry"].(string)
	ts, err := time.Parse(time.RFC3339, exp)
	if err != nil || !strings.HasSuffix(exp, "Z") || !ts.After(time.Now()) {
		t.Errorf("expiry %q not a future RFC 3339 UTC instant", exp)
	}
}

func TestRetrieveAnonymous(t *testing.T) {
	e := newEnv(t)
	wantStatus(t, e.register(nil), http.StatusOK)
	r := e.postJSON("/retrieve-applicationkey", map[string]any{
		"afId": afLocal, "aKId": e.v.AKID["base64"], "anonInd": true,
	}, nil)
	wantStatus(t, r, http.StatusOK)
	var data models.AkmaAfKeyData
	_ = json.Unmarshal(r.body, &data)
	if data.Supi != "" || data.Kaf != e.v.KAf {
		t.Errorf("anonymous response = %+v", data)
	}
}

// "notifUri" belongs to RoamingRestriction, which is not supported: ignored.
func TestRetrieveIgnoresNotifUri(t *testing.T) {
	e := newEnv(t)
	wantStatus(t, e.register(nil), http.StatusOK)
	r := e.postJSON("/retrieve-applicationkey", map[string]any{
		"afId": afLocal, "aKId": e.v.AKID["base64"], "notifUri": "http://192.168.16.129:9000/notify",
	}, nil)
	wantStatus(t, r, http.StatusOK)
}

func TestRetrieveKAkmaNotPresent(t *testing.T) {
	e := newEnv(t)
	wantProblem(t, e.retrieve(afLocal, e.v.AKID["base64"]), http.StatusForbidden, "K_AKMA_NOT_PRESENT")
}

// TS 33.535 cl. 6.2.1 step 2: AF outside the local policy, and an authorized
// AF_ID requested by another AF (AF spoofing), are rejected with 403 without
// cause.
func TestRetrieveAfNotAuthorized(t *testing.T) {
	e := newEnv(t)
	wantStatus(t, e.register(nil), http.StatusOK)
	for _, af := range []string{afNone, afRemote} {
		t.Run(af, func(t *testing.T) {
			wantProblem(t, e.retrieve(af, e.v.AKID["base64"]), http.StatusForbidden, "")
		})
	}
	// S15 of tls-sbi.md: the certificate of another AF.
	t.Run("the AF_ID of another AF", func(t *testing.T) {
		e.peer = peerOf(t, af2Instance, "AF")
		wantProblem(t, e.retrieve(afLocal, e.v.AKID["base64"]), http.StatusForbidden, "")
		wantStatus(t, e.retrieve(afRemote, e.v.AKID["base64"]), http.StatusOK)
	})
	t.Run("the NF instance of the AF with another type", func(t *testing.T) {
		e.peer = peerOf(t, afInstance, "AUSF")
		wantProblem(t, e.retrieve(afLocal, e.v.AKID["base64"]), http.StatusForbidden, "")
	})
	t.Run("a certificate without NF instance", func(t *testing.T) {
		e.peer = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{}}}
		wantProblem(t, e.retrieve(afLocal, e.v.AKID["base64"]), http.StatusForbidden, "")
	})
	// The SBI over http has no identity: only the list of AF_IDs.
	t.Run("without TLS", func(t *testing.T) {
		e.peer = nil
		wantStatus(t, e.retrieve(afRemote, e.v.AKID["base64"]), http.StatusOK)
		wantProblem(t, e.retrieve(afNone, e.v.AKID["base64"]), http.StatusForbidden, "")
	})
}

func TestRetrieveBadRequests(t *testing.T) {
	e := newEnv(t)
	cases := []struct {
		name  string
		body  map[string]any
		cause string
		param string
	}{
		{"no afId", map[string]any{"aKId": e.v.AKID["base64"]}, "MANDATORY_IE_MISSING", "/afId"},
		{"no aKId", map[string]any{"afId": afLocal}, "MANDATORY_IE_MISSING", "/aKId"},
		{"afId without dot", map[string]any{"afId": "af1akmaexampleFF00000001", "aKId": e.v.AKID["base64"]}, "MANDATORY_IE_INCORRECT", "/afId"},
		{"afId with 9 hex digits", map[string]any{"afId": "af1.akma.example.FF0000001", "aKId": e.v.AKID["base64"]}, "MANDATORY_IE_INCORRECT", "/afId"},
		{"aKId malformed", map[string]any{"afId": afLocal, "aKId": "not-an-akid"}, "MANDATORY_IE_INCORRECT", "/aKId"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			wantProblem(t, e.postJSON("/retrieve-applicationkey", c.body, nil), http.StatusBadRequest, c.cause, c.param)
		})
	}
}

// TS 33.535 cl. 6.1 NOTE 1a over the API: after a new registration for the
// same SUPI the old A-KID is unknown.
func TestReRegistrationOverAPI(t *testing.T) {
	e := newEnv(t)
	wantStatus(t, e.register(nil), http.StatusOK)
	wantStatus(t, e.retrieve(afLocal, e.v.AKID["base64"]), http.StatusOK)

	newAKID := "rid0000.atid" + strings.Repeat("A", 43) + "=@5gc.mnc093.mcc208.3gppnetwork.org"
	r := e.postJSON("/register-anchorkey", map[string]any{
		"supi": e.v.Supi, "aKId": newAKID, "kAkma": strings.Repeat("1", 64),
	}, nil)
	wantStatus(t, r, http.StatusOK)
	wantProblem(t, e.retrieve(afLocal, e.v.AKID["base64"]), http.StatusForbidden, "K_AKMA_NOT_PRESENT")
	wantStatus(t, e.retrieve(afLocal, newAKID), http.StatusOK)
}

// --- Naanf_AKMA_ContextRemove (TS 29.535 cl. 4.2.2.4.2) ---

func TestRemoveContext(t *testing.T) {
	e := newEnv(t)
	wantStatus(t, e.register(nil), http.StatusOK)

	r := e.postJSON("/remove-context", map[string]any{"supi": e.v.Supi}, nil)
	wantStatus(t, r, http.StatusNoContent)
	if len(r.body) != 0 {
		t.Errorf("204 with body %q", r.body)
	}
	wantProblem(t, e.retrieve(afLocal, e.v.AKID["base64"]), http.StatusForbidden, "K_AKMA_NOT_PRESENT")
	wantProblem(t, e.postJSON("/remove-context", map[string]any{"supi": e.v.Supi}, nil),
		http.StatusNotFound, "AKMA_CONTEXT_NOT_FOUND")
	wantProblem(t, e.postJSON("/remove-context", map[string]any{}, nil),
		http.StatusBadRequest, "MANDATORY_IE_MISSING", "/supi")
}

// --- Protocol errors (TS 29.500 cl. 5.2.7) ---

func TestUnsupportedMediaType(t *testing.T) {
	e := newEnv(t)
	body := `{"supi":"imsi-208930000000001"}`
	for _, ct := range []string{"", "text/plain", "application/problem+json", "application/x-www-form-urlencoded"} {
		t.Run("content-type="+ct, func(t *testing.T) {
			r := e.do(http.MethodPost, prefix+"/remove-context", ct, strings.NewReader(body), nil)
			wantProblem(t, r, http.StatusUnsupportedMediaType, "")
		})
	}
	r := e.do(http.MethodPost, prefix+"/remove-context", "application/json; charset=utf-8", strings.NewReader(body), nil)
	wantProblem(t, r, http.StatusNotFound, "AKMA_CONTEXT_NOT_FOUND")
}

// readerOnly hides the length of the body from the HTTP client.
type readerOnly struct{ io.Reader }

func TestContentTooLarge(t *testing.T) {
	e := newEnv(t)
	big := bytes.Repeat([]byte(" "), MaxJSONBodySize+1)
	t.Run("declared length", func(t *testing.T) {
		r := e.do(http.MethodPost, prefix+"/register-anchorkey", "application/json", bytes.NewReader(big), nil)
		wantProblem(t, r, http.StatusRequestEntityTooLarge, "MAX_JSON_SIZE_EXCEEDED")
	})
	t.Run("streamed", func(t *testing.T) {
		r := e.do(http.MethodPost, prefix+"/register-anchorkey", "application/json", readerOnly{bytes.NewReader(big)}, nil)
		wantProblem(t, r, http.StatusRequestEntityTooLarge, "MAX_JSON_SIZE_EXCEEDED")
	})
	t.Run("at the limit", func(t *testing.T) {
		body := append(bytes.Repeat([]byte(" "), MaxJSONBodySize-2), '{', '}')
		r := e.do(http.MethodPost, prefix+"/remove-context", "application/json", bytes.NewReader(body), nil)
		wantProblem(t, r, http.StatusBadRequest, "MANDATORY_IE_MISSING")
	})
}

// A Content-Length that does not match the DATA frames is sent with raw
// HTTP/2 frames, as the Go client always computes the length itself.
func TestIncorrectContentLength(t *testing.T) {
	e := newEnv(t)
	status, body := rawH2Post(t, e.ts.Listener.Addr().String(), prefix+"/remove-context",
		[][2]string{{"content-type", "application/json"}, {"content-length", "100"}},
		[]byte(`{"supi":"x"}`))
	if status != http.StatusLengthRequired || !bytes.Contains(body, []byte("INCORRECT_LENGTH")) {
		t.Errorf("status %d body %s, want 411 INCORRECT_LENGTH", status, body)
	}
}

// An invalid Content-Length value reaching the handler is answered with 411.
func TestInvalidContentLengthValue(t *testing.T) {
	e := newEnv(t)
	for _, v := range []string{"abc", "-1"} {
		req := httptest.NewRequest(http.MethodPost, prefix+"/remove-context", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Content-Length", v)
		rec := httptest.NewRecorder()
		e.server.router.ServeHTTP(rec, req)
		if rec.Code != http.StatusLengthRequired || !strings.Contains(rec.Body.String(), "INCORRECT_LENGTH") {
			t.Errorf("Content-Length %q: %d %s", v, rec.Code, rec.Body)
		}
	}
}

func TestRoutingErrors(t *testing.T) {
	e := newEnv(t)
	body := func() io.Reader { return strings.NewReader(`{}`) }
	cases := []struct {
		name, method, path string
		status             int
		cause              string
	}{
		{"GET on an operation", http.MethodGet, prefix + "/register-anchorkey", 501, ""},
		{"PUT on an operation", http.MethodPut, prefix + "/retrieve-applicationkey", 501, ""},
		{"DELETE on an operation", http.MethodDelete, prefix + "/remove-context", 501, ""},
		{"unknown API version", http.MethodPost, "/naanf-akma/v2/register-anchorkey", 400, "INVALID_API"},
		{"unknown operation", http.MethodPost, prefix + "/register-key", 404, "RESOURCE_URI_STRUCTURE_NOT_FOUND"},
		{"trailing slash", http.MethodPost, prefix + "/register-anchorkey/", 404, "RESOURCE_URI_STRUCTURE_NOT_FOUND"},
		{"other API", http.MethodPost, "/nausf-auth/v1/ue-authentications", 404, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			wantProblem(t, e.do(c.method, c.path, "application/json", body(), nil), c.status, c.cause)
		})
	}
}

func TestInternalError(t *testing.T) {
	e := newEnv(t)
	r := e.do(http.MethodPost, prefix+"/panic-for-test", "application/json", strings.NewReader(`{}`), nil)
	wantProblem(t, r, http.StatusInternalServerError, "SYSTEM_FAILURE")
}

// --- OAuth2 (TS 29.535 cl. 5.1.9; TS 33.501 cl. 13.4.1.1.2) ---

const anchorKeyScopes = "naanf-akma " + oauth.ScopeNaanfAkmaAnchorKey

func TestOAuth2(t *testing.T) {
	e := newEnv(t)
	ti := newTokenIssuer(t)
	e.useIssuer(ti)
	e.peer = peerOf(t, ausfInstance, "AUSF")
	ti.sub = ausfInstance
	other := newOtherIssuer(t)
	other.sub = ausfInstance
	future := time.Now().Add(time.Hour)

	t.Run("no token", func(t *testing.T) {
		r := e.register(nil)
		wantProblem(t, r, http.StatusUnauthorized, "")
		got := r.header.Get("WWW-Authenticate")
		if !strings.HasPrefix(got, `Bearer realm="`) || !strings.HasSuffix(got, `/naanf-akma/v1"`) {
			t.Errorf("WWW-Authenticate = %q", got)
		}
	})
	invalid := map[string]string{
		"other signer": other.token(t, anchorKeyScopes, future, "AANF"),
		"expired":      ti.token(t, anchorKeyScopes, time.Now().Add(-time.Minute), "AANF"),
		"not Bearer":   strings.Replace(ti.token(t, anchorKeyScopes, future, "AANF"), "Bearer", "Basic", 1),
	}
	for name, tok := range invalid {
		t.Run(name, func(t *testing.T) {
			r := e.register(map[string]string{"Authorization": tok})
			wantProblem(t, r, http.StatusUnauthorized, "")
			wantChallenge(t, r, `error="invalid_token"`)
		})
	}
	missing := map[string]string{
		"without exp":         ti.token(t, anchorKeyScopes, time.Unix(0, 0), "AANF"),
		"empty audience":      ti.token(t, anchorKeyScopes, future, ""),
		"without audience":    ti.token(t, anchorKeyScopes, future, nil),
		"empty audience list": ti.token(t, anchorKeyScopes, future, []string{}),
	}
	for name, tok := range missing {
		t.Run(name, func(t *testing.T) {
			r := e.register(map[string]string{"Authorization": tok})
			wantProblem(t, r, http.StatusUnauthorized, "ACCESS_TOKEN_CLAIM_MISSING")
			wantChallenge(t, r, `error="invalid_token"`)
		})
	}
	// S12 of tls-sbi.md: the token of another producer.
	mismatch := map[string]string{
		"audience of another":   ti.token(t, anchorKeyScopes, future, uuid.New().String()),
		"audience another type": ti.token(t, anchorKeyScopes, future, "UDM"),
	}
	for name, tok := range mismatch {
		t.Run(name, func(t *testing.T) {
			r := e.register(map[string]string{"Authorization": tok})
			wantProblem(t, r, http.StatusForbidden, "ACCESS_TOKEN_CLAIM_MISMATCH", "aud")
			wantChallenge(t, r, `error="invalid_token"`)
		})
	}
	// S11 of tls-sbi.md: the token of another NF instance.
	t.Run("sub of another certificate", func(t *testing.T) {
		tok := ti.token(t, anchorKeyScopes, future, "AANF")
		e.peer = peerOf(t, afInstance, "AF")
		defer func() { e.peer = peerOf(t, ausfInstance, "AUSF") }()
		r := e.register(map[string]string{"Authorization": tok})
		wantProblem(t, r, http.StatusForbidden, "ACCESS_TOKEN_CLAIM_MISMATCH", "sub")
	})
	scopes := map[string]struct{ scope, want string }{
		"other service":     {"nausf-auth", `scope="naanf-akma"`},
		"only the service":  {"naanf-akma", `scope="naanf-akma:anchorkey"`},
		"another operation": {"naanf-akma " + oauth.ScopeNaanfAkmaApplicationKey, `scope="naanf-akma:anchorkey"`},
	}
	for name, tc := range scopes {
		t.Run(name, func(t *testing.T) {
			r := e.register(map[string]string{"Authorization": ti.token(t, tc.scope, future, "AANF")})
			wantProblem(t, r, http.StatusForbidden, "")
			wantChallenge(t, r, `error="insufficient_scope"`)
			wantChallenge(t, r, tc.want)
		})
	}
	accepted := map[string]string{
		"audience NF instance": ti.token(t, anchorKeyScopes, future, aanfInstance),
		"audience NF type":     ti.token(t, anchorKeyScopes, future, "AANF"),
		"audience list":        ti.token(t, anchorKeyScopes, future, []string{uuid.New().String(), aanfInstance}),
		"several scopes":       ti.token(t, "nausf-auth "+anchorKeyScopes, future, "AANF"),
	}
	for name, tok := range accepted {
		t.Run(name, func(t *testing.T) {
			wantStatus(t, e.register(map[string]string{"Authorization": tok}), http.StatusOK)
		})
	}
	t.Run("remove requires a token", func(t *testing.T) {
		wantProblem(t, e.postJSON("/remove-context", map[string]any{"supi": e.v.Supi}, nil), http.StatusUnauthorized, "")
	})
	t.Run("remove requires the scope", func(t *testing.T) {
		header := map[string]string{"Authorization": ti.token(t, "naanf-akma", future, "AANF")}
		r := e.postJSON("/remove-context", map[string]any{"supi": e.v.Supi}, header)
		wantProblem(t, r, http.StatusForbidden, "")
		wantChallenge(t, r, `error="insufficient_scope"`)
	})
	// The AF is authorized by local policy, without a token.
	t.Run("retrieve without token", func(t *testing.T) {
		e.peer = peerOf(t, afInstance, "AF")
		wantStatus(t, e.retrieve(afLocal, e.v.AKID["base64"]), http.StatusOK)
	})
}

func wantChallenge(t *testing.T, r response, part string) {
	t.Helper()
	if got := r.header.Get("WWW-Authenticate"); !strings.HasPrefix(got, "Bearer ") || !strings.Contains(got, part) {
		t.Errorf("WWW-Authenticate = %q, want %s", got, part)
	}
}

// --- K_AF requested through the NEF (TS 33.535 cl. 6.3; nef.md cl. 4) ---

func TestRetrieveViaNef(t *testing.T) {
	e := newEnv(t)
	wantStatus(t, e.register(nil), http.StatusOK)
	nefs, err := aanf_context.NewNefPolicy([]factory.AuthorizedNef{
		{NfInstanceIds: []string{nefInstance}, AfIds: []string{afRemote}},
	})
	if err != nil {
		t.Fatal(err)
	}
	e.app.ctx.NefPolicy = nefs
	ti := newTokenIssuer(t)
	e.useIssuer(ti)
	ti.sub = nefInstance
	e.peer = peerOf(t, nefInstance, "NEF")
	future := time.Now().Add(time.Hour)
	scopes := "naanf-akma " + oauth.ScopeNaanfAkmaApplicationKey + " " + oauth.ScopeNaanfAkmaSupiAccess
	token := map[string]string{"Authorization": ti.token(t, scopes, future, "AANF")}
	retrieve := func(afID string, anon bool, header map[string]string) response {
		return e.postJSON("/retrieve-applicationkey",
			map[string]any{"afId": afID, "aKId": e.v.AKID["base64"], "anonInd": anon}, header)
	}

	t.Run("NEF with token, accepted AF_ID", func(t *testing.T) {
		r := retrieve(afRemote, false, token)
		wantStatus(t, r, http.StatusOK)
		var rsp models.AkmaAfKeyData
		if err := json.Unmarshal(r.body, &rsp); err != nil {
			t.Fatal(err)
		}
		// cl. 6.3 step 4: the AAnF answers the NEF with the SUPI.
		if rsp.Supi != e.v.Supi || rsp.Kaf == "" {
			t.Errorf("response %s", r.body)
		}
	})
	t.Run("NEF with token, anonymous access", func(t *testing.T) {
		r := retrieve(afRemote, true, token)
		wantStatus(t, r, http.StatusOK)
		if bytes.Contains(r.body, []byte(`"supi"`)) {
			t.Errorf("SUPI in the anonymous answer: %s", r.body)
		}
	})
	t.Run("token without supi-access: K_AF without the SUPI", func(t *testing.T) {
		header := map[string]string{
			"Authorization": ti.token(t, "naanf-akma "+oauth.ScopeNaanfAkmaApplicationKey, future, "AANF"),
		}
		r := retrieve(afRemote, false, header)
		wantStatus(t, r, http.StatusOK)
		if bytes.Contains(r.body, []byte(`"supi"`)) {
			t.Errorf("SUPI without the scope: %s", r.body)
		}
	})
	// S14 of tls-sbi.md.
	t.Run("token of the service only", func(t *testing.T) {
		header := map[string]string{"Authorization": ti.token(t, "naanf-akma", future, "AANF")}
		r := retrieve(afRemote, false, header)
		wantProblem(t, r, http.StatusForbidden, "")
		wantChallenge(t, r, `error="insufficient_scope", scope="naanf-akma:applicationkeyget"`)
	})
	t.Run("NEF with token, AF_ID not accepted from the NEF", func(t *testing.T) {
		wantProblem(t, retrieve(afLocal, false, token), http.StatusForbidden, "")
	})
	t.Run("invalid token", func(t *testing.T) {
		other := newOtherIssuer(t)
		other.sub = nefInstance
		bad := map[string]string{"Authorization": other.token(t, scopes, future, "AANF")}
		r := retrieve(afRemote, false, bad)
		wantProblem(t, r, http.StatusUnauthorized, "")
		wantChallenge(t, r, `error="invalid_token"`)
	})
	t.Run("the certificate of the NEF, without a token", func(t *testing.T) {
		wantProblem(t, retrieve(afRemote, false, nil), http.StatusForbidden, "")
	})
	t.Run("another NF of type NEF", func(t *testing.T) {
		e.peer = peerOf(t, uuid.New().String(), "NEF")
		defer func() { e.peer = peerOf(t, nefInstance, "NEF") }()
		ti.sub = sbitlsId(t, e.peer)
		defer func() { ti.sub = nefInstance }()
		r := retrieve(afRemote, false, map[string]string{"Authorization": ti.token(t, scopes, future, "AANF")})
		wantProblem(t, r, http.StatusForbidden, "")
	})
	t.Run("the instance of the NEF with another type", func(t *testing.T) {
		e.peer = peerOf(t, nefInstance, "AF")
		defer func() { e.peer = peerOf(t, nefInstance, "NEF") }()
		wantProblem(t, retrieve(afRemote, false, token), http.StatusForbidden, "")
	})
	// Without OAuth2, the NEF is recognized by its certificate alone.
	t.Run("OAuth2 not required", func(t *testing.T) {
		e.app.ctx.SetOAuth2Required(false)
		defer e.app.ctx.SetOAuth2Required(true)
		wantStatus(t, retrieve(afRemote, false, nil), http.StatusOK)
		wantProblem(t, retrieve(afLocal, false, nil), http.StatusForbidden, "")
	})
}

func TestNefPolicy(t *testing.T) {
	const other = "e4b00d27-d8ed-473f-9f93-af78e87fc0ce"
	p, err := aanf_context.NewNefPolicy([]factory.AuthorizedNef{
		{NfInstanceIds: []string{nefInstance}, AfIds: []string{afRemote}},
		{NfInstanceIds: []string{nefInstance, other}, AfIds: []string{"af4.akma.example.ff00000001"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	id := func(s string) afid.AfID {
		v, err := afid.Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	if !p.IsNef(nefInstance) || !p.IsNef(other) || p.IsNef(afInstance) {
		t.Error("IsNef")
	}
	if !p.Authorize(id(afRemote), nefInstance) || !p.Authorize(id("af4.akma.example.FF00000001"), nefInstance) ||
		p.Authorize(id(afRemote), other) || p.Authorize(id(afLocal), nefInstance) {
		t.Error("Authorize")
	}
	if got := strings.Join(p.AfIds(), ","); got != "af2.akma.example.FF00000001,af4.akma.example.FF00000001" {
		t.Errorf("AfIds = %s", got)
	}
	if _, err := aanf_context.NewNefPolicy([]factory.AuthorizedNef{
		{NfInstanceIds: []string{nefInstance}, AfIds: []string{"af1.akma.example"}},
	}); err == nil {
		t.Error("AF_ID without Ua* id accepted")
	}
	if _, err := aanf_context.NewNefPolicy([]factory.AuthorizedNef{
		{NfInstanceIds: []string{"192.0.2.20"}, AfIds: []string{afRemote}},
	}); err == nil {
		t.Error("NF instance that is not a UUID accepted")
	}
}

// --- No key material in the logs ---

func TestNoKeyInLogs(t *testing.T) {
	var buf bytes.Buffer
	out, lvl := logger.Log.Out, logger.Log.GetLevel()
	logger.Log.SetOutput(&buf)
	logger.Log.SetLevel(logrus.TraceLevel)
	t.Cleanup(func() { logger.Log.SetOutput(out); logger.Log.SetLevel(lvl) })

	e := newEnv(t)
	wantStatus(t, e.register(nil), http.StatusOK)
	wantStatus(t, e.retrieve(afLocal, e.v.AKID["base64"]), http.StatusOK)
	wantStatus(t, e.postJSON("/remove-context", map[string]any{"supi": e.v.Supi}, nil), http.StatusNoContent)

	logs := strings.ToLower(buf.String())
	if logs == "" {
		t.Fatal("no log captured")
	}
	for name, secret := range map[string]string{
		"K_AKMA": e.v.KAkma, "K_AF": e.v.KAf, "K_AF base64": e.v.KAfBase64,
	} {
		if strings.Contains(logs, strings.ToLower(secret)) {
			t.Errorf("%s found in the logs", name)
		}
	}
}

// rawH2Post sends one POST over a prior-knowledge HTTP/2 connection with the
// given headers and DATA, and returns the status and body of the response.
func rawH2Post(t *testing.T, addr, path string, headers [][2]string, data []byte) (int, []byte) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(conn, http2.ClientPreface); err != nil {
		t.Fatal(err)
	}
	fr := http2.NewFramer(conn, conn)
	if err := fr.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	var hb bytes.Buffer
	enc := hpack.NewEncoder(&hb)
	for _, h := range append([][2]string{
		{":method", "POST"}, {":scheme", "http"}, {":path", path}, {":authority", addr},
	}, headers...) {
		_ = enc.WriteField(hpack.HeaderField{Name: h[0], Value: h[1]})
	}
	if err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: hb.Bytes(), EndHeaders: true}); err != nil {
		t.Fatal(err)
	}
	if err := fr.WriteData(1, true, data); err != nil {
		t.Fatal(err)
	}

	status := 0
	var body []byte
	dec := hpack.NewDecoder(4096, func(f hpack.HeaderField) {
		if f.Name == ":status" {
			for _, c := range f.Value {
				status = status*10 + int(c-'0')
			}
		}
	})
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("read frame: %v (status %d)", err, status)
		}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				_ = fr.WriteSettingsAck()
			}
		case *http2.HeadersFrame:
			if f.StreamID == 1 {
				if _, err := dec.Write(f.HeaderBlockFragment()); err != nil {
					t.Fatal(err)
				}
				if f.StreamEnded() {
					return status, body
				}
			}
		case *http2.DataFrame:
			if f.StreamID == 1 {
				body = append(body, f.Data()...)
				if f.StreamEnded() {
					return status, body
				}
			}
		case *http2.RSTStreamFrame:
			if f.StreamID == 1 {
				t.Fatalf("stream reset: %v", f.ErrCode)
			}
		case *http2.GoAwayFrame:
			t.Fatalf("GOAWAY: %v", f.ErrCode)
		}
	}
}
