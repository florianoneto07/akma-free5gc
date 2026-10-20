package sbi

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
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
)

const (
	prefix   = "/naanf-akma/v1"
	afLocal  = "af1.akma.example.FF00000001" // authorized from 127.0.0.1
	afRemote = "af2.akma.example.FF00000001" // authorized from 192.0.2.10 only
	afNone   = "af3.akma.example.FF00000001" // not in the local policy
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
					{AfId: afLocal, SourceAddresses: []string{"127.0.0.1", "::1"}},
					{AfId: afRemote, SourceAddresses: []string{"192.0.2.10"}},
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

	ts := httptest.NewUnstartedServer(h2c.NewHandler(s.router, &http2.Server{}))
	ts.Start()
	t.Cleanup(ts.Close)

	client := &http.Client{Transport: &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}}
	return &env{t: t, app: app, server: s, ts: ts, client: client, v: loadVector(t)}
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
	// Forwarding headers do not change the source address.
	b, _ := json.Marshal(map[string]any{"afId": afRemote, "aKId": e.v.AKID["base64"]})
	r := e.do(http.MethodPost, prefix+"/retrieve-applicationkey", "application/json", bytes.NewReader(b),
		map[string]string{"X-Forwarded-For": "192.0.2.10", "X-Real-Ip": "192.0.2.10"})
	wantProblem(t, r, http.StatusForbidden, "")
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

type tokenIssuer struct {
	key     *rsa.PrivateKey
	pemPath string
}

func newTokenIssuer(t *testing.T) tokenIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "nrf.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return tokenIssuer{key, path}
}

func (ti tokenIssuer) token(t *testing.T, scope string, exp time.Time, aud any) string {
	t.Helper()
	claims := models.NrfAccessTokenAccessTokenClaims{
		Iss: uuid.New().String(), Sub: uuid.New().String(), Aud: aud, Scope: scope, Exp: int32(exp.Unix()),
	}
	s, err := jwt.NewWithClaims(jwt.SigningMethodRS512, claims).SignedString(ti.key)
	if err != nil {
		t.Fatal(err)
	}
	return "Bearer " + s
}

func TestOAuth2(t *testing.T) {
	e := newEnv(t)
	ti := newTokenIssuer(t)
	e.app.ctx.NrfCertPem = ti.pemPath
	e.app.ctx.SetOAuth2Required(true)
	other := newTokenIssuer(t)
	future := time.Now().Add(time.Hour)
	nfId := e.app.ctx.NfId

	t.Run("no token", func(t *testing.T) {
		r := e.register(nil)
		wantProblem(t, r, http.StatusUnauthorized, "")
		if r.header.Get("WWW-Authenticate") != "Bearer" {
			t.Errorf("WWW-Authenticate = %q", r.header.Get("WWW-Authenticate"))
		}
	})
	rejected := map[string]string{
		"other signer":          other.token(t, "naanf-akma", future, "AANF"),
		"other scope":           ti.token(t, "nausf-auth", future, "AANF"),
		"expired":               ti.token(t, "naanf-akma", time.Now().Add(-time.Minute), "AANF"),
		"without exp":           ti.token(t, "naanf-akma", time.Unix(0, 0), "AANF"),
		"audience of another":   ti.token(t, "naanf-akma", future, uuid.New().String()),
		"audience another type": ti.token(t, "naanf-akma", future, "UDM"),
		"empty audience":        ti.token(t, "naanf-akma", future, ""),
		"without audience":      ti.token(t, "naanf-akma", future, nil),
		"empty audience list":   ti.token(t, "naanf-akma", future, []string{}),
		"not Bearer":            strings.Replace(ti.token(t, "naanf-akma", future, "AANF"), "Bearer", "Basic", 1),
	}
	for name, tok := range rejected {
		t.Run(name, func(t *testing.T) {
			r := e.register(map[string]string{"Authorization": tok})
			wantProblem(t, r, http.StatusUnauthorized, "")
			if !strings.Contains(r.header.Get("WWW-Authenticate"), "invalid_token") {
				t.Errorf("WWW-Authenticate = %q", r.header.Get("WWW-Authenticate"))
			}
		})
	}
	accepted := map[string]string{
		"audience NF instance": ti.token(t, "naanf-akma", future, nfId),
		"audience NF type":     ti.token(t, "naanf-akma", future, "AANF"),
		"audience list":        ti.token(t, "naanf-akma", future, []string{uuid.New().String(), nfId}),
		"several scopes":       ti.token(t, "nausf-auth naanf-akma", future, "AANF"),
	}
	for name, tok := range accepted {
		t.Run(name, func(t *testing.T) {
			wantStatus(t, e.register(map[string]string{"Authorization": tok}), http.StatusOK)
		})
	}
	t.Run("remove requires a token", func(t *testing.T) {
		wantProblem(t, e.postJSON("/remove-context", map[string]any{"supi": e.v.Supi}, nil), http.StatusUnauthorized, "")
	})
	// The AF is authorized by local policy, without a token.
	t.Run("retrieve without token", func(t *testing.T) {
		wantStatus(t, e.retrieve(afLocal, e.v.AKID["base64"]), http.StatusOK)
	})
}

// --- K_AF requested through the NEF (TS 33.535 cl. 6.3; nef.md cl. 4) ---

func TestRetrieveViaNef(t *testing.T) {
	e := newEnv(t)
	wantStatus(t, e.register(nil), http.StatusOK)
	// The test client connects from the loopback address, which is also the
	// address of afLocal in the AF policy.
	nefs, err := aanf_context.NewNefPolicy([]factory.AuthorizedNef{
		{SourceAddresses: []string{"127.0.0.1", "::1"}, AfIds: []string{afRemote}},
	})
	if err != nil {
		t.Fatal(err)
	}
	e.app.ctx.NefPolicy = nefs
	ti := newTokenIssuer(t)
	e.app.ctx.NrfCertPem = ti.pemPath
	e.app.ctx.SetOAuth2Required(true)
	token := map[string]string{"Authorization": ti.token(t, "naanf-akma", time.Now().Add(time.Hour), "AANF")}
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
	t.Run("NEF with token, AF_ID not accepted from the NEF", func(t *testing.T) {
		wantProblem(t, retrieve(afLocal, false, token), http.StatusForbidden, "")
	})
	t.Run("invalid token", func(t *testing.T) {
		bad := map[string]string{"Authorization": newTokenIssuer(t).token(t, "naanf-akma", time.Now().Add(time.Hour), "AANF")}
		r := retrieve(afRemote, false, bad)
		wantProblem(t, r, http.StatusUnauthorized, "")
		if !strings.Contains(r.header.Get("WWW-Authenticate"), "invalid_token") {
			t.Errorf("WWW-Authenticate = %q", r.header.Get("WWW-Authenticate"))
		}
	})
	// Without a token, the request is an AF's, under the AF policy.
	t.Run("no token, AF policy", func(t *testing.T) {
		wantStatus(t, retrieve(afLocal, false, nil), http.StatusOK)
		wantProblem(t, retrieve(afRemote, false, nil), http.StatusForbidden, "")
	})
	// Without OAuth2, the NEF is recognized by its source address alone.
	t.Run("OAuth2 not required", func(t *testing.T) {
		e.app.ctx.SetOAuth2Required(false)
		defer e.app.ctx.SetOAuth2Required(true)
		wantStatus(t, retrieve(afRemote, false, nil), http.StatusOK)
		wantProblem(t, retrieve(afLocal, false, nil), http.StatusForbidden, "")
	})
}

func TestNefPolicy(t *testing.T) {
	p, err := aanf_context.NewNefPolicy([]factory.AuthorizedNef{
		{SourceAddresses: []string{"192.0.2.20"}, AfIds: []string{afRemote}},
		{SourceAddresses: []string{"192.0.2.20", "192.0.2.21"}, AfIds: []string{"af4.akma.example.ff00000001"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	nef, other := netip.MustParseAddr("192.0.2.20"), netip.MustParseAddr("192.0.2.21")
	id := func(s string) afid.AfID {
		v, err := afid.Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	if !p.IsNef(nef) || !p.IsNef(netip.MustParseAddr("::ffff:192.0.2.20")) || p.IsNef(netip.MustParseAddr("192.0.2.22")) {
		t.Error("IsNef")
	}
	if !p.Authorize(id(afRemote), nef) || !p.Authorize(id("af4.akma.example.FF00000001"), nef) ||
		p.Authorize(id(afRemote), other) || p.Authorize(id(afLocal), nef) {
		t.Error("Authorize")
	}
	if got := strings.Join(p.AfIds(), ","); got != "af2.akma.example.FF00000001,af4.akma.example.FF00000001" {
		t.Errorf("AfIds = %s", got)
	}
	if _, err := aanf_context.NewNefPolicy([]factory.AuthorizedNef{
		{SourceAddresses: []string{"192.0.2.20"}, AfIds: []string{"af1.akma.example"}},
	}); err == nil {
		t.Error("AF_ID without Ua* id accepted")
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
