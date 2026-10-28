package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/florianoneto07/akma-free5gc/af/af/internal/aanf"
	"github.com/florianoneto07/akma-free5gc/af/af/internal/config"
	"github.com/florianoneto07/akma-free5gc/af/af/internal/logger"
	"github.com/florianoneto07/akma-free5gc/af/uastar"
	"github.com/florianoneto07/akma-free5gc/af/ue/uaclient"
	"github.com/florianoneto07/akma-free5gc/shared/akma/afid"
	"github.com/florianoneto07/akma-free5gc/shared/akma/codec"
	"github.com/florianoneto07/akma-free5gc/shared/akma/kdf"
)

const (
	testFQDN = "af1.akma.example"
	testAKid = "rid0000.atidiz1FN8DkMGyxwtfTVYsKUsWnzOJdBOLlQEiQlK2gHNA=@5gc.mnc093.mcc208.3gppnetwork.org"
)

var testKaf = kdf.Key{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}

// fakeAanf plays the AAnF.
type fakeAanf struct {
	mu       sync.Mutex
	key      aanf.Key
	err      error
	lifetime time.Duration
	now      func() time.Time
	calls    int
	aKids    []string
	afIDs    []string
}

func (f *fakeAanf) ApplicationKey(_ context.Context, id afid.AfID, aKid string) (aanf.Key, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.aKids = append(f.aKids, aKid)
	f.afIDs = append(f.afIDs, id.Transport())
	if f.err != nil {
		return aanf.Key{}, f.err
	}
	k := f.key
	if f.lifetime != 0 {
		k.Expiry = f.now().Add(f.lifetime)
	}
	return k, nil
}

func (f *fakeAanf) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// clock is a settable time source.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type testAF struct {
	srv   *Server
	ts    *httptest.Server
	aanf  *fakeAanf
	clock *clock
}

func settings(t *testing.T, mutate func(*config.Configuration)) *config.Settings {
	t.Helper()
	c := config.Config{Configuration: config.Configuration{
		FQDN: testFQDN, UaStarID: "FF00000001", Listen: "127.0.0.1:0", AanfURI: "http://127.0.0.1:1",
	}}
	if mutate != nil {
		mutate(&c.Configuration)
	}
	s, err := c.Settings()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newTestAF(t *testing.T, mutate func(*config.Configuration)) *testAF {
	t.Helper()
	ck := &clock{t: time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)}
	fa := &fakeAanf{key: aanf.Key{KAf: testKaf, Supi: "imsi-208930000000001"}, lifetime: time.Hour, now: ck.now}
	srv := New(settings(t, mutate), fa)
	srv.now = ck.now
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	return &testAF{srv: srv, ts: ts, aanf: fa, clock: ck}
}

func (a *testAF) session(t *testing.T, kaf kdf.Key, qop string) *uaclient.Session {
	t.Helper()
	s, err := uaclient.NewSession(uaclient.Config{
		FQDN: testFQDN, Connect: a.ts.Listener.Addr().String(), Path: config.DefaultPath,
		AKID: testAKid, KAf: kaf, Qop: qop,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// get sends a GET with the given headers, Host set to the AF FQDN unless
// overridden.
func (a *testAF) get(t *testing.T, path string, header map[string]string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, a.ts.URL+path, nil)
	_, port, _ := net.SplitHostPort(a.ts.Listener.Addr().String())
	req.Host = testFQDN + ":" + port
	for k, v := range header {
		if k == "Host" {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	rsp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rsp.Body.Close() })
	return rsp
}

func cause(t *testing.T, rsp *http.Response) string {
	t.Helper()
	var e ErrorResponse
	if err := json.NewDecoder(rsp.Body).Decode(&e); err != nil {
		t.Fatalf("error body: %v", err)
	}
	return e.Cause
}

// TestInitiation: a request without AKMA parameters receives the challenge,
// which is the AKMA initiation message (TS 33.535 cl. 6.5).
func TestInitiation(t *testing.T) {
	af := newTestAF(t, nil)
	for _, ua := range []string{"akma-uaclient/0.1 3gpp-akma", "curl/8.0"} {
		rsp := af.get(t, config.DefaultPath, map[string]string{"User-Agent": ua})
		if rsp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s: status %d", ua, rsp.StatusCode)
		}
		c, err := uastar.ParseChallenge(rsp.Header.Get("WWW-Authenticate"))
		if err != nil {
			t.Fatal(err)
		}
		if c.Realm != "3GPP-bootstrapping-akma@af1.akma.example" || c.Algorithm != "SHA-256" ||
			len(c.Qop) != 1 || c.Qop[0] != "auth" || c.Charset != "UTF-8" || c.Stale || len(c.Nonce) != 44 || c.Opaque == "" {
			t.Fatalf("challenge %+v", c)
		}
	}
	if af.aanf.callCount() != 0 {
		t.Fatal("the AAnF was asked before any A-KID was received")
	}
}

// TestSessionEstablished: K_AF accepted, confirmation by rspauth, K_AF kept
// until expiry (criteria 3 and 4).
func TestSessionEstablished(t *testing.T) {
	af := newTestAF(t, nil)
	s := af.session(t, testKaf, uastar.QopAuth)
	for i := 1; i <= 3; i++ {
		r, err := s.Establish(context.Background())
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		if r.AKid != testAKid || !r.KafExpiry.Equal(af.clock.now().Add(time.Hour)) || r.NC != uastar.FormatNC(uint32(i)) {
			t.Fatalf("request %d: %+v", i, r)
		}
	}
	if n := af.aanf.callCount(); n != 1 {
		t.Fatalf("AAnF asked %d times, want 1 (active context)", n)
	}
	if af.aanf.aKids[0] != testAKid {
		t.Fatalf("aKId sent to the AAnF %q", af.aanf.aKids[0])
	}
}

func TestAuthInt(t *testing.T) {
	af := newTestAF(t, func(c *config.Configuration) { c.Qop = []string{"auth", "auth-int"} })
	if _, err := af.session(t, testKaf, uastar.QopAuthInt).Establish(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// TestWrongKafRejected: any other K_AF fails.
func TestWrongKafRejected(t *testing.T) {
	af := newTestAF(t, nil)
	wrong := testKaf
	wrong[31] ^= 1
	_, err := af.session(t, wrong, uastar.QopAuth).Establish(context.Background())
	var rej *uaclient.RejectedError
	if !errors.As(err, &rej) || rej.Status != http.StatusUnauthorized {
		t.Fatalf("err = %v", err)
	}
}

// TestKeyNotAvailable: no K_AKMA at the AAnF gives an error without the
// realm of the challenge (TS 33.535 B.1.2.2 step 6).
func TestKeyNotAvailable(t *testing.T) {
	af := newTestAF(t, nil)
	af.aanf.err = aanf.ErrKeyNotAvailable
	assertRejected(t, af, http.StatusForbidden, CauseAkmaKeyNotAvailable)
}

func TestAanfUnavailable(t *testing.T) {
	af := newTestAF(t, nil)
	af.aanf.err = aanf.ErrUnavailable
	assertRejected(t, af, http.StatusServiceUnavailable, CauseAanfUnavailable)
}

func assertRejected(t *testing.T, af *testAF, status int, want string) {
	t.Helper()
	creds := af.credentials(t, testKaf, nil)
	rsp := af.get(t, config.DefaultPath, map[string]string{"Authorization": creds.String()})
	if rsp.StatusCode != status {
		t.Fatalf("status %d, want %d", rsp.StatusCode, status)
	}
	if rsp.Header.Get("WWW-Authenticate") != "" {
		t.Fatal("error carries a challenge")
	}
	if got := cause(t, rsp); got != want {
		t.Fatalf("cause %q, want %q", got, want)
	}
}

// credentials obtains a challenge and returns valid credentials for nc 1,
// changed by mutate before the response is computed.
func (a *testAF) credentials(t *testing.T, kaf kdf.Key, mutate func(*uastar.Credentials)) uastar.Credentials {
	t.Helper()
	c, err := uastar.ParseChallenge(a.get(t, config.DefaultPath, nil).Header.Get("WWW-Authenticate"))
	if err != nil {
		t.Fatal(err)
	}
	creds := uastar.Credentials{
		Username: testAKid, Realm: c.Realm, URI: config.DefaultPath, Algorithm: uastar.Algorithm,
		Nonce: c.Nonce, NC: "00000001", CNonce: "Y25vbmNl", Qop: uastar.QopAuth, Opaque: c.Opaque,
	}
	if mutate != nil {
		mutate(&creds)
	}
	in := uastar.Input{
		Username: creds.Username, Realm: creds.Realm, Password: uastar.Password(kaf), Method: http.MethodGet,
		URI: creds.URI, Nonce: creds.Nonce, NC: creds.NC, CNonce: creds.CNonce, Qop: creds.Qop,
	}
	creds.Response = in.Response(nil)
	return creds
}

func TestRequestChecks(t *testing.T) {
	af := newTestAF(t, nil)
	for name, tc := range map[string]struct {
		mutate func(*uastar.Credentials)
		status int
	}{
		"uri differs from the target": {func(c *uastar.Credentials) { c.URI = "/other" }, http.StatusBadRequest},
		"MD5":                         {func(c *uastar.Credentials) { c.Algorithm = "MD5" }, http.StatusBadRequest},
		"qop not offered":             {func(c *uastar.Credentials) { c.Qop = uastar.QopAuthInt }, http.StatusBadRequest},
		"username not an A-KID":       {func(c *uastar.Credentials) { c.Username = "alice" }, http.StatusBadRequest},
		"realm of another AF": {func(c *uastar.Credentials) {
			c.Realm = "3GPP-bootstrapping-akma@af2.akma.example"
		}, http.StatusUnauthorized},
		"unknown nonce":    {func(c *uastar.Credentials) { c.Nonce = "bm9uY2U=" }, http.StatusUnauthorized},
		"opaque differs":   {func(c *uastar.Credentials) { c.Opaque = "b3BhcXVl" }, http.StatusUnauthorized},
		"valid (control)":  {nil, http.StatusOK},
		"nc zero (replay)": {func(c *uastar.Credentials) { c.NC = "00000000" }, http.StatusUnauthorized},
	} {
		t.Run(name, func(t *testing.T) {
			creds := af.credentials(t, testKaf, tc.mutate)
			rsp := af.get(t, config.DefaultPath, map[string]string{"Authorization": creds.String()})
			if rsp.StatusCode != tc.status {
				t.Fatalf("status %d, want %d", rsp.StatusCode, tc.status)
			}
		})
	}
}

func TestReplay(t *testing.T) {
	af := newTestAF(t, nil)
	authz := af.credentials(t, testKaf, nil).String()
	if rsp := af.get(t, config.DefaultPath, map[string]string{"Authorization": authz}); rsp.StatusCode != http.StatusOK {
		t.Fatalf("first: %d", rsp.StatusCode)
	}
	if rsp := af.get(t, config.DefaultPath, map[string]string{"Authorization": authz}); rsp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replay: %d", rsp.StatusCode)
	}
}

func TestHostPathMethod(t *testing.T) {
	af := newTestAF(t, nil)
	rsp := af.get(t, config.DefaultPath, map[string]string{"Host": "192.168.16.129:8080"})
	if rsp.StatusCode != http.StatusMisdirectedRequest || cause(t, rsp) != CauseMisdirectedRequest {
		t.Fatalf("other host: %d", rsp.StatusCode)
	}
	if rsp := af.get(t, config.DefaultPath, map[string]string{"Host": "AF1.AKMA.EXAMPLE"}); rsp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("host case: %d", rsp.StatusCode)
	}
	if rsp := af.get(t, "/other", nil); rsp.StatusCode != http.StatusNotFound {
		t.Fatalf("path: %d", rsp.StatusCode)
	}
	req, _ := http.NewRequest(http.MethodPost, af.ts.URL+config.DefaultPath, strings.NewReader("{}"))
	req.Host = testFQDN
	rsp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer rsp.Body.Close()
	if rsp.StatusCode != http.StatusMethodNotAllowed || rsp.Header.Get("Allow") != "GET" {
		t.Fatalf("method: %d %q", rsp.StatusCode, rsp.Header.Get("Allow"))
	}
}

// TestStaleNonce: the client adopts the new challenge without new
// credentials (RFC 7616 cl. 3.3 stale).
func TestStaleNonce(t *testing.T) {
	af := newTestAF(t, nil)
	s := af.session(t, testKaf, uastar.QopAuth)
	if _, err := s.Establish(context.Background()); err != nil {
		t.Fatal(err)
	}
	af.clock.advance(config.DefaultNonceLifetime + time.Second)
	r, err := s.Establish(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r.NC != "00000001" {
		t.Fatalf("nc %s after a new nonce", r.NC)
	}
}

// TestKafExpiryRefetch: an expired K_AF is never used; the AAnF is asked
// again (policy refetch).
func TestKafExpiryRefetch(t *testing.T) {
	af := newTestAF(t, func(c *config.Configuration) { c.NonceLifetime = "24h" })
	af.aanf.lifetime = time.Minute
	s := af.session(t, testKaf, uastar.QopAuth)
	if _, err := s.Establish(context.Background()); err != nil {
		t.Fatal(err)
	}
	af.clock.advance(time.Minute) // exactly at expiry: not usable any more
	r, err := s.Establish(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n := af.aanf.callCount(); n != 2 {
		t.Fatalf("AAnF asked %d times, want 2", n)
	}
	if !r.KafExpiry.Equal(af.clock.now().Add(time.Minute)) {
		t.Fatalf("expiry %s", r.KafExpiry)
	}
}

// TestKafExpiryReject: with the reject policy, the expired K_AF gives
// KAF_EXPIRED (TS 33.535 cl. 6.4.2).
func TestKafExpiryReject(t *testing.T) {
	af := newTestAF(t, func(c *config.Configuration) {
		c.NonceLifetime = "24h"
		c.KafExpiry = config.KafExpiryReject
	})
	af.aanf.lifetime = time.Minute
	s := af.session(t, testKaf, uastar.QopAuth)
	if _, err := s.Establish(context.Background()); err != nil {
		t.Fatal(err)
	}
	af.clock.advance(2 * time.Minute)
	_, err := s.Establish(context.Background())
	var rej *uaclient.RejectedError
	if !errors.As(err, &rej) || rej.Status != http.StatusForbidden || rej.Cause != CauseKafExpired {
		t.Fatalf("err = %v", err)
	}
	if n := af.aanf.callCount(); n != 1 {
		t.Fatalf("AAnF asked %d times, want 1", n)
	}
}

// TestExpiredOnArrival: a K_AF already expired when received is not used.
func TestExpiredOnArrival(t *testing.T) {
	af := newTestAF(t, nil)
	af.aanf.lifetime = -time.Second
	_, err := af.session(t, testKaf, uastar.QopAuth).Establish(context.Background())
	var rej *uaclient.RejectedError
	if !errors.As(err, &rej) || rej.Status != http.StatusServiceUnavailable {
		t.Fatalf("err = %v", err)
	}
}

// TestNoKeyInLogs runs successful and failed exchanges at trace level and
// looks for K_AF in hexadecimal and base64.
func TestNoKeyInLogs(t *testing.T) {
	var buf bytes.Buffer
	out, level := logger.Log.Out, logger.Log.GetLevel()
	logger.Log.SetOutput(&buf)
	logger.Log.SetLevel(logrus.TraceLevel)
	t.Cleanup(func() { logger.Log.SetOutput(out); logger.Log.SetLevel(level) })

	af := newTestAF(t, nil)
	if _, err := af.session(t, testKaf, uastar.QopAuth).Establish(context.Background()); err != nil {
		t.Fatal(err)
	}
	wrong := testKaf
	wrong[0] ^= 1
	_, _ = af.session(t, wrong, uastar.QopAuth).Establish(context.Background())

	log := buf.String()
	if !strings.Contains(log, "authenticated") {
		t.Fatalf("log not captured:\n%s", log)
	}
	for _, secret := range []string{codec.HexKey(testKaf), strings.ToUpper(codec.HexKey(testKaf)), uastar.Password(testKaf)} {
		if strings.Contains(log, secret) {
			t.Fatalf("K_AF in the log:\n%s", log)
		}
	}
}
