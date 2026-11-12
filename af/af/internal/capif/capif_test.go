package capif

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/florianoneto07/akma-free5gc/af/af/internal/config"
	"github.com/florianoneto07/akma-free5gc/af/af/internal/logger"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
)

const (
	testCredential = "credential-of-af1-external"
	// fakeServerSerial is the serial number of the certificate of the fake CCF.
	fakeServerSerial = 2
)

// fakeCCF is a CAPIF core function on CAPIF-1e: TLS with its own CA, the
// client certificate issued at onboarding, and the operations of the AF.
type fakeCCF struct {
	t      *testing.T
	srv    *httptest.Server
	caKey  *ecdsa.PrivateKey
	caCert *x509.Certificate
	caFile string
	nef    *fakeNEF

	mu         sync.Mutex
	crl        []byte
	secrets    map[string]string
	next       int
	onboarded  int
	offboarded int
	tokens     int
	expiresIn  int32
	noOAuth    bool
}

// fakeNEF serves check-authentication of AEF_Security_API.
type fakeNEF struct {
	srv     *httptest.Server
	mu      sync.Mutex
	checked []string
}

func newFakeNEF(t *testing.T) *fakeNEF {
	n := &fakeNEF{}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /aef-security/v1/check-authentication", func(w http.ResponseWriter, r *http.Request) {
		var req models.CapifCheckAuthenticationReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SupportedFeatures == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		n.mu.Lock()
		n.checked = append(n.checked, req.ApiInvokerId)
		n.mu.Unlock()
		writeJSON(w, http.StatusOK, models.CapifCheckAuthenticationRsp{SupportedFeatures: "0"})
	})
	n.srv = httptest.NewServer(mux)
	t.Cleanup(n.srv.Close)
	return n
}

// checks returns the API invokers of the check-authentication requests.
func (n *fakeNEF) checks() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.checked...)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func newFakeCCF(t *testing.T) *fakeCCF {
	t.Helper()
	f := &fakeCCF{t: t, secrets: map[string]string{}, expiresIn: 600, nef: newFakeNEF(t)}
	var err error
	f.caKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{Organization: []string{"AKMA test"}, CommonName: "CCF CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &f.caKey.PublicKey, f.caKey)
	if err != nil {
		t.Fatal(err)
	}
	f.caCert, _ = x509.ParseCertificate(der)
	f.caFile = filepath.Join(t.TempDir(), "ccf-ca.pem")
	if err := os.WriteFile(f.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	f.signCrl()
	crl := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		_, _ = w.Write(f.crl)
	}))
	t.Cleanup(crl.Close)
	srvKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srvDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(fakeServerSerial), Subject: pkix.Name{CommonName: "ccf"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		CRLDistributionPoints: []string{crl.URL + "/ccf-ca.crl"},
	}, f.caCert, &srvKey.PublicKey, f.caKey)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(f.caCert)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api-invoker-management/v1/onboardedInvokers", f.onboard)
	mux.HandleFunc("DELETE /api-invoker-management/v1/onboardedInvokers/{id}", f.offboard)
	mux.HandleFunc("GET /service-apis/v1/allServiceAPIs", f.discover)
	mux.HandleFunc("PUT /capif-security/v1/trustedInvokers/{id}", f.securityMethod)
	mux.HandleFunc("POST /capif-security/v1/securities/{id}/token", f.token)
	f.srv = httptest.NewUnstartedServer(mux)
	f.srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{srvDER}, PrivateKey: srvKey}},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    pool,
	}
	f.srv.EnableHTTP2 = true
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

// signCrl makes the CRL of the CA of the CCF, with the given serials revoked.
func (f *fakeCCF) signCrl(revoked ...int64) {
	f.t.Helper()
	list := &x509.RevocationList{
		Number: big.NewInt(int64(1 + len(revoked))), ThisUpdate: time.Now().Add(-time.Minute),
		NextUpdate: time.Now().Add(time.Hour),
	}
	for _, serial := range revoked {
		list.RevokedCertificateEntries = append(list.RevokedCertificateEntries, x509.RevocationListEntry{
			SerialNumber: big.NewInt(serial), RevocationTime: time.Now(),
		})
	}
	der, err := x509.CreateRevocationList(rand.Reader, list, f.caCert, f.caKey)
	if err != nil {
		f.t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.crl = der
}

func (f *fakeCCF) setNoOAuth(v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.noOAuth = v
}

// restart forgets every API invoker, as a restarted CCF does.
func (f *fakeCCF) restart() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.secrets = map[string]string{}
}

func (f *fakeCCF) counts() (onboarded, offboarded, tokens int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.onboarded, f.offboarded, f.tokens
}

// invoker returns the API invoker of the client certificate, if it is id
// and known.
func (f *fakeCCF) invoker(r *http.Request, id string) bool {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || r.TLS.VerifiedChains[0][0].Subject.CommonName != id {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.secrets[id]
	return ok
}

func (f *fakeCCF) onboard(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+testCredential {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var d models.CapifApiInvokerEnrolmentDetails
	if err := json.NewDecoder(r.Body).Decode(&d); err != nil || d.OnboardingInformation == nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	block, _ := pem.Decode([]byte(d.OnboardingInformation.ApiInvokerPublicKey))
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.next++
	f.onboarded++
	id, secret := "invoker-"+strconv.Itoa(f.next), "secret-"+strconv.Itoa(f.next)
	f.secrets[id] = secret
	f.mu.Unlock()
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(int64(100 + f.next)), Subject: pkix.Name{CommonName: id},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, f.caCert, pub, f.caKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	d.ApiInvokerId = id
	d.OnboardingInformation.ApiInvokerCertificate = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	d.OnboardingInformation.OnboardingSecret = secret
	w.Header().Set("Location", f.srv.URL+"/api-invoker-management/v1/onboardedInvokers/"+id)
	writeJSON(w, http.StatusCreated, d)
}

func (f *fakeCCF) offboard(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !f.invoker(r, id) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	f.mu.Lock()
	delete(f.secrets, id)
	f.offboarded++
	f.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (f *fakeCCF) discover(w http.ResponseWriter, r *http.Request) {
	if !f.invoker(r, r.URL.Query().Get("api-invoker-id")) {
		writeJSON(w, http.StatusForbidden, models.ProblemDetails{Status: http.StatusForbidden})
		return
	}
	host, port, _ := net.SplitHostPort(f.nef.srv.Listener.Addr().String())
	p, _ := strconv.Atoi(port)
	oauth := []models.CapifSecurityMethod{models.CapifSecurityMethod_OAUTH}
	writeJSON(w, http.StatusOK, models.CapifDiscoveredApis{ServiceAPIDescriptions: []models.CapifServiceApiDescription{{
		ApiName: AkmaAPI, ApiId: "api-1",
		AefProfiles: []models.CapifAefProfile{
			{AefId: "other-aef", SecurityMethods: []models.CapifSecurityMethod{models.CapifSecurityMethod_PSK},
				InterfaceDescriptions: []models.CapifInterfaceDescription{{Ipv4Addr: "192.0.2.1", Port: 1}}},
			{AefId: "nef-aef", SecurityMethods: oauth,
				InterfaceDescriptions: []models.CapifInterfaceDescription{{Ipv4Addr: host, Port: int32(p)}}},
		},
	}}})
}

func (f *fakeCCF) securityMethod(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !f.invoker(r, id) {
		writeJSON(w, http.StatusNotFound, models.ProblemDetails{Status: http.StatusNotFound})
		return
	}
	var sec models.CapifServiceSecurity
	if err := json.NewDecoder(r.Body).Decode(&sec); err != nil || sec.NotificationDestination == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	noOAuth := f.noOAuth
	f.mu.Unlock()
	for i := range sec.SecurityInfo {
		if !noOAuth {
			sec.SecurityInfo[i].SelSecurityMethod = models.CapifSecurityMethod_OAUTH
		}
	}
	w.Header().Set("Location", f.srv.URL+"/capif-security/v1/trustedInvokers/"+id)
	writeJSON(w, http.StatusCreated, sec)
}

func (f *fakeCCF) token(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	secret, known := f.secrets[id]
	f.mu.Unlock()
	if !f.invoker(r, id) || !known || r.PostForm.Get("client_id") != id || r.PostForm.Get("client_secret") != secret {
		writeJSON(w, http.StatusBadRequest, models.CapifAccessTokenErr{Error: "invalid_client"})
		return
	}
	if r.PostForm.Get("grant_type") != "client_credentials" || r.PostForm.Get("scope") != "3gpp#nef-aef:3gpp-akma" {
		writeJSON(w, http.StatusBadRequest, models.CapifAccessTokenErr{Error: "invalid_request"})
		return
	}
	f.mu.Lock()
	f.tokens++
	tok, expiresIn := "token-"+strconv.Itoa(f.tokens), f.expiresIn
	f.mu.Unlock()
	writeJSON(w, http.StatusOK, models.CapifAccessTokenRsp{
		AccessToken: tok, TokenType: "Bearer", ExpiresIn: expiresIn, Scope: "3gpp#nef-aef:3gpp-akma",
	})
}

// settings returns the capif section of the AF for f, with its files in dir.
func (f *fakeCCF) settings(t *testing.T, dir string) config.Capif {
	t.Helper()
	cred := filepath.Join(dir, "af1-external.jwt")
	if err := os.WriteFile(cred, []byte(testCredential+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return config.Capif{
		CcfURI:                  f.srv.URL,
		CcfCA:                   f.caFile,
		Credential:              cred,
		State:                   filepath.Join(dir, "state", "af1-external.json"),
		NotificationDestination: "https://192.0.2.10/capif/notify",
		APIScheme:               "http",
	}
}

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	out := logger.Log.Out
	logger.Log.SetOutput(&buf)
	t.Cleanup(func() { logger.Log.SetOutput(out) })
	return &buf
}

func tokenOf(t *testing.T, i *Invoker) string {
	t.Helper()
	ctx, err := i.TokenCtx(context.Background(), "", "")
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := ctx.Value(openapi.ContextAccessToken).(string)
	return tok
}

// TestStart covers the onboarding, the state, the discovery, the security
// method and check-authentication (TS 33.122 cl. 6.1, 6.3 and 6.5.2.3).
func TestStart(t *testing.T) {
	logs := captureLog(t)
	f := newFakeCCF(t)
	cfg := f.settings(t, t.TempDir())

	i, err := Start(context.Background(), cfg, "AKMA AF af1.akma.example")
	if err != nil {
		t.Fatal(err)
	}
	if on, _, _ := f.counts(); on != 1 || i.ID() != "invoker-1" ||
		i.APIRoot() != "http://"+f.nef.srv.Listener.Addr().String() || len(f.nef.checks()) != 1 ||
		f.nef.checks()[0] != "invoker-1" {
		t.Fatalf("onboarded %d, invoker %q, apiRoot %q, checked %v", on, i.ID(), i.APIRoot(), f.nef.checks())
	}
	info, err := os.Stat(cfg.State)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("state: %v %v", info, err)
	}
	st, err := loadState(cfg.State)
	if err != nil || st.APIInvokerID != "invoker-1" || st.OnboardingSecret != "secret-1" || st.CcfURI != f.srv.URL {
		t.Fatalf("state %+v %v", st, err)
	}
	for _, s := range []string{
		"Onboarded at the CCF as API invoker invoker-1",
		"3gpp-akma discovered at " + i.APIRoot() + ", AEF nef-aef",
		"Security method OAUTH at AEF nef-aef",
		"The NEF has the authentication data of API invoker invoker-1",
	} {
		if !strings.Contains(logs.String(), s) {
			t.Fatalf("no %q in the log:\n%s", s, logs)
		}
	}

	// The state of a running AF: no new onboarding.
	i, err = Start(context.Background(), cfg, "AKMA AF af1.akma.example")
	if on, _, _ := f.counts(); err != nil || on != 1 || i.ID() != "invoker-1" {
		t.Fatalf("second start: %v, onboarded %d, invoker %q", err, on, i.ID())
	}

	// Neither the credential, the onboarding secret, the private key nor a
	// token in the log.
	tok := tokenOf(t, i)
	for _, s := range []string{testCredential, "secret-1", "PRIVATE KEY", tok} {
		if strings.Contains(logs.String(), s) {
			t.Fatalf("%q in the log", s)
		}
	}
}

// TestToken covers the access token: requested at the first use, kept, and
// renewed 30 s before its end, or when the AEF refused it (TS 33.122
// Annex C.4.1 and C.5).
func TestToken(t *testing.T) {
	logs := captureLog(t)
	f := newFakeCCF(t)
	i, err := Start(context.Background(), f.settings(t, t.TempDir()), "AKMA AF")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	i.now = func() time.Time { return now }
	if _, _, tokens := f.counts(); tokens != 0 {
		t.Fatalf("token requested at the start: %d", tokens)
	}
	if tok := tokenOf(t, i); tok != "token-1" || tokenOf(t, i) != "token-1" {
		t.Fatalf("token %q", tok)
	}
	if !strings.Contains(logs.String(), "Access token obtained, expires in 600 s") {
		t.Fatalf("no token in the log:\n%s", logs)
	}
	now = now.Add(600*time.Second - 31*time.Second)
	if tok := tokenOf(t, i); tok != "token-1" {
		t.Fatalf("token renewed too early: %q", tok)
	}
	now = now.Add(2 * time.Second)
	if tok := tokenOf(t, i); tok != "token-2" {
		t.Fatalf("token not renewed: %q", tok)
	}
	i.Invalidate()
	if tok := tokenOf(t, i); tok != "token-3" {
		t.Fatalf("token after Invalidate: %q", tok)
	}
}

// TestRestartedCCF: the AF onboards again, once, when the CCF no longer
// knows it, at the start and when it requests a token.
func TestRestartedCCF(t *testing.T) {
	captureLog(t)
	f := newFakeCCF(t)
	cfg := f.settings(t, t.TempDir())
	if _, err := Start(context.Background(), cfg, "AKMA AF"); err != nil {
		t.Fatal(err)
	}

	// At the start, with the state of the CCF before its restart: the
	// discovery answers 403.
	f.restart()
	i, err := Start(context.Background(), cfg, "AKMA AF")
	if on, _, _ := f.counts(); err != nil || on != 2 || i.ID() != "invoker-2" {
		t.Fatalf("start after the restart: %v, onboarded %d, invoker %q", err, on, i.ID())
	}
	if st, _ := loadState(cfg.State); st == nil || st.APIInvokerID != "invoker-2" {
		t.Fatalf("state %+v", st)
	}

	// While running: the token request answers invalid_client.
	f.restart()
	if tok := tokenOf(t, i); tok != "token-1" {
		t.Fatalf("token after the restart: %q", tok)
	}
	if on, _, _ := f.counts(); on != 3 || i.ID() != "invoker-3" || len(f.nef.checks()) != 3 {
		t.Fatalf("onboarded %d, invoker %q, checked %v", on, i.ID(), f.nef.checks())
	}
}

// TestRevokedCCF: the AF does not talk to a CAPIF core function with a revoked
// certificate (TS 33.310 cl. 6.3.1).
func TestRevokedCCF(t *testing.T) {
	captureLog(t)
	f := newFakeCCF(t)
	f.signCrl(fakeServerSerial)
	_, err := Start(context.Background(), f.settings(t, t.TempDir()), "AKMA AF")
	if err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("start with a revoked certificate of the CCF: %v", err)
	}
	if on, _, _ := f.counts(); on != 0 {
		t.Fatalf("onboarded %d", on)
	}
}

// TestOffboard: with offboardOnExit, the AF offboards when it stops and
// deletes its state (TS 33.122 cl. 6.8 step 5).
func TestOffboard(t *testing.T) {
	logs := captureLog(t)
	f := newFakeCCF(t)
	cfg := f.settings(t, t.TempDir())
	i, err := Start(context.Background(), cfg, "AKMA AF")
	if err != nil {
		t.Fatal(err)
	}
	i.Close(context.Background())
	if _, off, _ := f.counts(); off != 0 {
		t.Fatal("offboarded without offboardOnExit")
	}

	cfg.OffboardOnExit = true
	i, err = Start(context.Background(), cfg, "AKMA AF")
	if err != nil {
		t.Fatal(err)
	}
	i.Close(context.Background())
	if _, off, _ := f.counts(); off != 1 || i.ID() != "" || !strings.Contains(logs.String(), "Offboarded from the CCF") {
		t.Fatalf("offboarded %d, invoker %q", off, i.ID())
	}
	if _, err := os.Stat(cfg.State); !os.IsNotExist(err) {
		t.Fatalf("state kept: %v", err)
	}
}

// TestStartRefused: no OAUTH for the AEF, a wrong credential, a state of
// another CCF.
func TestStartRefused(t *testing.T) {
	captureLog(t)
	f := newFakeCCF(t)
	dir := t.TempDir()
	cfg := f.settings(t, dir)

	f.setNoOAuth(true)
	if _, err := Start(context.Background(), cfg, "AKMA AF"); err == nil ||
		!strings.Contains(err.Error(), "no OAUTH") {
		t.Fatalf("without OAUTH: %v", err)
	}
	f.setNoOAuth(false)

	if err := os.WriteFile(cfg.Credential, []byte("forged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(cfg.State); err != nil {
		t.Fatal(err)
	}
	if _, err := Start(context.Background(), cfg, "AKMA AF"); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("wrong credential: %v", err)
	}

	// The state of another CCF is set aside.
	cfg = f.settings(t, dir)
	st := &state{CcfURI: "https://192.0.2.1:8020", APIInvokerID: "x", Certificate: "c", PrivateKey: "k",
		OnboardingSecret: "s"}
	if err := saveState(cfg.State, st); err != nil {
		t.Fatal(err)
	}
	i, err := Start(context.Background(), cfg, "AKMA AF")
	if err != nil || !strings.HasPrefix(i.ID(), "invoker-") {
		t.Fatalf("state of another CCF: %v", err)
	}
}

// TestChooseAEF covers the apiRoot of the discovered AKMA API (TS 29.222
// cl. 5.2.2.2.2 NOTE; table 8.2.4.2.3-1).
func TestChooseAEF(t *testing.T) {
	oauth := []models.CapifSecurityMethod{models.CapifSecurityMethod_OAUTH}
	psk := []models.CapifSecurityMethod{models.CapifSecurityMethod_PSK}
	api := func(profiles ...models.CapifAefProfile) []models.CapifServiceApiDescription {
		return []models.CapifServiceApiDescription{{ApiName: "3gpp-other", AefProfiles: profiles},
			{ApiName: AkmaAPI, AefProfiles: profiles}}
	}
	for want, apis := range map[string][]models.CapifServiceApiDescription{
		"http://192.168.16.130:8000 nef-aef": api(models.CapifAefProfile{AefId: "nef-aef", SecurityMethods: oauth,
			InterfaceDescriptions: []models.CapifInterfaceDescription{{Ipv4Addr: "192.168.16.130", Port: 8000}}}),
		"http://[2001:db8::1]:8000 a": api(models.CapifAefProfile{AefId: "a", SecurityMethods: psk,
			InterfaceDescriptions: []models.CapifInterfaceDescription{
				{Ipv4Addr: "192.0.2.1"},
				{Ipv6Addr: "2001:db8::1", Port: 8000, SecurityMethods: oauth},
			}}),
		"http://[2001:db8::1] a": api(models.CapifAefProfile{AefId: "a", SecurityMethods: oauth,
			InterfaceDescriptions: []models.CapifInterfaceDescription{{Ipv6Addr: "2001:db8::1"}}}),
		"http://nef.example:443/a/b b": api(models.CapifAefProfile{AefId: "b", SecurityMethods: oauth,
			InterfaceDescriptions: []models.CapifInterfaceDescription{{Fqdn: "nef.example", Port: 443,
				ApiPrefix: "/a/b"}}}),
		"http://nef.example/p c": api(
			models.CapifAefProfile{AefId: "x", SecurityMethods: psk, DomainName: "x.example"},
			models.CapifAefProfile{AefId: "c", SecurityMethods: oauth, DomainName: "nef.example/p"}),
	} {
		root, aef, err := chooseAEF(apis, "http")
		if err != nil || root+" "+aef != want {
			t.Fatalf("want %q, got %q %q %v", want, root, aef, err)
		}
	}
	for name, apis := range map[string][]models.CapifServiceApiDescription{
		"no OAUTH": api(models.CapifAefProfile{AefId: "a", SecurityMethods: psk,
			InterfaceDescriptions: []models.CapifInterfaceDescription{{Ipv4Addr: "192.0.2.1"}}}),
		"no address": api(models.CapifAefProfile{AefId: "a", SecurityMethods: oauth,
			InterfaceDescriptions: []models.CapifInterfaceDescription{{Port: 1}}}),
		"apiPrefix": api(models.CapifAefProfile{AefId: "a", SecurityMethods: oauth,
			InterfaceDescriptions: []models.CapifInterfaceDescription{{Ipv4Addr: "192.0.2.1", ApiPrefix: "p"}}}),
		"none": nil,
	} {
		if _, _, err := chooseAEF(apis, "http"); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

// The state file is written whole, and only its user reads it.
func TestState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a", "b", "state.json")
	if st, err := loadState(path); st != nil || err != nil {
		t.Fatalf("no state: %+v %v", st, err)
	}
	st := &state{CcfURI: "https://c", APIInvokerID: "i", Certificate: "c", PrivateKey: "k", OnboardingSecret: "s"}
	if err := saveState(path, st); err != nil {
		t.Fatal(err)
	}
	got, err := loadState(path)
	if err != nil || *got != *st {
		t.Fatalf("state %+v %v", got, err)
	}
	if err := os.WriteFile(path, []byte(`{"apiInvokerId":"i"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadState(path); err == nil {
		t.Fatal("incomplete state accepted")
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("temporary files left: %v", entries)
	}
	if err := removeState(path); err != nil {
		t.Fatal(err)
	}
	if err := removeState(path); err != nil {
		t.Fatalf("removing twice: %v", err)
	}
}
