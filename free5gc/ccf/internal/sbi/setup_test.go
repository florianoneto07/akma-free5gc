package sbi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	ccf_context "github.com/florianoneto07/akma-free5gc/free5gc/ccf/internal/context"
	"github.com/florianoneto07/akma-free5gc/free5gc/ccf/pkg/factory"
)

// testApp is the app.App of the tests.
type testApp struct {
	ctx *ccf_context.CCFContext
	cfg *factory.Config
}

func (a *testApp) SetLogEnable(bool)                {}
func (a *testApp) SetLogLevel(string)               {}
func (a *testApp) SetReportCaller(bool)             {}
func (a *testApp) Start()                           {}
func (a *testApp) Terminate()                       {}
func (a *testApp) Context() *ccf_context.CCFContext { return a.ctx }
func (a *testApp) Config() *factory.Config          { return a.cfg }

// testCCF is a CCF on httptest servers: CAPIF-1e with TLS, the internal
// interface without.
type testCCF struct {
	server   *Server
	ctx      *ccf_context.CCFContext
	external *httptest.Server
	internal *httptest.Server
	caPool   *x509.CertPool
	dir      string
}

const (
	testAfId      = "af1.akma.example.FF00000001"
	testOtherAfId = "af4.akma.example.FF00000001"
	testCrlUri    = "http://192.0.2.1:8030/ccf-ca.crl"
)

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// newTestCCF makes the keys and certificates of the CCF in a temporary
// directory and starts it.
func newTestCCF(t *testing.T) *testCCF {
	t.Helper()
	dir := t.TempDir()

	// The CA follows TS 33.310 cl. 6.1.4a: ECDSA P-384, path length 0.
	caKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"AKMA test"}, CommonName: "CCF test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	writePEM(t, filepath.Join(dir, "ccf-ca.pem"), "CERTIFICATE", caDER)
	caKeyDER, _ := x509.MarshalECPrivateKey(caKey)
	writePEM(t, filepath.Join(dir, "ccf-ca.key"), "EC PRIVATE KEY", caKeyDER)

	srvKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{Organization: []string{"AKMA test"}, CommonName: "ccf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, filepath.Join(dir, "ccf.pem"), "CERTIFICATE", srvDER)
	srvKeyDER, _ := x509.MarshalPKCS8PrivateKey(srvKey)
	writePEM(t, filepath.Join(dir, "ccf.key"), "PRIVATE KEY", srvKeyDER)

	// ES256 keys (TS 33.210 cl. 6.3.3.1), one in PKCS #8 and one in SEC 1.
	tokenKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tokenDER, _ := x509.MarshalPKCS8PrivateKey(tokenKey)
	writePEM(t, filepath.Join(dir, "ccf-token.key"), "PRIVATE KEY", tokenDER)
	credKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	credDER, _ := x509.MarshalECPrivateKey(credKey)
	writePEM(t, filepath.Join(dir, "ccf-credential.key"), "EC PRIVATE KEY", credDER)

	cfg := &factory.Config{
		Info: &factory.Info{Version: "1.0.0"},
		Configuration: &factory.Configuration{
			CcfName: "ccf",
			Capif1e: &factory.Capif1e{
				Listener:    factory.Listener{BindingIPv4: "127.0.0.1", Port: 8020},
				Certificate: filepath.Join(dir, "ccf.pem"),
				Key:         filepath.Join(dir, "ccf.key"),
			},
			Internal: &factory.Internal{Listener: factory.Listener{BindingIPv4: "127.0.0.1", Port: 8021}},
			Ca: &factory.Ca{
				Certificate: filepath.Join(dir, "ccf-ca.pem"), Key: filepath.Join(dir, "ccf-ca.key"),
				CrlUri: testCrlUri, CrlFile: filepath.Join(dir, "crl", "ccf-ca.crl"),
			},
			Token:         &factory.Token{Key: filepath.Join(dir, "ccf-token.key"), Lifetime: "10m"},
			CredentialKey: filepath.Join(dir, "ccf-credential.key"),
			Providers:     []factory.Provider{{Name: "nef", ApfId: "nef-apf", AefIds: []string{"nef-aef"}}},
			InvokerProfiles: []factory.InvokerProfile{
				{Name: "af1-external", Apis: []string{"3gpp-akma"}, AfIds: []string{testAfId, testOtherAfId}},
				{Name: "other", Apis: []string{"3gpp-other"}},
			},
		},
		Logger: &factory.Logger{Enable: true, Level: "info"},
	}
	if _, err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	ctx, err := ccf_context.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = ctx.StartCrl(); err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(&testApp{ctx: ctx, cfg: cfg})
	if err != nil {
		t.Fatal(err)
	}

	tc := &testCCF{server: server, ctx: ctx, dir: dir, caPool: x509.NewCertPool()}
	tc.caPool.AddCert(caCert)
	tlsConfig, err := server.TLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	tc.external = httptest.NewUnstartedServer(server.ExternalRouter())
	tc.external.TLS = tlsConfig
	tc.external.EnableHTTP2 = true
	tc.external.StartTLS()
	tc.internal = httptest.NewServer(server.InternalRouter())
	t.Cleanup(func() {
		tc.external.Close()
		tc.internal.Close()
	})
	return tc
}

// client returns an HTTPS client of CAPIF-1e, with the client certificate
// cert when given.
func (tc *testCCF) client(cert *tls.Certificate, maxVersion uint16, h2 bool) *http.Client {
	cfg := &tls.Config{RootCAs: tc.caPool, MaxVersion: maxVersion}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: h2}}
}
