package sbi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/free5gc/openapi/models"
	"github.com/free5gc/openapi/oauth"
	"github.com/free5gc/openapi/sbitls"
)

var oidNfTypes = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 34}

const nrfInstance = "cdee1983-45ab-41a6-8f5b-6f832d5206e8"

func nfTypesExtension(t *testing.T, nfType string) pkix.Extension {
	t.Helper()
	value, err := asn1.Marshal([]string{nfType})
	if err != nil {
		t.Fatal(err)
	}
	// IA5String, not the PrintableString of asn1.Marshal.
	value[2] = asn1.TagIA5String
	return pkix.Extension{Id: oidNfTypes, Value: value}
}

func uuidUri(t *testing.T, id string) *url.URL {
	t.Helper()
	uri, err := url.Parse("urn:uuid:" + id)
	if err != nil {
		t.Fatal(err)
	}
	return uri
}

// peerOf is the TLS state of a client with the certificate of an NF.
func peerOf(t *testing.T, id, nfType string) *tls.ConnectionState {
	t.Helper()
	return &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{
		URIs:       []*url.URL{uuidUri(t, id)},
		Extensions: []pkix.Extension{nfTypesExtension(t, nfType)},
	}}}
}

func sbitlsId(t *testing.T, state *tls.ConnectionState) string {
	t.Helper()
	id, err := sbitls.NfInstanceId(state.PeerCertificates[0])
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func writePem(t *testing.T, file, kind string, der []byte) {
	t.Helper()
	if err := os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// issue writes a certificate and its key.
func issue(t *testing.T, template, parent *x509.Certificate, signer *ecdsa.PrivateKey) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	writePem(t, certFile, "CERTIFICATE", der)
	writePem(t, keyFile, "PRIVATE KEY", pkcs8)
	return certFile, keyFile
}

// tokenIssuer is the NRF of a test: the certificate and the signer of the
// access tokens. sub is the client that the tokens name.
type tokenIssuer struct {
	signer  *oauth.Signer
	pemPath string
	sub     string
}

func newIssuer(t *testing.T, initTls bool) *tokenIssuer {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "operator CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDer, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDer)
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	writePem(t, caFile, "CERTIFICATE", caDer)
	crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(1), ThisUpdate: time.Now().Add(-time.Minute), NextUpdate: time.Now().Add(time.Hour),
	}, ca, caKey)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(crl)
	}))
	t.Cleanup(server.Close)

	leaf := func(serial int64, id string) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: id},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, URIs: []*url.URL{uuidUri(t, id)},
			CRLDistributionPoints: []string{server.URL + "/ca.crl"},
		}
	}
	token := leaf(2, nrfInstance)
	token.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 39}}
	certFile, keyFile := issue(t, token, ca, caKey)
	signer, err := oauth.NewSigner(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if initTls {
		own := leaf(3, aanfInstance)
		own.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
		own.ExtraExtensions = []pkix.Extension{nfTypesExtension(t, "AANF")}
		ownCert, ownKey := issue(t, own, ca, caKey)
		if err = sbitls.Init(sbitls.Config{Certificate: ownCert, Key: ownKey, CA: caFile}); err != nil {
			t.Fatal(err)
		}
	}
	return &tokenIssuer{signer: signer, pemPath: certFile}
}

// newTokenIssuer is the NRF of the operator, with the TLS of this AAnF.
func newTokenIssuer(t *testing.T) *tokenIssuer {
	t.Helper()
	return newIssuer(t, true)
}

// newOtherIssuer is an NRF of another CA.
func newOtherIssuer(t *testing.T) *tokenIssuer {
	t.Helper()
	return newIssuer(t, false)
}

func (e *env) useIssuer(ti *tokenIssuer) {
	e.app.ctx.NrfCertPem = ti.pemPath
	e.app.ctx.SetOAuth2Required(true)
}

func (ti *tokenIssuer) token(t *testing.T, scope string, exp time.Time, aud any) string {
	t.Helper()
	claims := models.NrfAccessTokenAccessTokenClaims{
		Iss: nrfInstance, Sub: ti.sub, Aud: aud, Scope: scope, Exp: int32(exp.Unix()),
	}
	s, err := ti.signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	return "Bearer " + s
}
