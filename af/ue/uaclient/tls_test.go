package uaclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/florianoneto07/akma-free5gc/af/akmatls"
	"github.com/florianoneto07/akma-free5gc/shared/akma/afid"
	"github.com/florianoneto07/akma-free5gc/shared/akma/kdf"
)

// tlsAF serves af over TLS with a certificate of af1.akma.example; it
// returns the address and a pool that trusts the certificate.
func tlsAF(t *testing.T, af *fakeAF) (string, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "af1.akma.example"},
		DNSNames: []string{"af1.akma.example"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	if af.realm == "" {
		af.realm = "3GPP-bootstrapping-akma@af1.akma.example"
	}
	if af.qop == "" {
		af.qop = "auth"
	}
	ts := httptest.NewUnstartedServer(af)
	ts.TLS = akmatls.ServerConfig(tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key})
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts.Listener.Addr().String(), pool
}

// TS 24.109 K.2: the K_AF is the one of 01 00 01 and the cipher suite of
// the connection, asked once the challenge has selected AKMA.
func TestK2KeyOfTheCipherSuite(t *testing.T) {
	for max, want := range map[uint16]string{tls.VersionTLS13: "0100011301", tls.VersionTLS12: "010001C02B"} {
		addr, pool := tlsAF(t, &fakeAF{info: honest(testKaf)})
		cfg := akmatls.ClientConfig("af1.akma.example", pool)
		cfg.MaxVersion = max
		var asked []string
		s, err := NewSession(Config{
			FQDN: "af1.akma.example", Connect: addr, Path: "/ua/v1/session", TLS: cfg,
			Keys: func(_ context.Context, id afid.UaStarID) (string, kdf.Key, error) {
				asked = append(asked, id.String())
				return testAKid, testKaf, nil
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		r, err := s.Establish(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(asked) != 1 || asked[0] != want || r.AfID != "af1.akma.example."+want || r.TLSVersion != max {
			t.Fatalf("asked %v, result %+v", asked, r)
		}
	}
}

// TS 33.535 B.1.2.2 step 4: a realm with the FQDN of another AF ends the
// session; the UE neither asks the ME for a K_AF nor sends the A-KID.
func TestK2RealmOfAnotherAF(t *testing.T) {
	af := &fakeAF{realm: "3GPP-bootstrapping-akma@af2.akma.example", info: honest(testKaf)}
	addr, pool := tlsAF(t, af)
	asked := false
	s, err := NewSession(Config{
		FQDN: "af1.akma.example", Connect: addr, Path: "/ua/v1/session",
		TLS: akmatls.ClientConfig("af1.akma.example", pool),
		Keys: func(context.Context, afid.UaStarID) (string, kdf.Key, error) {
			asked = true
			return testAKid, testKaf, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Establish(context.Background()); !errors.Is(err, ErrChallenge) {
		t.Fatalf("err = %v", err)
	}
	if asked {
		t.Fatal("K_AF asked after a challenge of another AF")
	}
	for _, a := range af.authzs {
		if strings.Contains(a, testAKid) {
			t.Fatal("A-KID sent")
		}
	}
}
