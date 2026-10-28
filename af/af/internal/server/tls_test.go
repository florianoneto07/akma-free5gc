package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/florianoneto07/akma-free5gc/af/af/internal/aanf"
	"github.com/florianoneto07/akma-free5gc/af/af/internal/config"
	"github.com/florianoneto07/akma-free5gc/af/akmatls"
	"github.com/florianoneto07/akma-free5gc/af/ue/uaclient"
	"github.com/florianoneto07/akma-free5gc/shared/akma/afid"
	"github.com/florianoneto07/akma-free5gc/shared/akma/kdf"
)

// testCert returns a certificate of the AF for name, self-signed, and a pool
// that trusts it.
func testCert(t *testing.T, name string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

// TS 24.109 K.2 over TLS 1.3 and TLS 1.2: the AF_ID carries the cipher suite
// of the connection, the same at the UE and at the AAnF (TS 33.220 H.3).
func TestDigestTLS(t *testing.T) {
	for _, tc := range []struct {
		max  uint16
		afID string
	}{
		{tls.VersionTLS13, "af1.akma.example.0100011301"},
		{tls.VersionTLS12, "af1.akma.example.010001C02B"},
	} {
		af := newTestAF(t, nil)
		cert, pool := testCert(t, testFQDN)
		ts := httptest.NewUnstartedServer(af.srv.DigestTLS())
		ts.TLS = akmatls.ServerConfig(cert)
		ts.StartTLS()
		t.Cleanup(ts.Close)

		var asked []string
		cfg := akmatls.ClientConfig(testFQDN, pool)
		cfg.MaxVersion = tc.max
		s, err := uaclient.NewSession(uaclient.Config{
			FQDN: testFQDN, Connect: ts.Listener.Addr().String(), Path: config.DefaultPath, TLS: cfg,
			Keys: func(_ context.Context, id afid.UaStarID) (string, kdf.Key, error) {
				asked = append(asked, testFQDN+"."+id.String())
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
		if r.AfID != tc.afID || len(asked) != 1 || asked[0] != tc.afID || r.TLSVersion != tc.max {
			t.Fatalf("result %+v, UE asked %v", r, asked)
		}
		if got := af.aanf.afIDs; len(got) != 1 || got[0] != tc.afID {
			t.Fatalf("AF_IDs at the AAnF %v, want %s", got, tc.afID)
		}
	}
}

// TS 33.222 cl. 5.3.0 step 1, cl. 5.3.1.3: the UE refuses a certificate of
// another FQDN before sending anything of AKMA.
func TestDigestTLSWrongCertificate(t *testing.T) {
	af := newTestAF(t, nil)
	cert, pool := testCert(t, "af2.akma.example")
	ts := httptest.NewUnstartedServer(af.srv.DigestTLS())
	ts.TLS = akmatls.ServerConfig(cert)
	ts.StartTLS()
	t.Cleanup(ts.Close)
	asked := false
	s, err := uaclient.NewSession(uaclient.Config{
		FQDN: testFQDN, Connect: ts.Listener.Addr().String(), Path: config.DefaultPath,
		TLS: akmatls.ClientConfig(testFQDN, pool),
		Keys: func(context.Context, afid.UaStarID) (string, kdf.Key, error) {
			asked = true
			return testAKid, testKaf, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var verr *tls.CertificateVerificationError
	if _, err := s.Establish(context.Background()); !errors.As(err, &verr) {
		t.Fatalf("err = %v, want a certificate verification error", err)
	}
	if asked || af.aanf.callCount() != 0 {
		t.Fatal("K_AF requested although the AF was not authenticated")
	}
}

// TS 24.109 K.3.2 e) and K.3.3 1) d): the A-KID after 3GPP-AKMA; and the
// errors that refuse the identity.
func TestPSKKey(t *testing.T) {
	af := newTestAF(t, nil)
	id := afid.AfID{FQDN: testFQDN, Protocol: afid.UaStarTLS13}
	sess, kaf, err := af.srv.PSKKey(context.Background(), id, akmatls.Identity(testAKid), "ue")
	if err != nil || kaf != testKaf || sess.AKid != testAKid || sess.AfID != id ||
		!sess.KafExpiry.Equal(af.clock.now().Add(time.Hour)) {
		t.Fatalf("PSKKey = %+v, %v", sess, err)
	}
	if got := af.aanf.afIDs; len(got) != 1 || got[0] != "af1.akma.example.0100000007" {
		t.Fatalf("AF_IDs at the AAnF %v", got)
	}
	for _, bad := range []string{testAKid, "3GPP-AKMA;not-an-akid", "3GPP-bootstrapping;" + testAKid} {
		if _, _, err := af.srv.PSKKey(context.Background(), id, bad, "ue"); !errors.Is(err, ErrPSKIdentity) {
			t.Errorf("identity %q: %v", bad, err)
		}
	}
	af.aanf.err = aanf.ErrKeyNotAvailable
	other := afid.AfID{FQDN: testFQDN, Protocol: akmatls.UaStarTLS(0xD001)}
	if _, _, err := af.srv.PSKKey(context.Background(), other, akmatls.Identity(testAKid), "ue"); !errors.Is(err,
		aanf.ErrKeyNotAvailable) {
		t.Fatalf("err = %v", err)
	}
}

// The PSK handler answers with the session of its connection.
func TestPSKHandler(t *testing.T) {
	af := newTestAF(t, nil)
	expiry := af.clock.now().Add(time.Hour)
	sess := PSKSession{AKid: testAKid, AfID: afid.AfID{FQDN: testFQDN, Protocol: afid.UaStarTLS13}, KafExpiry: expiry}
	ts := httptest.NewUnstartedServer(af.srv.PSK())
	ts.Config.ConnContext = func(ctx context.Context, _ net.Conn) context.Context {
		return WithPSKSession(ctx, func() (PSKSession, bool) { return sess, true })
	}
	ts.Start()
	t.Cleanup(ts.Close)
	af.ts = ts
	rsp := af.get(t, config.DefaultPath, nil)
	var r SessionResponse
	if err := json.NewDecoder(rsp.Body).Decode(&r); err != nil || rsp.StatusCode != http.StatusOK ||
		r.AKid != testAKid || !r.KafExpiry.Equal(expiry) {
		t.Fatalf("status %d, body %+v, %v", rsp.StatusCode, r, err)
	}
	if rsp := af.get(t, config.DefaultPath, map[string]string{"Host": "af2.akma.example"}); rsp.StatusCode !=
		http.StatusMisdirectedRequest {
		t.Fatalf("other host: status %d", rsp.StatusCode)
	}
	af.clock.advance(2 * time.Hour)
	if rsp := af.get(t, config.DefaultPath, nil); rsp.StatusCode != http.StatusForbidden || cause(t, rsp) != CauseKafExpired {
		t.Fatalf("after the expiry: status %d", rsp.StatusCode)
	}
}
