package akmatls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"sync/atomic"
	"testing"
	"time"
)

func TestUaStarTLS(t *testing.T) {
	for suite, want := range map[uint16]string{
		0x1301: "0100011301",
		0xC02B: "010001C02B",
		0xD001: "010001D001",
	} {
		if got := UaStarTLS(suite).String(); got != want {
			t.Errorf("UaStarTLS(%#04x) = %s, want %s", suite, got, want)
		}
	}
}

func TestIdentity(t *testing.T) {
	const aKid = "0001.abc@ba.akma.mnc093.mcc208.3gppnetwork.org"
	id := Identity(aKid)
	if id != "3GPP-AKMA;"+aKid {
		t.Fatalf("Identity = %q", id)
	}
	if got, err := ParseIdentity(id); err != nil || got != aKid {
		t.Fatalf("ParseIdentity(%q) = %q, %v", id, got, err)
	}
	for _, bad := range []string{"", "3GPP-AKMA", "3GPP-AKMA;", "3GPP-AKMA" + aKid, "3GPP-bootstrapping;" + aKid} {
		if _, err := ParseIdentity(bad); !errors.Is(err, ErrIdentity) {
			t.Errorf("ParseIdentity(%q) accepted", bad)
		}
	}
}

func testCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
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
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

// TS 33.222 cl. 5.3.1.5: a session is resumed for at most 24 hours.
func TestTicketLifetime(t *testing.T) {
	cert, pool := testCert(t)
	for _, v := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		var offset atomic.Int64
		now := func() time.Time { return time.Now().Add(time.Duration(offset.Load())) }
		srvCfg := ServerConfig(cert)
		srvCfg.Time = now
		boundTickets(srvCfg, SessionLifetime, now)
		l, err := tls.Listen("tcp", "127.0.0.1:0", srvCfg)
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				go func() {
					defer c.Close()
					_ = c.(*tls.Conn).Handshake()
					_, _ = c.Write([]byte{1}) // carries the TLS 1.3 ticket
					_, _ = c.Read(make([]byte, 1))
				}()
			}
		}()
		cliCfg := ClientConfig("af1.akma.example", pool)
		cliCfg.MaxVersion = v
		cliCfg.ClientSessionCache = tls.NewLRUClientSessionCache(4)
		dial := func() (tls.ConnectionState, error) {
			c, err := tls.Dial("tcp", l.Addr().String(), cliCfg)
			if err != nil {
				return tls.ConnectionState{}, err
			}
			defer c.Close()
			_, _ = c.Read(make([]byte, 1))
			return c.ConnectionState(), nil
		}
		if st, err := dial(); err != nil || st.DidResume || st.Version != v {
			t.Fatalf("%#04x first: %+v, %v", v, st.DidResume, err)
		}
		if st, err := dial(); err != nil || !st.DidResume {
			t.Fatalf("%#04x second: resumed %v, %v", v, st.DidResume, err)
		}
		offset.Store(int64(SessionLifetime + time.Hour))
		if st, err := dial(); err != nil || st.DidResume {
			t.Fatalf("%#04x after 25 hours: resumed %v, %v", v, st.DidResume, err)
		}
		l.Close()
	}
}
