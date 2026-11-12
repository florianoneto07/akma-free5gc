package context

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/florianoneto07/akma-free5gc/free5gc/ccf/pkg/factory"
)

func crlContext(t *testing.T, file string) *CCFContext {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{Organization: []string{"AKMA test"}, CommonName: "CCF test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId: []byte{1, 2, 3, 4},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &CCFContext{
		cfg:    &factory.Config{Configuration: &factory.Configuration{Ca: &factory.Ca{CrlFile: file}}},
		caCert: cert, caKey: key, invokers: map[string]*Invoker{}, Now: time.Now,
	}
}

func readCrl(t *testing.T, file string, c *CCFContext) *x509.RevocationList {
	t.Helper()
	der, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	list, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	if err = list.CheckSignatureFrom(c.caCert); err != nil {
		t.Fatal(err)
	}
	return list
}

func TestCrl(t *testing.T) {
	file := filepath.Join(t.TempDir(), "crl", "ccf-ca.crl")
	c := crlContext(t, file)
	if err := c.StartCrl(); err != nil {
		t.Fatal(err)
	}
	list := readCrl(t, file, c)
	if list.Number.Int64() != 1 || len(list.RevokedCertificateEntries) != 0 {
		t.Fatalf("CRL at the start: %d, %d revoked", list.Number, len(list.RevokedCertificateEntries))
	}
	if d := time.Until(list.NextUpdate); d < crlValidity-time.Minute || d > crlValidity {
		t.Fatalf("nextUpdate in %s", d)
	}

	serial := big.NewInt(4242)
	c.invokers["a"] = &Invoker{Id: "a", Serial: serial}
	if c.Revoked(serial) {
		t.Fatal("revoked before the offboarding")
	}
	if !c.Offboard("a") {
		t.Fatal("offboarding refused")
	}
	if c.Offboard("a") {
		t.Fatal("second offboarding accepted")
	}
	if !c.Revoked(serial) {
		t.Fatal("not revoked after the offboarding")
	}
	list = readCrl(t, file, c)
	if list.Number.Int64() != 2 || len(list.RevokedCertificateEntries) != 1 ||
		list.RevokedCertificateEntries[0].SerialNumber.Cmp(serial) != 0 ||
		list.RevokedCertificateEntries[0].ReasonCode != crlReasonCessation {
		t.Fatalf("CRL after the offboarding: %d, %+v", list.Number, list.RevokedCertificateEntries)
	}

	// The revocation survives a restart, with the same CA.
	restarted := &CCFContext{cfg: c.cfg, caCert: c.caCert, caKey: c.caKey, invokers: map[string]*Invoker{}, Now: time.Now}
	if err := restarted.StartCrl(); err != nil {
		t.Fatal(err)
	}
	if !restarted.Revoked(serial) {
		t.Fatal("revocation lost in a restart")
	}
	if list = readCrl(t, file, restarted); list.Number.Int64() != 3 || len(list.RevokedCertificateEntries) != 1 {
		t.Fatalf("CRL after a restart: %d, %d revoked", list.Number, len(list.RevokedCertificateEntries))
	}

	// Signed again one day before nextUpdate, and not before.
	restarted.renewCrl()
	if list = readCrl(t, file, restarted); list.Number.Int64() != 3 {
		t.Fatalf("CRL signed too early: %d", list.Number)
	}
	restarted.Now = func() time.Time { return time.Now().Add(crlValidity - crlRenewBefore + time.Hour) }
	restarted.renewCrl()
	if list = readCrl(t, file, restarted); list.Number.Int64() != 4 {
		t.Fatalf("CRL not signed again: %d", list.Number)
	}

	// A CRL of another CA is set aside.
	other := crlContext(t, file)
	if err := other.StartCrl(); err != nil {
		t.Fatal(err)
	}
	if other.Revoked(serial) {
		t.Fatal("revocation of another CA taken")
	}
}

func TestCrlNotConfigured(t *testing.T) {
	c := crlContext(t, "")
	if err := c.StartCrl(); err != nil {
		t.Fatal(err)
	}
	c.invokers["a"] = &Invoker{Id: "a", Serial: big.NewInt(1)}
	if !c.Offboard("a") {
		t.Fatal("offboarding refused")
	}
}
