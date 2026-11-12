package context

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeKey(t *testing.T, dir, name string, key any) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func caCertificate(t *testing.T, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{Organization: []string{"AKMA test"}, CommonName: "CA"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert
}

func TestLoadKeys(t *testing.T) {
	dir := t.TempDir()
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	other384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	if _, err := loadES256Key(writeKey(t, dir, "p256", p256)); err != nil {
		t.Fatalf("P-256 ES256 key: %v", err)
	}
	for name, key := range map[string]any{"P-384": p384, "RSA": rsaKey} {
		if _, err := loadES256Key(writeKey(t, dir, name, key)); err == nil {
			t.Fatalf("%s key accepted for ES256", name)
		}
	}

	// The CA key is ECDSA P-384 or P-521 and matches the CA certificate
	// (TS 33.310 cl. 6.1.1).
	if _, err := loadCAKey(writeKey(t, dir, "ca384", p384), caCertificate(t, p384)); err != nil {
		t.Fatalf("P-384 CA key: %v", err)
	}
	if _, err := loadCAKey(writeKey(t, dir, "ca256", p256), caCertificate(t, p256)); err == nil {
		t.Fatal("P-256 CA key accepted")
	}
	if _, err := loadCAKey(writeKey(t, dir, "other", other384), caCertificate(t, p384)); err == nil {
		t.Fatal("a key that is not the one of the CA certificate was accepted")
	}
}

func TestSubjectName(t *testing.T) {
	der, err := subjectName([]string{"AKMA test"}, "0a1b")
	if err != nil {
		t.Fatal(err)
	}
	// SEQUENCE { SET { SEQUENCE { OID 2.5.4.10, UTF8String } },
	//            SET { SEQUENCE { OID 2.5.4.3, UTF8String } } }
	want := []byte{0x30, 0x23,
		0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x09, 'A', 'K', 'M', 'A', ' ', 't', 'e', 's', 't',
		0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x04, '0', 'a', '1', 'b'}
	if string(der) != string(want) {
		t.Fatalf("subject %x, want %x", der, want)
	}
}
