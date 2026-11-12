package context

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// loadPrivateKey reads a PEM private key: PKCS #8, PKCS #1 (RSA) or SEC 1 (EC).
func loadPrivateKey(path string) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM block", path)
	}
	switch block.Type {
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("%s: unsupported key type", path)
		}
		return signer, nil
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("%s: unexpected PEM block %q", path, block.Type)
	}
}

// loadES256Key reads a PEM ECDSA P-256 private key, for ES256 (TS 33.210
// cl. 6.3.3.1).
func loadES256Key(path string) (*ecdsa.PrivateKey, error) {
	signer, err := loadPrivateKey(path)
	if err != nil {
		return nil, err
	}
	key, ok := signer.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%s: an ECDSA P-256 key is required (ES256)", path)
	}
	return key, nil
}

// loadCAKey reads the PEM private key of the CA of cert. TS 33.310
// cl. 6.1.1: "The security level of the public key used to sign the
// certificate shall be at least the same as the public keys in the
// certificate"; the CA signs ECDSA P-384 keys, so its key is ECDSA P-384 or
// P-521.
func loadCAKey(path string, cert *x509.Certificate) (crypto.Signer, error) {
	signer, err := loadPrivateKey(path)
	if err != nil {
		return nil, err
	}
	key, ok := signer.(*ecdsa.PrivateKey)
	if !ok || (key.Curve != elliptic.P384() && key.Curve != elliptic.P521()) {
		return nil, fmt.Errorf("%s: an ECDSA P-384 or P-521 key is required", path)
	}
	if !key.PublicKey.Equal(cert.PublicKey) {
		return nil, fmt.Errorf("%s: not the key of the CA certificate", path)
	}
	return key, nil
}

// loadCertificate reads a PEM certificate and returns it with its PEM text.
func loadCertificate(path string) (*x509.Certificate, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, "", fmt.Errorf("%s: no PEM certificate", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", path, err)
	}
	return cert, string(pem.EncodeToMemory(block)), nil
}

// maxInvokerRSABits bounds the RSA keys of the API invokers. TS 33.310
// cl. 6.1.1 requires support of RSA keys of at least 4096 bits, and the key
// that signs a certificate shall have at least the security level of the key
// in it: a 4096-bit RSA key stays below the 192 bits of the P-384 key of the
// CA (NIST SP 800-57 Part 1, table 2).
const maxInvokerRSABits = 4096

// ParseInvokerPublicKey reads the public key that an API invoker sends at
// onboarding: a PEM SubjectPublicKeyInfo ("PUBLIC KEY") with an ECDSA P-256 or
// P-384 key, or an RSA key of 2048 to 4096 bits with a public exponent of at
// least 65537 (TS 33.310 cl. 6.1.1). TS 29.222 table 8.4.4.2.5-1 does not
// define the encoding of apiInvokerPublicKey.
func ParseInvokerPublicKey(text string) (crypto.PublicKey, error) {
	block, _ := pem.Decode([]byte(text))
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("expected a PEM \"PUBLIC KEY\" block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() && k.Curve != elliptic.P384() {
			return nil, errors.New("only the P-256 and P-384 curves are accepted for ECDSA")
		}
	case *rsa.PublicKey:
		if n := k.N.BitLen(); n < 2048 || n > maxInvokerRSABits {
			return nil, errors.New("an RSA key of 2048 to 4096 bits is required")
		}
		if k.E < 65537 {
			return nil, errors.New("the RSA public exponent shall be no less than 65537")
		}
	default:
		return nil, errors.New("only ECDSA P-256, ECDSA P-384 and RSA keys are accepted")
	}
	return pub, nil
}
