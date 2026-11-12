package jws

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TestThumbprint checks the thumbprint of the P-256 key of RFC 7517
// Appendix A.1 against a value computed apart, in Python.
func TestThumbprint(t *testing.T) {
	x, _ := base64.RawURLEncoding.DecodeString("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4")
	y, _ := base64.RawURLEncoding.DecodeString("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM")
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Thumbprint(pub); err != nil || got != "cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s" {
		t.Fatalf("thumbprint %q %v", got, err)
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := Thumbprint(&p384.PublicKey); err == nil {
		t.Fatal("P-384 key accepted")
	}
}

func TestSignAndKeyfunc(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	claims := jwt.RegisteredClaims{Subject: "s", ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}
	parse := func(s string, pub *ecdsa.PublicKey) error {
		_, err := jwt.ParseWithClaims(s, &jwt.RegisteredClaims{}, Keyfunc(pub),
			jwt.WithValidMethods([]string{Alg}))
		return err
	}

	s, err := Sign(claims, key)
	if err != nil {
		t.Fatal(err)
	}
	kid, _ := Thumbprint(&key.PublicKey)
	header, _ := base64.RawURLEncoding.DecodeString(strings.Split(s, ".")[0])
	if string(header) != `{"alg":"ES256","kid":"`+kid+`","typ":"JWT"}` {
		t.Fatalf("header %s", header)
	}
	if err := parse(s, &key.PublicKey); err != nil {
		t.Fatalf("valid JWS: %v", err)
	}

	sign := func(header map[string]any, method jwt.SigningMethod, k any) string {
		tok := jwt.NewWithClaims(method, claims)
		for name, v := range header {
			tok.Header[name] = v
		}
		out, err := tok.SignedString(k)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	for name, s := range map[string]string{
		"another key":          sign(map[string]any{"kid": kid}, jwt.SigningMethodES256, other),
		"kid of another key":   sign(map[string]any{"kid": "x"}, jwt.SigningMethodES256, key),
		"kid that is a number": sign(map[string]any{"kid": 1}, jwt.SigningMethodES256, key),
		"crit":                 sign(map[string]any{"crit": []string{"b64"}, "b64": true}, jwt.SigningMethodES256, key),
		"RS512":                sign(nil, jwt.SigningMethodRS512, rsaKey),
		"HS256":                sign(nil, jwt.SigningMethodHS256, []byte("secret")),
		"none":                 sign(nil, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType),
	} {
		if parse(s, &key.PublicKey) == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	// Without kid, the JWS is checked with the configured key.
	if err := parse(sign(nil, jwt.SigningMethodES256, key), &key.PublicKey); err != nil {
		t.Fatalf("JWS without kid: %v", err)
	}
}
