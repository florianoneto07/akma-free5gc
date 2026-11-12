package credential

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/florianoneto07/akma-free5gc/free5gc/ccf/internal/jws"
)

func TestCredential(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Now()

	tok, err := Issue(key, "ccf", "af1-external", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if p, err := Verify(tok, &key.PublicKey, "ccf", now); err != nil || p != "af1-external" {
		t.Fatalf("valid credential: %q %v", p, err)
	}
	if p, err := Verify(tok, &key.PublicKey, "ccf", now.Add(time.Hour+20*time.Second)); err != nil || p == "" {
		t.Fatalf("within the leeway: %v", err)
	}
	for name, check := range map[string]func() error{
		"another key": func() error { _, err := Verify(tok, &other.PublicKey, "ccf", now); return err },
		"another issuer": func() error {
			_, err := Verify(tok, &key.PublicKey, "other", now)
			return err
		},
		"expired": func() error {
			_, err := Verify(tok, &key.PublicKey, "ccf", now.Add(time.Hour+time.Minute))
			return err
		},
		"another audience": func() error {
			s, _ := jws.Sign(jwt.RegisteredClaims{Issuer: "ccf", Subject: "p",
				Audience: jwt.ClaimStrings{"other"}, ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour))}, key)
			_, err := Verify(s, &key.PublicKey, "ccf", now)
			return err
		},
		"RS512": func() error {
			s, _ := jwt.NewWithClaims(jwt.SigningMethodRS512, jwt.RegisteredClaims{Issuer: "ccf", Subject: "p",
				Audience: jwt.ClaimStrings{Audience}, ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour))}).SignedString(rsaKey)
			_, err := Verify(s, &key.PublicKey, "ccf", now)
			return err
		},
		"HS256": func() error {
			s, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{Issuer: "ccf", Subject: "p",
				Audience: jwt.ClaimStrings{Audience}, ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour))}).
				SignedString([]byte("secret"))
			_, err := Verify(s, &key.PublicKey, "ccf", now)
			return err
		},
		"no profile": func() error {
			s, _ := jws.Sign(jwt.RegisteredClaims{Issuer: "ccf",
				Audience: jwt.ClaimStrings{Audience}, ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour))}, key)
			_, err := Verify(s, &key.PublicKey, "ccf", now)
			return err
		},
		"no exp": func() error {
			s, _ := jws.Sign(jwt.RegisteredClaims{Issuer: "ccf", Subject: "p",
				Audience: jwt.ClaimStrings{Audience}}, key)
			_, err := Verify(s, &key.PublicKey, "ccf", now)
			return err
		},
	} {
		if check() == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	if _, err := Issue(key, "ccf", "", now, time.Hour); err == nil {
		t.Fatal("empty profile accepted")
	}
}

func TestFromAuthorization(t *testing.T) {
	for in, want := range map[string]string{
		"Bearer abc": "abc", "bearer  abc ": "abc", "Basic abc": "", "abc": "", "": "",
	} {
		if got := FromAuthorization(in); got != want {
			t.Fatalf("%q: %q", in, got)
		}
	}
	if strings.Contains(Audience, " ") {
		t.Fatal("audience with a space")
	}
}
