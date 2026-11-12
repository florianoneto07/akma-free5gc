// Package jws signs and checks the JSON Web Signatures of the CCF, on the
// onboarding credentials and on the access tokens, with the JWS profile of
// TS 33.210 cl. 6.3.3.1: the "alg" ES256 and the "kid" header parameter
// "shall be supported"; "none" and the "jwk" header parameter "shall not be
// supported".
package jws

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// Alg is the JWS algorithm of the CCF: ECDSA with P-256 and SHA-256
// (RFC 7518 cl. 3.4).
const Alg = "ES256"

// Thumbprint returns the JWK thumbprint of a P-256 public key (RFC 7638
// cl. 3): the base64url SHA-256 of its required members (RFC 7518
// cl. 6.2.1) in lexicographic order, without white space.
func Thumbprint(pub *ecdsa.PublicKey) (string, error) {
	if pub == nil || pub.Curve != elliptic.P256() {
		return "", errors.New("jws: an ECDSA P-256 key is required")
	}
	point, err := pub.Bytes()
	if err != nil {
		return "", fmt.Errorf("jws: %w", err)
	}
	// point is 0x04 || x || y, each coordinate in 32 octets.
	enc := base64.RawURLEncoding
	jwk := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`,
		enc.EncodeToString(point[1:33]), enc.EncodeToString(point[33:65]))
	sum := sha256.Sum256([]byte(jwk))
	return enc.EncodeToString(sum[:]), nil
}

// Sign returns claims as a JWS in compact serialization (RFC 7515 cl. 7.1),
// signed with ES256 by key, with the thumbprint of the key as "kid".
func Sign(claims jwt.Claims, key *ecdsa.PrivateKey) (string, error) {
	kid, err := Thumbprint(&key.PublicKey)
	if err != nil {
		return "", err
	}
	t := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	t.Header["kid"] = kid
	return t.SignedString(key)
}

// Keyfunc returns pub to check a JWS. A "kid" shall name pub, and the "alg"
// shall be ES256, the algorithm of pub (TS 33.210 cl. 6.3.3.1). A JWS with
// "crit" is refused: the CCF understands no extension (RFC 7515
// cl. 4.1.11). The parser shall also be given jwt.WithValidMethods with Alg.
func Keyfunc(pub *ecdsa.PublicKey) jwt.Keyfunc {
	kid, err := Thumbprint(pub)
	return func(t *jwt.Token) (any, error) {
		if err != nil {
			return nil, err
		}
		if t.Method.Alg() != Alg {
			return nil, fmt.Errorf("jws: alg %q, the key is for %s", t.Method.Alg(), Alg)
		}
		if _, ok := t.Header["crit"]; ok {
			return nil, errors.New("jws: crit is not supported")
		}
		if v, ok := t.Header["kid"]; ok {
			if s, _ := v.(string); s != kid {
				return nil, errors.New("jws: unknown kid")
			}
		}
		return pub, nil
	}
}
