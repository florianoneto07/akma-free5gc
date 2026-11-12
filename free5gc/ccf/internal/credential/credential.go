// Package credential issues and checks the onboarding credentials of the API
// invokers. TS 33.122 cl. 6.1: the credential is obtained during the
// pre-provisioning of the onboarding enrolment information and "may be an
// OAuth 2.0 access token"; when it is, it is a JSON Web Token (RFC 7519) with
// a JSON Web Signature (RFC 7515). How the API invoker obtains it is out of
// the scope of the specification (NOTE 1). The JWS follows the profile of
// TS 33.210 cl. 6.3.3.1: ES256, with "kid".
package credential

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/florianoneto07/akma-free5gc/free5gc/ccf/internal/jws"
)

// Audience is the aud claim of a credential: the API the credential is for.
const Audience = "api-invoker-management"

// Leeway is the clock skew accepted on exp (TS 33.122 C.2.2: no more than
// 30 seconds).
const Leeway = 30 * time.Second

// Issue returns a credential, signed with ES256, for the invoker profile
// profile, valid from now for validity.
func Issue(key *ecdsa.PrivateKey, issuer, profile string, now time.Time, validity time.Duration) (string, error) {
	if profile == "" {
		return "", errors.New("credential: empty profile")
	}
	if validity <= 0 {
		return "", errors.New("credential: the validity must be positive")
	}
	claims := jwt.RegisteredClaims{
		Issuer:    issuer,
		Subject:   profile,
		Audience:  jwt.ClaimStrings{Audience},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(validity)),
	}
	return jws.Sign(claims, key)
}

// FromAuthorization returns the credential carried as a bearer in an
// Authorization header value (TS 29.222 cl. 5.5.2.2.2 NOTE 4; RFC 6750
// cl. 2.1), or "" when there is none.
func FromAuthorization(header string) string {
	scheme, value, ok := strings.Cut(strings.TrimSpace(header), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(value)
}

// Verify checks a credential: the ES256 signature with pub and its "kid",
// the issuer, the audience and the expiry. It returns the invoker profile it
// names.
func Verify(token string, pub *ecdsa.PublicKey, issuer string, now time.Time) (string, error) {
	var claims jwt.RegisteredClaims
	_, err := jwt.ParseWithClaims(token, &claims, jws.Keyfunc(pub),
		jwt.WithValidMethods([]string{jws.Alg}),
		jwt.WithIssuer(issuer),
		jwt.WithAudience(Audience),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(Leeway),
		jwt.WithTimeFunc(func() time.Time { return now }),
	)
	if err != nil {
		return "", fmt.Errorf("credential: %w", err)
	}
	if claims.Subject == "" {
		return "", errors.New("credential: no invoker profile (sub)")
	}
	return claims.Subject, nil
}
