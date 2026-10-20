// Package uastar implements a simplified Ua* protocol: HTTP Digest
// authentication (RFC 7616) with the AKMA parameters of TS 24.109 K.2 and
// TS 33.535 B.1.2.2, without the TLS tunnel, under the private Ua* security
// protocol identifier FF 00 00 00 01 (TS 33.220 H.2 NOTE 2).
//
// The Digest is that of RFC 7616, as in TS 33.222 cl. 5.3.0, which
// TS 33.535 B.1.2.2 adapts. TS 24.109 K.2 c) cites RFC 3310 (Digest AKA),
// whose password comes from the RES; with base64(K_AF) as the password, only
// RFC 7616 fits. Only the SHA-256 algorithm is supported (TS 33.222
// cl. 5.3.0 NOTE 1b discourages MD5).
package uastar

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/florianoneto07/akma-free5gc/shared/akma/codec"
	"github.com/florianoneto07/akma-free5gc/shared/akma/kdf"
)

const (
	// ProductToken is the User-Agent product token by which the UE
	// indicates AKMA based Digest (TS 24.109 K.2 b) 1)).
	ProductToken = "3gpp-akma"
	// RealmPrefix is the first part of the realm by which the AF selects
	// AKMA (TS 33.535 B.1.2.2 step 3; TS 24.109 K.2 b)2)). TS 24.109
	// K.2 c)3) uses "3gpp-akma" instead.
	RealmPrefix = "3GPP-bootstrapping-akma"
	// Algorithm is the only Digest algorithm supported.
	Algorithm = "SHA-256"
	// QopAuth and QopAuthInt are the qop values of RFC 7616 cl. 3.3.
	QopAuth    = "auth"
	QopAuthInt = "auth-int"
	// Charset is the only charset value of RFC 7616 cl. 4.
	Charset = "UTF-8"
)

// ErrUnsupported reports a Digest parameter value outside the supported
// profile.
var ErrUnsupported = errors.New("uastar: unsupported Digest parameter")

// Realm returns the realm "<prefix>@<FQDN of the AF>" (TS 24.109 cl. 5.2.2.1
// 3)).
func Realm(prefix, fqdn string) string { return prefix + "@" + fqdn }

// SplitRealm splits a realm at its last "@" into the constant first part and
// the FQDN of the AF.
func SplitRealm(realm string) (prefix, fqdn string, ok bool) {
	i := strings.LastIndexByte(realm, '@')
	if i <= 0 || i == len(realm)-1 {
		return "", "", false
	}
	return realm[:i], realm[i+1:], true
}

// Password returns the Digest password for K_AF: K_AF encoded in base64 as
// specified in RFC 4648 (TS 24.109 K.2 c) 2)).
func Password(kaf kdf.Key) string { return codec.Base64Key(kaf) }

// H is the unkeyed digest of RFC 7616 cl. 3.3: SHA-256 in lower-case
// hexadecimal.
func H(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// kd is the keyed digest KD(secret, data) = H(secret ":" data).
func kd(secret, data string) string { return H([]byte(secret + ":" + data)) }

// Input holds what both sides know when computing response and rspauth.
type Input struct {
	Username string // the A-KID
	Realm    string
	Password string // base64(K_AF)
	Method   string
	URI      string
	Nonce    string
	NC       string // eight hexadecimal digits
	CNonce   string
	Qop      string // QopAuth or QopAuthInt
}

func (in Input) digest(a2 string) string {
	ha1 := H([]byte(in.Username + ":" + in.Realm + ":" + in.Password))
	return kd(ha1, in.Nonce+":"+in.NC+":"+in.CNonce+":"+in.Qop+":"+H([]byte(a2)))
}

// Response computes the response parameter of the Authorization header
// field (RFC 7616 cl. 3.4.1-3.4.3). body is the request entity body, used
// only with qop=auth-int.
func (in Input) Response(body []byte) string {
	a2 := in.Method + ":" + in.URI
	if in.Qop == QopAuthInt {
		a2 += ":" + H(body)
	}
	return in.digest(a2)
}

// RspAuth computes the rspauth parameter of the Authentication-Info header
// field (RFC 7616 cl. 3.5): as the response, with A2 = ":" request-uri.
// body is the response entity body, used only with qop=auth-int.
func (in Input) RspAuth(body []byte) string {
	a2 := ":" + in.URI
	if in.Qop == QopAuthInt {
		a2 += ":" + H(body)
	}
	return in.digest(a2)
}

// Equal compares two digests in constant time.
func Equal(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// FormatNC renders a nonce count as exactly eight hexadecimal digits
// (RFC 7616 cl. 3.5).
func FormatNC(n uint32) string { return fmt.Sprintf("%08x", n) }

// ParseNC reads a nonce count of exactly eight hexadecimal digits.
func ParseNC(s string) (uint32, error) {
	if len(s) != 8 {
		return 0, fmt.Errorf("%w: nc must be 8 hexadecimal digits", ErrMalformedHeader)
	}
	n, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return 0, fmt.Errorf("%w: nc must be 8 hexadecimal digits", ErrMalformedHeader)
	}
	return uint32(n), nil
}

// HasProductToken reports whether a User-Agent value carries the AKMA
// product token.
func HasProductToken(userAgent string) bool {
	for _, f := range strings.Fields(userAgent) {
		name, _, _ := strings.Cut(f, "/")
		if strings.EqualFold(name, ProductToken) {
			return true
		}
	}
	return false
}
