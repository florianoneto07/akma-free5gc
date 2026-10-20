// Package codec encodes 256-bit keys at each layer boundary. Keys are kept
// as 32 octets internally (kdf.Key); the textual form depends on the layer:
//
//   - SBI attributes kAkma (TS 29.535) and kaf (TS 29.522): 64 hexadecimal
//     characters, lowercase on write. No specification fixes it; this
//     follows the precedent of Kausf in TS 29.503 ("^[A-Fa-f0-9]{64}$") and
//     of Kseaf in TS 29.509.
//   - K_AF as HTTP Digest password on Ua*: base64 per RFC 4648
//     (TS 24.109 K.2 c)2)).
package codec

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"regexp"

	"github.com/florianoneto07/akma-free5gc/shared/akma/kdf"
)

// ErrMalformedKey reports a key that is not 64 hexadecimal characters.
var ErrMalformedKey = errors.New("codec: key must be 64 hexadecimal characters")

// hexKeyPattern is anchored, as Kausf in TS 29.503 and unlike the TS 29.509
// patterns.
var hexKeyPattern = regexp.MustCompile(`^[A-Fa-f0-9]{64}$`)

// HexKey encodes k for the SBI attributes kAkma and kaf.
func HexKey(k kdf.Key) string {
	return hex.EncodeToString(k[:])
}

// ParseHexKey decodes an SBI key attribute; either case is accepted.
func ParseHexKey(s string) (kdf.Key, error) {
	if !hexKeyPattern.MatchString(s) {
		return kdf.Key{}, ErrMalformedKey
	}
	var k kdf.Key
	if _, err := hex.Decode(k[:], []byte(s)); err != nil {
		return kdf.Key{}, ErrMalformedKey
	}
	return k, nil
}

// Base64Key encodes K_AF as the HTTP Digest password (TS 24.109 K.2 c)2)).
func Base64Key(k kdf.Key) string {
	return base64.StdEncoding.EncodeToString(k[:])
}
