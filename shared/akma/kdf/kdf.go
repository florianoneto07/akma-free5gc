// Package kdf implements the generic key derivation function of
// 3GPP TS 33.220 Annex B.2, as used by AKMA (TS 33.535 Annex A).
package kdf

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/text/unicode/norm"
)

// KeyLen is the length in octets of a KDF output (HMAC-SHA-256, TS 33.220 B.2.0).
const KeyLen = sha256.Size

// MaxParamLen is the largest length of a single input parameter (TS 33.220 B.1).
const MaxParamLen = 65535

// FC values allocated to TS 33.535 (TS 33.535 A.1.2; TS 33.220 B.2.2).
const (
	FCKAkma byte = 0x80 // K_AKMA, TS 33.535 A.2
	FCATid  byte = 0x81 // A-TID, TS 33.535 A.3
	FCKAf   byte = 0x82 // K_AF, TS 33.535 A.4
)

// ErrParamTooLong reports an input parameter longer than MaxParamLen octets.
var ErrParamTooLong = errors.New("kdf: input parameter longer than 65535 octets")

// Key holds a 256-bit key or KDF output: K_AUSF, K_AKMA, A-TID or K_AF.
// Its String method never reveals the value; use package codec to encode it.
type Key [KeyLen]byte

// String returns a fixed placeholder so that keys do not end up in logs.
func (Key) String() string { return "[256-bit key]" }

// GoString returns the same placeholder as String.
func (k Key) GoString() string { return k.String() }

// String encodes a character string as a KDF input parameter: UTF-8 with
// Normalization Form KC (TS 33.220 B.2.1.2).
func String(s string) []byte {
	return []byte(norm.NFKC.String(s))
}

// S builds the input string S = FC || P0 || L0 || P1 || L1 || ... || Pn || Ln
// (TS 33.220 B.2.0), where Li is the length of Pi in octets encoded on two
// octets, most significant first (TS 33.220 B.2.1.3). Only single-octet FC
// values are supported; AKMA uses 0x80 to 0x82.
func S(fc byte, params ...[]byte) ([]byte, error) {
	n := 1
	for _, p := range params {
		n += len(p) + 2
	}
	s := make([]byte, 0, n)
	s = append(s, fc)
	for i, p := range params {
		if len(p) > MaxParamLen {
			return nil, fmt.Errorf("%w: P%d has %d octets", ErrParamTooLong, i, len(p))
		}
		s = append(s, p...)
		s = binary.BigEndian.AppendUint16(s, uint16(len(p)))
	}
	return s, nil
}

// Derive returns HMAC-SHA-256(key, S) with S built from fc and params
// (TS 33.220 B.2.0).
func Derive(key []byte, fc byte, params ...[]byte) (Key, error) {
	s, err := S(fc, params...)
	if err != nil {
		return Key{}, err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(s)
	var out Key
	copy(out[:], mac.Sum(nil))
	return out, nil
}
