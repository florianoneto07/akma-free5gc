package akid

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/florianoneto07/akma-free5gc/shared/akma/kdf"
)

// ErrMalformedAKID reports a string that is not an A-KID in the expected
// format "rid<RID>.<label><A-TID>@<realm>".
var ErrMalformedAKID = errors.New("akid: malformed A-KID")

// Encoding is the textual encoding of the A-TID value inside the A-KID. No
// specification fixes it: TS 33.535 cl. 6.1 and TS 29.522 table
// 5.14.5.4.2-1 only require an NAI whose username holds the A-TID. Base64 is
// the default by analogy with the GBA B-TID, base64encode(RAND)
// (TS 33.220 cl. 4.5.2).
type Encoding int

const (
	// EncodingBase64 is base64 per RFC 4648 section 4, with padding: 44
	// characters for a 32-octet A-TID. Default.
	EncodingBase64 Encoding = iota
	// EncodingBase64URL is base64url per RFC 4648 section 5, with padding.
	EncodingBase64URL
	// EncodingHex is lowercase hexadecimal on write; either case is accepted on read.
	EncodingHex
)

// Options configure the A-KID format.
type Options struct {
	// Encoding of the A-TID value.
	Encoding Encoding
	// Label written before the A-TID value. TS 29.522 table 5.14.5.4.2-1
	// prescribes "atid"; the example in the same table uses "akid".
	Label string
	// AcceptLabels lists the labels accepted when parsing.
	AcceptLabels []string
}

// DefaultOptions returns the defaults: base64, label "atid" on write,
// "atid" and "akid" accepted on read.
func DefaultOptions() Options {
	return Options{
		Encoding:     EncodingBase64,
		Label:        "atid",
		AcceptLabels: []string{"atid", "akid"},
	}
}

// AKID is the AKMA Key Identifier: an NAI "username@realm" (RFC 7542 cl. 2.2)
// whose username carries the Routing Indicator and the A-TID and whose realm
// carries the Home Network Domain (TS 33.535 cl. 6.1; TS 29.522 type AKId).
type AKID struct {
	RID   RID
	ATID  kdf.Key
	Realm string
}

// Format returns "rid<RID>.<label><A-TID>@<realm>" (TS 29.522 table 5.14.5.4.2-1).
func (a AKID) Format(o Options) (string, error) {
	if _, err := ParseRID(string(a.RID)); err != nil {
		return "", err
	}
	if a.Realm == "" || strings.Contains(a.Realm, "@") || o.Label == "" {
		return "", ErrMalformedAKID
	}
	v, err := encodeATID(a.ATID, o.Encoding)
	if err != nil {
		return "", err
	}
	return "rid" + string(a.RID) + "." + o.Label + v + "@" + a.Realm, nil
}

// Parse reads an A-KID. Any label in o.AcceptLabels is accepted; the A-TID
// value must decode, with o.Encoding, to exactly 32 octets.
func Parse(s string, o Options) (AKID, error) {
	user, realm, ok := strings.Cut(s, "@")
	if !ok || realm == "" || strings.Contains(realm, "@") {
		return AKID{}, ErrMalformedAKID
	}
	rest, ok := strings.CutPrefix(user, "rid")
	if !ok {
		return AKID{}, ErrMalformedAKID
	}
	ridStr, rest, ok := strings.Cut(rest, ".")
	if !ok {
		return AKID{}, ErrMalformedAKID
	}
	rid, err := ParseRID(ridStr)
	if err != nil {
		return AKID{}, err
	}
	var value string
	found := false
	for _, l := range o.AcceptLabels {
		if v, ok := strings.CutPrefix(rest, l); ok && l != "" {
			value, found = v, true
			break
		}
	}
	if !found {
		return AKID{}, ErrMalformedAKID
	}
	atid, err := decodeATID(value, o.Encoding)
	if err != nil {
		return AKID{}, err
	}
	return AKID{RID: rid, ATID: atid, Realm: realm}, nil
}

func encodeATID(k kdf.Key, e Encoding) (string, error) {
	switch e {
	case EncodingBase64:
		return base64.StdEncoding.EncodeToString(k[:]), nil
	case EncodingBase64URL:
		return base64.URLEncoding.EncodeToString(k[:]), nil
	case EncodingHex:
		return hex.EncodeToString(k[:]), nil
	default:
		return "", ErrMalformedAKID
	}
}

func decodeATID(v string, e Encoding) (kdf.Key, error) {
	var raw []byte
	var err error
	switch e {
	case EncodingBase64:
		raw, err = base64.StdEncoding.Strict().DecodeString(v)
	case EncodingBase64URL:
		raw, err = base64.URLEncoding.Strict().DecodeString(v)
	case EncodingHex:
		raw, err = hex.DecodeString(v)
	default:
		return kdf.Key{}, ErrMalformedAKID
	}
	if err != nil || len(raw) != kdf.KeyLen {
		return kdf.Key{}, ErrMalformedAKID
	}
	var k kdf.Key
	copy(k[:], raw)
	return k, nil
}
