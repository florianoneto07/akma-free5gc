package afid

import (
	"encoding/hex"
	"strings"
)

// UaStarID is the five-octet Ua security protocol identifier
// (TS 33.220 Annex H.1).
type UaStarID [5]byte

var (
	// UaStarDigest identifies the simplified Ua* protocol of this repository,
	// HTTP Digest (RFC 7616) without TLS. TS 24.109 Annex K specifies the
	// AKMA Digest profile only inside TLS, so the identifier is taken from the
	// private range (first octet 0xFF, TS 33.220 H.2 NOTE 2).
	UaStarDigest = UaStarID{0xFF, 0x00, 0x00, 0x00, 0x01}
	// UaStarTLS13 identifies shared-key TLS 1.3 (TS 33.220 H.3).
	UaStarTLS13 = UaStarID{0x01, 0x00, 0x00, 0x00, 0x07}
)

// String returns the identifier as ten uppercase hexadecimal characters, the
// form used inside AfId. TS 29.522 describes the identifier as "a string of 5
// octet"; the hexadecimal rendering follows the specification's example
// (table 5.14.5.4.2-1). Uppercase on write is a choice of this
// implementation; parsing accepts both cases.
func (u UaStarID) String() string {
	return strings.ToUpper(hex.EncodeToString(u[:]))
}
