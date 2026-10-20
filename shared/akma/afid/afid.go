// Package afid handles the AF identifier in its two forms:
//
//   - KDF form, P0 of TS 33.535 A.4: AF_ID = FQDN of the AF || Ua* security
//     protocol identifier, with the FQDN encoded as UTF-8/NFKC and the
//     identifier as five raw octets;
//   - transport form, type AfId of TS 29.522 (table 5.14.5.4.2-1):
//     "<FQDN>.<Ua* security protocol id>".
//
// The AAnF receives the transport form and must rebuild the KDF form; using
// the transport string as P0 yields a different K_AF without any error.
package afid

import (
	"encoding/hex"
	"errors"

	"github.com/florianoneto07/akma-free5gc/shared/akma/kdf"
)

// ErrMalformed reports an invalid AF identifier.
var ErrMalformed = errors.New("afid: malformed AF identifier")

// suffixLen is the length of "." followed by ten hexadecimal characters.
const suffixLen = 1 + 2*len(UaStarID{})

// AfID is an AF identifier: the AF's FQDN and the Ua* security protocol the
// AF uses with the UE.
type AfID struct {
	FQDN     string
	Protocol UaStarID
}

// New returns the AF identifier for fqdn and protocol p.
func New(fqdn string, p UaStarID) (AfID, error) {
	a := AfID{FQDN: fqdn, Protocol: p}
	if fqdn == "" || len(a.KDFParam()) > kdf.MaxParamLen {
		return AfID{}, ErrMalformed
	}
	return a, nil
}

// Parse reads the transport form "<FQDN>.<10 hexadecimal characters>"
// (TS 29.522). Hexadecimal digits are accepted in either case.
func Parse(s string) (AfID, error) {
	if len(s) <= suffixLen || s[len(s)-suffixLen] != '.' {
		return AfID{}, ErrMalformed
	}
	raw, err := hex.DecodeString(s[len(s)-suffixLen+1:])
	if err != nil {
		return AfID{}, ErrMalformed
	}
	var p UaStarID
	copy(p[:], raw)
	return New(s[:len(s)-suffixLen], p)
}

// Transport returns the transport form "<FQDN>.<Ua* id>" (TS 29.522).
func (a AfID) Transport() string {
	return a.FQDN + "." + a.Protocol.String()
}

// KDFParam returns P0 of TS 33.535 A.4: the FQDN encoded as a character
// string (UTF-8 with NFKC, TS 33.220 B.2.1.2) followed by the five raw octets
// of the Ua* security protocol identifier. Encoding the FQDN as a character
// string follows the NAF_Id of GBA (TS 33.220 B.3); TS 33.535 does not state
// it explicitly.
func (a AfID) KDFParam() []byte {
	return append(kdf.String(a.FQDN), a.Protocol[:]...)
}
