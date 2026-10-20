// Package supi converts the SBI representation of a SUPI (TS 29.571 type
// Supi) into the KDF input parameter of TS 33.501 Annex A.7.0, which
// TS 33.535 A.2 and A.3 use for K_AKMA and A-TID.
package supi

import (
	"errors"
	"regexp"
	"strings"
)

var (
	// ErrUnsupportedType reports a SUPI that is not of type IMSI. Only IMSI is
	// supported; TS 33.501 A.7.0 also defines P0 for NAI, GLI and GCI SUPIs.
	ErrUnsupportedType = errors.New("supi: only IMSI-type SUPI is supported")
	// ErrMalformed reports a value that is not a valid IMSI-type SUPI. Error
	// messages never include the SUPI itself.
	ErrMalformed = errors.New("supi: malformed SUPI")
)

const imsiPrefix = "imsi-"

// imsiDigits follows the IMSI part of the TS 29.571 Supi pattern "imsi-[0-9]{5,15}".
var imsiDigits = regexp.MustCompile(`^[0-9]{5,15}$`)

// Param is the SUPI as KDF input parameter. For an IMSI-type SUPI it is the
// IMSI as defined in TS 23.003 clause 2.2 — the decimal digits only, without
// the "imsi-" prefix that the SBI representation carries (TS 33.501 A.7.0).
type Param string

// FromSBI converts an SBI SUPI "imsi-<digits>" into the KDF parameter.
func FromSBI(sbi string) (Param, error) {
	switch {
	case strings.HasPrefix(sbi, imsiPrefix):
		p := Param(strings.TrimPrefix(sbi, imsiPrefix))
		if err := p.Validate(); err != nil {
			return "", err
		}
		return p, nil
	case strings.HasPrefix(sbi, "nai-"), strings.HasPrefix(sbi, "gci-"), strings.HasPrefix(sbi, "gli-"):
		return "", ErrUnsupportedType
	default:
		return "", ErrMalformed
	}
}

// Validate reports whether p is a well-formed IMSI KDF parameter. A value
// that still carries the "imsi-" prefix is rejected.
func (p Param) Validate() error {
	if !imsiDigits.MatchString(string(p)) {
		return ErrMalformed
	}
	return nil
}

// SBI returns the SBI representation "imsi-<digits>" (TS 29.571).
func (p Param) SBI() string {
	return imsiPrefix + string(p)
}
