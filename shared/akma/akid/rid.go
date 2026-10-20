// Package akid builds and parses the AKMA Key Identifier and its parts:
// Routing Indicator (TS 23.003 cl. 2.2B), Home Network Domain (TS 23.003
// cl. 28.2) and the A-KID NAI (TS 33.535 cl. 6.1; TS 29.522 type AKId).
package akid

import (
	"errors"
	"regexp"
)

// ErrMalformedRID reports an invalid Routing Indicator.
var ErrMalformedRID = errors.New("akid: malformed Routing Indicator")

// ridPattern is the pattern of routingId (TS 29.503) and of
// AanfInfo.routingIndicators (TS 29.510).
var ridPattern = regexp.MustCompile(`^[0-9]{1,4}$`)

// RID is a Routing Indicator: one to four decimal digits, each of them
// significant — "012" is not the same as "12" (TS 23.003 cl. 2.2B). It is
// always kept as a string; converting it to an integer drops leading zeros.
type RID string

// DefaultRID is the value used when no Routing Indicator is configured on the
// USIM or ME: a single digit "0" (TS 23.003 cl. 2.2B).
const DefaultRID RID = "0"

// ParseRID validates s as a Routing Indicator.
func ParseRID(s string) (RID, error) {
	if !ridPattern.MatchString(s) {
		return "", ErrMalformedRID
	}
	return RID(s), nil
}
