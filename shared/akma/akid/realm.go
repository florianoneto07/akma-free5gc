package akid

import (
	"errors"
	"regexp"
	"strings"
)

// ErrMalformedHomeNetwork reports an invalid MCC, MNC or Home Network Domain.
var ErrMalformedHomeNetwork = errors.New("akid: malformed home network")

var (
	mccPattern    = regexp.MustCompile(`^[0-9]{3}$`)
	mncPattern    = regexp.MustCompile(`^[0-9]{2,3}$`)
	domainPattern = regexp.MustCompile(`^5gc\.mnc([0-9]{3})\.mcc([0-9]{3})\.3gppnetwork\.org$`)
)

// HomeNetwork identifies the HPLMN by its MCC (three digits) and MNC (two or
// three digits). The MNC length depends on the MCC (TS 23.003 cl. 2.2) and
// cannot be inferred from the IMSI, so it is always given explicitly.
type HomeNetwork struct {
	MCC string
	MNC string
}

// NewHomeNetwork validates mcc and mnc.
func NewHomeNetwork(mcc, mnc string) (HomeNetwork, error) {
	if !mccPattern.MatchString(mcc) || !mncPattern.MatchString(mnc) {
		return HomeNetwork{}, ErrMalformedHomeNetwork
	}
	return HomeNetwork{MCC: mcc, MNC: mnc}, nil
}

// Domain returns the Home Network Domain "5gc.mnc<MNC>.mcc<MCC>.3gppnetwork.org"
// with both fields on three digits, a two-digit MNC being padded with a
// leading "0" (TS 23.003 cl. 28.2).
func (h HomeNetwork) Domain() string {
	mnc := h.MNC
	if len(mnc) == 2 {
		mnc = "0" + mnc
	}
	return "5gc.mnc" + mnc + ".mcc" + h.MCC + ".3gppnetwork.org"
}

// ParseDomain reads a PLMN Home Network Domain (TS 23.003 cl. 28.2). The
// returned MNC has three digits, as encoded in the domain: whether a leading
// "0" is padding cannot be told from the domain alone. SNPN domains
// ("5gc.nid<NID>...") are not supported.
func ParseDomain(d string) (HomeNetwork, error) {
	m := domainPattern.FindStringSubmatch(strings.ToLower(d))
	if m == nil {
		return HomeNetwork{}, ErrMalformedHomeNetwork
	}
	return HomeNetwork{MCC: m[2], MNC: m[1]}, nil
}
