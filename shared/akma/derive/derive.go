// Package derive implements the AKMA key derivations of TS 33.535 Annex A
// and the assembly of the A-KID (TS 33.535 cl. 6.1).
package derive

import (
	"github.com/florianoneto07/akma-free5gc/shared/akma/afid"
	"github.com/florianoneto07/akma-free5gc/shared/akma/akid"
	"github.com/florianoneto07/akma-free5gc/shared/akma/kdf"
	"github.com/florianoneto07/akma-free5gc/shared/akma/supi"
)

// KAkma derives K_AKMA from K_AUSF (TS 33.535 A.2):
// FC = 0x80, P0 = "AKMA", P1 = SUPI as in TS 33.501 A.7.0.
func KAkma(kAusf kdf.Key, s supi.Param) (kdf.Key, error) {
	if err := s.Validate(); err != nil {
		return kdf.Key{}, err
	}
	return kdf.Derive(kAusf[:], kdf.FCKAkma, kdf.String("AKMA"), kdf.String(string(s)))
}

// ATid derives the A-TID from K_AUSF (TS 33.535 A.3):
// FC = 0x81, P0 = "A-TID", P1 = SUPI as in TS 33.501 A.7.0.
// The A-TID derives from K_AUSF, not from K_AKMA.
func ATid(kAusf kdf.Key, s supi.Param) (kdf.Key, error) {
	if err := s.Validate(); err != nil {
		return kdf.Key{}, err
	}
	return kdf.Derive(kAusf[:], kdf.FCATid, kdf.String("A-TID"), kdf.String(string(s)))
}

// KAf derives K_AF from K_AKMA (TS 33.535 A.4): FC = 0x82, P0 = AF_ID.
// It takes an afid.AfID rather than a string, so the AfId transport form
// "<FQDN>.<Ua* id>" cannot be passed as P0 by mistake.
func KAf(kAkma kdf.Key, id afid.AfID) (kdf.Key, error) {
	return kdf.Derive(kAkma[:], kdf.FCKAf, id.KDFParam())
}

// AKID derives the A-TID from K_AUSF and assembles the A-KID with the
// Routing Indicator received from the UDM and the Home Network Domain
// (TS 33.535 cl. 6.1).
func AKID(kAusf kdf.Key, s supi.Param, rid akid.RID, hn akid.HomeNetwork) (akid.AKID, error) {
	if _, err := akid.ParseRID(string(rid)); err != nil {
		return akid.AKID{}, err
	}
	if _, err := akid.NewHomeNetwork(hn.MCC, hn.MNC); err != nil {
		return akid.AKID{}, err
	}
	atid, err := ATid(kAusf, s)
	if err != nil {
		return akid.AKID{}, err
	}
	return akid.AKID{RID: rid, ATID: atid, Realm: hn.Domain()}, nil
}
