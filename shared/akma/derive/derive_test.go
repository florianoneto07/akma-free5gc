package derive

import (
	"errors"
	"testing"

	"github.com/florianoneto07/akma-free5gc/shared/akma/afid"
	"github.com/florianoneto07/akma-free5gc/shared/akma/akid"
	"github.com/florianoneto07/akma-free5gc/shared/akma/kdf"
	"github.com/florianoneto07/akma-free5gc/shared/akma/supi"
)

var kAusf = kdf.Key{1, 2, 3, 4, 5, 6, 7, 8}

// TestSBIPrefixRejected checks that the SBI form of the SUPI cannot reach the
// KDF (TS 33.501 A.7.0: P0 is the IMSI of TS 23.003 cl. 2.2, digits only).
func TestSBIPrefixRejected(t *testing.T) {
	bad := supi.Param("imsi-208930000000001")
	if _, err := KAkma(kAusf, bad); !errors.Is(err, supi.ErrMalformed) {
		t.Errorf("KAkma: err = %v", err)
	}
	if _, err := ATid(kAusf, bad); !errors.Is(err, supi.ErrMalformed) {
		t.Errorf("ATid: err = %v", err)
	}
}

// TestKeySeparation checks that K_AKMA, A-TID and K_AF differ for the same
// inputs and that the Ua* identifier separates K_AF (TS 33.220 H.2).
func TestKeySeparation(t *testing.T) {
	p := supi.Param("208930000000001")
	k, _ := KAkma(kAusf, p)
	a, _ := ATid(kAusf, p)
	if k == a {
		t.Fatal("K_AKMA equals A-TID")
	}
	digest, _ := afid.New("af1.akma.example", afid.UaStarDigest)
	tls, _ := afid.New("af1.akma.example", afid.UaStarTLS13)
	k1, _ := KAf(k, digest)
	k2, _ := KAf(k, tls)
	if k1 == k2 {
		t.Fatal("different Ua* identifiers give the same K_AF")
	}
}

func TestAKID(t *testing.T) {
	hn, _ := akid.NewHomeNetwork("208", "93")
	p := supi.Param("208930000000001")
	a, err := AKID(kAusf, p, "0000", hn)
	if err != nil {
		t.Fatal(err)
	}
	atid, _ := ATid(kAusf, p)
	if a.RID != "0000" || a.ATID != atid || a.Realm != "5gc.mnc093.mcc208.3gppnetwork.org" {
		t.Fatalf("AKID = %+v", a)
	}
	if _, err := AKID(kAusf, p, "12345", hn); err == nil {
		t.Error("five-digit RID accepted")
	}
	if _, err := AKID(kAusf, p, "0", akid.HomeNetwork{MCC: "20", MNC: "93"}); err == nil {
		t.Error("two-digit MCC accepted")
	}
}
