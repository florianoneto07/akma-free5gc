// Package crosscheck compares the KDF of shared/akma with the KDF that
// free5GC already uses for K_SEAF, ueauth.GetKDFValue (free5gc/util v1.3.2),
// on the test vectors of shared/akma. It lives in its own module so that
// shared/akma does not depend on free5gc/util.
package crosscheck

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/free5gc/util/ueauth"

	"github.com/florianoneto07/akma-free5gc/shared/akma/afid"
	"github.com/florianoneto07/akma-free5gc/shared/akma/codec"
	"github.com/florianoneto07/akma-free5gc/shared/akma/derive"
	"github.com/florianoneto07/akma-free5gc/shared/akma/kdf"
	"github.com/florianoneto07/akma-free5gc/shared/akma/supi"
)

type vector struct {
	Name     string `json:"name"`
	KAusf    string `json:"k_ausf"`
	Supi     string `json:"supi"`
	FQDN     string `json:"fqdn"`
	UaStarID string `json:"ua_star_id"`
	KAkma    string `json:"k_akma"`
	ATid     string `json:"a_tid"`
	KAf      string `json:"k_af"`
}

// ueauthKDF calls free5GC's KDF with interleaved P/L parameters.
func ueauthKDF(t *testing.T, key []byte, fc string, params ...[]byte) string {
	t.Helper()
	var args [][]byte
	for _, p := range params {
		args = append(args, p, ueauth.KDFLen(p))
	}
	out, err := ueauth.GetKDFValue(key, fc, args...)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(out)
}

func TestAgainstUeauth(t *testing.T) {
	raw, err := os.ReadFile("../akma/testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Vectors []vector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	for _, v := range f.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			kAusf, _ := codec.ParseHexKey(v.KAusf)
			p, err := supi.FromSBI(v.Supi)
			if err != nil {
				t.Fatal(err)
			}
			ua, _ := hex.DecodeString(v.UaStarID)
			id, err := afid.New(v.FQDN, afid.UaStarID(ua))
			if err != nil {
				t.Fatal(err)
			}

			kAkma, _ := derive.KAkma(kAusf, p)
			atid, _ := derive.ATid(kAusf, p)
			kAf, _ := derive.KAf(kAkma, id)

			checks := []struct {
				name, ours, free5gc, oracle string
			}{
				{"K_AKMA", codec.HexKey(kAkma),
					ueauthKDF(t, kAusf[:], "80", kdf.String("AKMA"), kdf.String(string(p))), v.KAkma},
				{"A-TID", codec.HexKey(atid),
					ueauthKDF(t, kAusf[:], "81", kdf.String("A-TID"), kdf.String(string(p))), v.ATid},
				{"K_AF", codec.HexKey(kAf),
					ueauthKDF(t, kAkma[:], "82", id.KDFParam()), v.KAf},
			}
			for _, c := range checks {
				if c.ours != c.free5gc || c.ours != c.oracle {
					t.Errorf("%s: library %s, ueauth %s, oracle %s", c.name, c.ours, c.free5gc, c.oracle)
				}
			}
		})
	}
}
