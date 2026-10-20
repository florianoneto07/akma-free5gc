package akma_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/florianoneto07/akma-free5gc/shared/akma/afid"
	"github.com/florianoneto07/akma-free5gc/shared/akma/akid"
	"github.com/florianoneto07/akma-free5gc/shared/akma/codec"
	"github.com/florianoneto07/akma-free5gc/shared/akma/derive"
	"github.com/florianoneto07/akma-free5gc/shared/akma/kdf"
	"github.com/florianoneto07/akma-free5gc/shared/akma/supi"
)

// vectorFile mirrors testdata/vectors.json, produced by
// reference/kdf/gen_vectors.py (not 3GPP test vectors).
type vectorFile struct {
	Vectors []struct {
		Name          string            `json:"name"`
		KAusf         string            `json:"k_ausf"`
		Supi          string            `json:"supi"`
		SupiKDFParam  string            `json:"supi_kdf_param"`
		MCC           string            `json:"mcc"`
		MNC           string            `json:"mnc"`
		RID           string            `json:"rid"`
		FQDN          string            `json:"fqdn"`
		UaStarID      string            `json:"ua_star_id"`
		SKAkma        string            `json:"s_k_akma"`
		KAkma         string            `json:"k_akma"`
		SATid         string            `json:"s_a_tid"`
		ATid          string            `json:"a_tid"`
		Realm         string            `json:"realm"`
		AKID          map[string]string `json:"a_kid"`
		AfIDTransport string            `json:"af_id_transport"`
		AfIDKDFParam  string            `json:"af_id_kdf_param"`
		SKAf          string            `json:"s_k_af"`
		KAf           string            `json:"k_af"`
		KAfBase64     string            `json:"k_af_base64"`
	} `json:"vectors"`
	Counterexamples []struct {
		Name       string `json:"name"`
		Vector     string `json:"vector"`
		WrongInput string `json:"wrong_input"`
		KAkma      string `json:"k_akma"`
		KAf        string `json:"k_af"`
	} `json:"counterexamples"`
}

func load(t *testing.T) vectorFile {
	t.Helper()
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var f vectorFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	return f
}

func key(t *testing.T, s string) kdf.Key {
	t.Helper()
	k, err := codec.ParseHexKey(s)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func eq(t *testing.T, what, got, want string) {
	t.Helper()
	if got != want {
		t.Errorf("%s:\n got  %s\n want %s", what, got, want)
	}
}

var encodings = map[string]akid.Encoding{
	"base64":    akid.EncodingBase64,
	"base64url": akid.EncodingBase64URL,
	"hex":       akid.EncodingHex,
}

// TestVectors reproduces every vector of the reference oracle octet by octet:
// the S strings and outputs of TS 33.535 A.2, A.3 and A.4, the A-KID in each
// encoding, both forms of the AF identifier and the key encodings.
func TestVectors(t *testing.T) {
	for _, v := range load(t).Vectors {
		t.Run(v.Name, func(t *testing.T) {
			kAusf := key(t, v.KAusf)

			p, err := supi.FromSBI(v.Supi)
			if err != nil {
				t.Fatal(err)
			}
			eq(t, "SUPI KDF parameter", string(p), v.SupiKDFParam)

			s1, _ := kdf.S(kdf.FCKAkma, kdf.String("AKMA"), kdf.String(string(p)))
			eq(t, "S of K_AKMA", hex.EncodeToString(s1), v.SKAkma)
			kAkma, err := derive.KAkma(kAusf, p)
			if err != nil {
				t.Fatal(err)
			}
			eq(t, "K_AKMA", codec.HexKey(kAkma), v.KAkma)

			s2, _ := kdf.S(kdf.FCATid, kdf.String("A-TID"), kdf.String(string(p)))
			eq(t, "S of A-TID", hex.EncodeToString(s2), v.SATid)
			atid, err := derive.ATid(kAusf, p)
			if err != nil {
				t.Fatal(err)
			}
			eq(t, "A-TID", codec.HexKey(atid), v.ATid)

			hn, err := akid.NewHomeNetwork(v.MCC, v.MNC)
			if err != nil {
				t.Fatal(err)
			}
			eq(t, "realm", hn.Domain(), v.Realm)
			a, err := derive.AKID(kAusf, p, akid.RID(v.RID), hn)
			if err != nil {
				t.Fatal(err)
			}
			for name, e := range encodings {
				o := akid.DefaultOptions()
				o.Encoding = e
				s, err := a.Format(o)
				if err != nil {
					t.Fatal(err)
				}
				eq(t, "A-KID "+name, s, v.AKID[name])
				back, err := akid.Parse(v.AKID[name], o)
				if err != nil || back != a {
					t.Errorf("A-KID %s does not parse back: %v", name, err)
				}
			}

			ua, err := hex.DecodeString(v.UaStarID)
			if err != nil || len(ua) != 5 {
				t.Fatalf("Ua* id %q", v.UaStarID)
			}
			id, err := afid.New(v.FQDN, afid.UaStarID(ua))
			if err != nil {
				t.Fatal(err)
			}
			eq(t, "AfId transport", id.Transport(), v.AfIDTransport)
			eq(t, "AF_ID P0", hex.EncodeToString(id.KDFParam()), v.AfIDKDFParam)
			parsed, err := afid.Parse(v.AfIDTransport)
			if err != nil {
				t.Fatal(err)
			}
			eq(t, "AF_ID P0 from transport", hex.EncodeToString(parsed.KDFParam()), v.AfIDKDFParam)

			s3, _ := kdf.S(kdf.FCKAf, id.KDFParam())
			eq(t, "S of K_AF", hex.EncodeToString(s3), v.SKAf)
			kAf, err := derive.KAf(kAkma, parsed)
			if err != nil {
				t.Fatal(err)
			}
			eq(t, "K_AF", codec.HexKey(kAf), v.KAf)
			eq(t, "K_AF base64", codec.Base64Key(kAf), v.KAfBase64)
		})
	}
}

// TestCounterexamples shows that feeding SBI forms to the KDF yields wrong
// keys silently, and that the library refuses those inputs.
func TestCounterexamples(t *testing.T) {
	f := load(t)
	byName := map[string]int{}
	for i, v := range f.Vectors {
		byName[v.Name] = i
	}
	for _, c := range f.Counterexamples {
		v := f.Vectors[byName[c.Vector]]
		switch c.Name {
		case "supi-with-imsi-prefix":
			kAusf := key(t, v.KAusf)
			wrong, _ := kdf.Derive(kAusf[:], kdf.FCKAkma, kdf.String("AKMA"), kdf.String(c.WrongInput))
			eq(t, "K_AKMA with prefix", codec.HexKey(wrong), c.KAkma)
			if c.KAkma == v.KAkma {
				t.Error("prefix does not change K_AKMA")
			}
			if _, err := derive.KAkma(kAusf, supi.Param(c.WrongInput)); err == nil {
				t.Error("derive.KAkma accepted the SBI SUPI")
			}
		case "af-id-transport-as-p0":
			k := key(t, v.KAkma)
			wrong, _ := kdf.Derive(k[:], kdf.FCKAf, kdf.String(c.WrongInput))
			eq(t, "K_AF with transport P0", codec.HexKey(wrong), c.KAf)
			if c.KAf == v.KAf {
				t.Error("transport form gives the right K_AF")
			}
		default:
			t.Errorf("unknown counterexample %q", c.Name)
		}
	}
}
