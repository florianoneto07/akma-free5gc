package akmaoscore

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/florianoneto07/akma-free5gc/af/cbor"
	"github.com/florianoneto07/akma-free5gc/af/coap"
	"github.com/florianoneto07/akma-free5gc/af/oscore"
	"github.com/florianoneto07/akma-free5gc/shared/akma/akid"
	"github.com/florianoneto07/akma-free5gc/shared/akma/kdf"
)

const (
	aKid3 = "rid7.atidjP5j0bBNfT9o7j6lm58blvhRmyRmzpmKLC9wLZZb3Ac=@5gc.mnc410.mcc310.3gppnetwork.org"
	aKid2 = "rid0000.atidCMNGM3f5wGdrrXvlGa0krmGw1U/8S0poB5Gito498cI=@5gc.mnc093.mcc208.3gppnetwork.org"
)

func TestRequest(t *testing.T) {
	o := akid.DefaultOptions()
	for _, k := range []string{aKid3, aKid2} {
		r := Request{AKID: k, N1: bytes.Repeat([]byte{1}, NonceSize), AFSID: []byte{0xaf, 1, 2, 3}}
		b, err := r.Marshal(o)
		if err != nil {
			t.Fatal(err)
		}
		v, _ := cbor.Decode(b)
		a, _ := akid.Parse(k, o)
		hn, _ := akid.ParseDomain(a.Realm)
		if v.A[0].A[0].S != string(a.RID) || !bytes.Equal(v.A[0].A[1].B, a.ATID[:]) || v.A[0].A[2].S != hn.MCC+hn.MNC {
			t.Fatalf("A-KID in CBOR: %+v", v.A[0])
		}
		got, err := ParseRequest(b, o)
		if err != nil || got.AKID != k || !bytes.Equal(got.N1, r.N1) || !bytes.Equal(got.AFSID, r.AFSID) {
			t.Fatalf("%+v %v", got, err)
		}
	}
	// A two-digit MNC gives the same realm, padded (TS 23.003 cl. 28.2).
	a, _ := akid.Parse(aKid2, o)
	b := cbor.MustEncode(cbor.ArrayValue(
		cbor.ArrayValue(cbor.TextValue("0000"), cbor.BytesValue(a.ATID[:]), cbor.TextValue("20893")),
		cbor.BytesValue(make([]byte, 16)), cbor.BytesValue([]byte{1})))
	if got, err := ParseRequest(b, o); err != nil || got.AKID != aKid2 {
		t.Fatalf("MNC of two digits: %q %v", got.AKID, err)
	}
}

func TestRequestRefused(t *testing.T) {
	o := akid.DefaultOptions()
	a, _ := akid.Parse(aKid3, o)
	good := cbor.ArrayValue(cbor.TextValue("7"), cbor.BytesValue(a.ATID[:]), cbor.TextValue("310410"))
	n1 := cbor.BytesValue(make([]byte, 16))
	sid := cbor.BytesValue([]byte{1})
	oscInput := func(pairs ...cbor.Pair) cbor.Value { return cbor.BytesValue(cbor.MustEncode(cbor.MapValue(pairs...))) }
	pair := func(l, v int64) cbor.Pair { return cbor.Pair{Key: cbor.IntValue(l), Value: cbor.IntValue(v)} }
	for name, c := range map[string]struct {
		v    cbor.Value
		want error
	}{
		"not an array": {cbor.MapValue(), ErrPayload},
		"two items":    {cbor.ArrayValue(good, n1), ErrPayload},
		"CoAP Security protocol identifier first": {cbor.ArrayValue(cbor.BytesValue([]byte{1}), good, n1, sid), ErrPayload},
		"A-KID as text":      {cbor.ArrayValue(cbor.TextValue(aKid3), n1, sid), ErrPayload},
		"A-TID of 31":        {cbor.ArrayValue(cbor.ArrayValue(cbor.TextValue("7"), cbor.BytesValue(make([]byte, 31)), cbor.TextValue("310410")), n1, sid), ErrPayload},
		"HPLMN-ID as realm":  {cbor.ArrayValue(cbor.ArrayValue(cbor.TextValue("7"), cbor.BytesValue(a.ATID[:]), cbor.TextValue("5gc.mnc410.mcc310.3gppnetwork.org")), n1, sid), ErrPayload},
		"RID of 5 digits":    {cbor.ArrayValue(cbor.ArrayValue(cbor.TextValue("12345"), cbor.BytesValue(a.ATID[:]), cbor.TextValue("310410")), n1, sid), ErrPayload},
		"N1 of 7":            {cbor.ArrayValue(good, cbor.BytesValue(make([]byte, 7)), sid), ErrPayload},
		"AF-SID of 8":        {cbor.ArrayValue(good, n1, cbor.BytesValue(make([]byte, 8))), ErrPayload},
		"OSC-INP as a map":   {cbor.ArrayValue(good, n1, sid, cbor.MapValue()), ErrPayload},
		"OSC-INP other alg":  {cbor.ArrayValue(good, n1, sid, oscInput(pair(4, 11))), ErrOSCInput},
		"OSC-INP other HKDF": {cbor.ArrayValue(good, n1, sid, oscInput(pair(3, 6))), ErrOSCInput},
		"OSC-INP version 2":  {cbor.ArrayValue(good, n1, sid, oscInput(pair(1, 2))), ErrOSCInput},
		"OSC-INP salt":       {cbor.ArrayValue(good, n1, sid, oscInput(cbor.Pair{Key: cbor.IntValue(5), Value: cbor.BytesValue([]byte{1})})), ErrOSCInput},
		"OSC-INP contextId":  {cbor.ArrayValue(good, n1, sid, oscInput(cbor.Pair{Key: cbor.IntValue(6), Value: cbor.BytesValue([]byte{1})})), ErrOSCInput},
	} {
		if _, err := ParseRequest(cbor.MustEncode(c.v), o); !errors.Is(err, c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// OSC-INP with the defaults only is accepted.
	ok := cbor.ArrayValue(good, n1, sid, oscInput(pair(1, 1), pair(3, 5), pair(4, 10)))
	if _, err := ParseRequest(cbor.MustEncode(ok), o); err != nil {
		t.Fatalf("default OSC-INP: %v", err)
	}
}

func TestResponse(t *testing.T) {
	r := Response{N2: bytes.Repeat([]byte{2}, NonceSize), UESID: []byte{9, 9, 9, 9}}
	got, err := ParseResponse(r.Marshal())
	if err != nil || !bytes.Equal(got.N2, r.N2) || !bytes.Equal(got.UESID, r.UESID) {
		t.Fatalf("%+v %v", got, err)
	}
	if hex.EncodeToString(r.Marshal()[:2]) != "8250" {
		t.Fatalf("%x", r.Marshal())
	}
	for _, b := range []cbor.Value{
		cbor.ArrayValue(cbor.BytesValue(r.N2)),
		cbor.ArrayValue(cbor.BytesValue(r.N2), cbor.TextValue("x")),
		cbor.ArrayValue(cbor.BytesValue(r.N2), cbor.BytesValue(make([]byte, 8))),
	} {
		if _, err := ParseResponse(cbor.MustEncode(b)); !errors.Is(err, ErrPayload) {
			t.Errorf("%v", err)
		}
	}
}

// The Master Secret is the HKDF of RFC 5869 in its two steps: an extract
// with a salt of zeros, then one expand block.
func TestMasterSecret(t *testing.T) {
	var kaf kdf.Key
	for i := range kaf {
		kaf[i] = byte(i)
	}
	prk, _ := hkdf.Extract(sha256.New, kaf[:], make([]byte, sha256.Size))
	want, _ := hkdf.Expand(sha256.New, prk, "AKMA-OSCORE", 32)
	if got := MasterSecret(kaf); !bytes.Equal(got, want) || len(got) != 32 {
		t.Fatalf("%x", got)
	}
}

// The UE and the AF derive matching contexts: a request protected by one
// verifies at the other.
func TestContexts(t *testing.T) {
	var kaf kdf.Key
	kaf[0] = 1
	req, rsp := []byte{0x83, 1}, []byte{0x82, 2}
	ue, err := Context(kaf, req, rsp, []byte{0xaf}, []byte{0x0e}, true)
	if err != nil {
		t.Fatal(err)
	}
	af, err := Context(kaf, req, rsp, []byte{0xaf}, []byte{0x0e}, false)
	if err != nil {
		t.Fatal(err)
	}
	m := &coap.Message{Code: coap.GET}
	m.SetPath("/ua/v1/session")
	out, _, err := ue.ProtectRequest(m, nil)
	if err != nil {
		t.Fatal(err)
	}
	if in, _, err := af.VerifyRequest(out, option(t, out)); err != nil || in.Path() != "/ua/v1/session" {
		t.Fatalf("%v", err)
	}
	// Another response payload, another Master Salt: no match.
	other, _ := Context(kaf, req, []byte{0x82, 3}, []byte{0xaf}, []byte{0x0e}, false)
	out2, _, _ := ue.ProtectRequest(m, nil)
	if _, _, err := other.VerifyRequest(out2, option(t, out2)); !errors.Is(err, oscore.ErrDecrypt) {
		t.Fatalf("another Master Salt: %v", err)
	}
}

func option(t *testing.T, m *coap.Message) oscore.Option {
	t.Helper()
	v, _ := m.Option(coap.OptionOSCORE)
	o, err := oscore.ParseOption(v)
	if err != nil {
		t.Fatal(err)
	}
	return o
}
