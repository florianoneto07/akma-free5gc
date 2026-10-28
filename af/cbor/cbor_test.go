package cbor

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// The examples of RFC 8949 Appendix A that this package supports, with the
// value built here.
var examples = []struct {
	enc string
	v   Value
}{
	{"00", UintValue(0)},
	{"01", UintValue(1)},
	{"0a", UintValue(10)},
	{"17", UintValue(23)},
	{"1818", UintValue(24)},
	{"1819", UintValue(25)},
	{"1864", UintValue(100)},
	{"1903e8", UintValue(1000)},
	{"1a000f4240", UintValue(1000000)},
	{"1b000000e8d4a51000", UintValue(1000000000000)},
	{"1bffffffffffffffff", UintValue(18446744073709551615)},
	{"3bffffffffffffffff", Value{Kind: NegInt, N: 18446744073709551615}},
	{"20", IntValue(-1)},
	{"29", IntValue(-10)},
	{"3863", IntValue(-100)},
	{"3903e7", IntValue(-1000)},
	{"f4", BoolValue(false)},
	{"f5", BoolValue(true)},
	{"f6", NullValue()},
	{"40", BytesValue([]byte{})},
	{"4401020304", BytesValue([]byte{1, 2, 3, 4})},
	{"60", TextValue("")},
	{"6161", TextValue("a")},
	{"6449455446", TextValue("IETF")},
	{"62225c", TextValue("\"\\")},
	{"62c3bc", TextValue("ü")},
	{"63e6b0b4", TextValue("水")},
	{"64f0908591", TextValue("\U00010151")},
	{"80", ArrayValue()},
	{"83010203", ArrayValue(UintValue(1), UintValue(2), UintValue(3))},
	{"8301820203820405", ArrayValue(UintValue(1), ArrayValue(UintValue(2), UintValue(3)),
		ArrayValue(UintValue(4), UintValue(5)))},
	{"98190102030405060708090a0b0c0d0e0f101112131415161718181819", ArrayValue(seq(1, 25)...)},
	{"a0", MapValue()},
	{"a201020304", MapValue(Pair{UintValue(1), UintValue(2)}, Pair{UintValue(3), UintValue(4)})},
	{"a26161016162820203", MapValue(Pair{TextValue("a"), UintValue(1)},
		Pair{TextValue("b"), ArrayValue(UintValue(2), UintValue(3))})},
	{"826161a161626163", ArrayValue(TextValue("a"), MapValue(Pair{TextValue("b"), TextValue("c")}))},
	{"a56161614161626142616361436164614461656145", MapValue(
		Pair{TextValue("a"), TextValue("A")}, Pair{TextValue("b"), TextValue("B")},
		Pair{TextValue("c"), TextValue("C")}, Pair{TextValue("d"), TextValue("D")},
		Pair{TextValue("e"), TextValue("E")})},
}

func seq(from, to uint64) []Value {
	var a []Value
	for i := from; i <= to; i++ {
		a = append(a, UintValue(i))
	}
	return a
}

func TestExamples(t *testing.T) {
	for _, e := range examples {
		want, _ := hex.DecodeString(e.enc)
		got, err := Encode(e.v)
		if err != nil || hex.EncodeToString(got) != e.enc {
			t.Errorf("Encode %s: %x %v", e.enc, got, err)
		}
		v, err := Decode(want)
		if err != nil {
			t.Errorf("Decode %s: %v", e.enc, err)
			continue
		}
		again, _ := Encode(v)
		if hex.EncodeToString(again) != e.enc {
			t.Errorf("Decode %s, Encode: %x", e.enc, again)
		}
	}
}

// Examples of RFC 8949 Appendix A outside this package: floats, simple
// values other than false, true and null, tags, bignums (tags) and
// indefinite lengths.
func TestUnsupported(t *testing.T) {
	for _, enc := range []string{
		"f90000", "fb3ff199999999999a", "fa47c35000", "f7", "f0", "f8ff",
		"c11a514b67b0", "c249010000000000000000", "d74401020304",
		"5f42010243030405ff", "7f657374726561646d696e67ff", "9fff", "bf61610161629f0203ffff",
	} {
		b, _ := hex.DecodeString(enc)
		if _, err := Decode(b); !errors.Is(err, ErrFormat) {
			t.Errorf("Decode %s: %v", enc, err)
		}
	}
}

func TestMalformed(t *testing.T) {
	for _, c := range []struct{ name, enc string }{
		{"empty", ""},
		{"argument cut short", "19 03"},
		{"string cut short", "44 0102"},
		{"array cut short", "83 0102"},
		{"map cut short", "a2 0102 03"},
		{"reserved additional information", "1c"},
		{"trailing octets", "01 02"},
		{"text not in UTF-8", "62 c328"},
		{"repeated map key", "a2 01 02 01 03"},
		{"huge array count", "9b ffffffffffffffff"},
		{"huge string length", "5b ffffffffffffffff"},
		{"nested too deep", strings.Repeat("81", 20) + "00"},
	} {
		b, _ := hex.DecodeString(strings.ReplaceAll(c.enc, " ", ""))
		if _, err := Decode(b); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// Arguments longer than needed are well formed (RFC 8949 cl. 3) and read;
// Encode writes the shortest form.
func TestLongerArguments(t *testing.T) {
	for enc, want := range map[string]string{
		"1800":               "00",
		"190017":             "17",
		"1a00000018":         "1818",
		"5801ff":             "41ff",
		"98020102":           "820102",
		"b8010102":           "a10102",
		"3b0000000000000000": "20",
	} {
		b, _ := hex.DecodeString(enc)
		v, err := Decode(b)
		if err != nil {
			t.Fatalf("Decode %s: %v", enc, err)
		}
		if got := hex.EncodeToString(MustEncode(v)); got != want {
			t.Errorf("%s re-encoded as %s, want %s", enc, got, want)
		}
	}
}

// Map keys go in the bytewise order of their encodings (RFC 8949
// cl. 4.2.1), whatever the order given.
func TestMapOrder(t *testing.T) {
	m := MapValue(Pair{IntValue(-1), UintValue(0)}, Pair{UintValue(10), UintValue(0)},
		Pair{TextValue("a"), UintValue(0)}, Pair{UintValue(1), UintValue(0)})
	if got := hex.EncodeToString(MustEncode(m)); got != "a401000a002000616100" {
		t.Fatalf("%s", got)
	}
	if _, err := Encode(MapValue(Pair{UintValue(1), UintValue(0)}, Pair{UintValue(1), UintValue(2)})); err == nil {
		t.Fatal("repeated key encoded")
	}
}

func TestInt(t *testing.T) {
	for _, n := range []int64{0, 1, 23, 24, -1, -24, -25, 1<<63 - 1, -1 << 63} {
		v, err := Decode(MustEncode(IntValue(n)))
		if got, ok := v.Int(); err != nil || !ok || got != n {
			t.Errorf("%d: %d %v %v", n, got, ok, err)
		}
	}
	if _, ok := UintValue(1 << 63).Int(); ok {
		t.Error("2^63 fits in an int64")
	}
}
