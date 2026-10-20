package kdf

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// TestSWorkedExample checks the S string of K_AKMA for the worked example of
// testdata/vectors.json (not a 3GPP vector: TS 33.535 publishes none).
func TestSWorkedExample(t *testing.T) {
	s, err := S(FCKAkma, String("AKMA"), String("208930000000003"))
	if err != nil {
		t.Fatal(err)
	}
	want := "80414b4d410004323038393330303030303030303033000f"
	if got := hex.EncodeToString(s); got != want {
		t.Fatalf("S = %s, want %s", got, want)
	}
}

// TestLengthEncoding checks Li as two octets, most significant first
// (TS 33.220 B.2.1.3).
func TestLengthEncoding(t *testing.T) {
	p := bytes.Repeat([]byte{0xAA}, 0x0102)
	s, err := S(0x80, p)
	if err != nil {
		t.Fatal(err)
	}
	if got := s[len(s)-2:]; got[0] != 0x01 || got[1] != 0x02 {
		t.Fatalf("L0 = %x, want 0102", got)
	}
}

// TestParamTooLong checks the 65535-octet limit (TS 33.220 B.1).
func TestParamTooLong(t *testing.T) {
	if _, err := S(0x80, make([]byte, MaxParamLen)); err != nil {
		t.Fatalf("65535 octets rejected: %v", err)
	}
	if _, err := S(0x80, make([]byte, MaxParamLen+1)); !errors.Is(err, ErrParamTooLong) {
		t.Fatalf("65536 octets: err = %v, want ErrParamTooLong", err)
	}
}

// TestStringNFKC checks the character string encoding (TS 33.220 B.2.1.2).
func TestStringNFKC(t *testing.T) {
	cases := []struct{ in, want string }{
		{"AKMA", "AKMA"},
		{"café", "café"},
		{"café", "café"},
		{"ａｆ１", "af1"},
		{"ﬁ", "fi"},
	}
	for _, c := range cases {
		if got := String(c.in); string(got) != c.want {
			t.Errorf("String(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestDeriveOutputLength checks the full 256-bit output (TS 33.220 B.2.0).
func TestDeriveOutputLength(t *testing.T) {
	k, err := Derive([]byte("key"), 0x80, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if k == (Key{}) || len(k) != 32 {
		t.Fatal("unexpected output")
	}
}

// TestKeyNotPrinted checks that formatting a Key never reveals its value.
func TestKeyNotPrinted(t *testing.T) {
	var k Key
	for i := range k {
		k[i] = 0xAB
	}
	secret := hex.EncodeToString(k[:4])
	for _, f := range []string{"%v", "%+v", "%#v", "%s", "%x", "%X"} {
		out := strings.ToLower(fmt.Sprintf(f, k))
		if strings.Contains(out, secret) {
			t.Errorf("format %s reveals the key: %s", f, out)
		}
	}
}
