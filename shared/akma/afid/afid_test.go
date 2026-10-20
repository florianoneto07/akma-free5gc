package afid

import (
	"bytes"
	"errors"
	"testing"
)

func TestTransportUppercase(t *testing.T) {
	a, err := New("af1.akma.example", UaStarDigest)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := a.Transport(), "af1.akma.example.FF00000001"; got != want {
		t.Fatalf("Transport() = %q, want %q", got, want)
	}
}

// TestSpecExample parses the example of TS 29.522 table 5.14.5.4.2-1.
func TestSpecExample(t *testing.T) {
	a, err := Parse("www.app1.com.0100BC0001")
	if err != nil {
		t.Fatal(err)
	}
	if a.FQDN != "www.app1.com" || a.Protocol != (UaStarID{0x01, 0x00, 0xBC, 0x00, 0x01}) {
		t.Fatalf("Parse = %+v", a)
	}
}

func TestParseEitherCase(t *testing.T) {
	up, err1 := Parse("af1.akma.example.FF00000001")
	low, err2 := Parse("af1.akma.example.ff00000001")
	if err1 != nil || err2 != nil || up != low {
		t.Fatalf("Parse: %v %v %+v %+v", err1, err2, up, low)
	}
}

// TestKDFParam checks P0 = FQDN || five raw octets and L0 = len(FQDN) + 5
// (TS 33.535 A.4).
func TestKDFParam(t *testing.T) {
	a, _ := New("af1.akma.example", UaStarDigest)
	want := append([]byte("af1.akma.example"), 0xFF, 0x00, 0x00, 0x00, 0x01)
	if !bytes.Equal(a.KDFParam(), want) {
		t.Fatalf("KDFParam = %x, want %x", a.KDFParam(), want)
	}
	if len(a.KDFParam()) != len("af1.akma.example")+5 {
		t.Fatal("wrong L0")
	}
}

// TestTransportIsNotP0 checks that the two forms differ, so that using the
// transport string as P0 would change K_AF.
func TestTransportIsNotP0(t *testing.T) {
	a, _ := Parse("af1.akma.example.FF00000001")
	if bytes.Equal([]byte(a.Transport()), a.KDFParam()) {
		t.Fatal("transport form equals KDF form")
	}
}

func TestParseMalformed(t *testing.T) {
	for _, s := range []string{
		"",
		".FF00000001",                 // empty FQDN
		"af1.akma.example.FF0000000",  // nine hexadecimal characters
		"af1.akma.exampleFF00000001",  // no dot before the identifier
		"af1.akma.example.GG00000001", // not hexadecimal
		"FF00000001",
	} {
		if _, err := Parse(s); !errors.Is(err, ErrMalformed) {
			t.Errorf("Parse(%q): err = %v, want ErrMalformed", s, err)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	for _, p := range []UaStarID{UaStarDigest, UaStarTLS13, {}} {
		a, _ := New("af.example", p)
		b, err := Parse(a.Transport())
		if err != nil || a != b {
			t.Errorf("round trip of %v: %v %+v", p, err, b)
		}
	}
}
