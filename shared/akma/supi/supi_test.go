package supi

import (
	"errors"
	"strings"
	"testing"
)

func TestFromSBI(t *testing.T) {
	p, err := FromSBI("imsi-208930000000001")
	if err != nil {
		t.Fatal(err)
	}
	if p != "208930000000001" {
		t.Fatalf("Param = %q, want the IMSI digits without prefix", p)
	}
	if p.SBI() != "imsi-208930000000001" {
		t.Fatalf("SBI() = %q", p.SBI())
	}
}

// TestUnsupportedTypes checks that only IMSI-type SUPI is supported.
func TestUnsupportedTypes(t *testing.T) {
	for _, s := range []string{"nai-user@example.org", "gci-x@example.org", "gli-x@example.org"} {
		if _, err := FromSBI(s); !errors.Is(err, ErrUnsupportedType) {
			t.Errorf("FromSBI(%q): err = %v, want ErrUnsupportedType", s, err)
		}
	}
}

func TestMalformed(t *testing.T) {
	for _, s := range []string{
		"",
		"208930000000001",       // no SBI prefix
		"imsi-1234",             // fewer than 5 digits
		"imsi-1234567890123456", // more than 15 digits
		"imsi-20893000000000a",
		"IMSI-208930000000001",
	} {
		if _, err := FromSBI(s); !errors.Is(err, ErrMalformed) {
			t.Errorf("FromSBI(%q): err = %v, want ErrMalformed", s, err)
		}
	}
}

// TestPrefixRejectedAtKDFLayer checks that a parameter still carrying the SBI
// prefix is refused: P0 is the IMSI of TS 23.003 cl. 2.2, digits only
// (TS 33.501 A.7.0).
func TestPrefixRejectedAtKDFLayer(t *testing.T) {
	if err := Param("imsi-208930000000001").Validate(); !errors.Is(err, ErrMalformed) {
		t.Fatalf("Validate: err = %v, want ErrMalformed", err)
	}
}

// TestErrorsDoNotLeakSUPI checks that error messages never carry the SUPI.
func TestErrorsDoNotLeakSUPI(t *testing.T) {
	_, err := FromSBI("imsi-2089300000000a1")
	if err == nil || strings.Contains(err.Error(), "20893") {
		t.Fatalf("error = %v", err)
	}
}
