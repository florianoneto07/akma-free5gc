package akid

import (
	"errors"
	"strings"
	"testing"

	"github.com/florianoneto07/akma-free5gc/shared/akma/kdf"
)

func testKey() kdf.Key {
	var k kdf.Key
	for i := range k {
		k[i] = byte(i * 7)
	}
	return k
}

func TestParseRID(t *testing.T) {
	for _, s := range []string{"0", "7", "012", "0000", "1234"} {
		if r, err := ParseRID(s); err != nil || string(r) != s {
			t.Errorf("ParseRID(%q) = %q, %v", s, r, err)
		}
	}
	for _, s := range []string{"", "12345", "1a", " 12", "-1"} {
		if _, err := ParseRID(s); !errors.Is(err, ErrMalformedRID) {
			t.Errorf("ParseRID(%q): err = %v", s, err)
		}
	}
}

// TestLeadingZerosSignificant checks that "012" and "12" give different
// A-KIDs and that RIDs with leading zeros survive a round trip
// (TS 23.003 cl. 2.2B).
func TestLeadingZerosSignificant(t *testing.T) {
	o := DefaultOptions()
	seen := map[string]RID{}
	for _, r := range []RID{"0", "012", "12", "0000", "00"} {
		s, err := AKID{RID: r, ATID: testKey(), Realm: "5gc.mnc093.mcc208.3gppnetwork.org"}.Format(o)
		if err != nil {
			t.Fatal(err)
		}
		if prev, dup := seen[s]; dup {
			t.Fatalf("RID %q and %q give the same A-KID", prev, r)
		}
		seen[s] = r
		back, err := Parse(s, o)
		if err != nil || back.RID != r {
			t.Fatalf("round trip of RID %q: %q, %v", r, back.RID, err)
		}
	}
}

// TestHomeNetworkDomain checks TS 23.003 cl. 28.2, including its example.
func TestHomeNetworkDomain(t *testing.T) {
	cases := []struct{ mcc, mnc, want string }{
		{"345", "12", "5gc.mnc012.mcc345.3gppnetwork.org"},
		{"208", "93", "5gc.mnc093.mcc208.3gppnetwork.org"},
		{"310", "410", "5gc.mnc410.mcc310.3gppnetwork.org"},
	}
	for _, c := range cases {
		h, err := NewHomeNetwork(c.mcc, c.mnc)
		if err != nil {
			t.Fatal(err)
		}
		if got := h.Domain(); got != c.want {
			t.Errorf("Domain(%s,%s) = %s, want %s", c.mcc, c.mnc, got, c.want)
		}
		back, err := ParseDomain(c.want)
		if err != nil || back.Domain() != c.want {
			t.Errorf("ParseDomain(%s) = %+v, %v", c.want, back, err)
		}
	}
	for _, bad := range [][2]string{{"34", "12"}, {"345", "1"}, {"345", "1234"}, {"3a5", "12"}} {
		if _, err := NewHomeNetwork(bad[0], bad[1]); !errors.Is(err, ErrMalformedHomeNetwork) {
			t.Errorf("NewHomeNetwork(%v): err = %v", bad, err)
		}
	}
}

func TestEncodings(t *testing.T) {
	a := AKID{RID: "0000", ATID: testKey(), Realm: "5gc.mnc093.mcc208.3gppnetwork.org"}
	for _, e := range []Encoding{EncodingBase64, EncodingBase64URL, EncodingHex} {
		o := DefaultOptions()
		o.Encoding = e
		s, err := a.Format(o)
		if err != nil {
			t.Fatal(err)
		}
		back, err := Parse(s, o)
		if err != nil || back != a {
			t.Errorf("encoding %d: round trip failed: %v", e, err)
		}
	}
	s, _ := a.Format(DefaultOptions())
	value := strings.TrimSuffix(strings.TrimPrefix(s, "rid0000.atid"), "@"+a.Realm)
	if len(value) != 44 || !strings.HasSuffix(value, "=") {
		t.Fatalf("base64 A-TID = %q, want 44 characters ending in '='", value)
	}
}

// TestLabels checks the labels: "atid" written, "akid" (the example of
// TS 29.522 table 5.14.5.4.2-1) accepted.
func TestLabels(t *testing.T) {
	o := DefaultOptions()
	a := AKID{RID: "012", ATID: testKey(), Realm: "5gc.mnc012.mcc345.3gppnetwork.org"}
	s, _ := a.Format(o)
	if !strings.HasPrefix(s, "rid012.atid") || strings.Contains(s, "akid") {
		t.Fatalf("Format = %s, want label atid", s)
	}
	alt := strings.Replace(s, ".atid", ".akid", 1)
	back, err := Parse(alt, o)
	if err != nil || back != a {
		t.Fatalf("akid label not accepted on read: %v", err)
	}
	strict := o
	strict.AcceptLabels = []string{"atid"}
	if _, err := Parse(alt, strict); !errors.Is(err, ErrMalformedAKID) {
		t.Fatalf("akid accepted with AcceptLabels=[atid]: %v", err)
	}
}

// TestSpecExampleRejected: the example of TS 29.522 table 5.14.5.4.2-1 is
// syntactic only; "019345346" cannot be a 256-bit A-TID.
func TestSpecExampleRejected(t *testing.T) {
	_, err := Parse("rid012.akid019345346@5gc.mnc012.mcc345.3gppnetwork.org", DefaultOptions())
	if !errors.Is(err, ErrMalformedAKID) {
		t.Fatalf("err = %v, want ErrMalformedAKID", err)
	}
}

func TestParseMalformed(t *testing.T) {
	o := DefaultOptions()
	good, _ := AKID{RID: "0", ATID: testKey(), Realm: "5gc.mnc093.mcc208.3gppnetwork.org"}.Format(o)
	short := strings.Replace(good, good[11:15], "", 1) // drops characters from the A-TID
	for _, s := range []string{
		"",
		strings.Replace(good, "@", "", 1), // no realm
		good + "@x",                       // two '@'
		strings.TrimPrefix(good, "rid"),   // no "rid" label
		strings.Replace(good, "rid0.", "rid01234.", 1), // RID of five digits
		strings.Replace(good, "rid0.", "rid0", 1),      // no '.'
		strings.Replace(good, ".atid", ".xtid", 1),     // unknown label
		short,                                 // A-TID not 32 octets
		strings.Replace(good, "=@", "@", 1),   // missing padding
		strings.SplitN(good, "@", 2)[0] + "@", // empty realm
	} {
		if _, err := Parse(s, o); err == nil {
			t.Errorf("Parse(%q) accepted", s)
		}
	}
}

func TestFormatRejectsBadInput(t *testing.T) {
	o := DefaultOptions()
	if _, err := (AKID{RID: "12345", Realm: "x"}).Format(o); err == nil {
		t.Error("five-digit RID accepted")
	}
	if _, err := (AKID{RID: "0", Realm: ""}).Format(o); err == nil {
		t.Error("empty realm accepted")
	}
}
