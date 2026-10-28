package context

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/florianoneto07/akma-free5gc/shared/akma/afid"
	"github.com/florianoneto07/akma-free5gc/shared/akma/akid"
	"github.com/florianoneto07/akma-free5gc/shared/akma/codec"
	"github.com/florianoneto07/akma-free5gc/shared/akma/kdf"
)

type vector struct {
	Name          string            `json:"name"`
	Supi          string            `json:"supi"`
	KAkma         string            `json:"k_akma"`
	AKID          map[string]string `json:"a_kid"`
	AfIDTransport string            `json:"af_id_transport"`
	KAf           string            `json:"k_af"`
}

// loadVector reads a vector of the oracle (shared/akma/testdata).
func loadVector(t *testing.T, name string) vector {
	t.Helper()
	raw, err := os.ReadFile("../../../../shared/akma/testdata/vectors.json")
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
		if v.Name == name {
			return v
		}
	}
	t.Fatalf("vector %s not found", name)
	return vector{}
}

type fixture struct {
	supi    string
	akidStr string
	id      akid.AKID
	kAkma   kdf.Key
	af      afid.AfID
	kaf     kdf.Key
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	v := loadVector(t, "testbed-ue")
	id, err := akid.Parse(v.AKID["base64"], akid.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	kAkma, err := codec.ParseHexKey(v.KAkma)
	if err != nil {
		t.Fatal(err)
	}
	af, err := afid.Parse(v.AfIDTransport)
	if err != nil {
		t.Fatal(err)
	}
	kaf, err := codec.ParseHexKey(v.KAf)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{v.Supi, v.AKID["base64"], id, kAkma, af, kaf}
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time                { return c.t }
func (c *clock) advance(d time.Duration)       { c.t = c.t.Add(d) }
func newClock() *clock                         { return &clock{time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)} }
func otherKey(b byte) (k kdf.Key)              { k[0] = b; return k }
func otherAKID(id akid.AKID, b byte) akid.AKID { id.ATID[0] ^= b; return id }

func TestApplicationKeyMatchesOracle(t *testing.T) {
	f := newFixture(t)
	s := NewStore()
	s.Register(f.supi, f.id, f.akidStr, f.kAkma)

	supi, kaf, expiry, err := s.ApplicationKey(f.id, f.af, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if supi != f.supi || kaf != f.kaf {
		t.Errorf("got (%s, %s), want (%s, %s)", supi, codec.HexKey(kaf), f.supi, codec.HexKey(f.kaf))
	}
	if !expiry.After(time.Now()) || expiry.Location() != time.UTC {
		t.Errorf("expiry %v not a future UTC instant", expiry)
	}
}

// The A-KID is matched on its content: the "akid" label and the letter case
// of the realm do not change the K_AKMA it identifies.
func TestAKIDTextualVariants(t *testing.T) {
	f := newFixture(t)
	s := NewStore()
	s.Register(f.supi, f.id, f.akidStr, f.kAkma)

	variant := f.id
	variant.Realm = "5GC.MNC093.MCC208.3GPPNETWORK.ORG"
	if _, _, _, err := s.ApplicationKey(variant, f.af, time.Hour); err != nil {
		t.Errorf("realm in upper case: %v", err)
	}
	// RID "000" is not RID "0000".
	variant = f.id
	variant.RID = "000"
	if _, _, _, err := s.ApplicationKey(variant, f.af, time.Hour); err != ErrKAkmaNotPresent {
		t.Errorf("RID 000: err = %v, want ErrKAkmaNotPresent", err)
	}
}

func TestUnknownAKID(t *testing.T) {
	f := newFixture(t)
	s := NewStore()
	if _, _, _, err := s.ApplicationKey(f.id, f.af, time.Hour); err != ErrKAkmaNotPresent {
		t.Errorf("err = %v, want ErrKAkmaNotPresent", err)
	}
}

// TS 33.535 cl. 6.1 NOTE 1a: the new A-KID and K_AKMA replace the old ones;
// cl. 5.2: K_AF already issued stays until it expires.
func TestReRegistrationReplacesPair(t *testing.T) {
	f := newFixture(t)
	c := newClock()
	s := NewStore()
	s.SetClock(c.now)

	if s.Register(f.supi, f.id, f.akidStr, f.kAkma) {
		t.Error("first registration reported as replacement")
	}
	if _, _, _, err := s.ApplicationKey(f.id, f.af, time.Hour); err != nil {
		t.Fatal(err)
	}

	newID := otherAKID(f.id, 0xff)
	if !s.Register(f.supi, newID, "new", otherKey(1)) {
		t.Error("re-registration not reported as replacement")
	}
	if _, _, _, err := s.ApplicationKey(f.id, f.af, time.Hour); err != ErrKAkmaNotPresent {
		t.Errorf("old A-KID: err = %v, want ErrKAkmaNotPresent", err)
	}
	if n := s.AfKeyCount(f.supi); n != 1 {
		t.Errorf("K_AF records after re-registration = %d, want 1", n)
	}

	_, kaf, _, err := s.ApplicationKey(newID, f.af, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if kaf == f.kaf {
		t.Error("K_AF for the new A-KID derived from the old K_AKMA")
	}

	c.advance(2 * time.Hour)
	s.Register(f.supi, f.id, f.akidStr, f.kAkma)
	if n := s.AfKeyCount(f.supi); n != 0 {
		t.Errorf("expired K_AF records kept: %d", n)
	}
}

// TS 33.535 cl. 6.2.1 step 7: the AAnF derives K_AF "if it does not already
// have KAF"; the stored expiration time is returned until it is reached.
func TestKafReusedUntilExpiry(t *testing.T) {
	f := newFixture(t)
	c := newClock()
	s := NewStore()
	s.SetClock(c.now)
	s.Register(f.supi, f.id, f.akidStr, f.kAkma)

	_, _, e1, err := s.ApplicationKey(f.id, f.af, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if want := c.t.Add(time.Hour); !e1.Equal(want) {
		t.Errorf("expiry = %v, want %v", e1, want)
	}
	c.advance(30 * time.Minute)
	_, _, e2, _ := s.ApplicationKey(f.id, f.af, time.Hour)
	if !e2.Equal(e1) {
		t.Errorf("expiry changed before expiration: %v -> %v", e1, e2)
	}
	c.advance(30 * time.Minute)
	_, kaf, e3, _ := s.ApplicationKey(f.id, f.af, time.Hour)
	if !e3.After(e1) {
		t.Errorf("expiry not renewed after expiration: %v", e3)
	}
	// TS 33.535 cl. 5.2 NOTE: with the same K_AKMA the K_AF is not a new one.
	if kaf != f.kaf {
		t.Error("K_AF changed with the same K_AKMA")
	}
}

func TestRemove(t *testing.T) {
	f := newFixture(t)
	s := NewStore()
	s.Register(f.supi, f.id, f.akidStr, f.kAkma)
	if _, _, _, err := s.ApplicationKey(f.id, f.af, time.Hour); err != nil {
		t.Fatal(err)
	}
	if !s.Remove(f.supi) {
		t.Fatal("Remove of an existing context returned false")
	}
	if _, ok := s.Context(f.supi); ok {
		t.Error("context still present")
	}
	if _, _, _, err := s.ApplicationKey(f.id, f.af, time.Hour); err != ErrKAkmaNotPresent {
		t.Errorf("err = %v, want ErrKAkmaNotPresent", err)
	}
	if s.Remove(f.supi) {
		t.Error("second Remove returned true")
	}
}

// An A-KID registered again for another SUPI (A-TID collision) resolves to
// the latest registration; removing the first SUPI does not drop it.
func TestSameAKIDForAnotherSupi(t *testing.T) {
	f := newFixture(t)
	s := NewStore()
	s.Register(f.supi, f.id, f.akidStr, f.kAkma)
	s.Register("imsi-208930000000002", f.id, f.akidStr, otherKey(2))
	s.Remove(f.supi)

	supi, _, _, err := s.ApplicationKey(f.id, f.af, time.Hour)
	if err != nil || supi != "imsi-208930000000002" {
		t.Errorf("got (%s, %v), want the second SUPI", supi, err)
	}
}

func TestConcurrentAccess(t *testing.T) {
	f := newFixture(t)
	s := NewStore()
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 200; j++ {
				s.Register(f.supi, f.id, f.akidStr, f.kAkma)
				_, _, _, _ = s.ApplicationKey(f.id, f.af, time.Hour)
				if j%50 == 0 {
					s.Remove(f.supi)
				}
			}
		}()
	}
	for i := 0; i < 8; i++ {
		<-done
	}
}

// TS 33.535 cl. 6.4.4: the refresh of K_AKMA is requested once it is older
// than the policy, once per K_AKMA, and again after the retry interval.
func TestRefreshDue(t *testing.T) {
	f := newFixture(t)
	c := newClock()
	s := NewStore()
	s.SetClock(c.now)
	if _, due := s.RefreshDue(f.supi, time.Minute, 5*time.Minute); due {
		t.Fatal("refresh due without a context")
	}
	s.Register(f.supi, f.id, f.akidStr, f.kAkma)
	if ctx, _ := s.Context(f.supi); !ctx.Registered.Equal(c.t) {
		t.Errorf("Registered = %v, want %v", ctx.Registered, c.t)
	}

	c.advance(59 * time.Second)
	if _, due := s.RefreshDue(f.supi, time.Minute, 5*time.Minute); due {
		t.Fatal("refresh due before the policy age")
	}
	c.advance(time.Second)
	age, due := s.RefreshDue(f.supi, time.Minute, 5*time.Minute)
	if !due || age != time.Minute {
		t.Fatalf("refresh not due at the policy age: %v %v", age, due)
	}
	c.advance(4 * time.Minute)
	if _, due := s.RefreshDue(f.supi, time.Minute, 5*time.Minute); due {
		t.Fatal("refresh requested twice within the retry interval")
	}
	c.advance(time.Minute)
	if _, due := s.RefreshDue(f.supi, time.Minute, 5*time.Minute); !due {
		t.Fatal("refresh not requested again after the retry interval")
	}
	if _, due := s.RefreshDue(f.supi, 0, 5*time.Minute); due {
		t.Fatal("refresh due with the policy disabled")
	}

	// A new K_AKMA starts the policy again.
	s.Register(f.supi, otherAKID(f.id, 1), "other", otherKey(1))
	if _, due := s.RefreshDue(f.supi, time.Minute, 5*time.Minute); due {
		t.Fatal("refresh due for a new K_AKMA")
	}
	c.advance(time.Minute)
	if _, due := s.RefreshDue(f.supi, time.Minute, 5*time.Minute); !due {
		t.Fatal("refresh not due for the new K_AKMA at the policy age")
	}
}
