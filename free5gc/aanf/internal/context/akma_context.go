package context

import (
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/florianoneto07/akma-free5gc/shared/akma/afid"
	"github.com/florianoneto07/akma-free5gc/shared/akma/akid"
	"github.com/florianoneto07/akma-free5gc/shared/akma/derive"
	"github.com/florianoneto07/akma-free5gc/shared/akma/kdf"
)

// ErrKAkmaNotPresent reports that no K_AKMA is identified by the A-KID
// (TS 29.535 cl. 4.2.2.3.2, application error K_AKMA_NOT_PRESENT).
var ErrKAkmaNotPresent = errors.New("K_AKMA not present")

// UeAkmaContext is the AKMA context of a UE (TS 33.535 cl. 3.1): the SUPI,
// the current A-KID and K_AKMA, and the K_AF issued to AFs.
type UeAkmaContext struct {
	Supi string // SBI form, e.g. "imsi-..."; primary key
	// AKID is the A-KID as received from the AUSF; akidKey is its parsed form.
	AKID    string
	akidKey akidKey
	KAkma   kdf.Key
	Gpsi    string                  // always empty: AKMA_GPSI_Support is not supported
	AfKeys  map[string]*AfKeyRecord // by AF_ID transport form
	// Registered is when the current K_AKMA was registered.
	Registered time.Time
	// refreshAt is when its refresh was last requested from the UDM.
	refreshAt time.Time
}

// AfKeyRecord is a K_AF issued to an AF. The K_AF expiration time is part of
// the UE's AKMA context (TS 33.535 cl. 6.2.1 step 7).
type AfKeyRecord struct {
	AfID   afid.AfID
	KAf    kdf.Key
	Expiry time.Time
	// AKIDSent is the A-KID transmitted to the AF (TS 33.535 cl. 6.2.1
	// step 8 and NOTE 1); it also tells whether the K_AF was derived from the
	// current K_AKMA.
	AKIDSent string
	akidKey  akidKey
}

// akidKey identifies a K_AKMA independently of the textual form of the A-KID
// (label, letter case of the realm). The realm is a domain name and compares
// case-insensitively; the Routing Indicator compares as a string, every digit
// being significant (TS 23.003 cl. 2.2B).
type akidKey struct {
	rid   akid.RID
	atid  kdf.Key
	realm string
}

func keyOf(id akid.AKID) akidKey {
	return akidKey{rid: id.RID, atid: id.ATID, realm: strings.ToLower(id.Realm)}
}

// Store keeps the AKMA contexts in memory.
type Store struct {
	mu     sync.Mutex
	bySupi map[string]*UeAkmaContext
	byAKID map[akidKey]string // A-KID -> SUPI
	now    func() time.Time
}

// NewStore returns an empty store.
func NewStore() *Store {
	return &Store{
		bySupi: make(map[string]*UeAkmaContext),
		byAKID: make(map[akidKey]string),
		now:    time.Now,
	}
}

// SetClock replaces the clock used for K_AF lifetimes (tests).
func (s *Store) SetClock(now func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = now
}

// Register stores the latest A-KID and K_AKMA sent for supi
// (TS 33.535 cl. 6.1 step 4). A previous pair is deleted and its A-KID no
// longer identifies any K_AKMA (cl. 6.1 NOTE 1a); the K_AF already issued
// stay in the context until they expire (cl. 5.2). It reports whether a
// previous pair was replaced.
func (s *Store) Register(supi string, id akid.AKID, akidText string, kAkma kdf.Key) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	ctx, replaced := s.bySupi[supi]
	if !replaced {
		ctx = &UeAkmaContext{Supi: supi, AfKeys: make(map[string]*AfKeyRecord)}
		s.bySupi[supi] = ctx
	} else {
		if s.byAKID[ctx.akidKey] == supi {
			delete(s.byAKID, ctx.akidKey)
		}
		s.purgeExpired(ctx)
	}
	// Detection and handling of A-TID collisions are not addressed by
	// TS 33.535 (cl. 6.1 NOTE 2): the index keeps the latest registration.
	k := keyOf(id)
	ctx.AKID = akidText
	ctx.akidKey = k
	ctx.KAkma = kAkma
	ctx.Registered = s.now()
	ctx.refreshAt = time.Time{}
	s.byAKID[k] = supi
	return replaced
}

// RefreshDue tells whether the K_AKMA of supi was registered at least age
// ago and its refresh was not requested within retry; it then records the
// request. It returns the age of the K_AKMA.
func (s *Store) RefreshDue(supi string, age, retry time.Duration) (time.Duration, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ctx, ok := s.bySupi[supi]
	if !ok || age <= 0 {
		return 0, false
	}
	now := s.now()
	registeredFor := now.Sub(ctx.Registered)
	if registeredFor < age || (!ctx.refreshAt.IsZero() && now.Sub(ctx.refreshAt) < retry) {
		return registeredFor, false
	}
	ctx.refreshAt = now
	return registeredFor, true
}

// ApplicationKey returns the K_AF of af for the K_AKMA identified by id,
// with its expiration time and the SUPI of the UE. It derives K_AF from
// K_AKMA when the context does not already have a valid K_AF for af derived
// from the current K_AKMA (TS 33.535 cl. 6.2.1 step 7, cl. 5.2).
func (s *Store) ApplicationKey(id akid.AKID, af afid.AfID, lifetime time.Duration) (
	supi string, kaf kdf.Key, expiry time.Time, err error,
) {
	s.mu.Lock()
	defer s.mu.Unlock()

	k := keyOf(id)
	supi, ok := s.byAKID[k]
	if !ok {
		return "", kdf.Key{}, time.Time{}, ErrKAkmaNotPresent
	}
	ctx := s.bySupi[supi]
	if ctx == nil || ctx.akidKey != k {
		return "", kdf.Key{}, time.Time{}, ErrKAkmaNotPresent
	}

	now := s.now()
	s.purgeExpired(ctx)
	if rec, ok := ctx.AfKeys[af.Transport()]; ok && rec.akidKey == k {
		return supi, rec.KAf, rec.Expiry, nil
	}

	kaf, err = derive.KAf(ctx.KAkma, af)
	if err != nil {
		return "", kdf.Key{}, time.Time{}, err
	}
	rec := &AfKeyRecord{
		AfID:     af,
		KAf:      kaf,
		Expiry:   now.Add(lifetime).UTC().Truncate(time.Second),
		AKIDSent: ctx.AKID,
		akidKey:  k,
	}
	ctx.AfKeys[af.Transport()] = rec
	return supi, kaf, rec.Expiry, nil
}

// Remove deletes the AKMA context of supi (TS 33.535 cl. 6.6.1 step 3). It
// reports whether the context existed.
func (s *Store) Remove(supi string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	ctx, ok := s.bySupi[supi]
	if !ok {
		return false
	}
	if s.byAKID[ctx.akidKey] == supi {
		delete(s.byAKID, ctx.akidKey)
	}
	ctx.KAkma = kdf.Key{}
	for name, rec := range ctx.AfKeys {
		rec.KAf = kdf.Key{}
		delete(ctx.AfKeys, name)
	}
	delete(s.bySupi, supi)
	return true
}

// Context returns a copy of the AKMA context of supi, without the AF keys.
func (s *Store) Context(supi string) (UeAkmaContext, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, ok := s.bySupi[supi]
	if !ok {
		return UeAkmaContext{}, false
	}
	c := *ctx
	c.AfKeys = nil
	return c, true
}

// AfKeyCount returns the number of K_AF records kept for supi.
func (s *Store) AfKeyCount(supi string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx, ok := s.bySupi[supi]; ok {
		return len(ctx.AfKeys)
	}
	return 0
}

// purgeExpired deletes the expired K_AF records of ctx. Caller holds s.mu.
func (s *Store) purgeExpired(ctx *UeAkmaContext) {
	now := s.now()
	for name, rec := range ctx.AfKeys {
		if !now.Before(rec.Expiry) {
			rec.KAf = kdf.Key{}
			delete(ctx.AfKeys, name)
		}
	}
}
