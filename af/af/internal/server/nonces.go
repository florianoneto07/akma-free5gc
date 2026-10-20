package server

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// nonceCheck is the result of checking nonce, opaque and nc (RFC 7616
// cl. 3.4 and 5.4).
type nonceCheck int

const (
	nonceOK nonceCheck = iota
	nonceUnknown
	nonceStale
	nonceReplay
)

type nonceState struct {
	opaque string
	issued time.Time
	lastNC uint32
}

// nonceStore keeps the challenges issued by the AF. A nonce is valid for
// lifetime; it is remembered for twice as long so that a late request is
// answered with stale=true instead of as unknown.
type nonceStore struct {
	mu       sync.Mutex
	lifetime time.Duration
	m        map[string]*nonceState
}

func newNonceStore(lifetime time.Duration) *nonceStore {
	return &nonceStore{lifetime: lifetime, m: make(map[string]*nonceState)}
}

// issue returns a new nonce (32 random octets) and opaque (16 random
// octets), both in base64 (RFC 7616 cl. 3.3 advises base64 or hexadecimal).
func (s *nonceStore) issue(now time.Time) (nonce, opaque string) {
	nonce, opaque = random(32), random(16)
	s.mu.Lock()
	defer s.mu.Unlock()
	for n, st := range s.m {
		if now.Sub(st.issued) > 2*s.lifetime {
			delete(s.m, n)
		}
	}
	s.m[nonce] = &nonceState{opaque: opaque, issued: now}
	return nonce, opaque
}

// check verifies a nonce, its opaque and a nonce count without recording
// the count.
func (s *nonceStore) check(nonce, opaque string, nc uint32, now time.Time) nonceCheck {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.m[nonce]
	switch {
	case !ok || st.opaque != opaque:
		return nonceUnknown
	case now.Sub(st.issued) >= s.lifetime:
		return nonceStale
	case nc <= st.lastNC:
		return nonceReplay
	}
	return nonceOK
}

// commit records nc after a successful verification; it fails when a
// concurrent request already used this or a higher count.
func (s *nonceStore) commit(nonce string, nc uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.m[nonce]
	if !ok || nc <= st.lastNC {
		return false
	}
	st.lastNC = nc
	return true
}

func random(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return base64.StdEncoding.EncodeToString(b)
}
