//go:build wolfssl

// Copyright 2026 Floriano Neto.
// Licensed under the GNU General Public License v3.0 or later; see COPYING.

package wolftls

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"sync"
	"time"
)

// Sizes of the ticket callback buffers (WOLFSSL_TICKET_NAME_SZ,
// WOLFSSL_TICKET_IV_SZ, WOLFSSL_TICKET_MAC_SZ).
const (
	ticketNameSize = 16
	ticketIVSize   = 16
	ticketMACSize  = 32
)

// ticketIO are the buffers of one call of the ticket callback.
type ticketIO struct {
	name   *[ticketNameSize]byte
	iv     *[ticketIVSize]byte
	mac    *[ticketMACSize]byte
	ticket []byte // the session state, encrypted or decrypted in place
}

// ticketStore seals the session tickets of a Server with AES-256-GCM under
// a key of the process, and remembers for each ticket name the identity,
// the Key.Peer and the Key.Expiry of the full handshake. A ticket is
// accepted only while its entry is valid: until the earliest of the key
// expiry and the session lifetime (TS 33.222 cl. 5.4.1.4). A restart of the
// process voids every ticket.
type ticketStore struct {
	aead     cipher.AEAD
	lifetime time.Duration

	mu sync.Mutex
	m  map[[ticketNameSize]byte]ticketEntry
}

type ticketEntry struct {
	identity string
	peer     any
	expiry   time.Time // Key.Expiry, zero if none
	notAfter time.Time
}

func newTicketStore(lifetime time.Duration) (*ticketStore, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &ticketStore{aead: aead, lifetime: lifetime, m: make(map[[ticketNameSize]byte]ticketEntry)}, nil
}

// seal encrypts a new ticket of c and records its entry.
func (s *ticketStore) seal(t ticketIO, c *Conn) error {
	if _, err := rand.Read(t.name[:]); err != nil {
		return err
	}
	if _, err := rand.Read(t.iv[:]); err != nil {
		return err
	}
	out := s.aead.Seal(nil, t.iv[:s.aead.NonceSize()], t.ticket, s.aad(t))
	copy(t.ticket, out[:len(t.ticket)])
	clear(t.mac[:])
	copy(t.mac[:], out[len(t.ticket):])

	now := time.Now()
	e := ticketEntry{identity: c.identity, peer: c.peer, expiry: c.expiry, notAfter: now.Add(s.lifetime)}
	if !e.expiry.IsZero() && e.expiry.Before(e.notAfter) {
		e.notAfter = e.expiry
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for name, old := range s.m {
		if !now.Before(old.notAfter) {
			delete(s.m, name)
		}
	}
	s.m[*t.name] = e
	return nil
}

// open decrypts a ticket and gives c the identity of its full handshake.
// It reports false for an unknown, expired or altered ticket: wolfSSL then
// runs a full handshake.
func (s *ticketStore) open(t ticketIO, c *Conn) bool {
	s.mu.Lock()
	e, ok := s.m[*t.name]
	s.mu.Unlock()
	if !ok || !time.Now().Before(e.notAfter) {
		return false
	}
	tag := t.mac[:s.aead.Overhead()]
	in := append(append(make([]byte, 0, len(t.ticket)+len(tag)), t.ticket...), tag...)
	out, err := s.aead.Open(nil, t.iv[:s.aead.NonceSize()], in, s.aad(t))
	if err != nil {
		return false
	}
	copy(t.ticket, out)
	clear(out)
	c.identity, c.peer, c.expiry = e.identity, e.peer, e.expiry
	return true
}

func (s *ticketStore) aad(t ticketIO) []byte {
	return append(append(make([]byte, 0, ticketNameSize+ticketIVSize), t.name[:]...), t.iv[:]...)
}
