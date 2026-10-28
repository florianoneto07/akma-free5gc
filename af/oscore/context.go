// Package oscore is OSCORE (RFC 8613) for the Ua* profile of TS 33.535
// Annex D: the security context (cl. 3), the protection of requests and
// responses (cl. 4 to 8) with AES-CCM-16-64-128 and HKDF SHA-256, the
// replay window (cl. 7.4), and the derivation of new contexts of Appendix
// B.2. The messages are those of the coap package.
package oscore

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/florianoneto07/akma-free5gc/af/cbor"
)

// Algorithms of the security context: the defaults of RFC 8613 cl. 3.2,
// the only ones of this package.
const (
	// AlgAESCCM16_64_128 is the COSE value of AES-CCM-16-64-128 (RFC 9053
	// cl. 4.2).
	AlgAESCCM16_64_128 = 10
	keySize            = 16
	nonceSize          = ccmNonceSize
	tagSize            = 8
	// MaxIDSize is the longest Sender ID: the nonce minus 6 octets
	// (RFC 8613 cl. 3.3).
	MaxIDSize = nonceSize - 6
	// MaxSequence is the largest Sender Sequence Number, 2^40 - 1
	// (RFC 8613 cl. 7.2.1).
	MaxSequence = 1<<40 - 1
	// Version is the OSCORE version of the AAD (RFC 8613 cl. 5.4).
	Version = 1
)

// Params are the input parameters of a security context (RFC 8613
// cl. 3.2). The algorithms are the defaults.
type Params struct {
	MasterSecret []byte
	MasterSalt   []byte // empty: the default
	SenderID     []byte
	RecipientID  []byte
	// IDContext is the ID Context; nil when there is none, which differs
	// from an empty one in the derivation.
	IDContext []byte
}

// Context is a security context. Its methods are safe for concurrent use.
type Context struct {
	p            Params
	senderKey    []byte
	recipientKey []byte
	commonIV     []byte
	sender       cipher.AEAD
	recipient    cipher.AEAD

	mu     sync.Mutex
	seq    uint64 // next Sender Sequence Number
	replay window
}

// Derive derives the Sender Key, the Recipient Key and the Common IV
// (RFC 8613 cl. 3.2.1).
func Derive(p Params) (*Context, error) {
	if len(p.MasterSecret) == 0 {
		return nil, errors.New("oscore: empty Master Secret")
	}
	if len(p.SenderID) > MaxIDSize || len(p.RecipientID) > MaxIDSize {
		return nil, fmt.Errorf("oscore: Sender ID or Recipient ID longer than %d octets", MaxIDSize)
	}
	if bytes.Equal(p.SenderID, p.RecipientID) {
		// Both directions would have the same key and nonces (cl. 3.3).
		return nil, errors.New("oscore: Sender ID equal to the Recipient ID")
	}
	p = Params{
		MasterSecret: slices.Clone(p.MasterSecret), MasterSalt: slices.Clone(p.MasterSalt),
		SenderID: cloneNonNil(p.SenderID), RecipientID: cloneNonNil(p.RecipientID), IDContext: cloneKeepNil(p.IDContext),
	}
	c := &Context{p: p}
	var err error
	if c.senderKey, err = c.derive(p.SenderID, "Key", keySize); err != nil {
		return nil, err
	}
	if c.recipientKey, err = c.derive(p.RecipientID, "Key", keySize); err != nil {
		return nil, err
	}
	if c.commonIV, err = c.derive([]byte{}, "IV", nonceSize); err != nil {
		return nil, err
	}
	if c.sender, err = newAEAD(c.senderKey); err != nil {
		return nil, err
	}
	if c.recipient, err = newAEAD(c.recipientKey); err != nil {
		return nil, err
	}
	return c, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return newCCM(b, tagSize)
}

func cloneNonNil(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return slices.Clone(b)
}

func cloneKeepNil(b []byte) []byte {
	if b == nil {
		return nil
	}
	return cloneNonNil(b)
}

// info is the CBOR array of RFC 8613 cl. 3.2.1.
func (c *Context) info(id []byte, typ string, l int) []byte {
	idc := cbor.NullValue()
	if c.p.IDContext != nil {
		idc = cbor.BytesValue(c.p.IDContext)
	}
	return cbor.MustEncode(cbor.ArrayValue(cbor.BytesValue(id), idc, cbor.IntValue(AlgAESCCM16_64_128),
		cbor.TextValue(typ), cbor.UintValue(uint64(l))))
}

func (c *Context) derive(id []byte, typ string, l int) ([]byte, error) {
	return hkdf.Key(sha256.New, c.p.MasterSecret, c.p.MasterSalt, string(c.info(id, typ, l)), l)
}

// WithIDContext returns the context with the same input parameters and
// another ID Context, as Appendix B.2 derives them.
func (c *Context) WithIDContext(id []byte) (*Context, error) {
	p := c.p
	p.IDContext = cloneNonNil(id)
	return Derive(p)
}

// SenderID returns the Sender ID.
func (c *Context) SenderID() []byte { return slices.Clone(c.p.SenderID) }

// RecipientID returns the Recipient ID.
func (c *Context) RecipientID() []byte { return slices.Clone(c.p.RecipientID) }

// IDContext returns the ID Context, nil when there is none.
func (c *Context) IDContext() []byte { return cloneKeepNil(c.p.IDContext) }

// nonce is the AEAD nonce of RFC 8613 cl. 5.2: the length of the ID of the
// endpoint that generated the Partial IV, that ID padded to 7 octets, the
// Partial IV padded to 5 octets, all XORed with the Common IV.
func (c *Context) nonce(idPIV, piv []byte) []byte {
	n := make([]byte, nonceSize)
	n[0] = byte(len(idPIV))
	copy(n[1+MaxIDSize-len(idPIV):1+MaxIDSize], idPIV)
	copy(n[nonceSize-len(piv):], piv)
	for i := range n {
		n[i] ^= c.commonIV[i]
	}
	return n
}

// nextPIV takes the next Sender Sequence Number and returns it as a Partial
// IV: big endian without leading zeros, 0 as one octet (RFC 8613 cl. 6.1).
func (c *Context) nextPIV() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seq > MaxSequence {
		return nil, ErrSequenceExhausted
	}
	s := c.seq
	c.seq++
	return encodePIV(s), nil
}

func encodePIV(s uint64) []byte {
	b := []byte{byte(s)}
	for s >>= 8; s > 0; s >>= 8 {
		b = append([]byte{byte(s)}, b...)
	}
	return b
}

func decodePIV(piv []byte) uint64 {
	var s uint64
	for _, c := range piv {
		s = s<<8 | uint64(c)
	}
	return s
}

// ErrSequenceExhausted reports a context whose Sender Sequence Number
// reached 2^40: a new one is needed (RFC 8613 cl. 7.2.1).
var ErrSequenceExhausted = errors.New("oscore: Sender Sequence Number exhausted")

// aad is the additional authenticated data of RFC 8613 cl. 5.4: the
// Enc_structure of COSE with the external_aad. No Class I option is
// defined, so the options field is empty.
func aad(requestKID, requestPIV []byte) []byte {
	ext := cbor.MustEncode(cbor.ArrayValue(cbor.UintValue(Version),
		cbor.ArrayValue(cbor.IntValue(AlgAESCCM16_64_128)), cbor.BytesValue(requestKID),
		cbor.BytesValue(requestPIV), cbor.BytesValue([]byte{})))
	return cbor.MustEncode(cbor.ArrayValue(cbor.TextValue("Encrypt0"), cbor.BytesValue([]byte{}),
		cbor.BytesValue(ext)))
}

// window is the anti-replay window of RFC 8613 cl. 7.4, the sliding window
// of RFC 6347 cl. 4.1.2.6 with 32 positions.
type window struct {
	any  bool   // a sequence number was received
	top  uint64 // the highest one received
	bits uint32 // bit i: top - i received
}

const windowSize = 32

func (w *window) seen(s uint64) bool {
	switch {
	case !w.any || s > w.top:
		return false
	case w.top-s >= windowSize:
		return true // too old to tell: refused
	}
	return w.bits&(1<<(w.top-s)) != 0
}

func (w *window) mark(s uint64) {
	switch {
	case !w.any:
		w.any, w.top, w.bits = true, s, 1
	case s > w.top:
		if shift := s - w.top; shift >= windowSize {
			w.bits = 1
		} else {
			w.bits = w.bits<<shift | 1
		}
		w.top = s
	default:
		w.bits |= 1 << (w.top - s)
	}
}
