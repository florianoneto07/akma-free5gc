package oscore

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
)

// ccm is CCM mode (RFC 3610) over a 128-bit block cipher, with a 13-octet
// nonce, so a 2-octet length field (L = 2). With AES-128 and an 8-octet tag
// it is AES-CCM-16-64-128, the AEAD algorithm 10 of COSE (RFC 9053 cl. 4.2)
// and the default of OSCORE (RFC 8613 cl. 3.2). The Go library has no CCM.
type ccm struct {
	b   cipher.Block
	tag int // M
}

const (
	ccmNonceSize = 13
	ccmMaxLength = 1<<16 - 1 // 2^(8L) - 1
)

// newCCM returns CCM over b with a tag of tagSize octets: 4, 6, 8, 10, 12,
// 14 or 16 (RFC 3610 cl. 2).
func newCCM(b cipher.Block, tagSize int) (cipher.AEAD, error) {
	if b.BlockSize() != 16 {
		return nil, errors.New("oscore: CCM needs a 128-bit block cipher")
	}
	if tagSize < 4 || tagSize > 16 || tagSize%2 != 0 {
		return nil, fmt.Errorf("oscore: CCM tag of %d octets", tagSize)
	}
	return &ccm{b: b, tag: tagSize}, nil
}

func (c *ccm) NonceSize() int { return ccmNonceSize }
func (c *ccm) Overhead() int  { return c.tag }

// mac is the CBC-MAC of RFC 3610 cl. 2.2: the first block B0 holds the
// flags, the nonce and the length of the message; then the length and the
// octets of the additional data, then the message, each padded with zeros
// to a whole block.
func (c *ccm) mac(nonce, msg, aad []byte) [16]byte {
	var x [16]byte
	flags := byte((c.tag-2)/2)<<3 | 1 // L - 1 = 1
	if len(aad) > 0 {
		flags |= 1 << 6
	}
	x[0] = flags
	copy(x[1:14], nonce)
	binary.BigEndian.PutUint16(x[14:], uint16(len(msg)))
	c.b.Encrypt(x[:], x[:])

	block := func(p []byte) {
		subtle.XORBytes(x[:len(p)], x[:len(p)], p)
		c.b.Encrypt(x[:], x[:])
	}
	pad := func(data []byte) {
		for len(data) >= 16 {
			block(data[:16])
			data = data[16:]
		}
		if len(data) > 0 {
			var last [16]byte
			copy(last[:], data)
			block(last[:])
		}
	}
	if len(aad) > 0 {
		var head []byte
		switch {
		case len(aad) < 1<<16-1<<8:
			head = binary.BigEndian.AppendUint16(nil, uint16(len(aad)))
		case uint64(len(aad)) < 1<<32:
			head = binary.BigEndian.AppendUint32([]byte{0xFF, 0xFE}, uint32(len(aad)))
		default:
			head = binary.BigEndian.AppendUint64([]byte{0xFF, 0xFF}, uint64(len(aad)))
		}
		pad(append(head, aad...))
	}
	pad(msg)
	return x
}

// ctr returns the counter block A_i of RFC 3610 cl. 2.3.
func ctr(nonce []byte, i uint16) []byte {
	a := make([]byte, 16)
	a[0] = 1 // L - 1
	copy(a[1:14], nonce)
	binary.BigEndian.PutUint16(a[14:], i)
	return a
}

func (c *ccm) Seal(dst, nonce, plaintext, aad []byte) []byte {
	if len(nonce) != ccmNonceSize {
		panic("oscore: CCM nonce of the wrong size")
	}
	if len(plaintext) > ccmMaxLength {
		panic("oscore: CCM message too long")
	}
	t := c.mac(nonce, plaintext, aad)
	ret, out := sliceForAppend(dst, len(plaintext)+c.tag)
	cipher.NewCTR(c.b, ctr(nonce, 1)).XORKeyStream(out, plaintext)
	var s0 [16]byte
	c.b.Encrypt(s0[:], ctr(nonce, 0))
	subtle.XORBytes(out[len(plaintext):], t[:c.tag], s0[:c.tag])
	return ret
}

var errOpen = errors.New("oscore: message authentication failed")

func (c *ccm) Open(dst, nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(nonce) != ccmNonceSize {
		panic("oscore: CCM nonce of the wrong size")
	}
	if len(ciphertext) < c.tag || len(ciphertext)-c.tag > ccmMaxLength {
		return nil, errOpen
	}
	n := len(ciphertext) - c.tag
	ret, out := sliceForAppend(dst, n)
	cipher.NewCTR(c.b, ctr(nonce, 1)).XORKeyStream(out, ciphertext[:n])
	t := c.mac(nonce, out, aad)
	var s0 [16]byte
	c.b.Encrypt(s0[:], ctr(nonce, 0))
	subtle.XORBytes(s0[:c.tag], s0[:c.tag], t[:c.tag])
	if subtle.ConstantTimeCompare(s0[:c.tag], ciphertext[n:]) != 1 {
		clear(out)
		return nil, errOpen
	}
	return ret, nil
}

// sliceForAppend extends in by n octets, as in crypto/cipher.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	return head, head[len(in):]
}
