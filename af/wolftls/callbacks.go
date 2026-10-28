//go:build wolfssl

// Copyright 2026 Floriano Neto.
// Licensed under the GNU General Public License v3.0 or later; see COPYING.

package wolftls

/*
#include "shim.h"
*/
import "C"

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"runtime/cgo"
	"time"
	"unicode"
	"unicode/utf8"
	"unsafe"
)

// The callbacks run inside wolfSSL calls that hold Conn.mu, on the goroutine
// that made the call. A panic must not cross into C: each one is recovered
// and fails the operation.

func connOf(h C.uintptr_t) *Conn {
	return cgo.Handle(h).Value().(*Conn)
}

//export wolftlsRecv
func wolftlsRecv(h C.uintptr_t, buf *C.char, sz C.int) (ret C.int) {
	defer func() {
		if recover() != nil {
			ret = C.WOLFSSL_CBIO_ERR_GENERAL
		}
	}()
	n, err := connOf(h).in.take(unsafe.Slice((*byte)(unsafe.Pointer(buf)), int(sz)))
	switch {
	case n > 0:
		return C.int(n)
	case err == nil:
		return C.WOLFSSL_CBIO_ERR_WANT_READ
	case errors.Is(err, io.EOF):
		return C.WOLFSSL_CBIO_ERR_CONN_CLOSE
	default:
		return C.WOLFSSL_CBIO_ERR_GENERAL
	}
}

//export wolftlsSend
func wolftlsSend(h C.uintptr_t, buf *C.char, sz C.int) (ret C.int) {
	defer func() {
		if recover() != nil {
			ret = C.WOLFSSL_CBIO_ERR_GENERAL
		}
	}()
	n, err := connOf(h).raw.Write(unsafe.Slice((*byte)(unsafe.Pointer(buf)), int(sz)))
	if err != nil && n == 0 {
		return C.WOLFSSL_CBIO_ERR_GENERAL
	}
	return C.int(n)
}

//export wolftlsServerKey
func wolftlsServerKey(h C.uintptr_t, identity *C.char, suite C.int, key *C.uchar, max C.uint,
	lifetime *C.uint) (ret C.uint) {
	c := connOf(h)
	defer func() {
		if r := recover(); r != nil {
			c.keyErr, ret = fmt.Errorf("wolftls: Key: %v", r), 0
		}
	}()
	id := C.GoString(identity)
	if !isText(id) {
		// After refusing a session ticket, wolfSSL offers its octets as
		// an external identity. A PSK identity is UTF-8 text (RFC 4279
		// cl. 5.1): anything else is refused without asking Key.
		return 0
	}
	req := KeyRequest{Identity: id, RemoteAddr: c.raw.RemoteAddr()}
	if !is13(c.server.cfg.Version) {
		req.CipherSuite = uint16(suite)
	}
	k, err := c.server.cfg.Key(req)
	if err != nil {
		c.keyErr = err
		return 0
	}
	if len(k.PSK) == 0 || len(k.PSK) > int(max) {
		c.keyErr = fmt.Errorf("wolftls: PSK of %d octets", len(k.PSK))
		return 0
	}
	life := c.server.cfg.SessionLifetime
	if !k.Expiry.IsZero() {
		until := time.Until(k.Expiry)
		if until <= 0 {
			c.keyErr = errors.New("wolftls: key already expired")
			return 0
		}
		if life == 0 || until < life {
			life = until
		}
	}
	*lifetime = C.uint(life / time.Second)
	c.identity, c.peer, c.expiry = id, k.Peer, k.Expiry
	return C.uint(copy(unsafe.Slice((*byte)(unsafe.Pointer(key)), int(max)), k.PSK))
}

//export wolftlsClientKey
func wolftlsClientKey(h C.uintptr_t, hint *C.char, suite C.int, identity *C.char, idMax C.uint,
	key *C.uchar, keyMax C.uint) (ret C.uint) {
	c := connOf(h)
	defer func() {
		if r := recover(); r != nil {
			c.keyErr, ret = fmt.Errorf("wolftls: Key: %v", r), 0
		}
	}()
	// wolfSSL may ask more than once in one handshake (binders,
	// HelloRetryRequest): the key service is asked once per suite.
	k, ok := c.clientKey[uint16(suite)]
	if !ok {
		hintS := ""
		if hint != nil {
			hintS = C.GoString(hint)
		}
		id, psk, err := c.client.cfg.Key(hintS, uint16(suite))
		if err != nil {
			c.keyErr = err
			return 0
		}
		k = clientKey{identity: id, psk: append([]byte(nil), psk...)}
		if c.clientKey == nil {
			c.clientKey = make(map[uint16]clientKey)
		}
		c.clientKey[uint16(suite)] = k
	}
	if len(k.identity)+1 > int(idMax) || len(k.psk) == 0 || len(k.psk) > int(keyMax) {
		c.keyErr = fmt.Errorf("wolftls: identity of %d octets or PSK of %d octets", len(k.identity), len(k.psk))
		return 0
	}
	ids := unsafe.Slice((*byte)(unsafe.Pointer(identity)), int(idMax))
	ids[copy(ids, k.identity)] = 0
	c.identity = k.identity
	return C.uint(copy(unsafe.Slice((*byte)(unsafe.Pointer(key)), int(keyMax)), k.psk))
}

//export wolftlsGenCookie
func wolftlsGenCookie(h C.uintptr_t, buf *C.uchar, sz C.int) (ret C.int) {
	defer func() {
		if recover() != nil {
			ret = -1
		}
	}()
	c := connOf(h)
	mac := hmac.New(sha256.New, c.server.cookieSecret)
	mac.Write([]byte(c.raw.RemoteAddr().String()))
	return C.int(copy(unsafe.Slice((*byte)(unsafe.Pointer(buf)), int(sz)), mac.Sum(nil)))
}

//export wolftlsTicket
func wolftlsTicket(h C.uintptr_t, name, iv, mac *C.uchar, enc C.int, ticket *C.uchar, inLen C.int,
	outLen *C.int) (ret C.int) {
	defer func() {
		if recover() != nil {
			ret = C.WOLFSSL_TICKET_RET_REJECT
		}
	}()
	c := connOf(h)
	t := ticketIO{
		name:   (*[ticketNameSize]byte)(unsafe.Pointer(name)),
		iv:     (*[ticketIVSize]byte)(unsafe.Pointer(iv)),
		mac:    (*[ticketMACSize]byte)(unsafe.Pointer(mac)),
		ticket: unsafe.Slice((*byte)(unsafe.Pointer(ticket)), int(inLen)),
	}
	if enc != 0 {
		if err := c.server.tickets.seal(t, c); err != nil {
			return C.WOLFSSL_TICKET_RET_FATAL
		}
		*outLen = inLen
		return C.WOLFSSL_TICKET_RET_OK
	}
	if !c.server.tickets.open(t, c) {
		return C.WOLFSSL_TICKET_RET_REJECT
	}
	*outLen = inLen
	return C.WOLFSSL_TICKET_RET_OK
}

// isText reports whether s is UTF-8 without control characters.
func isText(s string) bool {
	if s == "" || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
