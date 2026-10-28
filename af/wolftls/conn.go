//go:build wolfssl

// Copyright 2026 Floriano Neto.
// Licensed under the GNU General Public License v3.0 or later; see COPYING.

package wolftls

/*
#include "shim.h"
*/
import "C"

import (
	"errors"
	"io"
	"net"
	"os"
	"runtime/cgo"
	"sync"
	"time"
	"unsafe"
)

const (
	// bufSize is the size of the C buffers of Read and Write: one TLS
	// record of plaintext.
	bufSize = 16 << 10
	// maxBuffered bounds what the pump reads ahead of wolfSSL.
	maxBuffered = 256 << 10
	// closeTimeout bounds the close_notify sent by Close.
	closeTimeout = 2 * time.Second
	// dtlsMTU is the path MTU given to wolfSSL for DTLS: below the MTU of
	// the GTP tunnel of the user plane; a PSK handshake fits with room.
	dtlsMTU = 1200
	// maxQueued bounds the datagrams queued for wolfSSL in DTLS.
	maxQueued = 64
)

// ConnState describes an established connection.
type ConnState struct {
	Version     uint16
	CipherSuite uint16
	// Identity is the PSK identity of the full handshake, also on a
	// resumed connection of a server.
	Identity string
	Resumed  bool
	// Peer is the Key.Peer of the server's Key function.
	Peer any
	// Expiry is the Key.Expiry of the server's Key function.
	Expiry time.Time
}

// Conn is a TLS or DTLS connection over a net.Conn. wolfSSL never blocks:
// it reads from a buffer that a goroutine (the pump) fills from the
// net.Conn, and a call that finds the buffer empty waits outside the lock of
// the connection. Read and Write may therefore run at the same time, as
// net/http does. In DTLS the buffer keeps datagrams apart, each Read
// returns one record, and the wait follows the retransmission timer of
// wolfSSL during the handshake.
type Conn struct {
	raw    net.Conn
	server *Server
	client *Client
	dtls   bool
	handle cgo.Handle

	hsMu  sync.Mutex
	hsRun bool
	hsErr error

	// mu guards ssl, the C buffers and the fields below it. The callbacks
	// run inside wolfSSL calls made with mu held, so they never take it.
	mu         sync.Mutex
	ssl        *C.WOLFSSL
	rbuf, wbuf unsafe.Pointer
	setupErr   error
	done       bool // handshake completed
	identity   string
	peer       any
	expiry     time.Time
	resumed    bool
	keyErr     error
	clientKey  map[uint16]clientKey
	expire     *time.Timer

	in       inbox
	readDL   deadline
	closeErr error
	once     sync.Once
}

type clientKey struct {
	identity string
	psk      []byte
}

func newConn(raw net.Conn, ctx *C.WOLFSSL_CTX, s *Server, c *Client, dtls bool) *Conn {
	conn := &Conn{raw: raw, server: s, client: c, dtls: dtls}
	conn.in.init(dtls)
	conn.readDL.init()
	conn.handle = cgo.NewHandle(conn)
	conn.ssl = C.wolfSSL_new(ctx)
	if conn.ssl == nil {
		conn.setupErr = errors.New("wolftls: wolfSSL_new failed")
	} else {
		C.wolftls_attach(conn.ssl, C.uintptr_t(conn.handle))
		if dtls {
			C.wolfSSL_dtls_set_using_nonblock(conn.ssl, 1)
			C.wolfSSL_dtls_set_mtu(conn.ssl, dtlsMTU)
		}
		conn.rbuf = C.malloc(bufSize)
		conn.wbuf = C.malloc(bufSize)
	}
	go conn.in.pump(raw)
	return conn
}

// Handshake runs the handshake once; later calls return its result.
func (c *Conn) Handshake() error {
	c.hsMu.Lock()
	defer c.hsMu.Unlock()
	if !c.hsRun {
		c.hsRun = true
		c.hsErr = c.handshake()
		if c.hsErr != nil {
			c.wipeClientKeys()
		}
	}
	return c.hsErr
}

func (c *Conn) handshake() error {
	c.mu.Lock()
	err := c.setupErr
	c.mu.Unlock()
	if err != nil {
		return err
	}
	for {
		wake := c.in.notified()
		if err := c.readDL.check(); err != nil {
			return err
		}
		c.mu.Lock()
		if c.ssl == nil {
			c.mu.Unlock()
			return net.ErrClosed
		}
		var ret C.int
		if c.client != nil {
			ret = C.wolfSSL_connect(c.ssl)
		} else {
			ret = C.wolfSSL_accept(c.ssl)
		}
		if ret == C.WOLFSSL_SUCCESS {
			c.established()
			c.mu.Unlock()
			return nil
		}
		code := C.wolfSSL_get_error(c.ssl, ret)
		var hsErr error
		if code != C.WOLFSSL_ERROR_WANT_READ {
			hsErr = c.errorLocked("handshake", code)
		}
		timer := c.retransmitTimer(true)
		c.mu.Unlock()
		if hsErr != nil {
			return hsErr
		}
		if err := c.waitRead(wake, timer); err != nil {
			return err
		}
	}
}

// retransmitTimer returns the time to wait before wolfSSL retransmits its
// last DTLS flight, zero when nothing waits for it: TLS, or DTLS after the
// handshake with nothing unacknowledged. mu is held.
func (c *Conn) retransmitTimer(handshake bool) time.Duration {
	if !c.dtls || c.ssl == nil {
		return 0
	}
	if !handshake && C.wolfSSL_dtls13_has_pending_msg(c.ssl) != 1 {
		return 0
	}
	secs := C.wolfSSL_dtls_get_current_timeout(c.ssl)
	if secs <= 0 {
		secs = 1
	}
	return time.Duration(secs) * time.Second
}

// retransmit tells wolfSSL that its DTLS timer expired: it sends its last
// flight again, or gives up after its last retry.
func (c *Conn) retransmit() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ssl == nil {
		return net.ErrClosed
	}
	if C.wolfSSL_dtls_got_timeout(c.ssl) != C.WOLFSSL_SUCCESS {
		return &Error{Op: "handshake", Text: "no answer from the peer after the last retransmission", Cause: c.keyErr}
	}
	return nil
}

// established records the end of a successful handshake. mu is held.
func (c *Conn) established() {
	c.done = true
	c.wipeClientKeys()
	if C.wolfSSL_session_reused(c.ssl) == 1 {
		c.resumed = true
	}
	if c.server == nil || c.expiry.IsZero() {
		return
	}
	c.expire = time.AfterFunc(time.Until(c.expiry), func() {
		if c.server.cfg.Expired != nil {
			c.server.cfg.Expired(c)
		}
		c.Close()
	})
}

func (c *Conn) wipeClientKeys() {
	for _, k := range c.clientKey {
		clear(k.psk)
	}
	c.clientKey = nil
}

// Read reads application data.
func (c *Conn) Read(p []byte) (int, error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}
	if len(p) == 0 {
		return 0, nil
	}
	for {
		wake := c.in.notified()
		if err := c.readDL.check(); err != nil {
			return 0, err
		}
		c.mu.Lock()
		if c.ssl == nil {
			c.mu.Unlock()
			return 0, net.ErrClosed
		}
		ret := C.wolfSSL_read(c.ssl, c.rbuf, C.int(min(len(p), bufSize)))
		if ret > 0 {
			n := copy(p, unsafe.Slice((*byte)(c.rbuf), int(ret)))
			c.mu.Unlock()
			return n, nil
		}
		code := C.wolfSSL_get_error(c.ssl, ret)
		var err error
		switch {
		case code == C.WOLFSSL_ERROR_WANT_READ:
		case code == C.WOLFSSL_ERROR_ZERO_RETURN:
			err = io.EOF
		case errors.Is(c.in.failure(), io.EOF):
			err = io.ErrUnexpectedEOF
		default:
			err = c.errorLocked("read", code)
		}
		timer := c.retransmitTimer(false)
		c.mu.Unlock()
		if err != nil {
			return 0, err
		}
		if err := c.waitRead(wake, timer); err != nil {
			return 0, err
		}
	}
}

// Write writes application data.
func (c *Conn) Write(p []byte) (int, error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for n < len(p) {
		if c.ssl == nil {
			return n, net.ErrClosed
		}
		chunk := min(len(p)-n, bufSize)
		copy(unsafe.Slice((*byte)(c.wbuf), chunk), p[n:n+chunk])
		ret := C.wolfSSL_write(c.ssl, c.wbuf, C.int(chunk))
		if ret <= 0 {
			return n, c.errorLocked("write", C.wolfSSL_get_error(c.ssl, ret))
		}
		n += int(ret)
	}
	return n, nil
}

// Close sends close_notify after a completed handshake and closes the
// underlying connection.
func (c *Conn) Close() error {
	c.once.Do(func() {
		_ = c.raw.SetWriteDeadline(time.Now().Add(closeTimeout))
		c.mu.Lock()
		if c.expire != nil {
			c.expire.Stop()
		}
		if c.ssl != nil {
			if c.done {
				C.wolfSSL_shutdown(c.ssl)
			}
			C.wolfSSL_free(c.ssl)
			c.ssl = nil
			C.free(c.rbuf)
			C.free(c.wbuf)
		}
		c.wipeClientKeys()
		c.mu.Unlock()
		c.closeErr = c.raw.Close()
		c.in.stop()
		c.handle.Delete()
	})
	return c.closeErr
}

// State returns the state of the connection after the handshake.
func (c *Conn) State() ConnState {
	c.mu.Lock()
	defer c.mu.Unlock()
	st := ConnState{Identity: c.identity, Resumed: c.resumed, Peer: c.peer, Expiry: c.expiry}
	if c.ssl != nil && c.done {
		st.Version = uint16(C.wolfSSL_version(c.ssl))
		st.CipherSuite = uint16(C.wolfSSL_get_current_cipher_suite(c.ssl))
	}
	return st
}

// Session returns the session of a client connection, to resume it with a
// later one. In TLS 1.3 the session ticket arrives after the handshake:
// call it after reading from the connection.
func (c *Conn) Session() *Session {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client == nil || c.ssl == nil || !c.done {
		return nil
	}
	s := C.wolfSSL_get1_session(c.ssl)
	if s == nil {
		return nil
	}
	return &Session{s: s}
}

func (c *Conn) LocalAddr() net.Addr  { return c.raw.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr { return c.raw.RemoteAddr() }

func (c *Conn) SetDeadline(t time.Time) error {
	c.readDL.set(t)
	return c.raw.SetWriteDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	c.readDL.set(t)
	return nil
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.raw.SetWriteDeadline(t)
}

// waitRead waits for data, the read deadline or, when timer is not zero,
// the DTLS retransmission timer.
func (c *Conn) waitRead(wake <-chan struct{}, timer time.Duration) error {
	var expired <-chan time.Time
	if timer > 0 {
		t := time.NewTimer(timer)
		defer t.Stop()
		expired = t.C
	}
	select {
	case <-wake:
		return nil
	case <-c.readDL.wait():
		return os.ErrDeadlineExceeded
	case <-expired:
		return c.retransmit()
	}
}

// errorLocked builds the error of a failed wolfSSL call. mu is held.
func (c *Conn) errorLocked(op string, code C.int) error {
	var buf [80]C.char
	C.wolftls_error_string(code, &buf[0], C.int(len(buf)))
	return &Error{Op: op, Code: int(code), Text: C.GoString(&buf[0]), Cause: c.keyErr}
}

// inbox holds what the pump read from the underlying connection and
// wolfSSL has not consumed yet: a stream of octets in TLS, a queue of
// datagrams in DTLS.
type inbox struct {
	mu        sync.Mutex
	room      *sync.Cond
	datagrams bool
	buf       []byte
	queue     [][]byte
	err       error         // end or failure of the underlying connection
	notify    chan struct{} // closed and replaced when buf, queue or err change
	halt      bool
}

func (b *inbox) init(datagrams bool) {
	b.room = sync.NewCond(&b.mu)
	b.notify = make(chan struct{})
	b.datagrams = datagrams
}

func (b *inbox) pump(r io.Reader) {
	tmp := make([]byte, bufSize)
	for {
		b.mu.Lock()
		for (len(b.buf) >= maxBuffered || len(b.queue) >= maxQueued) && !b.halt {
			b.room.Wait()
		}
		halt := b.halt
		b.mu.Unlock()
		if halt {
			return
		}
		n, err := r.Read(tmp)
		b.mu.Lock()
		if b.datagrams {
			if n > 0 {
				b.queue = append(b.queue, append([]byte(nil), tmp[:n]...))
			}
		} else {
			b.buf = append(b.buf, tmp[:n]...)
		}
		if err != nil && b.err == nil {
			b.err = err
		}
		b.wake()
		b.mu.Unlock()
		if err != nil {
			return
		}
	}
}

// take moves buffered octets into p: in DTLS, one datagram, cut to p if
// longer. Nothing buffered: 0 and the failure of the underlying connection,
// nil while it is open.
func (b *inbox) take(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.datagrams {
		if len(b.queue) == 0 {
			return 0, b.err
		}
		n := copy(p, b.queue[0])
		b.queue[0] = nil
		b.queue = b.queue[1:]
		b.room.Signal()
		return n, nil
	}
	if len(b.buf) == 0 {
		return 0, b.err
	}
	n := copy(p, b.buf)
	b.buf = b.buf[:copy(b.buf, b.buf[n:])]
	b.room.Signal()
	return n, nil
}

func (b *inbox) notified() <-chan struct{} {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.notify
}

func (b *inbox) failure() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.err
}

func (b *inbox) stop() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.halt = true
	if b.err == nil {
		b.err = net.ErrClosed
	}
	b.room.Broadcast()
	b.wake()
}

// wake signals a change. mu is held.
func (b *inbox) wake() {
	close(b.notify)
	b.notify = make(chan struct{})
}

// deadline is a read deadline: a channel closed when it passes.
type deadline struct {
	mu     sync.Mutex
	timer  *time.Timer
	passed chan struct{}
}

func (d *deadline) init() {
	d.passed = make(chan struct{})
}

func (d *deadline) set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil && !d.timer.Stop() {
		<-d.passed // the timer fired: wait until it closed the channel
	}
	d.timer = nil
	closed := isClosed(d.passed)
	if t.IsZero() {
		if closed {
			d.passed = make(chan struct{})
		}
		return
	}
	if dur := time.Until(t); dur > 0 {
		if closed {
			d.passed = make(chan struct{})
		}
		ch := d.passed
		d.timer = time.AfterFunc(dur, func() { close(ch) })
		return
	}
	if !closed {
		close(d.passed)
	}
}

func (d *deadline) wait() <-chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.passed
}

func (d *deadline) check() error {
	if isClosed(d.wait()) {
		return os.ErrDeadlineExceeded
	}
	return nil
}

func isClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}
