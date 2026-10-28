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
	"net"
	"sync"
	"time"
	"unsafe"
)

const (
	// maxPeers bounds the associations of a DTLS listener, open or in
	// handshake.
	maxPeers = 1024
	// acceptBacklog bounds the associations waiting for Accept.
	acceptBacklog = 64
)

// ListenDTLS returns a listener whose connections are the DTLS
// associations of the clients of pc, one per client address. The listener
// owns pc and closes it.
func (s *Server) ListenDTLS(pc *net.UDPConn) (net.Listener, error) {
	if !isDTLS(s.cfg.Version) {
		return nil, errors.New("wolftls: ListenDTLS needs a DTLS server")
	}
	l := &dtlsListener{s: s, pc: pc, peers: make(map[string]*dtlsPeer),
		accept: make(chan *Conn, acceptBacklog), closed: make(chan struct{})}
	go l.loop()
	return l, nil
}

// dtlsListener reads the datagrams of every client from one UDP socket and
// hands each to the association of its source address.
type dtlsListener struct {
	s      *Server
	pc     *net.UDPConn
	accept chan *Conn
	closed chan struct{}
	once   sync.Once

	mu    sync.Mutex
	peers map[string]*dtlsPeer
}

func (l *dtlsListener) loop() {
	buf := make([]byte, 64<<10)
	for {
		n, addr, err := l.pc.ReadFromUDP(buf)
		if err != nil {
			l.Close()
			return
		}
		p, conn := l.peer(addr)
		if p == nil {
			continue
		}
		select {
		case p.queue <- append([]byte(nil), buf[:n]...):
		default: // the association does not keep up: the datagram is lost
		}
		if conn != nil {
			select {
			case l.accept <- conn:
			default:
				conn.Close()
			}
		}
	}
}

// peer returns the association of addr, and the new connection when it is
// new. A new association binds the cookies of wolfSSL to addr (RFC 9147
// cl. 5.1; RFC 6347 cl. 4.2.1).
func (l *dtlsListener) peer(addr *net.UDPAddr) (*dtlsPeer, *Conn) {
	key := addr.String()
	l.mu.Lock()
	defer l.mu.Unlock()
	if p, ok := l.peers[key]; ok {
		return p, nil
	}
	if len(l.peers) >= maxPeers {
		return nil, nil
	}
	p := &dtlsPeer{l: l, addr: addr, key: key, queue: make(chan []byte, maxQueued), closed: make(chan struct{})}
	conn := newConn(p, l.s.ctx, l.s, nil, true)
	if conn.ssl != nil {
		ip := addr.IP.To4()
		if ip == nil {
			ip = addr.IP.To16()
		}
		if C.wolftls_dtls_peer(conn.ssl, (*C.uchar)(unsafe.Pointer(&ip[0])), C.int(len(ip)), C.int(addr.Port),
			cBool(is13(l.s.cfg.Version))) != 0 {
			conn.setupErr = errors.New("wolftls: DTLS peer address not set")
		}
	}
	l.peers[key] = p
	return p, conn
}

func (l *dtlsListener) remove(p *dtlsPeer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.peers[p.key] == p {
		delete(l.peers, p.key)
	}
}

func (l *dtlsListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.accept:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *dtlsListener) Close() error {
	l.once.Do(func() {
		close(l.closed)
		l.pc.Close()
		l.mu.Lock()
		peers := make([]*dtlsPeer, 0, len(l.peers))
		for _, p := range l.peers {
			peers = append(peers, p)
		}
		l.mu.Unlock()
		for _, p := range peers {
			p.Close()
		}
	})
	return nil
}

func (l *dtlsListener) Addr() net.Addr { return l.pc.LocalAddr() }

// dtlsPeer is the net.Conn of one client address on the shared socket:
// Read returns its datagrams, Write sends to it.
type dtlsPeer struct {
	l      *dtlsListener
	addr   *net.UDPAddr
	key    string
	queue  chan []byte
	closed chan struct{}
	once   sync.Once
}

func (p *dtlsPeer) Read(b []byte) (int, error) {
	select {
	case d := <-p.queue:
		return copy(b, d), nil
	case <-p.closed:
		return 0, net.ErrClosed
	}
}

func (p *dtlsPeer) Write(b []byte) (int, error) {
	select {
	case <-p.closed:
		return 0, net.ErrClosed
	default:
	}
	return p.l.pc.WriteToUDP(b, p.addr)
}

// Close forgets the association: a later datagram from the same address
// starts a new one.
func (p *dtlsPeer) Close() error {
	p.once.Do(func() {
		close(p.closed)
		p.l.remove(p)
	})
	return nil
}

func (p *dtlsPeer) LocalAddr() net.Addr  { return p.l.pc.LocalAddr() }
func (p *dtlsPeer) RemoteAddr() net.Addr { return p.addr }

// The deadlines of a Conn are kept by the Conn itself; a send on UDP does
// not wait.
func (p *dtlsPeer) SetDeadline(time.Time) error      { return nil }
func (p *dtlsPeer) SetReadDeadline(time.Time) error  { return nil }
func (p *dtlsPeer) SetWriteDeadline(time.Time) error { return nil }
