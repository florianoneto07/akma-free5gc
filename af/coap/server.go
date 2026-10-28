package coap

import (
	"net"
	"sync"
	"time"
)

// Server answers CoAP requests on a UDP socket. The datagrams of each
// source address go to a Responder of their own, one at a time and in
// order, so that a retransmitted confirmable request gets the response
// already sent (RFC 7252 cl. 4.5), also when handle takes longer than the
// retransmission timer.
type Server struct {
	// Handle computes the response to a request from the address from.
	Handle func(req *Message, from net.Addr) *Message
	// MaxPeers bounds the source addresses served at once; 1024 if zero.
	MaxPeers int
}

const (
	defaultMaxPeers = 1024
	peerQueue       = 64
	maxDatagram     = 1 << 16
)

type peer struct {
	in chan []byte
}

// Serve reads requests from pc until reading fails, as when pc is closed,
// and returns that error.
func (s *Server) Serve(pc net.PacketConn) error {
	maxPeers := s.MaxPeers
	if maxPeers == 0 {
		maxPeers = defaultMaxPeers
	}
	var (
		mu    sync.Mutex
		peers = make(map[string]*peer)
		wg    sync.WaitGroup
	)
	done := make(chan struct{})
	defer func() {
		close(done)
		wg.Wait()
	}()
	buf := make([]byte, maxDatagram)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return err
		}
		d := append([]byte(nil), buf[:n]...)
		key := from.String()
		mu.Lock()
		p, ok := peers[key]
		if !ok {
			if len(peers) >= maxPeers {
				mu.Unlock()
				continue
			}
			p = &peer{in: make(chan []byte, peerQueue)}
			peers[key] = p
			wg.Add(1)
			go func() {
				defer wg.Done()
				s.serve(pc, from, p, done, func() bool {
					mu.Lock()
					defer mu.Unlock()
					if len(p.in) > 0 {
						return false // a datagram came meanwhile
					}
					delete(peers, key)
					return true
				})
			}()
		}
		select {
		case p.in <- d:
		default: // queue full: dropped, as on a congested network
		}
		mu.Unlock()
	}
}

// serve answers the datagrams of one address until it has been idle for
// ExchangeLifetime, the time a Responder keeps its responses.
func (s *Server) serve(pc net.PacketConn, from net.Addr, p *peer, done <-chan struct{}, leave func() bool) {
	var r Responder
	idle := time.NewTimer(ExchangeLifetime)
	defer idle.Stop()
	for {
		select {
		case <-done:
			return
		case d := <-p.in:
			out := r.Answer(d, time.Now(), func(m *Message) *Message { return s.Handle(m, from) })
			if out != nil {
				_, _ = pc.WriteTo(out, from)
			}
			idle.Reset(ExchangeLifetime)
		case <-idle.C:
			if leave() {
				return
			}
			idle.Reset(ExchangeLifetime)
		}
	}
}
