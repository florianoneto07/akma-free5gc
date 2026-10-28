package coap

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"time"
)

// Transmission parameters (RFC 7252 cl. 4.8).
const (
	AckTimeout       = 2 * time.Second
	AckRandomFactor  = 1.5
	MaxRetransmit    = 4
	ExchangeLifetime = 247 * time.Second
)

// ErrReset reports a Reset answer to a confirmable request.
var ErrReset = errors.New("coap: request reset by the server")

// ErrTimeout reports a confirmable request left unanswered after the last
// retransmission.
var ErrTimeout = errors.New("coap: no acknowledgement after the last retransmission")

// Client sends confirmable requests over one datagram connection, such as
// a DTLS association, and takes the response piggybacked in the
// acknowledgement (RFC 7252 cl. 5.2.1).
type Client struct {
	conn net.Conn
	mu   sync.Mutex
	mid  uint16
}

// NewClient returns a client over conn. Each Read of conn returns one
// message.
func NewClient(conn net.Conn) *Client {
	var b [2]byte
	_, _ = rand.Read(b[:])
	return &Client{conn: conn, mid: binary.BigEndian.Uint16(b[:])}
}

// Do sends req as a confirmable message with a new message ID and a random
// token, retransmits it with exponential back-off until the acknowledgement
// comes (RFC 7252 cl. 4.2), and returns the response.
func (c *Client) Do(ctx context.Context, req *Message) (*Message, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.mid++
	req.Type, req.MessageID = Confirmable, c.mid
	if req.Token == nil {
		req.Token = make([]byte, 8)
		if _, err := rand.Read(req.Token); err != nil {
			return nil, err
		}
	}
	out, err := req.Marshal()
	if err != nil {
		return nil, err
	}
	timeout := initialTimeout()
	buf := make([]byte, 2048)
	for attempt := 0; ; attempt++ {
		if _, err := c.conn.Write(out); err != nil {
			return nil, err
		}
		deadline := time.Now().Add(timeout)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		for {
			_ = c.conn.SetReadDeadline(deadline)
			n, err := c.conn.Read(buf)
			if err != nil {
				if errors.Is(err, os.ErrDeadlineExceeded) {
					break
				}
				return nil, err
			}
			rsp, err := Parse(buf[:n])
			if err != nil || rsp.MessageID != req.MessageID {
				continue // not the answer to this request
			}
			switch {
			case rsp.Type == Reset:
				return nil, ErrReset
			case rsp.Type == Acknowledgement && rsp.Code != Empty:
				if string(rsp.Token) != string(req.Token) {
					return nil, fmt.Errorf("%w: token of the response differs", ErrFormat)
				}
				_ = c.conn.SetReadDeadline(time.Time{})
				return rsp, nil
			default:
				return nil, fmt.Errorf("coap: answer %d %s is not a piggybacked response", rsp.Type, rsp.Code)
			}
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if attempt == MaxRetransmit {
			return nil, ErrTimeout
		}
		timeout *= 2
	}
}

// initialTimeout is a random time between AckTimeout and AckTimeout times
// AckRandomFactor (RFC 7252 cl. 4.2).
func initialTimeout() time.Duration {
	span := int64(float64(AckTimeout) * (AckRandomFactor - 1))
	r, err := rand.Int(rand.Reader, big.NewInt(span))
	if err != nil {
		return AckTimeout
	}
	return AckTimeout + time.Duration(r.Int64())
}

// Responder answers the confirmable requests of one peer in the
// acknowledgement, and answers a retransmitted request with the same
// response (RFC 7252 cl. 4.2, 4.5).
type Responder struct {
	mu   sync.Mutex
	seen map[uint16]seenResponse
}

type seenResponse struct {
	data []byte
	at   time.Time
}

// Answer returns the datagram to send for the datagram in, or nil for none.
// handle computes the response to a new request; its Type, MessageID and
// Token are set here.
func (r *Responder) Answer(in []byte, now time.Time, handle func(*Message) *Message) []byte {
	req, err := Parse(in)
	if err != nil {
		// A confirmable message that cannot be processed is rejected
		// (RFC 7252 cl. 4.2).
		if len(in) >= 4 && in[0]>>6 == 1 && Type(in[0]>>4&3) == Confirmable {
			rst, _ := (&Message{Type: Reset, MessageID: binary.BigEndian.Uint16(in[2:])}).Marshal()
			return rst
		}
		return nil
	}
	switch {
	case req.Type == Confirmable && req.Code == Empty:
		// "CoAP ping" (RFC 7252 cl. 4.3).
		rst, _ := (&Message{Type: Reset, MessageID: req.MessageID}).Marshal()
		return rst
	case req.Type != Confirmable && req.Type != NonConfirmable, !req.Code.IsRequest():
		return nil
	}
	r.mu.Lock()
	if r.seen == nil {
		r.seen = make(map[uint16]seenResponse)
	}
	for id, s := range r.seen {
		if now.Sub(s.at) > ExchangeLifetime {
			delete(r.seen, id)
		}
	}
	if s, ok := r.seen[req.MessageID]; ok && req.Type == Confirmable {
		r.mu.Unlock()
		return s.data
	}
	r.mu.Unlock()

	rsp := handle(req)
	if req.Type == Confirmable {
		rsp.Type = Acknowledgement
	} else {
		rsp.Type = NonConfirmable
	}
	rsp.MessageID, rsp.Token = req.MessageID, req.Token
	out, err := rsp.Marshal()
	if err != nil {
		out, _ = (&Message{Type: rsp.Type, Code: InternalServerError, MessageID: req.MessageID, Token: req.Token}).Marshal()
	}
	if req.Type == Confirmable {
		r.mu.Lock()
		r.seen[req.MessageID] = seenResponse{data: out, at: now}
		r.mu.Unlock()
	}
	return out
}
