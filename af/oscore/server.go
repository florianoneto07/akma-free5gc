package oscore

import (
	"bytes"
	"crypto/rand"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/florianoneto07/akma-free5gc/af/coap"
)

// Entry is a security context of a server and what the application keeps
// with it.
type Entry struct {
	Context *Context
	// Group gathers the contexts that Limits.MaxPerGroup bounds together.
	Group string
	// Expiry is when the context is removed.
	Expiry time.Time
	Data   any

	created time.Time
	pending bool // no request verified with it yet
}

// Limits bound the state of a Server.
type Limits struct {
	MaxContexts int
	// MaxPerGroup keeps the newest contexts of a group.
	MaxPerGroup int
	// PendingLifetime removes a context with which no request was verified,
	// and the R2 of Appendix B.2 not used.
	PendingLifetime time.Duration
}

// RenewalNonceSize is the length of R2, and of R1 and R3 at the client
// (Appendix B.2: "typically, at least 8 bytes long").
const RenewalNonceSize = 8

// Server keeps the security contexts of a server by Recipient ID and
// verifies and protects the messages of each (RFC 8613 cl. 8.2, 8.3). It
// answers the protocol of Appendix B.2 to derive new contexts. Its methods
// are safe for concurrent use.
type Server struct {
	// Renewed, if set, is called when the protocol of Appendix B.2 gives
	// the context of an entry a new ID Context: c is the new context.
	Renewed func(e *Entry, c *Context)

	limits  Limits
	now     func() time.Time
	mu      sync.Mutex
	entries map[string]*Entry // by Recipient ID
	r2      map[string]r2Use  // by R2
}

type r2Use struct {
	kid     string
	created time.Time
}

// NewServer returns a server; now is the clock, time.Now when nil.
func NewServer(l Limits, now func() time.Time) *Server {
	if now == nil {
		now = time.Now
	}
	return &Server{limits: l, now: now, entries: make(map[string]*Entry), r2: make(map[string]r2Use)}
}

// ErrFull reports a server at Limits.MaxContexts.
var ErrFull = errors.New("oscore: no room for another security context")

// ErrIDInUse reports a Recipient ID that another context has.
var ErrIDInUse = errors.New("oscore: Recipient ID in use")

// InUse reports whether a context has the Recipient ID id.
func (s *Server) InUse(id []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.entries[string(id)]
	return ok
}

// Add keeps a new context, pending until a request verifies with it. The
// oldest contexts of its group beyond MaxPerGroup are removed.
func (s *Server) Add(e *Entry) error {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	rid := string(e.Context.p.RecipientID)
	if _, ok := s.entries[rid]; ok {
		return ErrIDInUse
	}
	s.pruneLocked(now)
	if len(s.entries) >= s.limits.MaxContexts {
		return ErrFull
	}
	e.created, e.pending = now, true
	s.entries[rid] = e
	var group []*Entry
	for _, o := range s.entries {
		if o.Group == e.Group {
			group = append(group, o)
		}
	}
	if len(group) > s.limits.MaxPerGroup {
		slices.SortFunc(group, func(a, b *Entry) int { return a.created.Compare(b.created) })
		for _, o := range group[:len(group)-s.limits.MaxPerGroup] {
			delete(s.entries, string(o.Context.p.RecipientID))
		}
	}
	return nil
}

// Remove removes the contexts for which drop is true and returns them.
func (s *Server) Remove(drop func(*Entry) bool) []*Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*Entry
	for id, e := range s.entries {
		if drop(e) {
			delete(s.entries, id)
			out = append(out, e)
		}
	}
	return out
}

// Prune removes the expired contexts, the pending ones older than
// PendingLifetime, and the old R2, and returns the removed contexts.
func (s *Server) Prune() []*Entry {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pruneLocked(now)
}

func (s *Server) pruneLocked(now time.Time) []*Entry {
	var out []*Entry
	for id, e := range s.entries {
		if !now.Before(e.Expiry) || (e.pending && now.Sub(e.created) > s.limits.PendingLifetime) {
			delete(s.entries, id)
			out = append(out, e)
		}
	}
	for r, u := range s.r2 {
		if now.Sub(u.created) > s.limits.PendingLifetime {
			delete(s.r2, r)
		}
	}
	return out
}

// Len returns the number of contexts.
func (s *Server) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// Handle processes a request with the OSCORE option: it finds the context
// by the 'kid', verifies the request, calls handle with the decrypted
// request, and returns the protected response, or the unprotected error of
// RFC 8613 cl. 8.2. A 'kid context' other than the ID Context of the
// context starts or ends the protocol of Appendix B.2.
func (s *Server) Handle(m *coap.Message, handle func(*coap.Message, *Entry) *coap.Message) *coap.Message {
	opt, ok, err := optionOf(m)
	if !ok {
		return ErrorResponse(ErrDecode)
	}
	if err != nil {
		return ErrorResponse(err)
	}
	if !opt.HasKID || len(opt.PartialIV) == 0 {
		return ErrorResponse(ErrDecode)
	}
	now := s.now()
	s.mu.Lock()
	e, ok := s.entries[string(opt.KID)]
	if ok && !now.Before(e.Expiry) {
		delete(s.entries, string(opt.KID))
		ok = false
	}
	var ctx *Context
	if ok {
		ctx = e.Context
	}
	s.mu.Unlock()
	if !ok {
		return ErrorResponse(ErrNoContext)
	}

	if opt.HasKIDContext && !sameIDContext(ctx, opt.KIDContext) {
		return s.renew(m, opt, e, ctx, handle)
	}
	in, r, err := ctx.VerifyRequest(m, opt)
	if err != nil {
		return ErrorResponse(err)
	}
	s.mu.Lock()
	e.pending = false
	s.mu.Unlock()
	out, err := ctx.ProtectResponse(r, handle(in, e), false, nil)
	if err != nil {
		return &coap.Message{Code: coap.InternalServerError}
	}
	return out
}

func sameIDContext(c *Context, kidContext []byte) bool {
	return c.p.IDContext != nil && bytes.Equal(c.p.IDContext, kidContext)
}

// renew runs the server side of Appendix B.2. A 'kid context' that starts
// with an R2 this server sent is request #2 (step 4): the context with that
// ID Context replaces the current one, and the request is processed. Any
// other is request #1 (step 2): verified with ID Context ID1, it gets a 4.01
// protected with ID Context R2 || ID1, with R2 in the 'kid context'.
func (s *Server) renew(m *coap.Message, opt Option, e *Entry, base *Context,
	handle func(*coap.Message, *Entry) *coap.Message) *coap.Message {
	kc := opt.KIDContext
	if len(kc) > RenewalNonceSize {
		s.mu.Lock()
		u, ok := s.r2[string(kc[:RenewalNonceSize])]
		s.mu.Unlock()
		if ok && u.kid == string(opt.KID) {
			ctx3, err := base.WithIDContext(kc)
			if err != nil {
				return ErrorResponse(ErrDecode)
			}
			in, r, err := ctx3.VerifyRequest(m, opt)
			if err != nil {
				return ErrorResponse(err)
			}
			s.mu.Lock()
			_, still := s.r2[string(kc[:RenewalNonceSize])]
			delete(s.r2, string(kc[:RenewalNonceSize]))
			if still && s.entries[string(opt.KID)] == e {
				e.Context, e.pending = ctx3, false
			}
			s.mu.Unlock()
			if !still {
				return ErrorResponse(ErrReplay) // request #2 seen before
			}
			if s.Renewed != nil {
				s.Renewed(e, ctx3)
			}
			out, err := ctx3.ProtectResponse(r, handle(in, e), false, nil)
			if err != nil {
				return &coap.Message{Code: coap.InternalServerError}
			}
			return out
		}
	}
	ctx1, err := base.WithIDContext(kc)
	if err != nil {
		return ErrorResponse(ErrDecode)
	}
	_, r, err := ctx1.VerifyRequest(m, opt)
	if err != nil {
		return ErrorResponse(err)
	}
	r2 := make([]byte, RenewalNonceSize)
	if _, err := rand.Read(r2); err != nil {
		return &coap.Message{Code: coap.InternalServerError}
	}
	ctx2, err := base.WithIDContext(append(slices.Clone(r2), kc...))
	if err != nil {
		return ErrorResponse(ErrDecode)
	}
	s.mu.Lock()
	n := 0
	for _, u := range s.r2 {
		if u.kid == string(opt.KID) {
			n++
		}
	}
	full := n >= s.limits.MaxPerGroup || len(s.r2) >= s.limits.MaxContexts
	if !full {
		s.r2[string(r2)] = r2Use{kid: string(opt.KID), created: s.now()}
	}
	s.mu.Unlock()
	if full {
		return &coap.Message{Code: coap.ServiceUnavailable}
	}
	// A context other than the one of the request: the response carries a
	// Partial IV (RFC 8613 cl. 8.3).
	out, err := ctx2.ProtectResponse(r, &coap.Message{Code: coap.Unauthorized}, true, r2)
	if err != nil {
		return &coap.Message{Code: coap.InternalServerError}
	}
	return out
}

// ErrorResponse is the unprotected error response of RFC 8613 cl. 8.2 for
// err: an Outer Max-Age of zero and a diagnostic payload.
func ErrorResponse(err error) *coap.Message {
	code, diag := coap.BadOption, "Failed to decode COSE"
	switch {
	case errors.Is(err, ErrNoContext):
		code, diag = coap.Unauthorized, "Security context not found"
	case errors.Is(err, ErrReplay):
		code, diag = coap.Unauthorized, "Replay detected"
	case errors.Is(err, ErrDecrypt):
		code, diag = coap.BadRequest, "Decryption failed"
	}
	m := &coap.Message{Code: code, Payload: []byte(diag)}
	m.Add(coap.OptionMaxAge, []byte{})
	return m
}
