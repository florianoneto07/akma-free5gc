package oscore

import (
	"context"
	"crypto/rand"
	"fmt"
	"slices"
	"sync"

	"github.com/florianoneto07/akma-free5gc/af/coap"
)

// Client sends requests protected with one security context.
type Client struct {
	coap *coap.Client
	mu   sync.Mutex
	ctx  *Context
}

// NewClient returns a client that sends its requests over c with the
// context ctx.
func NewClient(c *coap.Client, ctx *Context) *Client {
	return &Client{coap: c, ctx: ctx}
}

// Context returns the current security context.
func (c *Client) Context() *Context {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ctx
}

// UnprotectedError is a response without the OSCORE option, as the server
// answers a request it could not verify (RFC 8613 cl. 8.2).
type UnprotectedError struct {
	Code       coap.Code
	Diagnostic string
}

func (e *UnprotectedError) Error() string {
	return fmt.Sprintf("oscore: unprotected %s response %q", e.Code, e.Diagnostic)
}

// Do sends req protected and returns the verified response.
func (c *Client) Do(ctx context.Context, req *coap.Message) (*coap.Message, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.do(ctx, c.ctx, req, nil)
}

func (c *Client) do(ctx context.Context, sc *Context, req *coap.Message, kidContext []byte) (*coap.Message, error) {
	out, r, err := sc.ProtectRequest(req, kidContext)
	if err != nil {
		return nil, err
	}
	rsp, err := c.coap.Do(ctx, out)
	if err != nil {
		return nil, err
	}
	if _, ok := rsp.Option(coap.OptionOSCORE); !ok {
		return nil, &UnprotectedError{Code: rsp.Code, Diagnostic: string(rsp.Payload)}
	}
	return sc.VerifyResponse(r, rsp)
}

// Renew derives a new context with the server by the protocol of Appendix
// B.2, sending req as request #1 and as request #2, and returns the
// response to request #2. The new context, with ID Context R2 || R3,
// replaces the current one.
func (c *Client) Renew(ctx context.Context, req *coap.Message) (*coap.Message, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	r1, err := random(RenewalNonceSize)
	if err != nil {
		return nil, err
	}
	ctx1, err := c.ctx.WithIDContext(r1)
	if err != nil {
		return nil, err
	}
	// Request #1, with ID Context R1 in the 'kid context'.
	out, r, err := ctx1.ProtectRequest(cloneMessage(req), r1)
	if err != nil {
		return nil, err
	}
	rsp, err := c.coap.Do(ctx, out)
	if err != nil {
		return nil, err
	}
	opt, ok, err := optionOf(rsp)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, &UnprotectedError{Code: rsp.Code, Diagnostic: string(rsp.Payload)}
	}
	if !opt.HasKIDContext || len(opt.KIDContext) == 0 {
		return nil, fmt.Errorf("%w: response #1 without R2", ErrDecode)
	}
	r2 := opt.KIDContext
	ctx2, err := c.ctx.WithIDContext(append(slices.Clone(r2), r1...))
	if err != nil {
		return nil, err
	}
	in, err := ctx2.VerifyResponse(r, rsp)
	if err != nil {
		return nil, err
	}
	if in.Code != coap.Unauthorized {
		return nil, fmt.Errorf("oscore: response #1 is %s, not 4.01", in.Code)
	}
	// Request #2, with ID Context R2 || R3.
	r3, err := random(RenewalNonceSize)
	if err != nil {
		return nil, err
	}
	id3 := append(slices.Clone(r2), r3...)
	ctx3, err := c.ctx.WithIDContext(id3)
	if err != nil {
		return nil, err
	}
	final, err := c.do(ctx, ctx3, cloneMessage(req), id3)
	if err != nil {
		return nil, err
	}
	c.ctx = ctx3
	return final, nil
}

func random(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

func cloneMessage(m *coap.Message) *coap.Message {
	c := *m
	c.Options = slices.Clone(m.Options)
	c.Token = nil
	return &c
}
