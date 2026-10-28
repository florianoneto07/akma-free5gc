package oscore

import (
	"bytes"
	"errors"
	"fmt"
	"slices"

	"github.com/florianoneto07/akma-free5gc/af/coap"
)

// Option is the value of the OSCORE option (RFC 8613 cl. 6.1). A field is
// absent when its Has flag is false.
type Option struct {
	PartialIV     []byte
	HasKID        bool
	KID           []byte
	HasKIDContext bool
	KIDContext    []byte
}

// Errors of the processing of a protected message (RFC 8613 cl. 8.2, 8.4).
var (
	// ErrDecode reports an OSCORE option or a COSE object that does not
	// decode: 4.02 Bad Option, "Failed to decode COSE".
	ErrDecode = errors.New("oscore: failed to decode COSE")
	// ErrNoContext reports a 'kid' without a Recipient Context: 4.01
	// Unauthorized, "Security context not found".
	ErrNoContext = errors.New("oscore: security context not found")
	// ErrReplay reports a Partial IV already received: 4.01 Unauthorized,
	// "Replay detected" (cl. 7.4).
	ErrReplay = errors.New("oscore: replay detected")
	// ErrDecrypt reports a message that does not decrypt: 4.00 Bad
	// Request, "Decryption failed".
	ErrDecrypt = errors.New("oscore: decryption failed")
)

// ParseOption decodes the value of the OSCORE option: the flag octet with
// the length n of the Partial IV and the flags k and h, the Partial IV, the
// length and value of the 'kid context', then the 'kid' (cl. 6.1).
func ParseOption(v []byte) (Option, error) {
	var o Option
	if len(v) == 0 {
		return o, nil
	}
	flags := v[0]
	n := int(flags & 0x07)
	if flags&0xE0 != 0 || n > 5 || flags == 0 {
		// Reserved bits and lengths; all flags zero needs an empty value.
		return o, fmt.Errorf("%w: OSCORE option flags %#x", ErrDecode, flags)
	}
	v = v[1:]
	if len(v) < n {
		return o, fmt.Errorf("%w: Partial IV cut short", ErrDecode)
	}
	o.PartialIV, v = slices.Clone(v[:n]), v[n:]
	if flags&0x10 != 0 {
		if len(v) < 1 || len(v) < 1+int(v[0]) {
			return o, fmt.Errorf("%w: kid context cut short", ErrDecode)
		}
		s := int(v[0])
		o.HasKIDContext, o.KIDContext, v = true, slices.Clone(v[1:1+s]), v[1+s:]
	}
	if flags&0x08 != 0 {
		o.HasKID, o.KID = true, slices.Clone(v)
	} else if len(v) != 0 {
		return o, fmt.Errorf("%w: octets after the OSCORE option fields", ErrDecode)
	}
	return o, nil
}

// Marshal encodes the option value; with no field, it is empty.
func (o Option) Marshal() []byte {
	if len(o.PartialIV) == 0 && !o.HasKID && !o.HasKIDContext {
		return []byte{}
	}
	flags := byte(len(o.PartialIV))
	if o.HasKID {
		flags |= 0x08
	}
	if o.HasKIDContext {
		flags |= 0x10
	}
	b := append([]byte{flags}, o.PartialIV...)
	if o.HasKIDContext {
		b = append(append(b, byte(len(o.KIDContext))), o.KIDContext...)
	}
	return append(b, o.KID...)
}

// outerOption reports the options of Class U, which stay outside the
// encryption: Uri-Host, Uri-Port, OSCORE, Proxy-Uri and Proxy-Scheme
// (cl. 4.1). Every other option, unknown ones included, is Class E (cl. 4.1:
// unknown options are processed as Class E). No Class I option is defined.
func outerOption(n uint16) bool {
	switch n {
	case coap.OptionURIHost, coap.OptionURIPort, coap.OptionOSCORE, coap.OptionProxyURI, coap.OptionProxyScheme:
		return true
	}
	return false
}

// Request is what binds a response to its protected request: the 'kid' and
// Partial IV of the request and the AEAD nonce built from them (cl. 5.4,
// 8.3).
type Request struct {
	KID       []byte
	PartialIV []byte
	nonce     []byte
}

// protect encrypts the Code, the Class E options and the payload of m
// (cl. 5.3) and returns the protected message, whose Code is outerCode.
func protect(aead interface {
	Seal(dst, nonce, plaintext, aad []byte) []byte
}, m *coap.Message, outerCode coap.Code, opt Option, nonce, ad []byte) (*coap.Message, error) {
	var inner, outer []coap.Option
	for _, o := range m.Options {
		switch {
		case o.Number == coap.OptionOSCORE:
			return nil, errors.New("oscore: message already has an OSCORE option")
		case o.Number == coap.OptionProxyURI:
			return nil, errors.New("oscore: Proxy-Uri is not supported")
		case outerOption(o.Number):
			outer = append(outer, o)
		default:
			inner = append(inner, o)
		}
	}
	plain, err := coap.AppendOptions([]byte{byte(m.Code)}, inner, m.Payload)
	if err != nil {
		return nil, err
	}
	out := &coap.Message{Type: m.Type, Code: outerCode, MessageID: m.MessageID, Token: m.Token,
		Options: append(outer, coap.Option{Number: coap.OptionOSCORE, Value: opt.Marshal()})}
	out.Payload = aead.Seal(nil, nonce, plain, ad)
	return out, nil
}

// unprotect decrypts the payload of a protected message and returns the
// message with the decrypted Code and options; the Class U options of the
// outer message are kept, the OSCORE option is removed, and the Class E
// options of the outer message are discarded (cl. 8.2 step 1, 8.4).
func unprotect(aead interface {
	Open(dst, nonce, ciphertext, aad []byte) ([]byte, error)
}, m *coap.Message, nonce, ad []byte) (*coap.Message, error) {
	if len(m.Payload) == 0 {
		return nil, fmt.Errorf("%w: no ciphertext", ErrDecode)
	}
	plain, err := aead.Open(nil, nonce, m.Payload, ad)
	if err != nil {
		return nil, ErrDecrypt
	}
	if len(plain) == 0 {
		return nil, fmt.Errorf("%w: plaintext without code", ErrDecode)
	}
	opts, payload, err := coap.ParseOptions(plain[1:])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecode, err)
	}
	in := &coap.Message{Type: m.Type, Code: coap.Code(plain[0]), MessageID: m.MessageID, Token: m.Token,
		Payload: payload}
	for _, o := range m.Options {
		if outerOption(o.Number) && o.Number != coap.OptionOSCORE {
			in.Options = append(in.Options, o)
		}
	}
	for _, o := range opts {
		if outerOption(o.Number) {
			return nil, fmt.Errorf("%w: Class U option %d inside the plaintext", ErrDecode, o.Number)
		}
		in.Options = append(in.Options, o)
	}
	return in, nil
}

// optionOf returns the decoded OSCORE option of m.
func optionOf(m *coap.Message) (Option, bool, error) {
	v, ok := m.Option(coap.OptionOSCORE)
	if !ok {
		return Option{}, false, nil
	}
	o, err := ParseOption(v)
	return o, true, err
}

// ProtectRequest protects a request with the next Sender Sequence Number,
// the Sender ID as 'kid' and, when kidContext is not nil, a 'kid context'
// (cl. 8.1). The outer Code is POST (cl. 4.2).
func (c *Context) ProtectRequest(m *coap.Message, kidContext []byte) (*coap.Message, *Request, error) {
	if !m.Code.IsRequest() {
		return nil, nil, errors.New("oscore: not a request")
	}
	piv, err := c.nextPIV()
	if err != nil {
		return nil, nil, err
	}
	opt := Option{PartialIV: piv, HasKID: true, KID: c.p.SenderID}
	if kidContext != nil {
		opt.HasKIDContext, opt.KIDContext = true, kidContext
	}
	r := &Request{KID: slices.Clone(c.p.SenderID), PartialIV: piv, nonce: c.nonce(c.p.SenderID, piv)}
	out, err := protect(c.sender, m, coap.POST, opt, r.nonce, aad(r.KID, r.PartialIV))
	if err != nil {
		return nil, nil, err
	}
	return out, r, nil
}

// VerifyRequest verifies a protected request whose 'kid' is the Recipient
// ID of c (cl. 8.2 steps 3 to 7): the Partial IV must be new for the
// replay window, and the request must decrypt. It returns the decrypted
// request.
func (c *Context) VerifyRequest(m *coap.Message, opt Option) (*coap.Message, *Request, error) {
	if !opt.HasKID || len(opt.PartialIV) == 0 {
		return nil, nil, fmt.Errorf("%w: request without kid or Partial IV", ErrDecode)
	}
	if !bytes.Equal(opt.KID, c.p.RecipientID) {
		return nil, nil, ErrNoContext
	}
	s := decodePIV(opt.PartialIV)
	c.mu.Lock()
	replayed := c.replay.seen(s)
	c.mu.Unlock()
	if replayed {
		return nil, nil, ErrReplay
	}
	r := &Request{KID: slices.Clone(opt.KID), PartialIV: slices.Clone(opt.PartialIV),
		nonce: c.nonce(opt.KID, opt.PartialIV)}
	in, err := unprotect(c.recipient, m, r.nonce, aad(r.KID, r.PartialIV))
	if err != nil {
		return nil, nil, err
	}
	if !in.Code.IsRequest() {
		return nil, nil, fmt.Errorf("%w: decrypted code %s is not a method", ErrDecode, in.Code)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.replay.seen(s) { // a parallel copy got here first
		return nil, nil, ErrReplay
	}
	c.replay.mark(s)
	return in, r, nil
}

// ProtectResponse protects the response to r. With partialIV, or when the
// context differs from the one of the request (Appendix B.2), the response
// carries the next Sender Sequence Number as Partial IV and its own nonce;
// otherwise it reuses the nonce of the request (cl. 8.3). A kidContext not
// nil goes in the option. The outer Code is 2.04 Changed (cl. 4.2).
func (c *Context) ProtectResponse(r *Request, m *coap.Message, partialIV bool, kidContext []byte) (*coap.Message, error) {
	var opt Option
	nonce := r.nonce
	if partialIV {
		piv, err := c.nextPIV()
		if err != nil {
			return nil, err
		}
		opt.PartialIV, nonce = piv, c.nonce(c.p.SenderID, piv)
	}
	if kidContext != nil {
		opt.HasKIDContext, opt.KIDContext = true, kidContext
	}
	return protect(c.sender, m, coap.Changed, opt, nonce, aad(r.KID, r.PartialIV))
}

// VerifyResponse verifies the protected response to r (cl. 8.4) and returns
// the decrypted response. A Partial IV in the response gives the nonce, with
// the Recipient ID as the ID of its sender.
func (c *Context) VerifyResponse(r *Request, m *coap.Message) (*coap.Message, error) {
	opt, ok, err := optionOf(m)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("%w: response without OSCORE option", ErrDecode)
	}
	if opt.HasKID {
		return nil, fmt.Errorf("%w: kid in a response", ErrDecode)
	}
	nonce := r.nonce
	if len(opt.PartialIV) > 0 {
		nonce = c.nonce(c.p.RecipientID, opt.PartialIV)
	}
	in, err := unprotect(c.recipient, m, nonce, aad(r.KID, r.PartialIV))
	if err != nil {
		return nil, err
	}
	if in.Code.IsRequest() || in.Code == coap.Empty {
		return nil, fmt.Errorf("%w: decrypted code %s is not a response", ErrDecode, in.Code)
	}
	return in, nil
}
