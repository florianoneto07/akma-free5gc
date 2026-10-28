// Package coap is the part of CoAP (RFC 7252) that the Ua* profiles over
// DTLS and OSCORE use: the message format (cl. 3), the options (cl. 5.4,
// 5.10), a confirmable exchange with a piggybacked response (cl. 4.2,
// 5.2.1), and a server over a UDP socket (cl. 4.5). The client has no
// transport of its own: the messages go over a datagram connection, such as
// a DTLS association or a connected UDP socket.
package coap

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Type is the message type (RFC 7252 cl. 3).
type Type uint8

const (
	Confirmable     Type = 0
	NonConfirmable  Type = 1
	Acknowledgement Type = 2
	Reset           Type = 3
)

// Code is the request method or response code, class.detail (RFC 7252
// cl. 3, 12.1).
type Code uint8

// MakeCode returns the code class.detail.
func MakeCode(class, detail uint8) Code { return Code(class<<5 | detail&0x1F) }

// Codes of RFC 7252 cl. 12.1.
const (
	Empty               Code = 0
	GET                 Code = 1
	POST                Code = 2
	PUT                 Code = 3
	DELETE              Code = 4
	Created             Code = 2<<5 | 1
	Changed             Code = 2<<5 | 4
	Content             Code = 2<<5 | 5
	BadRequest          Code = 4<<5 | 0
	Unauthorized        Code = 4<<5 | 1
	BadOption           Code = 4<<5 | 2
	Forbidden           Code = 4<<5 | 3
	NotFound            Code = 4<<5 | 4
	MethodNotAllowed    Code = 4<<5 | 5
	UnsupportedFormat   Code = 4<<5 | 15
	InternalServerError Code = 5<<5 | 0
	ServiceUnavailable  Code = 5<<5 | 3
)

// String returns the code as class.detail, such as "2.05".
func (c Code) String() string { return fmt.Sprintf("%d.%02d", c>>5, c&0x1F) }

// IsRequest reports whether c is a method.
func (c Code) IsRequest() bool { return c >= 1 && c <= 31 }

// Option numbers (RFC 7252 cl. 5.10, 12.2).
const (
	OptionIfMatch       uint16 = 1
	OptionURIHost       uint16 = 3
	OptionETag          uint16 = 4
	OptionIfNoneMatch   uint16 = 5
	OptionObserve       uint16 = 6
	OptionURIPort       uint16 = 7
	OptionLocationPath  uint16 = 8
	OptionOSCORE        uint16 = 9
	OptionURIPath       uint16 = 11
	OptionContentFormat uint16 = 12
	OptionMaxAge        uint16 = 14
	OptionURIQuery      uint16 = 15
	OptionAccept        uint16 = 17
	OptionLocationQuery uint16 = 20
	OptionProxyURI      uint16 = 35
	OptionProxyScheme   uint16 = 39
	OptionSize1         uint16 = 60
)

// Content formats (RFC 7252 cl. 12.3).
const (
	FormatText uint = 0
	FormatJSON uint = 50
	FormatCBOR uint = 60
)

// Critical reports whether an option number is critical: odd numbers
// (RFC 7252 cl. 5.4.1).
func Critical(n uint16) bool { return n&1 == 1 }

// Option is one option of a message.
type Option struct {
	Number uint16
	Value  []byte
}

// Message is a CoAP message.
type Message struct {
	Type      Type
	Code      Code
	MessageID uint16
	Token     []byte
	Options   []Option
	Payload   []byte
}

// ErrFormat reports a message that is not well formed (RFC 7252 cl. 3).
var ErrFormat = errors.New("coap: message format error")

// Marshal encodes m. The options go in the order of their numbers; options
// of the same number keep their order.
func (m *Message) Marshal() ([]byte, error) {
	if len(m.Token) > 8 {
		return nil, fmt.Errorf("%w: token of %d octets", ErrFormat, len(m.Token))
	}
	b := make([]byte, 4, 64+len(m.Payload))
	b[0] = 1<<6 | byte(m.Type&3)<<4 | byte(len(m.Token))
	b[1] = byte(m.Code)
	binary.BigEndian.PutUint16(b[2:], m.MessageID)
	b = append(b, m.Token...)
	return AppendOptions(b, m.Options, m.Payload)
}

// AppendOptions appends options in the order of their numbers, options of
// the same number keeping their order, then the payload marker and the
// payload, if any (RFC 7252 cl. 3, 3.1). It is also the encoding of the
// options and payload in the plaintext of OSCORE (RFC 8613 cl. 5.3).
func AppendOptions(b []byte, options []Option, payload []byte) ([]byte, error) {
	opts := slices.Clone(options)
	slices.SortStableFunc(opts, func(a, b Option) int { return int(a.Number) - int(b.Number) })
	prev := uint16(0)
	for _, o := range opts {
		if len(o.Value) > 65535+269 {
			return nil, fmt.Errorf("%w: option %d of %d octets", ErrFormat, o.Number, len(o.Value))
		}
		delta, length := uint32(o.Number-prev), uint32(len(o.Value))
		dn, dext := nibble(delta)
		ln, lext := nibble(length)
		b = append(b, dn<<4|ln)
		b = append(b, dext...)
		b = append(b, lext...)
		b = append(b, o.Value...)
		prev = o.Number
	}
	if len(payload) > 0 {
		b = append(b, 0xFF)
		b = append(b, payload...)
	}
	return b, nil
}

// nibble returns the 4-bit field of an option delta or length and its
// extended octets (RFC 7252 cl. 3.1).
func nibble(v uint32) (byte, []byte) {
	switch {
	case v < 13:
		return byte(v), nil
	case v < 269:
		return 13, []byte{byte(v - 13)}
	default:
		return 14, binary.BigEndian.AppendUint16(nil, uint16(v-269))
	}
}

// Parse decodes a message (RFC 7252 cl. 3).
func Parse(b []byte) (*Message, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("%w: %d octets", ErrFormat, len(b))
	}
	if b[0]>>6 != 1 {
		return nil, fmt.Errorf("%w: version %d", ErrFormat, b[0]>>6)
	}
	tkl := int(b[0] & 0x0F)
	if tkl > 8 {
		return nil, fmt.Errorf("%w: token length %d", ErrFormat, tkl)
	}
	m := &Message{Type: Type(b[0] >> 4 & 3), Code: Code(b[1]), MessageID: binary.BigEndian.Uint16(b[2:])}
	p := b[4:]
	if len(p) < tkl {
		return nil, fmt.Errorf("%w: token cut short", ErrFormat)
	}
	m.Token = slices.Clone(p[:tkl])
	p = p[tkl:]
	if m.Code == Empty && (tkl != 0 || len(p) != 0) {
		return nil, fmt.Errorf("%w: empty message with token, options or payload", ErrFormat)
	}
	var err error
	if m.Options, m.Payload, err = ParseOptions(p); err != nil {
		return nil, err
	}
	return m, nil
}

// ParseOptions decodes options and the payload after them (RFC 7252 cl. 3,
// 3.1; RFC 8613 cl. 5.3).
func ParseOptions(p []byte) ([]Option, []byte, error) {
	var opts []Option
	number := uint32(0)
	for len(p) > 0 {
		if p[0] == 0xFF {
			if len(p) == 1 {
				return nil, nil, fmt.Errorf("%w: payload marker without payload", ErrFormat)
			}
			return opts, slices.Clone(p[1:]), nil
		}
		dn, ln := uint32(p[0]>>4), uint32(p[0]&0x0F)
		p = p[1:]
		var err error
		var delta, length uint32
		if delta, p, err = extended(dn, p); err != nil {
			return nil, nil, err
		}
		if length, p, err = extended(ln, p); err != nil {
			return nil, nil, err
		}
		number += delta
		if number > 65535 || uint32(len(p)) < length {
			return nil, nil, fmt.Errorf("%w: option %d cut short", ErrFormat, number)
		}
		opts = append(opts, Option{Number: uint16(number), Value: slices.Clone(p[:length])})
		p = p[length:]
	}
	return opts, nil, nil
}

func extended(n uint32, p []byte) (uint32, []byte, error) {
	switch n {
	case 13:
		if len(p) < 1 {
			return 0, nil, fmt.Errorf("%w: extended option field cut short", ErrFormat)
		}
		return uint32(p[0]) + 13, p[1:], nil
	case 14:
		if len(p) < 2 {
			return 0, nil, fmt.Errorf("%w: extended option field cut short", ErrFormat)
		}
		return uint32(binary.BigEndian.Uint16(p)) + 269, p[2:], nil
	case 15:
		return 0, nil, fmt.Errorf("%w: reserved option nibble 15", ErrFormat)
	}
	return n, p, nil
}

// Option returns the value of the first option n and whether there is one.
func (m *Message) Option(n uint16) ([]byte, bool) {
	for _, o := range m.Options {
		if o.Number == n {
			return o.Value, true
		}
	}
	return nil, false
}

// Add appends an option.
func (m *Message) Add(n uint16, v []byte) { m.Options = append(m.Options, Option{Number: n, Value: v}) }

// Path returns the request path built from the Uri-Path options, "/" when
// there is none (RFC 7252 cl. 6.5).
func (m *Message) Path() string {
	var segs []string
	for _, o := range m.Options {
		if o.Number == OptionURIPath {
			segs = append(segs, string(o.Value))
		}
	}
	return "/" + strings.Join(segs, "/")
}

// SetPath adds one Uri-Path option per segment of path.
func (m *Message) SetPath(path string) {
	for _, seg := range strings.Split(strings.Trim(path, "/"), "/") {
		if seg != "" {
			m.Add(OptionURIPath, []byte(seg))
		}
	}
}

// ContentFormat returns the Content-Format option.
func (m *Message) ContentFormat() (uint, bool) {
	v, ok := m.Option(OptionContentFormat)
	if !ok || len(v) > 2 {
		return 0, false
	}
	return uint(DecodeUint(v)), true
}

// EncodeUint returns v in the shortest big-endian form of RFC 7252
// cl. 3.2: zero is no octet.
func EncodeUint(v uint32) []byte {
	b := binary.BigEndian.AppendUint32(nil, v)
	for len(b) > 0 && b[0] == 0 {
		b = b[1:]
	}
	return b
}

// DecodeUint reads a uint option value of up to four octets.
func DecodeUint(b []byte) uint32 {
	var v uint32
	for _, c := range b {
		v = v<<8 | uint32(c)
	}
	return v
}

// UnknownCritical returns the first critical option of m whose number is
// not in known (RFC 7252 cl. 5.4.1).
func (m *Message) UnknownCritical(known ...uint16) (uint16, bool) {
	for _, o := range m.Options {
		if Critical(o.Number) && !slices.Contains(known, o.Number) {
			return o.Number, true
		}
	}
	return 0, false
}
