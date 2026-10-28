// Package cbor is the part of CBOR (RFC 8949) that the OSCORE profile of
// Ua* uses (TS 33.535 D.3.5; RFC 8613 cl. 3.2.1, 5.4): integers, byte and
// text strings, arrays, maps, false, true and null.
//
// Encode writes the deterministic encoding of RFC 8949 cl. 4.2.1: the
// shortest form of each argument and the keys of a map in the bytewise order
// of their encodings. Decode reads one well-formed item of definite length.
// It also takes arguments longer than needed, but refuses indefinite
// lengths, tags and floating-point numbers, which the profile does not use,
// and maps with a repeated key (RFC 8949 cl. 5.6).
package cbor

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"unicode/utf8"
)

// Kind is the type of a Value.
type Kind uint8

const (
	Invalid Kind = iota
	Uint         // major type 0
	NegInt       // major type 1: the value is -1-N
	Bytes        // major type 2
	Text         // major type 3
	Array        // major type 4
	Map          // major type 5
	Bool         // simple values 20 and 21
	Null         // simple value 22
)

// Value is one data item.
type Value struct {
	Kind Kind
	N    uint64  // Uint: the value; NegInt: the argument; Bool: 0 or 1
	B    []byte  // Bytes
	S    string  // Text
	A    []Value // Array
	M    []Pair  // Map
}

// Pair is one entry of a map.
type Pair struct {
	Key, Value Value
}

// Constructors.

func UintValue(n uint64) Value  { return Value{Kind: Uint, N: n} }
func BytesValue(b []byte) Value { return Value{Kind: Bytes, B: b} }
func TextValue(s string) Value  { return Value{Kind: Text, S: s} }
func ArrayValue(a ...Value) Value {
	return Value{Kind: Array, A: a}
}
func MapValue(m ...Pair) Value { return Value{Kind: Map, M: m} }
func NullValue() Value         { return Value{Kind: Null} }
func BoolValue(b bool) Value {
	if b {
		return Value{Kind: Bool, N: 1}
	}
	return Value{Kind: Bool}
}

// IntValue returns n as an unsigned or a negative integer.
func IntValue(n int64) Value {
	if n >= 0 {
		return Value{Kind: Uint, N: uint64(n)}
	}
	return Value{Kind: NegInt, N: uint64(-(n + 1))}
}

// Int returns the value of an integer that fits in an int64.
func (v Value) Int() (int64, bool) {
	switch {
	case v.Kind == Uint && v.N <= 1<<63-1:
		return int64(v.N), true
	case v.Kind == NegInt && v.N <= 1<<63-1:
		return -1 - int64(v.N), true
	}
	return 0, false
}

// Get returns the value of the key k of a map.
func (v Value) Get(k Value) (Value, bool) {
	for _, p := range v.M {
		if equal(p.Key, k) {
			return p.Value, true
		}
	}
	return Value{}, false
}

func equal(a, b Value) bool {
	ea, err1 := Encode(a)
	eb, err2 := Encode(b)
	return err1 == nil && err2 == nil && bytes.Equal(ea, eb)
}

// ErrFormat reports an input that is not a well-formed item, or uses what
// this package does not support.
var ErrFormat = errors.New("cbor: malformed or unsupported item")

// Encode returns the deterministic encoding of v.
func Encode(v Value) ([]byte, error) {
	return appendValue(nil, v)
}

// MustEncode is Encode for values built in the program, which always
// encode.
func MustEncode(v Value) []byte {
	b, err := Encode(v)
	if err != nil {
		panic(err)
	}
	return b
}

func appendValue(b []byte, v Value) ([]byte, error) {
	switch v.Kind {
	case Uint:
		return appendHead(b, 0, v.N), nil
	case NegInt:
		return appendHead(b, 1, v.N), nil
	case Bytes:
		return append(appendHead(b, 2, uint64(len(v.B))), v.B...), nil
	case Text:
		if !utf8.ValidString(v.S) {
			return nil, fmt.Errorf("%w: text string not in UTF-8", ErrFormat)
		}
		return append(appendHead(b, 3, uint64(len(v.S))), v.S...), nil
	case Array:
		b = appendHead(b, 4, uint64(len(v.A)))
		for _, e := range v.A {
			var err error
			if b, err = appendValue(b, e); err != nil {
				return nil, err
			}
		}
		return b, nil
	case Map:
		type entry struct{ k, v []byte }
		entries := make([]entry, 0, len(v.M))
		for _, p := range v.M {
			k, err := Encode(p.Key)
			if err != nil {
				return nil, err
			}
			e, err := Encode(p.Value)
			if err != nil {
				return nil, err
			}
			entries = append(entries, entry{k, e})
		}
		slices.SortFunc(entries, func(x, y entry) int { return bytes.Compare(x.k, y.k) })
		for i := 1; i < len(entries); i++ {
			if bytes.Equal(entries[i-1].k, entries[i].k) {
				return nil, fmt.Errorf("%w: repeated map key", ErrFormat)
			}
		}
		b = appendHead(b, 5, uint64(len(entries)))
		for _, e := range entries {
			b = append(append(b, e.k...), e.v...)
		}
		return b, nil
	case Bool:
		return append(b, 0xF4|byte(v.N&1)), nil
	case Null:
		return append(b, 0xF6), nil
	}
	return nil, fmt.Errorf("%w: kind %d", ErrFormat, v.Kind)
}

// appendHead writes the initial byte and the shortest argument (RFC 8949
// cl. 3, 4.2.1).
func appendHead(b []byte, major byte, n uint64) []byte {
	m := major << 5
	switch {
	case n < 24:
		return append(b, m|byte(n))
	case n <= 0xFF:
		return append(b, m|24, byte(n))
	case n <= 0xFFFF:
		return binary.BigEndian.AppendUint16(append(b, m|25), uint16(n))
	case n <= 0xFFFFFFFF:
		return binary.BigEndian.AppendUint32(append(b, m|26), uint32(n))
	}
	return binary.BigEndian.AppendUint64(append(b, m|27), n)
}

// maxDepth bounds the nesting of arrays and maps.
const maxDepth = 16

// Decode reads exactly one item from b.
func Decode(b []byte) (Value, error) {
	v, rest, err := decode(b, 0)
	if err != nil {
		return Value{}, err
	}
	if len(rest) != 0 {
		return Value{}, fmt.Errorf("%w: %d octets after the item", ErrFormat, len(rest))
	}
	return v, nil
}

func decode(b []byte, depth int) (Value, []byte, error) {
	if depth > maxDepth {
		return Value{}, nil, fmt.Errorf("%w: nested deeper than %d", ErrFormat, maxDepth)
	}
	if len(b) == 0 {
		return Value{}, nil, fmt.Errorf("%w: cut short", ErrFormat)
	}
	major, ai := b[0]>>5, b[0]&0x1F
	b = b[1:]
	if major == 7 {
		switch ai {
		case 20, 21:
			return Value{Kind: Bool, N: uint64(ai - 20)}, b, nil
		case 22:
			return Value{Kind: Null}, b, nil
		}
		return Value{}, nil, fmt.Errorf("%w: simple value or float %d", ErrFormat, ai)
	}
	if major == 6 {
		return Value{}, nil, fmt.Errorf("%w: tag", ErrFormat)
	}
	var n uint64
	switch {
	case ai < 24:
		n = uint64(ai)
	case ai <= 27:
		size := 1 << (ai - 24)
		if len(b) < size {
			return Value{}, nil, fmt.Errorf("%w: argument cut short", ErrFormat)
		}
		for _, c := range b[:size] {
			n = n<<8 | uint64(c)
		}
		b = b[size:]
	case ai == 31:
		return Value{}, nil, fmt.Errorf("%w: indefinite length", ErrFormat)
	default:
		return Value{}, nil, fmt.Errorf("%w: reserved additional information %d", ErrFormat, ai)
	}
	switch major {
	case 0:
		return Value{Kind: Uint, N: n}, b, nil
	case 1:
		return Value{Kind: NegInt, N: n}, b, nil
	case 2, 3:
		if n > uint64(len(b)) {
			return Value{}, nil, fmt.Errorf("%w: string cut short", ErrFormat)
		}
		s := b[:n]
		if major == 2 {
			return Value{Kind: Bytes, B: slices.Clone(s)}, b[n:], nil
		}
		if !utf8.Valid(s) {
			return Value{}, nil, fmt.Errorf("%w: text string not in UTF-8", ErrFormat)
		}
		return Value{Kind: Text, S: string(s)}, b[n:], nil
	case 4:
		// Each item takes at least one octet.
		if n > uint64(len(b)) {
			return Value{}, nil, fmt.Errorf("%w: array cut short", ErrFormat)
		}
		a := make([]Value, 0, n)
		for range n {
			var e Value
			var err error
			if e, b, err = decode(b, depth+1); err != nil {
				return Value{}, nil, err
			}
			a = append(a, e)
		}
		return Value{Kind: Array, A: a}, b, nil
	default: // 5
		if n > uint64(len(b))/2 {
			return Value{}, nil, fmt.Errorf("%w: map cut short", ErrFormat)
		}
		m := make([]Pair, 0, n)
		for range n {
			var p Pair
			var err error
			if p.Key, b, err = decode(b, depth+1); err != nil {
				return Value{}, nil, err
			}
			if _, dup := (Value{Kind: Map, M: m}).Get(p.Key); dup {
				return Value{}, nil, fmt.Errorf("%w: repeated map key", ErrFormat)
			}
			if p.Value, b, err = decode(b, depth+1); err != nil {
				return Value{}, nil, err
			}
			m = append(m, p)
		}
		return Value{Kind: Map, M: m}, b, nil
	}
}
