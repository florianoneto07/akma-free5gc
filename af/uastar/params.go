package uastar

import (
	"errors"
	"fmt"
	"strings"
)

// ErrMalformedHeader reports a header field that is not a valid Digest
// challenge or credentials list.
var ErrMalformedHeader = errors.New("uastar: malformed Digest header field")

// splitScheme separates the authentication scheme from the parameters of a
// WWW-Authenticate or Authorization field value (RFC 9110 cl. 11.3, 11.6.2).
func splitScheme(v string) (scheme, rest string) {
	v = strings.TrimLeft(v, " \t")
	i := strings.IndexAny(v, " \t")
	if i < 0 {
		return v, ""
	}
	return v[:i], v[i+1:]
}

// parseParams reads a comma-separated list of auth-param
// (token BWS "=" BWS ( token / quoted-string ), RFC 9110 cl. 11.2). Names are
// case-insensitive and returned in lower case; a repeated name is an error.
func parseParams(s string) (map[string]string, error) {
	params := make(map[string]string)
	i := 0
	skip := func() {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
	}
	for {
		skip()
		for i < len(s) && s[i] == ',' { // empty list elements
			i++
			skip()
		}
		if i >= len(s) {
			return params, nil
		}
		start := i
		for i < len(s) && isTchar(s[i]) {
			i++
		}
		name := strings.ToLower(s[start:i])
		if name == "" {
			return nil, fmt.Errorf("%w: parameter name expected at %d", ErrMalformedHeader, i)
		}
		skip()
		if i >= len(s) || s[i] != '=' {
			return nil, fmt.Errorf("%w: '=' expected after %q", ErrMalformedHeader, name)
		}
		i++
		skip()
		var value string
		if i < len(s) && s[i] == '"' {
			var b strings.Builder
			i++
			closed := false
			for i < len(s) {
				c := s[i]
				if c == '\\' && i+1 < len(s) {
					b.WriteByte(s[i+1])
					i += 2
					continue
				}
				if c == '"' {
					closed = true
					i++
					break
				}
				b.WriteByte(c)
				i++
			}
			if !closed {
				return nil, fmt.Errorf("%w: unterminated quoted string in %q", ErrMalformedHeader, name)
			}
			value = b.String()
		} else {
			start = i
			for i < len(s) && isTchar(s[i]) {
				i++
			}
			value = s[start:i]
			if value == "" {
				return nil, fmt.Errorf("%w: value expected for %q", ErrMalformedHeader, name)
			}
		}
		if _, dup := params[name]; dup {
			return nil, fmt.Errorf("%w: repeated parameter %q", ErrMalformedHeader, name)
		}
		params[name] = value
		skip()
		if i < len(s) && s[i] != ',' {
			return nil, fmt.Errorf("%w: ',' expected after %q", ErrMalformedHeader, name)
		}
	}
}

// isTchar reports whether c is a tchar of RFC 9110 cl. 5.6.2.
func isTchar(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
}

// quote renders s as a quoted-string (RFC 9110 cl. 5.6.4).
func quote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		if s[i] == '"' || s[i] == '\\' {
			b.WriteByte('\\')
		}
		b.WriteByte(s[i])
	}
	b.WriteByte('"')
	return b.String()
}

// paramList joins name=value pairs with ", ".
type paramList []string

func (l *paramList) quoted(name, value string) { *l = append(*l, name+"="+quote(value)) }
func (l *paramList) token(name, value string)  { *l = append(*l, name+"="+value) }
func (l paramList) String() string             { return strings.Join(l, ", ") }
