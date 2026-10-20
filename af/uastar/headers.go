package uastar

import (
	"fmt"
	"strings"
)

// Challenge is the Digest challenge of the WWW-Authenticate header field
// (RFC 7616 cl. 3.3).
type Challenge struct {
	Realm     string
	Qop       []string
	Algorithm string
	Nonce     string
	Opaque    string
	Stale     bool
	Charset   string
}

// String renders the field value. realm, qop, nonce and opaque are quoted;
// algorithm, stale and charset are not (RFC 7616 cl. 3.3).
func (c Challenge) String() string {
	var l paramList
	l.quoted("realm", c.Realm)
	l.quoted("qop", strings.Join(c.Qop, ", "))
	l.token("algorithm", c.Algorithm)
	l.quoted("nonce", c.Nonce)
	l.quoted("opaque", c.Opaque)
	if c.Stale {
		l.token("stale", "true")
	}
	if c.Charset != "" {
		l.token("charset", c.Charset)
	}
	return "Digest " + l.String()
}

// ParseChallenge reads a WWW-Authenticate field value with one Digest
// challenge.
func ParseChallenge(v string) (Challenge, error) {
	scheme, rest := splitScheme(v)
	if !strings.EqualFold(scheme, "Digest") {
		return Challenge{}, fmt.Errorf("%w: scheme %q is not Digest", ErrMalformedHeader, scheme)
	}
	p, err := parseParams(rest)
	if err != nil {
		return Challenge{}, err
	}
	c := Challenge{
		Realm:     p["realm"],
		Algorithm: p["algorithm"],
		Nonce:     p["nonce"],
		Opaque:    p["opaque"],
		Stale:     strings.EqualFold(p["stale"], "true"),
		Charset:   p["charset"],
	}
	if c.Algorithm == "" {
		c.Algorithm = "MD5" // RFC 7616 cl. 3.3: absent means MD5
	}
	for _, q := range strings.Split(p["qop"], ",") {
		if q = strings.TrimSpace(q); q != "" {
			c.Qop = append(c.Qop, q)
		}
	}
	if c.Realm == "" || c.Nonce == "" {
		return Challenge{}, fmt.Errorf("%w: realm and nonce are required", ErrMalformedHeader)
	}
	return c, nil
}

// Credentials are the Digest credentials of the Authorization header field
// (RFC 7616 cl. 3.4).
type Credentials struct {
	Username  string
	Realm     string
	URI       string
	Algorithm string
	Nonce     string
	NC        string
	CNonce    string
	Qop       string
	Response  string
	Opaque    string
}

// String renders the field value. algorithm, qop and nc are not quoted
// (RFC 7616 cl. 3.4).
func (c Credentials) String() string {
	var l paramList
	l.quoted("username", c.Username)
	l.quoted("realm", c.Realm)
	l.quoted("uri", c.URI)
	l.token("algorithm", c.Algorithm)
	l.quoted("nonce", c.Nonce)
	l.token("nc", c.NC)
	l.quoted("cnonce", c.CNonce)
	l.token("qop", c.Qop)
	l.quoted("response", c.Response)
	l.quoted("opaque", c.Opaque)
	return "Digest " + l.String()
}

// ErrNotDigest reports an Authorization field value with another scheme.
var ErrNotDigest = fmt.Errorf("%w: not a Digest authorization", ErrMalformedHeader)

// ParseCredentials reads an Authorization field value. Every parameter that
// the supported profile uses is required; username* and userhash=true are
// not supported (RFC 7616 cl. 3.4 and 3.4.4).
func ParseCredentials(v string) (Credentials, error) {
	scheme, rest := splitScheme(v)
	if !strings.EqualFold(scheme, "Digest") {
		return Credentials{}, ErrNotDigest
	}
	p, err := parseParams(rest)
	if err != nil {
		return Credentials{}, err
	}
	if _, ok := p["username*"]; ok {
		return Credentials{}, fmt.Errorf("%w: username*", ErrUnsupported)
	}
	if strings.EqualFold(p["userhash"], "true") {
		return Credentials{}, fmt.Errorf("%w: userhash", ErrUnsupported)
	}
	c := Credentials{
		Username:  p["username"],
		Realm:     p["realm"],
		URI:       p["uri"],
		Algorithm: p["algorithm"],
		Nonce:     p["nonce"],
		NC:        p["nc"],
		CNonce:    p["cnonce"],
		Qop:       p["qop"],
		Response:  p["response"],
		Opaque:    p["opaque"],
	}
	for name, value := range map[string]string{
		"username": c.Username, "realm": c.Realm, "uri": c.URI, "algorithm": c.Algorithm,
		"nonce": c.Nonce, "nc": c.NC, "cnonce": c.CNonce, "qop": c.Qop,
		"response": c.Response, "opaque": c.Opaque,
	} {
		if value == "" {
			return Credentials{}, fmt.Errorf("%w: %s is required", ErrMalformedHeader, name)
		}
	}
	if _, err := ParseNC(c.NC); err != nil {
		return Credentials{}, err
	}
	return c, nil
}

// AuthInfo is the Authentication-Info header field (RFC 7616 cl. 3.5).
type AuthInfo struct {
	RspAuth   string
	Qop       string
	NC        string
	CNonce    string
	NextNonce string
}

// String renders the field value. rspauth, cnonce and nextnonce are quoted;
// qop and nc are not (RFC 7616 cl. 3.5).
func (a AuthInfo) String() string {
	var l paramList
	l.quoted("rspauth", a.RspAuth)
	l.token("qop", a.Qop)
	l.token("nc", a.NC)
	l.quoted("cnonce", a.CNonce)
	if a.NextNonce != "" {
		l.quoted("nextnonce", a.NextNonce)
	}
	return l.String()
}

// ParseAuthInfo reads an Authentication-Info field value; rspauth, qop, nc
// and cnonce are required (RFC 7616 cl. 3.5, with qop).
func ParseAuthInfo(v string) (AuthInfo, error) {
	p, err := parseParams(v)
	if err != nil {
		return AuthInfo{}, err
	}
	a := AuthInfo{RspAuth: p["rspauth"], Qop: p["qop"], NC: p["nc"], CNonce: p["cnonce"], NextNonce: p["nextnonce"]}
	if a.RspAuth == "" || a.Qop == "" || a.NC == "" || a.CNonce == "" {
		return AuthInfo{}, fmt.Errorf("%w: rspauth, qop, nc and cnonce are required", ErrMalformedHeader)
	}
	return a, nil
}
