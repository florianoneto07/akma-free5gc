package uastar

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

type digestVector struct {
	Name         string `json:"name"`
	SharedVector string `json:"shared_vector"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	Realm        string `json:"realm"`
	Method       string `json:"method"`
	URI          string `json:"uri"`
	Nonce        string `json:"nonce"`
	NC           string `json:"nc"`
	CNonce       string `json:"cnonce"`
	Qop          string `json:"qop"`
	RequestBody  string `json:"request_body"`
	ResponseBody string `json:"response_body"`
	Response     string `json:"response"`
	RspAuth      string `json:"rspauth"`
}

// sharedPasswords returns k_af_base64 of each shared/akma vector.
func sharedPasswords(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile("../../shared/akma/testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Vectors []struct {
			Name      string `json:"name"`
			KAfBase64 string `json:"k_af_base64"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	out := make(map[string]string)
	for _, v := range doc.Vectors {
		out[v.Name] = v.KAfBase64
	}
	return out
}

// TestDigestVectors checks response and rspauth against the vectors of the
// independent Python implementation (testdata/gen_digest_vectors.py),
// which include the SHA-256 example of RFC 7616 cl. 3.9.1.
func TestDigestVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/digest_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Vectors []digestVector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	passwords := sharedPasswords(t)
	for _, v := range doc.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			password := v.Password
			if v.SharedVector != "" {
				password = passwords[v.SharedVector]
			}
			in := Input{
				Username: v.Username, Realm: v.Realm, Password: password, Method: v.Method,
				URI: v.URI, Nonce: v.Nonce, NC: v.NC, CNonce: v.CNonce, Qop: v.Qop,
			}
			if got := in.Response([]byte(v.RequestBody)); got != v.Response {
				t.Errorf("response = %s, want %s", got, v.Response)
			}
			if got := in.RspAuth([]byte(v.ResponseBody)); got != v.RspAuth {
				t.Errorf("rspauth = %s, want %s", got, v.RspAuth)
			}
		})
	}
	if len(doc.Vectors) < 3 {
		t.Fatalf("%d vectors, want at least 3", len(doc.Vectors))
	}
}

// TestRFC7616Example pins the published value, independently of the
// generated file.
func TestRFC7616Example(t *testing.T) {
	in := Input{
		Username: "Mufasa", Realm: "http-auth@example.org", Password: "Circle of Life",
		Method: "GET", URI: "/dir/index.html",
		Nonce: "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", NC: "00000001",
		CNonce: "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ", Qop: QopAuth,
	}
	const want = "753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1"
	if got := in.Response(nil); got != want {
		t.Fatalf("response = %s, want %s", got, want)
	}
}

func TestChallengeRoundTrip(t *testing.T) {
	c := Challenge{
		Realm: Realm(RealmPrefix, "af1.akma.example"), Qop: []string{QopAuth, QopAuthInt},
		Algorithm: Algorithm, Nonce: "n+/=", Opaque: "o", Stale: true, Charset: Charset,
	}
	s := c.String()
	for _, want := range []string{
		`realm="3GPP-bootstrapping-akma@af1.akma.example"`, `qop="auth, auth-int"`,
		"algorithm=SHA-256", `nonce="n+/="`, "stale=true", "charset=UTF-8",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("%s lacks %s", s, want)
		}
	}
	got, err := ParseChallenge(s)
	if err != nil {
		t.Fatal(err)
	}
	if got.Realm != c.Realm || got.Nonce != c.Nonce || got.Opaque != c.Opaque || !got.Stale ||
		len(got.Qop) != 2 || got.Qop[1] != QopAuthInt || got.Algorithm != Algorithm {
		t.Fatalf("round trip: %+v", got)
	}
}

func TestParseChallengeDefaultsToMD5(t *testing.T) {
	c, err := ParseChallenge(`Digest realm="r@x", nonce="n", qop="auth"`)
	if err != nil {
		t.Fatal(err)
	}
	if c.Algorithm != "MD5" {
		t.Fatalf("algorithm = %q", c.Algorithm)
	}
}

func TestCredentialsRoundTrip(t *testing.T) {
	c := Credentials{
		Username: "rid0000.atidiz1FN8DkMGyxwtfTVYsKUsWnzOJdBOLlQEiQlK2gHNA=@5gc.mnc093.mcc208.3gppnetwork.org",
		Realm:    "3GPP-bootstrapping-akma@af1.akma.example", URI: "/ua/v1/session", Algorithm: Algorithm,
		Nonce: "n", NC: "0000000a", CNonce: "c", Qop: QopAuth, Response: strings.Repeat("ab", 32), Opaque: "o",
	}
	s := c.String()
	for _, want := range []string{"algorithm=SHA-256", "nc=0000000a", "qop=auth,"} {
		if !strings.Contains(s, want) {
			t.Errorf("%s lacks %s", s, want)
		}
	}
	got, err := ParseCredentials(s)
	if err != nil {
		t.Fatal(err)
	}
	if got != c {
		t.Fatalf("round trip:\n got %+v\nwant %+v", got, c)
	}
}

func TestParseCredentialsRejects(t *testing.T) {
	full := `username="u", realm="r", uri="/", algorithm=SHA-256, nonce="n", nc=00000001, cnonce="c", qop=auth, response="x", opaque="o"`
	for name, tc := range map[string]struct {
		value string
		err   error
	}{
		"basic scheme":   {"Basic dXNlcjpwYXNz", ErrNotDigest},
		"missing opaque": {"Digest " + strings.Replace(full, `, opaque="o"`, "", 1), ErrMalformedHeader},
		"repeated":       {"Digest " + full + `, nonce="m"`, ErrMalformedHeader},
		"short nc":       {"Digest " + strings.Replace(full, "00000001", "1", 1), ErrMalformedHeader},
		"username*":      {"Digest " + full + `, username*=UTF-8''x`, ErrUnsupported},
		"userhash":       {"Digest " + full + ", userhash=true", ErrUnsupported},
		"unterminated":   {`Digest username="u`, ErrMalformedHeader},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseCredentials(tc.value); !errors.Is(err, tc.err) {
				t.Fatalf("err = %v, want %v", err, tc.err)
			}
		})
	}
}

func TestQuotedStringEscapes(t *testing.T) {
	p, err := parseParams(`a="x\"y\\z" , b=tok,,`)
	if err != nil {
		t.Fatal(err)
	}
	if p["a"] != `x"y\z` || p["b"] != "tok" {
		t.Fatalf("params = %q", p)
	}
	if q := quote(`x"y\z`); q != `"x\"y\\z"` {
		t.Fatalf("quote = %s", q)
	}
}

func TestAuthInfoRoundTrip(t *testing.T) {
	a := AuthInfo{RspAuth: "r", Qop: QopAuth, NC: "00000001", CNonce: "c"}
	s := a.String()
	if s != `rspauth="r", qop=auth, nc=00000001, cnonce="c"` {
		t.Fatalf("String = %s", s)
	}
	got, err := ParseAuthInfo(s)
	if err != nil || got != a {
		t.Fatalf("round trip: %+v, %v", got, err)
	}
	if _, err := ParseAuthInfo(`qop=auth, nc=00000001, cnonce="c"`); err == nil {
		t.Fatal("missing rspauth accepted")
	}
}

func TestSplitRealm(t *testing.T) {
	for in, want := range map[string][2]string{
		"3GPP-bootstrapping-akma@af1.akma.example": {"3GPP-bootstrapping-akma", "af1.akma.example"},
		"a@b@c.example": {"a@b", "c.example"},
	} {
		p, f, ok := SplitRealm(in)
		if !ok || p != want[0] || f != want[1] {
			t.Errorf("SplitRealm(%q) = %q, %q, %v", in, p, f, ok)
		}
	}
	for _, in := range []string{"noat", "@x", "x@"} {
		if _, _, ok := SplitRealm(in); ok {
			t.Errorf("SplitRealm(%q) accepted", in)
		}
	}
}

func TestHasProductToken(t *testing.T) {
	for ua, want := range map[string]bool{
		"akma-uaclient/0.1 3gpp-akma": true,
		"3GPP-AKMA":                   true,
		"curl/8.0":                    false,
		"x 3gpp-gba":                  false,
		"":                            false,
	} {
		if got := HasProductToken(ua); got != want {
			t.Errorf("HasProductToken(%q) = %v", ua, got)
		}
	}
}

func TestNC(t *testing.T) {
	if FormatNC(26) != "0000001a" {
		t.Fatal(FormatNC(26))
	}
	if n, err := ParseNC("0000001A"); err != nil || n != 26 {
		t.Fatalf("ParseNC = %d, %v", n, err)
	}
}
