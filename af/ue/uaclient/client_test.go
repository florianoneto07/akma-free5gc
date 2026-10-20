package uaclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/florianoneto07/akma-free5gc/af/uastar"
	"github.com/florianoneto07/akma-free5gc/shared/akma/kdf"
)

const testAKid = "rid0000.atidiz1FN8DkMGyxwtfTVYsKUsWnzOJdBOLlQEiQlK2gHNA=@5gc.mnc093.mcc208.3gppnetwork.org"

var testKaf = kdf.Key{9, 8, 7}

// fakeAF answers the challenge given by realm, then 200 with an
// Authentication-Info built by info, and records every Authorization.
type fakeAF struct {
	mu     sync.Mutex
	realm  string
	qop    string
	info   func(creds uastar.Credentials, body []byte) string
	authzs []string
}

func (f *fakeAF) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	authz := r.Header.Get("Authorization")
	f.mu.Lock()
	f.authzs = append(f.authzs, authz)
	f.mu.Unlock()
	if authz == "" {
		w.Header().Set("WWW-Authenticate", uastar.Challenge{
			Realm: f.realm, Qop: []string{f.qop}, Algorithm: uastar.Algorithm, Nonce: "bg==", Opaque: "bw==",
		}.String())
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	creds, err := uastar.ParseCredentials(authz)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	body := []byte(`{"aKid":"` + creds.Username + `","kafExpiry":"2026-10-18T13:00:00Z"}`)
	if f.info != nil {
		if v := f.info(creds, body); v != "" {
			w.Header().Set("Authentication-Info", v)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// honest computes rspauth with K_AF, as the AF of this repository does.
func honest(kaf kdf.Key) func(uastar.Credentials, []byte) string {
	return func(c uastar.Credentials, body []byte) string {
		in := uastar.Input{
			Username: c.Username, Realm: c.Realm, Password: uastar.Password(kaf), Method: http.MethodGet,
			URI: c.URI, Nonce: c.Nonce, NC: c.NC, CNonce: c.CNonce, Qop: c.Qop,
		}
		return uastar.AuthInfo{RspAuth: in.RspAuth(body), Qop: c.Qop, NC: c.NC, CNonce: c.CNonce}.String()
	}
}

func run(t *testing.T, af *fakeAF) (Result, error) {
	t.Helper()
	if af.realm == "" {
		af.realm = "3GPP-bootstrapping-akma@af1.akma.example"
	}
	if af.qop == "" {
		af.qop = uastar.QopAuth
	}
	ts := httptest.NewServer(af)
	t.Cleanup(ts.Close)
	s, err := NewSession(Config{
		FQDN: "af1.akma.example", Connect: ts.Listener.Addr().String(), Path: "/ua/v1/session",
		AKID: testAKid, KAf: testKaf,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s.Establish(context.Background())
}

func TestHonestAF(t *testing.T) {
	r, err := run(t, &fakeAF{info: honest(testKaf)})
	if err != nil {
		t.Fatal(err)
	}
	if r.AKid != testAKid || r.NC != "00000001" {
		t.Fatalf("result %+v", r)
	}
}

// TestAFWithoutKaf: an AF that does not prove K_AF is refused.
func TestAFWithoutKaf(t *testing.T) {
	other := testKaf
	other[0] ^= 1
	for name, info := range map[string]func(uastar.Credentials, []byte) string{
		"no Authentication-Info": nil,
		"rspauth of another key": honest(other),
		"response echoed as rspauth": func(c uastar.Credentials, _ []byte) string {
			return uastar.AuthInfo{RspAuth: c.Response, Qop: c.Qop, NC: c.NC, CNonce: c.CNonce}.String()
		},
		"other cnonce": func(c uastar.Credentials, b []byte) string {
			c.CNonce = "eA=="
			return honest(testKaf)(c, b)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := run(t, &fakeAF{info: info}); !errors.Is(err, ErrServerAuth) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

// TestChallengeChecks: the A-KID is not sent when the challenge does not
// select AKMA for this AF (TS 33.535 B.1.2.2 step 4; TS 24.109 K.2 d)).
func TestChallengeChecks(t *testing.T) {
	for name, af := range map[string]*fakeAF{
		"FQDN of another AF": {realm: "3GPP-bootstrapping-akma@af2.akma.example"},
		"GBA realm":          {realm: "3GPP-bootstrapping@af1.akma.example"},
		"realm without @":    {realm: "af1.akma.example"},
		"qop not offered":    {qop: uastar.QopAuthInt},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := run(t, af); !errors.Is(err, ErrChallenge) {
				t.Fatalf("err = %v", err)
			}
			for _, a := range af.authzs {
				if strings.Contains(a, testAKid) {
					t.Fatal("A-KID sent after a rejected challenge")
				}
			}
		})
	}
}

func TestHostAndProductToken(t *testing.T) {
	var host, ua string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, ua = r.Host, r.UserAgent()
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()
	s, err := NewSession(Config{FQDN: "af1.akma.example", Connect: ts.Listener.Addr().String(), Path: "/ua/v1/session"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Establish(context.Background())
	var rej *RejectedError
	if !errors.As(err, &rej) || rej.Status != http.StatusNotFound {
		t.Fatalf("err = %v", err)
	}
	if !strings.HasPrefix(host, "af1.akma.example:") || !uastar.HasProductToken(ua) {
		t.Fatalf("Host %q, User-Agent %q", host, ua)
	}
}
