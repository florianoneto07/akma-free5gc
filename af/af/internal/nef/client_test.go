package nef

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"golang.org/x/oauth2"

	"github.com/florianoneto07/akma-free5gc/af/af/internal/aanf"
	"github.com/florianoneto07/akma-free5gc/shared/akma/afid"
	"github.com/florianoneto07/akma-free5gc/shared/akma/codec"
	"github.com/florianoneto07/akma-free5gc/shared/akma/kdf"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
)

const testAKid = "rid0000.atidiz1FN8DkMGyxwtfTVYsKUsWnzOJdBOLlQEiQlK2gHNA=@5gc.mnc093.mcc208.3gppnetwork.org"

// staticTokens adds a fixed bearer token, as the NRF registration does.
type staticTokens struct {
	target models.NrfNfManagementNfType
	scope  string
}

func (s *staticTokens) TokenCtx(ctx context.Context, target models.NrfNfManagementNfType, scope string) (
	context.Context, error,
) {
	s.target, s.scope = target, scope
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test-token", TokenType: "Bearer"})
	return context.WithValue(ctx, openapi.ContextOAuth2, ts), nil
}

type request struct {
	auth string
	body models.AkmaAfKeyRequest
}

// fakeNef serves POST /3gpp-akma/v1/retrieve over h2c and records the
// request.
func fakeNef(t *testing.T, got *request, handler func(w http.ResponseWriter)) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /3gpp-akma/v1/retrieve", func(w http.ResponseWriter, r *http.Request) {
		got.auth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&got.body); err != nil {
			t.Errorf("request body: %v", err)
		}
		handler(w)
	})
	ts := httptest.NewUnstartedServer(h2c.NewHandler(mux, &http2.Server{}))
	ts.Start()
	t.Cleanup(ts.Close)
	return "http://" + ts.Listener.Addr().(*net.TCPAddr).String()
}

func newClient(t *testing.T, apiRoot string, anonymous bool, tokens TokenSource) *Client {
	t.Helper()
	id, err := afid.New("af1.akma.example", afid.UaStarDigest)
	if err != nil {
		t.Fatal(err)
	}
	return New(apiRoot, id, anonymous, tokens)
}

func writeJSON(w http.ResponseWriter, status int, contentType string, v any) {
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func TestApplicationKey(t *testing.T) {
	kaf := kdf.Key{1, 2, 3}
	exp := time.Date(2026, 10, 19, 20, 0, 0, 0, time.UTC)
	for _, anonymous := range []bool{false, true} {
		var got request
		root := fakeNef(t, &got, func(w http.ResponseWriter) {
			writeJSON(w, http.StatusOK, "application/json", models.AkmaAfKeyData{Kaf: codec.HexKey(kaf), Expiry: &exp})
		})
		tokens := &staticTokens{}
		k, err := newClient(t, root, anonymous, tokens).ApplicationKey(context.Background(), testAKid)
		if err != nil {
			t.Fatal(err)
		}
		if k.KAf != kaf || !k.Expiry.Equal(exp) || k.Supi != "" {
			t.Errorf("key %+v", k)
		}
		if got.body.AfId != "af1.akma.example.FF00000001" || got.body.AKId != testAKid || got.body.AnonInd != anonymous {
			t.Errorf("request %+v", got.body)
		}
		if got.auth != "Bearer test-token" {
			t.Errorf("Authorization %q", got.auth)
		}
		if tokens.target != models.NrfNfManagementNfType_NEF || tokens.scope != "3gpp-akma" {
			t.Errorf("token for %s %s", tokens.target, tokens.scope)
		}
	}
}

func TestApplicationKeyErrors(t *testing.T) {
	for name, tc := range map[string]struct {
		handler func(w http.ResponseWriter)
		want    error
	}{
		"K_AKMA_NOT_PRESENT": {func(w http.ResponseWriter) {
			writeJSON(w, http.StatusForbidden, "application/problem+json",
				models.ProblemDetails{Status: 403, Cause: "K_AKMA_NOT_PRESENT"})
		}, aanf.ErrKeyNotAvailable},
		"AF not authorized": {func(w http.ResponseWriter) {
			writeJSON(w, http.StatusForbidden, "application/problem+json", models.ProblemDetails{Status: 403})
		}, aanf.ErrUnavailable},
		"token refused": {func(w http.ResponseWriter) {
			writeJSON(w, http.StatusUnauthorized, "application/json", map[string]string{"error": "invalid token"})
		}, aanf.ErrUnavailable},
		"AAnF unavailable": {func(w http.ResponseWriter) {
			writeJSON(w, http.StatusServiceUnavailable, "application/problem+json", models.ProblemDetails{Status: 503})
		}, aanf.ErrUnavailable},
		"204": {func(w http.ResponseWriter) { w.WriteHeader(http.StatusNoContent) }, aanf.ErrUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			var got request
			_, err := newClient(t, fakeNef(t, &got, tc.handler), false, &staticTokens{}).
				ApplicationKey(context.Background(), testAKid)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}
