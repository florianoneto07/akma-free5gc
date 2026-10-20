package aanf

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

	"github.com/florianoneto07/akma-free5gc/shared/akma/afid"
	"github.com/florianoneto07/akma-free5gc/shared/akma/codec"
	"github.com/florianoneto07/akma-free5gc/shared/akma/kdf"
	"github.com/free5gc/openapi/models"
)

const testAKid = "rid0000.atidiz1FN8DkMGyxwtfTVYsKUsWnzOJdBOLlQEiQlK2gHNA=@5gc.mnc093.mcc208.3gppnetwork.org"

// fakeAanf serves retrieve-applicationkey over h2c, as the AAnF does, and
// records the request body.
func fakeAanf(t *testing.T, handler func(w http.ResponseWriter, req models.AkmaAfKeyRequest)) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /naanf-akma/v1/retrieve-applicationkey", func(w http.ResponseWriter, r *http.Request) {
		var req models.AkmaAfKeyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("request body: %v", err)
		}
		handler(w, req)
	})
	ts := httptest.NewUnstartedServer(h2c.NewHandler(mux, &http2.Server{}))
	ts.Start()
	t.Cleanup(ts.Close)
	return "http://" + ts.Listener.Addr().(*net.TCPAddr).String()
}

func client(t *testing.T, apiRoot string) *Client {
	t.Helper()
	return clientAnon(t, apiRoot, false)
}

func clientAnon(t *testing.T, apiRoot string, anonymous bool) *Client {
	t.Helper()
	id, err := afid.New("af1.akma.example", afid.UaStarDigest)
	if err != nil {
		t.Fatal(err)
	}
	return New(apiRoot, id, anonymous)
}

func writeJSON(w http.ResponseWriter, status int, contentType string, v any) {
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// TestApplicationKey: afId in transport form, aKId exactly as given; K_AF,
// expiry and SUPI read from AkmaAfKeyData.
func TestApplicationKey(t *testing.T) {
	kaf := kdf.Key{1, 2, 3}
	exp := time.Date(2026, 10, 18, 13, 0, 0, 0, time.UTC)
	var got models.AkmaAfKeyRequest
	root := fakeAanf(t, func(w http.ResponseWriter, req models.AkmaAfKeyRequest) {
		got = req
		writeJSON(w, http.StatusOK, "application/json",
			models.AkmaAfKeyData{Kaf: codec.HexKey(kaf), Expiry: &exp, Supi: "imsi-208930000000001"})
	})
	k, err := client(t, root).ApplicationKey(context.Background(), testAKid)
	if err != nil {
		t.Fatal(err)
	}
	if got.AfId != "af1.akma.example.FF00000001" || got.AKId != testAKid || got.AnonInd {
		t.Fatalf("request %+v", got)
	}
	if k.KAf != kaf || !k.Expiry.Equal(exp) || k.Supi != "imsi-208930000000001" {
		t.Fatalf("key %+v", k)
	}
}

// TestApplicationKeyAnonymous: an anonymous AF sends anonInd
// (TS 33.535 cl. 6.2.2; TS 29.535 cl. 4.2.2.3.2).
func TestApplicationKeyAnonymous(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	var got models.AkmaAfKeyRequest
	root := fakeAanf(t, func(w http.ResponseWriter, req models.AkmaAfKeyRequest) {
		got = req
		writeJSON(w, http.StatusOK, "application/json", models.AkmaAfKeyData{Kaf: codec.HexKey(kdf.Key{7}), Expiry: &exp})
	})
	k, err := clientAnon(t, root, true).ApplicationKey(context.Background(), testAKid)
	if err != nil {
		t.Fatal(err)
	}
	if !got.AnonInd || k.Supi != "" {
		t.Fatalf("request %+v, key SUPI %q", got, k.Supi)
	}
}

func TestApplicationKeyErrors(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	for name, tc := range map[string]struct {
		handler func(w http.ResponseWriter, req models.AkmaAfKeyRequest)
		want    error
	}{
		"K_AKMA_NOT_PRESENT": {func(w http.ResponseWriter, _ models.AkmaAfKeyRequest) {
			writeJSON(w, http.StatusForbidden, "application/problem+json",
				models.ProblemDetails{Status: 403, Cause: "K_AKMA_NOT_PRESENT"})
		}, ErrKeyNotAvailable},
		"AF not authorized": {func(w http.ResponseWriter, _ models.AkmaAfKeyRequest) {
			writeJSON(w, http.StatusForbidden, "application/problem+json",
				models.ProblemDetails{Status: 403, Detail: "AF not authorized by local policy"})
		}, ErrUnavailable},
		"internal error": {func(w http.ResponseWriter, _ models.AkmaAfKeyRequest) {
			writeJSON(w, http.StatusInternalServerError, "application/problem+json",
				models.ProblemDetails{Status: 500, Cause: "SYSTEM_FAILURE"})
		}, ErrUnavailable},
		"malformed kaf": {func(w http.ResponseWriter, _ models.AkmaAfKeyRequest) {
			writeJSON(w, http.StatusOK, "application/json", models.AkmaAfKeyData{Kaf: "zz", Expiry: &exp})
		}, ErrUnavailable},
		"no expiry": {func(w http.ResponseWriter, _ models.AkmaAfKeyRequest) {
			writeJSON(w, http.StatusOK, "application/json", models.AkmaAfKeyData{Kaf: codec.HexKey(kdf.Key{})})
		}, ErrUnavailable},
		"204": {func(w http.ResponseWriter, _ models.AkmaAfKeyRequest) {
			w.WriteHeader(http.StatusNoContent)
		}, ErrUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := client(t, fakeAanf(t, tc.handler)).ApplicationKey(context.Background(), testAKid)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestApplicationKeyUnreachable(t *testing.T) {
	_, err := client(t, "http://127.0.0.1:1").ApplicationKey(context.Background(), testAKid)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v", err)
	}
}
