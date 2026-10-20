package nrf

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/free5gc/openapi/models"
)

const nfID = "b6f417f0-06fa-4c38-b291-33066f5a5fe8"

// fakeNrf registers and deregisters NF instances over h2c, as the NRF does.
func fakeNrf(t *testing.T, oauth2 bool, got *models.NrfNfManagementNfProfile, deregistered *bool) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /nnrf-nfm/v1/nf-instances/{id}", func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(got); err != nil {
			t.Errorf("profile: %v", err)
		}
		rsp := *got
		rsp.CustomInfo = map[string]any{"oauth2": oauth2}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(rsp)
	})
	mux.HandleFunc("DELETE /nnrf-nfm/v1/nf-instances/{id}", func(w http.ResponseWriter, r *http.Request) {
		*deregistered = r.PathValue("id") == nfID
		w.WriteHeader(http.StatusNoContent)
	})
	ts := httptest.NewUnstartedServer(h2c.NewHandler(mux, &http2.Server{}))
	ts.Start()
	t.Cleanup(ts.Close)
	return "http://" + ts.Listener.Addr().(*net.TCPAddr).String()
}

func TestRegisterWithoutOAuth2(t *testing.T) {
	var got models.NrfNfManagementNfProfile
	var deregistered bool
	r, err := Register(context.Background(), fakeNrf(t, false, &got, &deregistered), nfID, "192.168.16.129")
	if err != nil {
		t.Fatal(err)
	}
	if got.NfInstanceId != nfID || got.NfType != models.NrfNfManagementNfType_AF ||
		len(got.Ipv4Addresses) != 1 || got.Ipv4Addresses[0] != "192.168.16.129" {
		t.Errorf("profile %+v", got)
	}
	if r.OAuth2() {
		t.Error("OAuth2 required")
	}
	// Without OAuth2, no token is requested.
	ctx := context.Background()
	if tctx, err := r.TokenCtx(ctx, models.NrfNfManagementNfType_NEF, "3gpp-akma"); err != nil || tctx != ctx {
		t.Errorf("TokenCtx: %v", err)
	}
	if err := r.Deregister(ctx); err != nil || !deregistered {
		t.Errorf("Deregister: %v", err)
	}
}
