package consumer

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/free5gc/openapi/models"
)

// fakeUdm answers the discovery of the UDM, as the NRF, and trigger-auth, as
// the UDM, on the same server.
type fakeUdm struct {
	mu          sync.Mutex
	url         string
	discoveries int
	triggers    []string
	userAgents  []string
	status      int
}

func (u *fakeUdm) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u.mu.Lock()
	defer u.mu.Unlock()
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/nnrf-disc/v1/nf-instances":
		u.discoveries++
		q := r.URL.Query()
		if q.Get("target-nf-type") != "UDM" || q.Get("requester-nf-type") != "AANF" {
			http.Error(w, "unexpected query "+r.URL.RawQuery, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(models.SearchResult{NfInstances: []models.NrfNfDiscoveryNfProfile{{
			NfInstanceId: "5f2c0d3e-0000-4000-8000-000000000003",
			NfType:       models.NrfNfManagementNfType_UDM,
			NfStatus:     models.NrfNfManagementNfStatus_REGISTERED,
			NfServices: []models.NrfNfDiscoveryNfService{{
				ServiceInstanceId: "0",
				ServiceName:       models.ServiceName_NUDM_UECM,
				Scheme:            models.UriScheme_HTTP,
				NfServiceStatus:   models.NfServiceStatus_REGISTERED,
				ApiPrefix:         u.url,
			}},
		}}})
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/registrations/trigger-auth"):
		body, _ := io.ReadAll(r.Body)
		var info models.AuthTriggerInfo
		_ = json.Unmarshal(body, &info)
		ueID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/nudm-uecm/v1/"), "/registrations/trigger-auth")
		if info.Supi != ueID {
			http.Error(w, "supi "+info.Supi+" for "+ueID, http.StatusBadRequest)
			return
		}
		u.triggers = append(u.triggers, info.Supi)
		u.userAgents = append(u.userAgents, r.UserAgent())
		if u.status == http.StatusNoContent {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(u.status)
		_ = json.NewEncoder(w).Encode(models.ProblemDetails{
			Status: int32(u.status), Cause: "REAUTHENTICATION_NOT_ALLOWED", Detail: "interval",
		})
	default:
		http.Error(w, r.Method+" "+r.URL.Path, http.StatusNotFound)
	}
}

// TS 29.503 cl. 5.3.2.16; TS 33.535 cl. 6.4.4.
func TestTriggerAuth(t *testing.T) {
	udm := &fakeUdm{status: http.StatusNoContent}
	ts := httptest.NewServer(h2c.NewHandler(udm, &http2.Server{}))
	t.Cleanup(ts.Close)
	udm.url = ts.URL
	c, ctx := newConsumer(t, &fakeNRF{}, nil)
	ctx.NrfUri = ts.URL

	const supi = "imsi-208930000000001"
	if err := c.TriggerAuth(supi); err != nil {
		t.Fatal(err)
	}
	udm.mu.Lock()
	udm.status = http.StatusForbidden
	udm.mu.Unlock()
	err := c.TriggerAuth(supi)
	if err == nil || !strings.Contains(err.Error(), "403 REAUTHENTICATION_NOT_ALLOWED") {
		t.Fatalf("refused trigger: %v", err)
	}

	udm.mu.Lock()
	defer udm.mu.Unlock()
	if udm.discoveries != 1 {
		t.Errorf("%d discoveries of the UDM, want 1", udm.discoveries)
	}
	if len(udm.triggers) != 2 {
		t.Fatalf("triggers: %v", udm.triggers)
	}
	// TS 29.500 table 5.2.2.2-1: the User-Agent starts with the NF type.
	if want := "AANF-" + ctx.NfId; udm.userAgents[0] != want {
		t.Errorf("User-Agent %q, want %q", udm.userAgents[0], want)
	}
}
