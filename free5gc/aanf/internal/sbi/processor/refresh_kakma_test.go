package processor

import (
	"sync"
	"testing"
	"time"

	aanf_context "github.com/florianoneto07/akma-free5gc/free5gc/aanf/internal/context"
	"github.com/florianoneto07/akma-free5gc/free5gc/aanf/pkg/factory"
	"github.com/florianoneto07/akma-free5gc/shared/akma/akid"
	"github.com/florianoneto07/akma-free5gc/shared/akma/kdf"
)

type refreshApp struct{ ctx *aanf_context.AANFContext }

func (a *refreshApp) SetLogEnable(bool)                  {}
func (a *refreshApp) SetLogLevel(string)                 {}
func (a *refreshApp) SetReportCaller(bool)               {}
func (a *refreshApp) Start()                             {}
func (a *refreshApp) Terminate()                         {}
func (a *refreshApp) Context() *aanf_context.AANFContext { return a.ctx }
func (a *refreshApp) Config() *factory.Config            { return nil }

type refresher struct {
	mu    sync.Mutex
	supis []string
	done  chan struct{}
}

func (r *refresher) TriggerAuth(supi string) error {
	r.mu.Lock()
	r.supis = append(r.supis, supi)
	r.mu.Unlock()
	r.done <- struct{}{}
	return nil
}

// TS 33.535 cl. 6.4.4: a K_AF request for an old K_AKMA asks the UDM once
// for the refresh; nothing is asked with the policy disabled.
func TestRefreshKAkma(t *testing.T) {
	const supi = "imsi-208930000000001"
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	store := aanf_context.NewStore()
	store.SetClock(func() time.Time { return now })
	id, err := akid.Parse("rid0000.atidAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=@5gc.mnc093.mcc208.3gppnetwork.org",
		akid.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	store.Register(supi, id, "a-kid", kdf.Key{1})

	ctx := &aanf_context.AANFContext{Store: store}
	r := &refresher{done: make(chan struct{}, 4)}
	p := &Processor{ProcessorAanf: &refreshApp{ctx: ctx}, Refresher: r}

	now = now.Add(time.Hour)
	p.refreshKAkma(supi)
	ctx.KakmaRefresh = 30 * time.Minute
	p.refreshKAkma(supi)
	select {
	case <-r.done:
	case <-time.After(2 * time.Second):
		t.Fatal("no Nudm_UECM_AuthTrigger")
	}
	p.refreshKAkma(supi)
	select {
	case <-r.done:
		t.Fatal("second Nudm_UECM_AuthTrigger for the same K_AKMA")
	case <-time.After(100 * time.Millisecond):
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.supis) != 1 || r.supis[0] != supi {
		t.Errorf("triggers: %v", r.supis)
	}
}
