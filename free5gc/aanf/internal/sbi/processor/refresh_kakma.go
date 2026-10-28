package processor

import (
	"time"

	"github.com/florianoneto07/akma-free5gc/free5gc/aanf/internal/logger"
)

// kakmaRefreshRetry is the wait before the AAnF asks again for the refresh
// of a K_AKMA that did not change.
const kakmaRefreshRetry = 5 * time.Minute

// KAkmaRefresher asks the UDM for a new primary authentication of a UE
// (Nudm_UECM_AuthTrigger, TS 29.503 cl. 5.3.2.16).
type KAkmaRefresher interface {
	TriggerAuth(supi string) error
}

// refreshKAkma applies the local authentication policy of TS 33.535
// cl. 6.4.4 after a K_AF was provided for the K_AKMA of supi: when that
// K_AKMA is older than akma.kakmaRefresh, the AAnF asks the UDM for a new
// primary authentication, which re-keys K_AKMA (cl. 6.4.1). It asks once per
// K_AKMA, and again after kakmaRefreshRetry if the K_AKMA did not change. The
// K_AF already issued stay valid until they expire (cl. 6.4.2).
func (p *Processor) refreshKAkma(supi string) {
	aanfCtx := p.Context()
	if aanfCtx.KakmaRefresh <= 0 || p.Refresher == nil {
		return
	}
	age, due := aanfCtx.Store.RefreshDue(supi, aanfCtx.KakmaRefresh, kakmaRefreshRetry)
	if !due {
		return
	}
	logger.AkmaLog.Infof("K_AKMA of %s registered %s ago: refresh requested from the UDM (TS 33.535 cl. 6.4.4)",
		supi, age.Round(time.Second))
	go func() {
		if err := p.Refresher.TriggerAuth(supi); err != nil {
			logger.AkmaLog.Warnf("Refresh of K_AKMA of %s not accepted by the UDM: %v", supi, err)
			return
		}
		logger.AkmaLog.Infof("Refresh of K_AKMA of %s accepted by the UDM: new primary authentication requested", supi)
	}()
}
