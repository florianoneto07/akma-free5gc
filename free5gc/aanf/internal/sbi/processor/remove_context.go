package processor

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/florianoneto07/akma-free5gc/free5gc/aanf/internal/logger"
	"github.com/florianoneto07/akma-free5gc/free5gc/aanf/internal/util"
	"github.com/free5gc/openapi/models"
)

// RemoveContext deletes the AKMA context of a UE (Naanf_AKMA_ContextRemove,
// TS 29.535 cl. 4.2.2.4.2; TS 33.535 cl. 6.6.1).
func (p *Processor) RemoveContext(c *gin.Context, req *models.CtxRemove) {
	// TS 29.535 table 5.1.6.2.3-1 NOTE: "The "supi" attribute shall be
	// included."
	if req.Supi == "" {
		util.WriteProblem(c, util.Problem(http.StatusBadRequest, util.CauseMandatoryIEMissing, "",
			util.Param("/supi", "required")))
		return
	}
	if !p.Context().Store.Remove(req.Supi) {
		logger.AkmaLog.Infof("AKMA context of %s to remove not found", req.Supi)
		util.WriteProblem(c, util.Problem(http.StatusNotFound, util.CauseAkmaContextNotFound, ""))
		return
	}
	logger.AkmaLog.Infof("AKMA context of %s removed", req.Supi)
	c.Status(http.StatusNoContent)
}
