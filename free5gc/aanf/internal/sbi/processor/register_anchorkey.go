package processor

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/florianoneto07/akma-free5gc/free5gc/aanf/internal/logger"
	"github.com/florianoneto07/akma-free5gc/free5gc/aanf/internal/util"
	"github.com/florianoneto07/akma-free5gc/shared/akma/akid"
	"github.com/florianoneto07/akma-free5gc/shared/akma/codec"
	"github.com/free5gc/openapi/models"
)

// RegisterAnchorKey stores the AKMA related key material sent by the AUSF
// (Naanf_AKMA_AnchorKey_Register, TS 29.535 cl. 4.2.2.2.2; TS 33.535 cl. 6.1
// steps 4-5).
func (p *Processor) RegisterAnchorKey(c *gin.Context, req *models.AkmaKeyInfo) {
	aanfCtx := p.Context()

	if pd := validateAkmaKeyInfo(req); pd != nil {
		util.WriteProblem(c, pd)
		return
	}
	id, err := akid.Parse(req.AKId, aanfCtx.AKidOptions)
	if err != nil {
		util.WriteProblem(c, util.Problem(http.StatusBadRequest, util.CauseMandatoryIEIncorrect, "",
			util.Param("/aKId", "not an A-KID \"rid<RID>.<label><A-TID>@<realm>\"")))
		return
	}
	kAkma, err := codec.ParseHexKey(req.KAkma)
	if err != nil {
		util.WriteProblem(c, util.Problem(http.StatusBadRequest, util.CauseMandatoryIEIncorrect, "",
			util.Param("/kAkma", "expected 64 hexadecimal characters")))
		return
	}

	replaced := aanfCtx.Store.Register(req.Supi, id, req.AKId, kAkma)
	if replaced {
		logger.AkmaLog.Infof("AKMA context of %s registered, A-KID %s (previous context replaced)",
			req.Supi, req.AKId)
	} else {
		logger.AkmaLog.Infof("AKMA context of %s registered, A-KID %s", req.Supi, req.AKId)
	}

	rsp := models.AkmaKeyInfo{
		Supi:     req.Supi,
		AKId:     req.AKId,
		KAkma:    req.KAkma,
		SuppFeat: negotiatedFeatures(req.SuppFeat),
	}
	util.WriteJSON(c, http.StatusOK, rsp)
}

// validateAkmaKeyInfo checks the presence conditions of TS 29.535 table
// 5.1.6.2.2-1.
func validateAkmaKeyInfo(req *models.AkmaKeyInfo) *models.ProblemDetails {
	var missing []models.InvalidParam
	// The AAnF does not support AKMA_GPSI_Support: "only the supi
	// attribute shall be present".
	if req.Supi == "" {
		missing = append(missing, util.Param("/supi", "required"))
	}
	if req.AKId == "" {
		missing = append(missing, util.Param("/aKId", "required"))
	}
	if req.KAkma == "" {
		missing = append(missing, util.Param("/kAkma", "required"))
	}
	if len(missing) > 0 {
		return util.Problem(http.StatusBadRequest, util.CauseMandatoryIEMissing, "", missing...)
	}
	if req.Gpsi != "" {
		return util.Problem(http.StatusBadRequest, util.CauseOptionalIEIncorrect, "",
			util.Param("/gpsi", "the AKMA_GPSI_Support feature is not supported"))
	}
	if !suppFeatPattern.MatchString(req.SuppFeat) {
		return util.Problem(http.StatusBadRequest, util.CauseOptionalIEIncorrect, "",
			util.Param("/suppFeat", "not a SupportedFeatures string"))
	}
	return nil
}
