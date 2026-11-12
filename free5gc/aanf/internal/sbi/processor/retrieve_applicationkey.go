package processor

import (
	"errors"
	"net"
	"net/http"
	"slices"
	"time"

	"github.com/gin-gonic/gin"

	aanf_context "github.com/florianoneto07/akma-free5gc/free5gc/aanf/internal/context"
	"github.com/florianoneto07/akma-free5gc/free5gc/aanf/internal/logger"
	"github.com/florianoneto07/akma-free5gc/free5gc/aanf/internal/util"
	"github.com/florianoneto07/akma-free5gc/shared/akma/afid"
	"github.com/florianoneto07/akma-free5gc/shared/akma/akid"
	"github.com/florianoneto07/akma-free5gc/shared/akma/codec"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/openapi/oauth"
	"github.com/free5gc/openapi/sbitls"
)

// RetrieveApplicationKey returns the K_AF of the requesting AF
// (Naanf_AKMA_ApplicationKey_Get and _AnonUser_Get, TS 29.535 cl. 4.2.2.3.2;
// TS 33.535 cl. 6.2.1, 6.2.2 and 6.3). The consumer, an AF or a NEF, is the NF
// instance of its client certificate; grant is what its access token gives,
// already verified, and nil without a token.
func (p *Processor) RetrieveApplicationKey(c *gin.Context, req *models.AkmaAfKeyRequest, grant *oauth.Grant) {
	aanfCtx := p.Context()

	if pd := validateAkmaAfKeyRequest(req); pd != nil {
		util.WriteProblem(c, pd)
		return
	}
	af, err := afid.Parse(req.AfId)
	if err != nil {
		util.WriteProblem(c, util.Problem(http.StatusBadRequest, util.CauseMandatoryIEIncorrect, "",
			util.Param("/afId", "expected \"<FQDN>.<Ua* security protocol id>\"")))
		return
	}
	id, err := akid.Parse(req.AKId, aanfCtx.AKidOptions)
	if err != nil {
		util.WriteProblem(c, util.Problem(http.StatusBadRequest, util.CauseMandatoryIEIncorrect, "",
			util.Param("/aKId", "not an A-KID \"rid<RID>.<label><A-TID>@<realm>\"")))
		return
	}

	// TS 33.535 cl. 6.2.1 step 2: the AAnF checks, with its local policy,
	// whether it can provide the service to the AF, and otherwise rejects
	// the procedure. Through a NEF, the request is processed in the same way
	// (cl. 6.3 step 3), with the AF_IDs accepted from that NEF. No application
	// error is defined for this case (TS 29.535 table 5.1.7.3-1): 403 without
	// cause. The source address is only for the log.
	instance, nfTypes := consumerOf(c)
	remote, _, _ := net.SplitHostPort(c.Request.RemoteAddr)
	viaNef := slices.Contains(nfTypes, string(models.NrfNfManagementNfType_NEF)) &&
		aanfCtx.NefPolicy.IsNef(instance) && (grant != nil || !aanfCtx.RequiresOAuth2())
	switch {
	case c.Request.TLS == nil:
		// The SBI over http, as in the test bench of free5GC: there is no
		// certificate, and the policy can only be the list of AF_IDs.
		if !aanfCtx.AfPolicy.Listed(af) {
			logger.AkmaLog.Warnf("AF at %s not authorized for AF_ID %s", remote, af.Transport())
			util.WriteProblem(c, util.Problem(http.StatusForbidden, "", "AF not authorized by local policy"))
			return
		}
	case viaNef && !aanfCtx.NefPolicy.Authorize(af, instance):
		logger.AkmaLog.Warnf("NEF %s at %s not authorized for AF_ID %s", instance, remote, af.Transport())
		util.WriteProblem(c, util.Problem(http.StatusForbidden, "", "AF_ID not accepted from this NEF"))
		return
	case !viaNef && !(slices.Contains(nfTypes, string(models.NrfNfManagementNfType_AF)) &&
		aanfCtx.AfPolicy.Authorize(af, instance)):
		logger.AkmaLog.Warnf("NF %s at %s not authorized for AF_ID %s", instance, remote, af.Transport())
		util.WriteProblem(c, util.Problem(http.StatusForbidden, "", "AF not authorized by local policy"))
		return
	}

	// The roaming status is not subscribed (TS 33.535 cl. 6.2.1 step 5 is not
	// implemented), so ROAMING_AKMA_SERVICE_DENIED is never returned. A K_AF
	// is always derivable when K_AKMA is present, so the "204 No Content" of
	// TS 29.535 cl. 4.2.2.3.2 is never returned either.
	supi, kaf, expiry, err := aanfCtx.Store.ApplicationKey(id, af, aanfCtx.KafLifetime)
	if errors.Is(err, aanf_context.ErrKAkmaNotPresent) {
		logger.AkmaLog.Infof("K_AKMA not present for A-KID %s, requested by AF_ID %s", req.AKId, af.Transport())
		util.WriteProblem(c, util.Problem(http.StatusForbidden, util.CauseKAkmaNotPresent, ""))
		return
	}
	if err != nil {
		logger.AkmaLog.Errorf("K_AF derivation failed: %v", err)
		util.WriteProblem(c, util.Problem(http.StatusInternalServerError, util.CauseSystemFailure, ""))
		return
	}

	exp := expiry.UTC()
	rsp := models.AkmaAfKeyData{
		Kaf:      codec.HexKey(kaf),
		Expiry:   &exp,
		SuppFeat: negotiatedFeatures(req.SuppFeat),
	}
	// TS 29.535 table 5.1.4.3.2-2 NOTE 2: "supi" is included except in the
	// anonymous user access procedure (TS 33.535 cl. 6.2.2). With an access
	// token, also only with the scope of the SUPI (table 5.1.9-1).
	if !req.AnonInd && (grant == nil || grant.Has(oauth.ScopeNaanfAkmaSupiAccess)) {
		rsp.Supi = supi
	}
	via := ""
	if viaNef {
		via = ", through the NEF at " + remote
	}
	if rsp.Supi == "" {
		via += ", without the SUPI"
	}
	logger.AkmaLog.Infof("K_AF of %s provided to AF_ID %s for A-KID %s, expires %s%s",
		supi, af.Transport(), req.AKId, exp.Format(time.RFC3339), via)
	util.WriteJSON(c, http.StatusOK, rsp)
	p.refreshKAkma(supi)
}

// consumerOf returns the NF instance ID and the NF types of the client
// certificate of a request (TS 33.310 cl. 6.1.3c.3), empty without them.
func consumerOf(c *gin.Context) (string, []string) {
	cert := sbitls.PeerCertificate(c.Request.TLS)
	if cert == nil {
		return "", nil
	}
	instance, err := sbitls.NfInstanceId(cert)
	if err != nil {
		return "", nil
	}
	nfTypes, err := sbitls.NfTypes(cert)
	if err != nil {
		return instance, nil
	}
	return instance, nfTypes
}

// validateAkmaAfKeyRequest checks the mandatory attributes of TS 29.522
// table 5.14.5.3.2-1. "notifUri" belongs to the RoamingRestriction feature,
// which is not supported, and is ignored.
func validateAkmaAfKeyRequest(req *models.AkmaAfKeyRequest) *models.ProblemDetails {
	var missing []models.InvalidParam
	if req.AfId == "" {
		missing = append(missing, util.Param("/afId", "required"))
	}
	if req.AKId == "" {
		missing = append(missing, util.Param("/aKId", "required"))
	}
	if len(missing) > 0 {
		return util.Problem(http.StatusBadRequest, util.CauseMandatoryIEMissing, "", missing...)
	}
	if !suppFeatPattern.MatchString(req.SuppFeat) {
		return util.Problem(http.StatusBadRequest, util.CauseOptionalIEIncorrect, "",
			util.Param("/suppFeat", "not a SupportedFeatures string"))
	}
	return nil
}
