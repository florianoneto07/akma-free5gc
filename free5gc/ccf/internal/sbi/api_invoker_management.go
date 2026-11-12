package sbi

import (
	"net/http"
	"slices"

	"github.com/gin-gonic/gin"

	ccf_context "github.com/florianoneto07/akma-free5gc/free5gc/ccf/internal/context"
	"github.com/florianoneto07/akma-free5gc/free5gc/ccf/internal/credential"
	"github.com/florianoneto07/akma-free5gc/free5gc/ccf/internal/logger"
	"github.com/florianoneto07/akma-free5gc/free5gc/ccf/internal/util"
	"github.com/florianoneto07/akma-free5gc/free5gc/ccf/pkg/factory"
	"github.com/free5gc/openapi/models"
)

// HTTPOnboard is Onboard_API_Invoker: POST .../onboardedInvokers (TS 29.222
// cl. 5.5.2.2 and 8.4.2.2.3.1). The CCF onboards automatically the API
// invokers with a valid onboarding credential (NOTE 1 of cl. 5.5.2.2.2).
func (s *Server) HTTPOnboard(c *gin.Context) {
	ctx := s.Context()
	token := credential.FromAuthorization(c.GetHeader("Authorization"))
	if token == "" {
		logger.CapifLog.Warnf("Onboarding refused: no onboarding credential")
		writeUnauthorized(c, false, "onboarding credential missing")
		return
	}
	name, err := credential.Verify(token, &ctx.CredentialKey().PublicKey,
		s.Config().Configuration.CcfName, ctx.Now())
	if err != nil {
		logger.CapifLog.Warnf("Onboarding refused: %v", err)
		writeUnauthorized(c, true, "onboarding credential invalid")
		return
	}
	profile, ok := s.Config().Profile(name)
	if !ok {
		logger.CapifLog.Warnf("Onboarding refused: unknown profile %s", name)
		writeUnauthorized(c, true, "onboarding credential of an unknown profile")
		return
	}

	var req models.CapifApiInvokerEnrolmentDetails
	if !readJSON(c, &req) {
		return
	}
	if pd := checkEnrolment(&req); pd != nil {
		util.WriteProblem(c, pd)
		return
	}
	pub, err := ccf_context.ParseInvokerPublicKey(req.OnboardingInformation.ApiInvokerPublicKey)
	if err != nil {
		util.WriteProblem(c, util.Problem(http.StatusBadRequest, util.CauseMandatoryIEIncorrect, "",
			util.Param("/onboardingInformation/apiInvokerPublicKey", err.Error())))
		return
	}

	inv, err := ctx.Onboard(profile.Name, req.OnboardingInformation.ApiInvokerPublicKey, pub,
		req.NotificationDestination, req.ApiInvokerInformation)
	if err != nil {
		logger.CapifLog.Errorf("Onboarding failed: %v", err)
		util.WriteProblem(c, util.Problem(http.StatusInternalServerError, util.CauseSystemFailure, ""))
		return
	}
	rsp := models.CapifApiInvokerEnrolmentDetails{
		ApiInvokerId: inv.Id,
		OnboardingInformation: &models.CapifOnboardingInformation{
			ApiInvokerPublicKey:   inv.PublicKey,
			ApiInvokerCertificate: inv.Certificate,
			OnboardingSecret:      inv.Secret,
		},
		NotificationDestination: inv.NotificationDestination,
		ApiInvokerInformation:   inv.Information,
		ApiList:                 s.apiList(profile),
		SupportedFeatures:       "0",
	}
	c.Header("Location", s.externalRoot()+invokerManagementPrefix+"/onboardedInvokers/"+inv.Id)
	util.WriteJSON(c, http.StatusCreated, rsp)
	logger.CapifLog.Infof("API invoker %s onboarded, profile %s", inv.Id, profile.Name)
}

// checkEnrolment checks the attributes of an onboarding request (TS 29.222
// tables 8.4.4.2.2-1 and 8.4.4.2.5-1).
func checkEnrolment(req *models.CapifApiInvokerEnrolmentDetails) *models.ProblemDetails {
	missing := func(param string) *models.ProblemDetails {
		return util.Problem(http.StatusBadRequest, util.CauseMandatoryIEMissing, "", util.Param(param, "missing"))
	}
	switch {
	case req.ApiInvokerId != "":
		return util.Problem(http.StatusBadRequest, util.CauseOptionalIEIncorrect, "",
			util.Param("/apiInvokerId", "shall not be present in the onboarding request"))
	case req.OnboardingInformation == nil:
		return missing("/onboardingInformation")
	case req.OnboardingInformation.ApiInvokerPublicKey == "":
		return missing("/onboardingInformation/apiInvokerPublicKey")
	case req.NotificationDestination == "":
		return missing("/notificationDestination")
	case !isAbsoluteURI(req.NotificationDestination):
		return util.Problem(http.StatusBadRequest, util.CauseMandatoryIEIncorrect, "",
			util.Param("/notificationDestination", "not an absolute URI"))
	case req.SupportedFeatures == "":
		// "shall be provided in the HTTP POST request" (table 8.4.4.2.2-1)
		return missing("/supportedFeatures")
	case !supportedFeaturesPattern.MatchString(req.SupportedFeatures):
		return util.Problem(http.StatusBadRequest, util.CauseMandatoryIEIncorrect, "",
			util.Param("/supportedFeatures", "not a SupportedFeatures string"))
	}
	return nil
}

// apiList returns the published service APIs of the invoker profile, the
// APIs the API invoker is allowed to invoke, or nil when there is none.
func (s *Server) apiList(profile factory.InvokerProfile) *models.CapifApiList {
	var out []models.CapifServiceApiDescription
	for _, d := range s.Context().PublishedAPIs("") {
		if slices.Contains(profile.Apis, d.ApiName) {
			d.ShareableInfo = nil
			out = append(out, d)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return &models.CapifApiList{ServiceAPIDescriptions: out}
}

// HTTPOffboard is Offboard_API_Invoker: DELETE .../onboardedInvokers/
// {onboardingId} (TS 29.222 cl. 5.5.2.3 and 8.4.2.3.3.1), with the client
// certificate of the API invoker. The CCF deletes the profile, the security
// context and the onboarding secret (TS 33.122 cl. 6.8 step 3), and revokes
// the certificate.
func (s *Server) HTTPOffboard(c *gin.Context) {
	id := c.Param("onboardingId")
	if !requireInvoker(c, id) {
		return
	}
	if !s.Context().Offboard(id) {
		util.WriteProblem(c, util.Problem(http.StatusNotFound, "", "unknown API invoker"))
		return
	}
	// "The CAPIF core function shall tear down the TLS session with the API
	// invoker" (TS 33.122 cl. 6.8 step 6): net/http closes the connection
	// after the response, or sends GOAWAY on HTTP/2.
	c.Header("Connection", "close")
	c.Status(http.StatusNoContent)
	logger.CapifLog.Infof("API invoker %s offboarded", id)
}
