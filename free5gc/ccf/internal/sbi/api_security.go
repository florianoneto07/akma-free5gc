package sbi

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"

	"github.com/gin-gonic/gin"

	ccf_context "github.com/florianoneto07/akma-free5gc/free5gc/ccf/internal/context"
	"github.com/florianoneto07/akma-free5gc/free5gc/ccf/internal/logger"
	"github.com/florianoneto07/akma-free5gc/free5gc/ccf/internal/util"
	"github.com/free5gc/openapi/models"
)

// HTTPObtainSecurityMethod is Obtain_Security_Method: PUT .../trustedInvokers/
// {apiInvokerId} (TS 29.222 cl. 5.6.2.2 and 8.5.2.3.3.3), with the client
// certificate of the API invoker. For each item, the CCF selects the first
// method preferred by the API invoker that the AEF published and that its
// policy accepts: only OAUTH (TS 33.122 cl. 6.3.1.2 step 3). Without a common
// method, selSecurityMethod is absent (table 8.5.4.2.3-1).
func (s *Server) HTTPObtainSecurityMethod(c *gin.Context) {
	ctx := s.Context()
	id := c.Param("apiInvokerId")
	if !requireInvoker(c, id) {
		return
	}
	if _, ok := ctx.Invoker(id); !ok {
		util.WriteProblem(c, util.Problem(http.StatusNotFound, "", "unknown API invoker"))
		return
	}
	var req models.CapifServiceSecurity
	if !readJSON(c, &req) {
		return
	}
	switch {
	case len(req.SecurityInfo) == 0:
		util.WriteProblem(c, util.Problem(http.StatusBadRequest, util.CauseMandatoryIEMissing, "",
			util.Param("/securityInfo", "missing")))
		return
	case req.NotificationDestination == "":
		util.WriteProblem(c, util.Problem(http.StatusBadRequest, util.CauseMandatoryIEMissing, "",
			util.Param("/notificationDestination", "missing")))
		return
	case !isAbsoluteURI(req.NotificationDestination):
		util.WriteProblem(c, util.Problem(http.StatusBadRequest, util.CauseMandatoryIEIncorrect, "",
			util.Param("/notificationDestination", "not an absolute URI")))
		return
	}

	items := make([]models.CapifSecurityInformation, len(req.SecurityInfo))
	aefs := make([]string, len(req.SecurityInfo))
	for i, si := range req.SecurityInfo {
		at := fmt.Sprintf("/securityInfo/%d", i)
		if (si.AefId == "") == (si.InterfaceDetails == nil) {
			util.WriteProblem(c, util.Problem(http.StatusBadRequest, util.CauseMandatoryIEIncorrect, "",
				util.Param(at, "exactly one of aefId and interfaceDetails")))
			return
		}
		if len(si.PrefSecurityMethods) == 0 {
			util.WriteProblem(c, util.Problem(http.StatusBadRequest, util.CauseMandatoryIEMissing, "",
				util.Param(at+"/prefSecurityMethods", "missing")))
			return
		}
		aef := si.AefId
		if si.InterfaceDetails != nil {
			aef, _ = ctx.AefByInterface(*si.InterfaceDetails)
		}
		si.SelSecurityMethod = ""
		si.AuthenticationInfo, si.AuthorizationInfo = "", ""
		if aef != "" {
			published := ctx.AefSecurityMethods(aef)
			for _, m := range si.PrefSecurityMethods {
				if m == models.CapifSecurityMethod_OAUTH && slices.Contains(published, m) {
					si.SelSecurityMethod = m
					break
				}
			}
		}
		items[i], aefs[i] = si, aef
	}
	ctx.SetSecurityContext(id, ccf_context.SecurityContext{
		Items: items, Aefs: aefs, NotificationDestination: req.NotificationDestination,
	})
	c.Header("Location", s.externalRoot()+securityPrefix+"/trustedInvokers/"+id)
	util.WriteJSON(c, http.StatusCreated, models.CapifServiceSecurity{
		SecurityInfo:            items,
		NotificationDestination: req.NotificationDestination,
		SupportedFeatures:       "0",
	})
	for i, si := range items {
		if si.SelSecurityMethod != "" {
			logger.CapifLog.Infof("Security method %s for API invoker %s at AEF %s", si.SelSecurityMethod, id, aefs[i])
		} else {
			logger.CapifLog.Warnf("No common security method for API invoker %s at AEF %q", id, aefs[i])
		}
	}
}

// tokenError answers an access token request with AccessTokenErr (TS 29.222
// table 8.5.2.3.4.4.2-3; RFC 6749 cl. 5.2): 401 with a Basic challenge for
// invalid_client when the client authenticated with HTTP Basic, 400 otherwise.
func tokenError(c *gin.Context, code, description string, basic bool) {
	status := http.StatusBadRequest
	if code == models.CapifAccessTokenErrError_INVALID_CLIENT && basic {
		status = http.StatusUnauthorized
		c.Header("WWW-Authenticate", `Basic realm="capif-security"`)
	}
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	util.WriteJSON(c, status, models.CapifAccessTokenErr{Error: code, ErrorDescription: description})
	c.Abort()
}

// HTTPObtainAuthorization is Obtain_Authorization: POST .../securities/
// {securityId}/token (TS 29.222 cl. 5.6.2.3.2 and 8.5.2.3.4.4; TS 33.122
// cl. 6.5.2.3 and Annex C), in application/x-www-form-urlencoded. The client
// is authenticated by the client certificate of the API invoker and by the
// onboarding secret, in client_secret or with HTTP Basic.
func (s *Server) HTTPObtainAuthorization(c *gin.Context) {
	ctx := s.Context()
	securityId := c.Param("securityId")
	body, ok := readBody(c, "application/x-www-form-urlencoded")
	if !ok {
		return
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		tokenError(c, models.CapifAccessTokenErrError_INVALID_REQUEST, "malformed form", false)
		return
	}
	user, pass, basic := c.Request.BasicAuth()
	clientId, secret := form.Get("client_id"), form.Get("client_secret")
	if basic {
		if clientId == "" {
			clientId = user
		}
		secret = pass
	}
	cn, certOK := invokerFromCert(c)
	inv, known := ctx.Invoker(securityId)
	if !certOK || cn != securityId || clientId != securityId || (basic && user != securityId) || !known ||
		subtle.ConstantTimeCompare([]byte(secret), []byte(inv.Secret)) != 1 {
		logger.CapifLog.Warnf("Access token refused for API invoker %s: client authentication failed", securityId)
		tokenError(c, models.CapifAccessTokenErrError_INVALID_CLIENT, "client authentication failed", basic)
		return
	}
	switch grant := form.Get("grant_type"); {
	case grant == "":
		tokenError(c, models.CapifAccessTokenErrError_INVALID_REQUEST, "grant_type missing", basic)
		return
	case grant != "client_credentials":
		tokenError(c, models.CapifAccessTokenErrError_UNSUPPORTED_GRANT_TYPE, "only client_credentials", basic)
		return
	}
	if inv.Security == nil {
		tokenError(c, models.CapifAccessTokenErrError_UNAUTHORIZED_CLIENT,
			"no security method obtained for the API invoker", basic)
		return
	}
	oauthAefs := map[string]bool{}
	for i, si := range inv.Security.Items {
		if si.SelSecurityMethod == models.CapifSecurityMethod_OAUTH && inv.Security.Aefs[i] != "" {
			oauthAefs[inv.Security.Aefs[i]] = true
		}
	}
	profile, _ := s.Config().Profile(inv.Profile)
	granted := ccf_context.Scope{}
	if requested := form.Get("scope"); requested != "" {
		scope, err := ccf_context.ParseScope(requested)
		if err != nil {
			tokenError(c, models.CapifAccessTokenErrError_INVALID_SCOPE, err.Error(), basic)
			return
		}
		for aef, apis := range scope {
			if !oauthAefs[aef] {
				tokenError(c, models.CapifAccessTokenErrError_INVALID_SCOPE,
					"no OAUTH security method at AEF "+aef, basic)
				return
			}
			for _, api := range apis {
				if !slices.Contains(profile.Apis, api) || !ctx.AefPublishes(aef, api) {
					tokenError(c, models.CapifAccessTokenErrError_INVALID_SCOPE,
						"API "+api+" not allowed at AEF "+aef, basic)
					return
				}
			}
		}
		granted = scope
	} else {
		// Without scope, every API of the profile published at an AEF with
		// OAUTH (RFC 6749 cl. 3.3).
		for aef := range oauthAefs {
			for _, api := range profile.Apis {
				if ctx.AefPublishes(aef, api) {
					granted[aef] = append(granted[aef], api)
				}
			}
		}
		if len(granted) == 0 {
			tokenError(c, models.CapifAccessTokenErrError_INVALID_SCOPE, "no API to grant", basic)
			return
		}
	}

	token, expiresIn, err := ctx.IssueToken(inv.Id, granted.String())
	if err != nil {
		logger.CapifLog.Errorf("Access token for API invoker %s: %v", inv.Id, err)
		util.WriteProblem(c, util.Problem(http.StatusInternalServerError, util.CauseSystemFailure, ""))
		return
	}
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	util.WriteJSON(c, http.StatusOK, models.CapifAccessTokenRsp{
		AccessToken: token,
		TokenType:   "Bearer",
		ExpiresIn:   expiresIn,
		Scope:       granted.String(),
	})
	logger.CapifLog.Infof("Access token for API invoker %s, scope %s, expires in %d s", inv.Id, granted, expiresIn)
}

// authorizationInfo is the content of authorizationInfo for the AEF: the
// AF_IDs the NEF accepts from the API invoker (TS 33.535 cl. 6.3 step 2).
// TS 29.222 table 8.5.4.2.3-1 does not define the format of this string.
type authorizationInfo struct {
	AkmaAfIds []string `json:"akmaAfIds"`
}

// boolQuery reads an optional boolean query parameter.
func boolQuery(q url.Values, name string) (bool, bool) {
	switch q.Get(name) {
	case "", "false":
		return false, true
	case "true":
		return true, true
	}
	return false, false
}

// HTTPObtainAPIInvokerInfo is Obtain_API_Invoker_Info: GET .../
// trustedInvokers/{apiInvokerId} (TS 29.222 cl. 5.6.2.4 and 8.5.2.3.3.1), on
// the internal interface. Only the items of the AEFs of the client (TS 33.122
// cl. 6.6). Without TLS on CAPIF-3, the CCF does not know which AEF asks and
// gives every item of the security context.
func (s *Server) HTTPObtainAPIInvokerInfo(c *gin.Context) {
	ctx := s.Context()
	var aefIds []string
	if c.Request.TLS != nil {
		p, known := s.clientProvider(c)
		if !known {
			util.WriteProblem(c, util.Problem(http.StatusForbidden, "", "the client certificate is of no API provider"))
			return
		}
		aefIds = p.AefIds
	}
	q := c.Request.URL.Query()
	authn, ok1 := boolQuery(q, "authenticationInfo")
	authz, ok2 := boolQuery(q, "authorizationInfo")
	if !ok1 || !ok2 {
		util.WriteProblem(c, util.Problem(http.StatusBadRequest, util.CauseOptionalQueryParamIncorrect, "",
			util.Param("authenticationInfo, authorizationInfo", "true or false")))
		return
	}
	id := c.Param("apiInvokerId")
	inv, ok := ctx.Invoker(id)
	if !ok || inv.Security == nil {
		util.WriteProblem(c, util.Problem(http.StatusNotFound, "", "unknown API invoker or no security context"))
		return
	}
	var info string
	if authz {
		profile, _ := s.Config().Profile(inv.Profile)
		ids := profile.AfIds
		if ids == nil {
			ids = []string{}
		}
		b, err := json.Marshal(authorizationInfo{AkmaAfIds: ids})
		if err != nil {
			util.WriteProblem(c, util.Problem(http.StatusInternalServerError, util.CauseSystemFailure, ""))
			return
		}
		info = string(b)
	}
	items := make([]models.CapifSecurityInformation, 0, len(inv.Security.Items))
	for i, item := range inv.Security.Items {
		if inv.Security.Aefs[i] != "" {
			// The AEF resolved from interfaceDetails replaces it: only one of
			// the two is present (table 8.5.4.2.3-1).
			item.AefId = inv.Security.Aefs[i]
			item.InterfaceDetails = nil
		}
		if aefIds != nil && !slices.Contains(aefIds, item.AefId) {
			continue
		}
		if authn {
			// The CA of the CCF, for the AEF to validate the certificate of
			// the API invoker (TS 33.122 cl. 6.5.2.3 step 5).
			item.AuthenticationInfo = ctx.CaPEM()
		}
		if authz {
			item.AuthorizationInfo = info
		}
		items = append(items, item)
	}
	if len(items) == 0 {
		util.WriteProblem(c, util.Problem(http.StatusNotFound, "", "no security context for this AEF"))
		return
	}
	util.WriteJSON(c, http.StatusOK, models.CapifServiceSecurity{
		SecurityInfo:            items,
		NotificationDestination: inv.Security.NotificationDestination,
	})
	logger.CapifLog.Infof("Security information of API invoker %s given to the internal interface", id)
}
