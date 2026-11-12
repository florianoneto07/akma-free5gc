package sbi

import (
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/florianoneto07/akma-free5gc/free5gc/ccf/internal/logger"
	"github.com/florianoneto07/akma-free5gc/free5gc/ccf/internal/util"
	"github.com/florianoneto07/akma-free5gc/free5gc/ccf/pkg/factory"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/openapi/sbitls"
)

// provider answers 403 unless {apfId} is an API publishing function of the
// configuration, its authorization details are with the CCF (TS 23.222
// cl. 8.3.3, pre-condition 1), and the client is that API provider: the NF
// instance of its certificate (TS 33.122 cl. 6.6). Without TLS on CAPIF-3/4,
// the CCF recognizes it by the internal interface.
func (s *Server) provider(c *gin.Context) (factory.Provider, bool) {
	p, ok := s.Config().Provider(c.Param("apfId"))
	if !ok {
		util.WriteProblem(c, util.Problem(http.StatusForbidden, "", "unknown API publishing function"))
		return p, false
	}
	if c.Request.TLS != nil {
		if client, known := s.clientProvider(c); !known || client.ApfId != p.ApfId {
			util.WriteProblem(c, util.Problem(http.StatusForbidden, "", "the client certificate is of another API provider"))
			return p, false
		}
	}
	return p, true
}

// clientProvider returns the API provider of the client certificate of a
// request on the internal interface.
func (s *Server) clientProvider(c *gin.Context) (factory.Provider, bool) {
	cert := sbitls.PeerCertificate(c.Request.TLS)
	if cert == nil {
		return factory.Provider{}, false
	}
	id, err := sbitls.NfInstanceId(cert)
	if err != nil {
		return factory.Provider{}, false
	}
	return s.Config().ProviderOf(id)
}

// HTTPPublish is Publish_Service_API: POST .../{apfId}/service-apis
// (TS 29.222 cl. 5.3.2.2 and 8.2.2.2.3.1). The same service API published
// again by the same APF for one of the same AEFs replaces the previous one.
func (s *Server) HTTPPublish(c *gin.Context) {
	p, ok := s.provider(c)
	if !ok {
		return
	}
	var d models.CapifServiceApiDescription
	if !readJSON(c, &d) {
		return
	}
	if pd := checkServiceAPI(&d, p); pd != nil {
		util.WriteProblem(c, pd)
		return
	}
	d.SupportedFeatures = "0"
	stored, replaced := s.Context().Publish(p.ApfId, d)
	c.Header("Location", s.internalRoot()+publishPrefix+"/"+p.ApfId+"/service-apis/"+stored.ApiId)
	util.WriteJSON(c, http.StatusCreated, stored)
	aefs := make([]string, 0, len(stored.AefProfiles))
	for _, ap := range stored.AefProfiles {
		aefs = append(aefs, ap.AefId)
	}
	logger.CapifLog.Infof("%s published by %s as %s, AEF %s", stored.ApiName, p.ApfId, stored.ApiId,
		strings.Join(aefs, ", "))
	if len(replaced) > 0 {
		logger.CapifLog.Infof("%s replaces %s", stored.ApiId, strings.Join(replaced, ", "))
	}
}

// checkServiceAPI checks a service API to publish (TS 29.222 tables
// 8.2.4.2.2-1 to 8.2.4.2.4-1).
func checkServiceAPI(d *models.CapifServiceApiDescription, p factory.Provider) *models.ProblemDetails {
	missing := func(param string) *models.ProblemDetails {
		return util.Problem(http.StatusBadRequest, util.CauseMandatoryIEMissing, "", util.Param(param, "missing"))
	}
	incorrect := func(param, reason string) *models.ProblemDetails {
		return util.Problem(http.StatusBadRequest, util.CauseMandatoryIEIncorrect, "", util.Param(param, reason))
	}
	switch {
	case d.ApiName == "":
		return missing("/apiName")
	case d.ApiId != "":
		return util.Problem(http.StatusBadRequest, util.CauseOptionalIEIncorrect, "",
			util.Param("/apiId", "shall not be present in the publication request"))
	case d.SupportedFeatures == "":
		// NOTE 1 of table 8.2.4.2.2-1: provided in the HTTP POST request.
		return missing("/supportedFeatures")
	case !supportedFeaturesPattern.MatchString(d.SupportedFeatures):
		return incorrect("/supportedFeatures", "not a SupportedFeatures string")
	case len(d.AefProfiles) == 0:
		// "For CAPIF-4/4e interface, API publishing function shall provide
		// this attribute" (table 8.2.4.2.2-1).
		return missing("/aefProfiles")
	}
	for i, ap := range d.AefProfiles {
		at := fmt.Sprintf("/aefProfiles/%d", i)
		switch {
		case ap.AefId == "":
			return missing(at + "/aefId")
		case !slices.Contains(p.AefIds, ap.AefId):
			return incorrect(at+"/aefId", "not an AEF of this API provider")
		case len(ap.Versions) == 0:
			return missing(at + "/versions")
		case (ap.DomainName == "") == (len(ap.InterfaceDescriptions) == 0):
			return incorrect(at, "exactly one of domainName and interfaceDescriptions")
		}
		for j, v := range ap.Versions {
			if v.ApiVersion == "" {
				return missing(fmt.Sprintf("%s/versions/%d/apiVersion", at, j))
			}
		}
		// NOTE 4 of table 8.2.4.2.4-1: an AEF defined by 3GPP that serves
		// API invokers via CAPIF-2e gives its security methods.
		everyInterface := len(ap.InterfaceDescriptions) > 0
		for j, ifc := range ap.InterfaceDescriptions {
			n := 0
			for _, a := range []string{ifc.Ipv4Addr, ifc.Ipv6Addr, ifc.Fqdn} {
				if a != "" {
					n++
				}
			}
			if n != 1 {
				return incorrect(fmt.Sprintf("%s/interfaceDescriptions/%d", at, j),
					"exactly one of ipv4Addr, ipv6Addr and fqdn")
			}
			everyInterface = everyInterface && len(ifc.SecurityMethods) > 0
		}
		if len(ap.SecurityMethods) == 0 && !everyInterface {
			return missing(at + "/securityMethods")
		}
	}
	return nil
}

// HTTPGetPublishedAPIs is Get_Service_API: GET .../{apfId}/service-apis
// (TS 29.222 cl. 8.2.2.2.3.2).
func (s *Server) HTTPGetPublishedAPIs(c *gin.Context) {
	p, ok := s.provider(c)
	if !ok {
		return
	}
	util.WriteJSON(c, http.StatusOK, s.Context().PublishedAPIs(p.ApfId))
}

// HTTPGetPublishedAPI is Get_Service_API for one service API:
// GET .../{apfId}/service-apis/{serviceApiId} (TS 29.222 cl. 8.2.2.3.3.1).
func (s *Server) HTTPGetPublishedAPI(c *gin.Context) {
	p, ok := s.provider(c)
	if !ok {
		return
	}
	d, ok := s.Context().PublishedAPI(p.ApfId, c.Param("serviceApiId"))
	if !ok {
		util.WriteProblem(c, util.Problem(http.StatusNotFound, "", "unknown service API"))
		return
	}
	util.WriteJSON(c, http.StatusOK, d)
}

// HTTPUnpublish is Unpublish_Service_API: DELETE .../{apfId}/service-apis/
// {serviceApiId} (TS 29.222 cl. 8.2.2.3.3.3).
func (s *Server) HTTPUnpublish(c *gin.Context) {
	p, ok := s.provider(c)
	if !ok {
		return
	}
	id := c.Param("serviceApiId")
	if !s.Context().Unpublish(p.ApfId, id) {
		util.WriteProblem(c, util.Problem(http.StatusNotFound, "", "unknown service API"))
		return
	}
	c.Status(http.StatusNoContent)
	logger.CapifLog.Infof("Service API %s unpublished by %s", id, p.ApfId)
}
