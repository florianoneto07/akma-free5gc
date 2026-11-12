package sbi

import (
	"net/http"
	"net/url"
	"slices"

	"github.com/gin-gonic/gin"

	"github.com/florianoneto07/akma-free5gc/free5gc/ccf/internal/logger"
	"github.com/florianoneto07/akma-free5gc/free5gc/ccf/internal/util"
	"github.com/free5gc/openapi/models"
)

// Query parameters of table 8.1.2.2.3.1-1 of TS 29.222.
var (
	// discoverFilters have no feature. preferred-aef-loc is accepted and
	// ignored: the CCF has no location of the AEFs ("This parameter is
	// ignored by the CCF if there is no matching record found").
	discoverFilters = []string{
		"api-invoker-id", "api-name", "api-version", "comm-type", "protocol",
		"aef-id", "data-format", "api-cat", "preferred-aef-loc",
	}
	// discoverFeatureParams belong to features the CCF does not support.
	discoverFeatureParams = []string{
		"req-api-prov-name", "api-supported-features", "ue-ip-addr", "service-kpis",
		"net-slice-info", "grant-types", "api-ids", "supported-features", "res-ops",
	}
)

// HTTPDiscover is Discover_Service_API: GET .../allServiceAPIs (TS 29.222
// cl. 5.2.2.2 and 8.1.2.2.3.1), with the client certificate of the API
// invoker. The discovery policy is the invoker profile: only its APIs are
// returned (cl. 5.2.2.2.2 step 2b).
func (s *Server) HTTPDiscover(c *gin.Context) {
	q := c.Request.URL.Query()
	id := q.Get("api-invoker-id")
	if id == "" {
		util.WriteProblem(c, util.Problem(http.StatusBadRequest, util.CauseMandatoryQueryParamMissing, "",
			util.Param("api-invoker-id", "missing")))
		return
	}
	if !requireInvoker(c, id) {
		return
	}
	inv, ok := s.Context().Invoker(id)
	if !ok {
		util.WriteProblem(c, util.Problem(http.StatusForbidden, "", "unknown API invoker"))
		return
	}
	var invalid []models.InvalidParam
	for name := range q {
		switch {
		case slices.Contains(discoverFilters, name):
		case slices.Contains(discoverFeatureParams, name):
			invalid = append(invalid, util.Param(name, "feature not supported"))
		default:
			invalid = append(invalid, util.Param(name, "unknown query parameter"))
		}
	}
	if len(invalid) > 0 {
		slices.SortFunc(invalid, func(a, b models.InvalidParam) int {
			if a.Param < b.Param {
				return -1
			}
			return 1
		})
		util.WriteProblem(c, util.Problem(http.StatusBadRequest, util.CauseInvalidQueryParam, "", invalid...))
		return
	}

	profile, _ := s.Config().Profile(inv.Profile)
	var out []models.CapifServiceApiDescription
	for _, d := range s.Context().PublishedAPIs("") {
		if !slices.Contains(profile.Apis, d.ApiName) ||
			!matchValue(q, "api-name", d.ApiName) || !matchValue(q, "api-cat", d.ServiceAPICategory) {
			continue
		}
		var profiles []models.CapifAefProfile
		for _, p := range d.AefProfiles {
			if matchAefProfile(q, p) {
				profiles = append(profiles, p)
			}
		}
		if len(profiles) == 0 {
			continue
		}
		d.AefProfiles = profiles
		// "The shareableInformation for each of serviceAPIDescription is
		// not provided in the filtered search results" (cl. 5.2.2.2.2).
		d.ShareableInfo = nil
		out = append(out, d)
	}
	// Without any match, serviceAPIDescriptions is absent (cardinality 1..N).
	util.WriteJSON(c, http.StatusOK, models.CapifDiscoveredApis{ServiceAPIDescriptions: out})
	logger.CapifLog.Infof("%d service API(s) discovered by API invoker %s", len(out), id)
}

// matchValue tells whether the query parameter name is absent or equal to v.
func matchValue(q url.Values, name, v string) bool {
	want := q.Get(name)
	return want == "" || want == v
}

// matchAefProfile applies the filters of an AEF profile.
func matchAefProfile(q url.Values, p models.CapifAefProfile) bool {
	if !matchValue(q, "aef-id", p.AefId) || !matchValue(q, "protocol", string(p.Protocol)) ||
		!matchValue(q, "data-format", string(p.DataFormat)) {
		return false
	}
	if v := q.Get("api-version"); v != "" &&
		!slices.ContainsFunc(p.Versions, func(ver models.CapifVersion) bool { return ver.ApiVersion == v }) {
		return false
	}
	if v := q.Get("comm-type"); v != "" {
		ct := models.CapifCommunicationType(v)
		found := false
		for _, ver := range p.Versions {
			for _, r := range ver.Resources {
				found = found || r.CommType == ct
			}
			for _, o := range ver.CustOperations {
				found = found || o.CommType == ct
			}
		}
		if !found {
			return false
		}
	}
	return true
}
