package util

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/free5gc/openapi/models"
)

// Protocol errors of TS 29.500 table 5.2.7.2-1, which apply to the CAPIF APIs
// (TS 29.222 cl. 7.7; TS 29.122 cl. 5.2.6).
const (
	CauseInvalidAPI                   = "INVALID_API"
	CauseInvalidMsgFormat             = "INVALID_MSG_FORMAT"
	CauseInvalidQueryParam            = "INVALID_QUERY_PARAM"
	CauseMandatoryQueryParamMissing   = "MANDATORY_QUERY_PARAM_MISSING"
	CauseOptionalQueryParamIncorrect  = "OPTIONAL_QUERY_PARAM_INCORRECT"
	CauseMandatoryIEIncorrect         = "MANDATORY_IE_INCORRECT"
	CauseOptionalIEIncorrect          = "OPTIONAL_IE_INCORRECT"
	CauseMandatoryIEMissing           = "MANDATORY_IE_MISSING"
	CauseResourceURIStructureNotFound = "RESOURCE_URI_STRUCTURE_NOT_FOUND"
	CauseIncorrectLength              = "INCORRECT_LENGTH"
	CauseMaxJSONSizeExceeded          = "MAX_JSON_SIZE_EXCEEDED"
	CauseSystemFailure                = "SYSTEM_FAILURE"
)

// ProblemContentType is the media type of ProblemDetails (TS 29.122
// table 5.2.6-1 NOTE 2).
const ProblemContentType = "application/problem+json"

// Problem returns a ProblemDetails with the given status, cause and detail.
// An empty cause leaves the attribute out.
func Problem(status int, cause, detail string, invalid ...models.InvalidParam) *models.ProblemDetails {
	return &models.ProblemDetails{
		Status:        int32(status),
		Title:         http.StatusText(status),
		Cause:         cause,
		Detail:        detail,
		InvalidParams: invalid,
	}
}

// Param returns an InvalidParam for the JSON Pointer or query parameter param.
func Param(param, reason string) models.InvalidParam {
	return models.InvalidParam{Param: param, Reason: reason}
}

// WriteProblem writes pd as an application/problem+json response and aborts
// the handler chain.
func WriteProblem(c *gin.Context, pd *models.ProblemDetails) {
	body, err := json.Marshal(pd)
	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	c.Data(int(pd.Status), ProblemContentType, body)
	c.Abort()
}

// WriteJSON writes v as an application/json response.
func WriteJSON(c *gin.Context, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		WriteProblem(c, Problem(http.StatusInternalServerError, CauseSystemFailure, ""))
		return
	}
	c.Data(status, "application/json", body)
}
