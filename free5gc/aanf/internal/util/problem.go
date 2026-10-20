package util

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/free5gc/openapi/models"
)

// Protocol and application errors of TS 29.500 table 5.2.7.2-1 and
// TS 29.535 table 5.1.7.3-1 used by the AAnF.
const (
	CauseInvalidAPI                   = "INVALID_API"
	CauseInvalidMsgFormat             = "INVALID_MSG_FORMAT"
	CauseMandatoryIEIncorrect         = "MANDATORY_IE_INCORRECT"
	CauseOptionalIEIncorrect          = "OPTIONAL_IE_INCORRECT"
	CauseMandatoryIEMissing           = "MANDATORY_IE_MISSING"
	CauseResourceURIStructureNotFound = "RESOURCE_URI_STRUCTURE_NOT_FOUND"
	CauseIncorrectLength              = "INCORRECT_LENGTH"
	CauseMaxJSONSizeExceeded          = "MAX_JSON_SIZE_EXCEEDED"
	CauseSystemFailure                = "SYSTEM_FAILURE"

	CauseKAkmaNotPresent     = "K_AKMA_NOT_PRESENT"
	CauseAkmaContextNotFound = "AKMA_CONTEXT_NOT_FOUND"
)

// ProblemContentType is the media type of ProblemDetails (TS 29.500
// cl. 5.2.7.1; RFC 9457).
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

// Param returns an InvalidParam for the JSON Pointer param.
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
