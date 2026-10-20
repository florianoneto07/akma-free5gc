package sbi

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/florianoneto07/akma-free5gc/free5gc/aanf/internal/logger"
	"github.com/florianoneto07/akma-free5gc/free5gc/aanf/internal/util"
	"github.com/florianoneto07/akma-free5gc/free5gc/aanf/pkg/factory"
	"github.com/free5gc/openapi/models"
)

// MaxJSONBodySize is the maximum size of a JSON body: 16 million octets
// (TS 29.501 cl. 6.2). Larger bodies are rejected with 413
// MAX_JSON_SIZE_EXCEEDED (TS 29.500 table 5.2.7.2-1).
const MaxJSONBodySize = 16_000_000

// apiName is the <apiName> of the Naanf_AKMA API (TS 29.535 cl. 5.1.1).
const apiName = "/naanf-akma/"

// Route is an operation of the Naanf_AKMA API.
type Route struct {
	Name    string
	Pattern string
	// Token tells whether the operation requires an OAuth2 access token.
	// Naanf_AKMA_ApplicationKey_Get is authorized by local policy instead
	// (TS 33.535 cl. 6.2.1 step 2): the AF does not reach the NRF. A NEF
	// sends a token, which is verified when present (cl. 6.3 step 3).
	Token   bool
	Handler gin.HandlerFunc
}

func (s *Server) getAkmaRoutes() []Route {
	return []Route{
		{"RegisterAKMAKey", "/register-anchorkey", true, s.HTTPRegisterAKMAKey},
		{"GetAKMAAPPKeyMaterial", "/retrieve-applicationkey", false, s.HTTPGetAKMAAPPKeyMaterial},
		{"RemoveContext", "/remove-context", true, s.HTTPRemoveContext},
	}
}

func (s *Server) applyAkmaRoutes(router *gin.Engine) {
	group := router.Group(factory.AanfAkmaResUriPrefix)
	for _, r := range s.getAkmaRoutes() {
		handlers := []gin.HandlerFunc{checkContentLength}
		if r.Token {
			handlers = append(handlers, s.authorizationCheck(models.ServiceName_NAANF_AKMA))
		}
		handlers = append(handlers, r.Handler)
		// All operations are custom operations invoked with POST
		// (TS 29.535 table 5.1.4.1-1).
		group.POST(r.Pattern, handlers...)
	}
}

// HTTPRegisterAKMAKey is POST .../register-anchorkey.
func (s *Server) HTTPRegisterAKMAKey(c *gin.Context) {
	var req models.AkmaKeyInfo
	if !readJSON(c, &req) {
		return
	}
	s.Processor().RegisterAnchorKey(c, &req)
}

// HTTPGetAKMAAPPKeyMaterial is POST .../retrieve-applicationkey.
func (s *Server) HTTPGetAKMAAPPKeyMaterial(c *gin.Context) {
	var req models.AkmaAfKeyRequest
	if !readJSON(c, &req) {
		return
	}
	token := c.Request.Header.Get("Authorization")
	if token != "" {
		if err := s.Context().AuthorizationCheck(token, models.ServiceName_NAANF_AKMA); err != nil {
			logger.UtilLog.Debugf("Authorization check failed: %v", err)
			writeUnauthorized(c, token)
			return
		}
	}
	// The source address is taken from the connection, never from
	// forwarding headers, which the AF could set.
	ap, err := netip.ParseAddrPort(c.Request.RemoteAddr)
	if err != nil {
		util.WriteProblem(c, util.Problem(http.StatusInternalServerError, util.CauseSystemFailure, ""))
		return
	}
	s.Processor().RetrieveApplicationKey(c, &req, ap.Addr().Unmap(), token != "")
}

// HTTPRemoveContext is POST .../remove-context.
func (s *Server) HTTPRemoveContext(c *gin.Context) {
	var req models.CtxRemove
	if !readJSON(c, &req) {
		return
	}
	s.Processor().RemoveContext(c, &req)
}

// authorizationCheck verifies the OAuth2 access token when OAuth2 is
// required (TS 29.535 cl. 5.1.9; TS 33.501 cl. 13.4.1). A missing or invalid
// token is answered with 401 and a WWW-Authenticate challenge (RFC 6750
// cl. 3).
func (s *Server) authorizationCheck(serviceName models.ServiceName) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.Request.Header.Get("Authorization")
		if err := s.Context().AuthorizationCheck(token, serviceName); err != nil {
			logger.UtilLog.Debugf("Authorization check failed: %v", err)
			writeUnauthorized(c, token)
			return
		}
		c.Next()
	}
}

// writeUnauthorized answers 401 with a WWW-Authenticate challenge
// (RFC 6750 cl. 3; TS 29.500 cl. 6.7.3).
func writeUnauthorized(c *gin.Context, token string) {
	if token == "" {
		c.Header("WWW-Authenticate", `Bearer`)
	} else {
		c.Header("WWW-Authenticate", `Bearer error="invalid_token"`)
	}
	util.WriteProblem(c, util.Problem(http.StatusUnauthorized, "", "access token missing or invalid"))
}

// checkContentLength rejects a Content-Length header whose value is not a
// valid length with 411 INCORRECT_LENGTH (TS 29.500 table 5.2.7.2-1).
func checkContentLength(c *gin.Context) {
	values := c.Request.Header.Values("Content-Length")
	if len(values) == 0 {
		c.Next()
		return
	}
	for _, v := range values {
		if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err != nil || n < 0 || v != values[0] {
			util.WriteProblem(c, util.Problem(http.StatusLengthRequired, util.CauseIncorrectLength, "",
				util.Param("Content-Length", "invalid value")))
			return
		}
	}
	c.Next()
}

// readJSON reads the request body as application/json into v. It answers
// 415 for another content type (TS 29.500 cl. 5.2.7.2), 413 for a body larger
// than MaxJSONBodySize, 411 when the body does not match the declared
// Content-Length and 400 INVALID_MSG_FORMAT when the body is not valid JSON
// for v. Unknown attributes are discarded (TS 29.500 cl. 5.2.7.2).
func readJSON(c *gin.Context, v any) bool {
	mt, _, err := mime.ParseMediaType(c.GetHeader("Content-Type"))
	if err != nil || mt != "application/json" {
		util.WriteProblem(c, util.Problem(http.StatusUnsupportedMediaType, "",
			"the request body shall be application/json"))
		return false
	}
	if c.Request.ContentLength > MaxJSONBodySize {
		util.WriteProblem(c, util.Problem(http.StatusRequestEntityTooLarge, util.CauseMaxJSONSizeExceeded, ""))
		return false
	}
	body, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, MaxJSONBodySize))
	if err != nil {
		var tooLarge *http.MaxBytesError
		switch {
		case errors.As(err, &tooLarge):
			util.WriteProblem(c, util.Problem(http.StatusRequestEntityTooLarge, util.CauseMaxJSONSizeExceeded, ""))
		case c.Request.ContentLength >= 0:
			util.WriteProblem(c, util.Problem(http.StatusLengthRequired, util.CauseIncorrectLength, "",
				util.Param("Content-Length", "does not match the body")))
		default:
			util.WriteProblem(c, util.Problem(http.StatusBadRequest, util.CauseInvalidMsgFormat, ""))
		}
		return false
	}
	if err := json.Unmarshal(body, v); err != nil {
		util.WriteProblem(c, util.Problem(http.StatusBadRequest, util.CauseInvalidMsgFormat, jsonErrorDetail(err)))
		return false
	}
	return true
}

// jsonErrorDetail describes a JSON error without echoing body content.
func jsonErrorDetail(err error) string {
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) {
		return "attribute \"" + typeErr.Field + "\" has a wrong type"
	}
	return "the body is not valid JSON"
}

// noRoute answers requests that match no operation (TS 29.500 cl. 5.2.7.2):
//   - under /naanf-akma/: a method other than POST is supported by no
//     resource of the API, 501; an API version other than v1, 400
//     INVALID_API; an unknown operation, 404
//     RESOURCE_URI_STRUCTURE_NOT_FOUND;
//   - elsewhere: 404.
func noRoute(c *gin.Context) {
	path := c.Request.URL.Path
	rest, ok := strings.CutPrefix(path, apiName)
	if !ok {
		util.WriteProblem(c, util.Problem(http.StatusNotFound, "", ""))
		return
	}
	if c.Request.Method != http.MethodPost {
		util.WriteProblem(c, util.Problem(http.StatusNotImplemented, "", ""))
		return
	}
	version, _, _ := strings.Cut(rest, "/")
	if version != "v1" {
		util.WriteProblem(c, util.Problem(http.StatusBadRequest, util.CauseInvalidAPI,
			"supported API version: v1"))
		return
	}
	util.WriteProblem(c, util.Problem(http.StatusNotFound, util.CauseResourceURIStructureNotFound, ""))
}

// recoverWithProblem answers a panic in a handler with 500 SYSTEM_FAILURE.
func recoverWithProblem() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if p := recover(); p != nil {
				logger.SBILog.Errorf("panic: %v\n%s", p, debug.Stack())
				util.WriteProblem(c, util.Problem(http.StatusInternalServerError, util.CauseSystemFailure, ""))
			}
		}()
		c.Next()
	}
}
