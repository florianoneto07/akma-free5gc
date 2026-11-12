package sbi

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/florianoneto07/akma-free5gc/free5gc/ccf/internal/logger"
	"github.com/florianoneto07/akma-free5gc/free5gc/ccf/internal/util"
	logger_util "github.com/free5gc/util/logger"
)

// MaxBodySize is the largest request body the CCF reads; larger bodies are
// rejected with 413 MAX_JSON_SIZE_EXCEEDED (TS 29.500 table 5.2.7.2-1).
const MaxBodySize = 64 << 10

// supportedFeaturesPattern is SupportedFeatures of TS 29.571.
var supportedFeaturesPattern = regexp.MustCompile(`^[A-Fa-f0-9]*$`)

// newRouter returns a router for the APIs named apiNames.
func newRouter(apiNames []string) *gin.Engine {
	router := logger_util.NewGinWithLogrus(logger.GinLog)
	// A trailing slash is a different resource: answer 404 instead of a
	// redirection.
	router.RedirectTrailingSlash = false
	router.RedirectFixedPath = false
	router.HandleMethodNotAllowed = true
	// No proxy is trusted.
	_ = router.SetTrustedProxies(nil)
	router.Use(recoverWithProblem())
	router.NoRoute(noRoute(apiNames))
	router.NoMethod(noMethod(router))
	return router
}

// noRoute answers requests that match no resource (TS 29.500 cl. 5.2.7.2):
// under an API of this interface, 400 INVALID_API for an API version other
// than v1 and 404 RESOURCE_URI_STRUCTURE_NOT_FOUND otherwise; elsewhere,
// including the APIs of the other interface, 404.
func noRoute(apiNames []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		path := strings.TrimPrefix(c.Request.URL.Path, "/")
		api, rest, _ := strings.Cut(path, "/")
		if !slices.Contains(apiNames, api) {
			util.WriteProblem(c, util.Problem(http.StatusNotFound, "", ""))
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
}

// noMethod answers 405 with the Allow header (RFC 9110 cl. 15.5.6).
func noMethod(router *gin.Engine) gin.HandlerFunc {
	return func(c *gin.Context) {
		var allow []string
		for _, r := range router.Routes() {
			if matchPattern(r.Path, c.Request.URL.Path) && !slices.Contains(allow, r.Method) {
				allow = append(allow, r.Method)
			}
		}
		slices.Sort(allow)
		c.Header("Allow", strings.Join(allow, ", "))
		util.WriteProblem(c, util.Problem(http.StatusMethodNotAllowed, "", ""))
	}
}

// matchPattern tells whether path matches a route pattern with ":name"
// segments.
func matchPattern(pattern, path string) bool {
	ps := strings.Split(pattern, "/")
	xs := strings.Split(path, "/")
	if len(ps) != len(xs) {
		return false
	}
	for i := range ps {
		if strings.HasPrefix(ps[i], ":") {
			if xs[i] == "" {
				return false
			}
			continue
		}
		if ps[i] != xs[i] {
			return false
		}
	}
	return true
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

// checkContentLength rejects a Content-Length header whose value is not a
// valid length with 411 INCORRECT_LENGTH (TS 29.500 table 5.2.7.2-1).
func checkContentLength(c *gin.Context) {
	values := c.Request.Header.Values("Content-Length")
	for _, v := range values {
		if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err != nil || n < 0 || v != values[0] {
			util.WriteProblem(c, util.Problem(http.StatusLengthRequired, util.CauseIncorrectLength, "",
				util.Param("Content-Length", "invalid value")))
			return
		}
	}
	c.Next()
}

// readBody reads the request body of the media type mediaType: 415 for
// another media type, 413 for a body larger than MaxBodySize and 411 when the
// body does not match the declared Content-Length.
func readBody(c *gin.Context, mediaType string) ([]byte, bool) {
	mt, _, err := mime.ParseMediaType(c.GetHeader("Content-Type"))
	if err != nil || mt != mediaType {
		util.WriteProblem(c, util.Problem(http.StatusUnsupportedMediaType, "",
			"the request body shall be "+mediaType))
		return nil, false
	}
	if c.Request.ContentLength > MaxBodySize {
		util.WriteProblem(c, util.Problem(http.StatusRequestEntityTooLarge, util.CauseMaxJSONSizeExceeded, ""))
		return nil, false
	}
	body, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, MaxBodySize))
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
		return nil, false
	}
	return body, true
}

// readJSON reads an application/json body into v; 400 INVALID_MSG_FORMAT
// when it is not valid JSON for v. Unknown attributes are discarded.
func readJSON(c *gin.Context, v any) bool {
	body, ok := readBody(c, "application/json")
	if !ok {
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

// invokerFromCert returns the API invoker ID of the verified client
// certificate: its subject Common Name (TS 29.222 table 8.4.4.2.5-1).
func invokerFromCert(c *gin.Context) (string, bool) {
	state := c.Request.TLS
	if state == nil || len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
		return "", false
	}
	cn := state.VerifiedChains[0][0].Subject.CommonName
	return cn, cn != ""
}

// requireInvoker answers 403 unless the request carries the client
// certificate of the API invoker id (TS 33.122 cl. 6.3.1.1).
func requireInvoker(c *gin.Context, id string) bool {
	cn, ok := invokerFromCert(c)
	if !ok {
		util.WriteProblem(c, util.Problem(http.StatusForbidden, "",
			"the client certificate of the API invoker is required"))
		return false
	}
	if cn != id {
		util.WriteProblem(c, util.Problem(http.StatusForbidden, "",
			"the client certificate belongs to another API invoker"))
		return false
	}
	return true
}

// writeUnauthorized answers 401 with a Bearer challenge (RFC 6750 cl. 3;
// RFC 9110 cl. 15.5.2).
func writeUnauthorized(c *gin.Context, withToken bool, detail string) {
	if withToken {
		c.Header("WWW-Authenticate", `Bearer error="invalid_token"`)
	} else {
		c.Header("WWW-Authenticate", `Bearer`)
	}
	util.WriteProblem(c, util.Problem(http.StatusUnauthorized, "", detail))
}

// isAbsoluteURI tells whether s is an absolute URI with a host, as Uri of
// TS 29.122 requires for the notification destinations.
func isAbsoluteURI(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.IsAbs() && u.Host != ""
}
