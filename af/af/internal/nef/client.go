// Package nef requests K_AF through the NEF, as an AF outside the operator
// network (TS 33.535 cl. 6.3; TS 29.522 cl. 4.4.23.2 and 5.14), with the
// AKMA API of the NEF: POST {apiRoot}/3gpp-akma/v1/retrieve.
package nef

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/florianoneto07/akma-free5gc/af/af/internal/aanf"
	"github.com/florianoneto07/akma-free5gc/shared/akma/afid"
	"github.com/florianoneto07/akma-free5gc/shared/akma/codec"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
)

// causeKAkmaNotPresent is the application error of TS 29.522
// table 5.14.7.3-1.
const causeKAkmaNotPresent = "K_AKMA_NOT_PRESENT"

// TokenSource adds an access token for the NEF API to a context.
type TokenSource interface {
	TokenCtx(ctx context.Context, target models.NrfNfManagementNfType, scope string) (context.Context, error)
}

// Invalidator is a TokenSource that drops its token when the NEF refuses
// it, to give a new one: with CAPIF, the API invoker "shall return to the
// CAPIF Core Function" (TS 33.122 Annex C.4.1).
type Invalidator interface {
	Invalidate()
}

// Client requests K_AF from the NEF.
type Client struct {
	cfg       *configuration
	anonymous bool
	tokens    TokenSource
}

// New returns a client of the NEF at apiRoot. With anonymous, the requests
// carry anonInd (TS 33.535 cl. 6.2.2).
func New(apiRoot string, anonymous bool, tokens TokenSource) *Client {
	return &Client{
		cfg:       &configuration{basePath: apiRoot + "/3gpp-akma/v1"},
		anonymous: anonymous,
		tokens:    tokens,
	}
}

// Source names where the client obtains K_AF, for the log.
func (c *Client) Source() string { return "the NEF" }

// ApplicationKey requests the K_AF of aKid for the AF_ID id. The NEF never
// returns the SUPI (TS 33.535 cl. 6.3 step 5). When the NEF refuses the
// access token (RFC 6750 cl. 3.1) of an Invalidator, the request is sent
// again once, with a new token.
func (c *Client) ApplicationKey(ctx context.Context, id afid.AfID, aKid string) (aanf.Key, error) {
	key, status, err := c.retrieve(ctx, id, aKid)
	if inv, ok := c.tokens.(Invalidator); ok && status == http.StatusUnauthorized {
		inv.Invalidate()
		key, _, err = c.retrieve(ctx, id, aKid)
	}
	return key, err
}

// retrieve sends the request once. It returns the HTTP status of the
// answer, 0 without an answer.
func (c *Client) retrieve(ctx context.Context, id afid.AfID, aKid string) (aanf.Key, int, error) {
	ctx, err := c.tokens.TokenCtx(ctx, models.NrfNfManagementNfType_NEF, string(models.ServiceName_3GPP_AKMA))
	if err != nil {
		return aanf.Key{}, 0, fmt.Errorf("%w: access token: %v", aanf.ErrUnavailable, err)
	}
	body := models.AkmaAfKeyRequest{AfId: id.Transport(), AKId: aKid, AnonInd: c.anonymous}
	headers := map[string]string{
		"Content-Type": "application/json",
		"Accept":       "application/json, application/problem+json",
	}
	req, err := openapi.PrepareRequest(ctx, c.cfg, c.cfg.basePath+"/retrieve", http.MethodPost, body,
		headers, url.Values{}, url.Values{}, "", "", nil)
	if err != nil {
		return aanf.Key{}, 0, fmt.Errorf("%w: %v", aanf.ErrUnavailable, err)
	}
	rsp, err := openapi.CallAPI(c.cfg, req)
	if err != nil {
		return aanf.Key{}, 0, fmt.Errorf("%w: %v", aanf.ErrUnavailable, err)
	}
	defer rsp.Body.Close()
	data, err := io.ReadAll(rsp.Body)
	if err != nil {
		return aanf.Key{}, rsp.StatusCode, fmt.Errorf("%w: %v", aanf.ErrUnavailable, err)
	}

	switch rsp.StatusCode {
	case http.StatusOK:
		var d models.AkmaAfKeyData
		if err := openapi.Deserialize(&d, data, rsp.Header.Get("Content-Type")); err != nil {
			return aanf.Key{}, rsp.StatusCode, fmt.Errorf("%w: %v", aanf.ErrUnavailable, err)
		}
		kaf, err := codec.ParseHexKey(d.Kaf)
		if err != nil {
			return aanf.Key{}, rsp.StatusCode, fmt.Errorf("%w: kaf: %v", aanf.ErrUnavailable, err)
		}
		if d.Expiry == nil {
			return aanf.Key{}, rsp.StatusCode, fmt.Errorf("%w: expiry missing", aanf.ErrUnavailable)
		}
		return aanf.Key{KAf: kaf, Expiry: *d.Expiry}, rsp.StatusCode, nil
	case http.StatusNoContent:
		return aanf.Key{}, rsp.StatusCode, fmt.Errorf("%w: NEF answered 204 No Content", aanf.ErrUnavailable)
	}
	var pd models.ProblemDetails
	if len(data) > 0 {
		_ = openapi.Deserialize(&pd, data, rsp.Header.Get("Content-Type"))
	}
	if rsp.StatusCode == http.StatusForbidden && pd.Cause == causeKAkmaNotPresent {
		return aanf.Key{}, rsp.StatusCode, aanf.ErrKeyNotAvailable
	}
	if pd.Cause != "" {
		return aanf.Key{}, rsp.StatusCode,
			fmt.Errorf("%w: NEF answered %d %s", aanf.ErrUnavailable, rsp.StatusCode, pd.Cause)
	}
	return aanf.Key{}, rsp.StatusCode, fmt.Errorf("%w: NEF answered %d", aanf.ErrUnavailable, rsp.StatusCode)
}

// configuration is the openapi.Configuration of the NEF client.
type configuration struct {
	basePath string
}

func (c *configuration) BasePath() string                    { return c.basePath }
func (c *configuration) Host() string                        { return "" }
func (c *configuration) UserAgent() string                   { return "AF" }
func (c *configuration) DefaultHeader() map[string]string    { return map[string]string{} }
func (c *configuration) HTTPClient() *http.Client            { return nil }
func (c *configuration) Metrics() openapi.RequestMetricsHook { return nil }
