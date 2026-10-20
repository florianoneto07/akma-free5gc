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

// Client requests K_AF from the NEF for one AF_ID.
type Client struct {
	cfg       *configuration
	afID      afid.AfID
	anonymous bool
	tokens    TokenSource
}

// New returns a client of the NEF at apiRoot. With anonymous, the requests
// carry anonInd (TS 33.535 cl. 6.2.2).
func New(apiRoot string, id afid.AfID, anonymous bool, tokens TokenSource) *Client {
	return &Client{
		cfg:       &configuration{basePath: apiRoot + "/3gpp-akma/v1"},
		afID:      id,
		anonymous: anonymous,
		tokens:    tokens,
	}
}

// Source names where the client obtains K_AF, for the log.
func (c *Client) Source() string { return "the NEF" }

// ApplicationKey requests the K_AF of aKid. The NEF never returns the SUPI
// (TS 33.535 cl. 6.3 step 5).
func (c *Client) ApplicationKey(ctx context.Context, aKid string) (aanf.Key, error) {
	ctx, err := c.tokens.TokenCtx(ctx, models.NrfNfManagementNfType_NEF, string(models.ServiceName_3GPP_AKMA))
	if err != nil {
		return aanf.Key{}, fmt.Errorf("%w: access token: %v", aanf.ErrUnavailable, err)
	}
	body := models.AkmaAfKeyRequest{AfId: c.afID.Transport(), AKId: aKid, AnonInd: c.anonymous}
	headers := map[string]string{
		"Content-Type": "application/json",
		"Accept":       "application/json, application/problem+json",
	}
	req, err := openapi.PrepareRequest(ctx, c.cfg, c.cfg.basePath+"/retrieve", http.MethodPost, body,
		headers, url.Values{}, url.Values{}, "", "", nil)
	if err != nil {
		return aanf.Key{}, fmt.Errorf("%w: %v", aanf.ErrUnavailable, err)
	}
	rsp, err := openapi.CallAPI(c.cfg, req)
	if err != nil {
		return aanf.Key{}, fmt.Errorf("%w: %v", aanf.ErrUnavailable, err)
	}
	defer rsp.Body.Close()
	data, err := io.ReadAll(rsp.Body)
	if err != nil {
		return aanf.Key{}, fmt.Errorf("%w: %v", aanf.ErrUnavailable, err)
	}

	switch rsp.StatusCode {
	case http.StatusOK:
		var d models.AkmaAfKeyData
		if err := openapi.Deserialize(&d, data, rsp.Header.Get("Content-Type")); err != nil {
			return aanf.Key{}, fmt.Errorf("%w: %v", aanf.ErrUnavailable, err)
		}
		kaf, err := codec.ParseHexKey(d.Kaf)
		if err != nil {
			return aanf.Key{}, fmt.Errorf("%w: kaf: %v", aanf.ErrUnavailable, err)
		}
		if d.Expiry == nil {
			return aanf.Key{}, fmt.Errorf("%w: expiry missing", aanf.ErrUnavailable)
		}
		return aanf.Key{KAf: kaf, Expiry: *d.Expiry}, nil
	case http.StatusNoContent:
		return aanf.Key{}, fmt.Errorf("%w: NEF answered 204 No Content", aanf.ErrUnavailable)
	}
	var pd models.ProblemDetails
	if len(data) > 0 {
		_ = openapi.Deserialize(&pd, data, rsp.Header.Get("Content-Type"))
	}
	if rsp.StatusCode == http.StatusForbidden && pd.Cause == causeKAkmaNotPresent {
		return aanf.Key{}, aanf.ErrKeyNotAvailable
	}
	if pd.Cause != "" {
		return aanf.Key{}, fmt.Errorf("%w: NEF answered %d %s", aanf.ErrUnavailable, rsp.StatusCode, pd.Cause)
	}
	return aanf.Key{}, fmt.Errorf("%w: NEF answered %d", aanf.ErrUnavailable, rsp.StatusCode)
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
