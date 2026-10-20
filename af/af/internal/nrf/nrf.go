// Package nrf registers the AF at the NRF and obtains its access tokens
// (TS 29.510 cl. 5.2.2.2 and 5.4.2.2). Only the AF outside the operator
// network uses it, to obtain the token of the NEF API: free5GC has no CAPIF
// (TS 29.522 cl. 7.2), and its NEF accepts tokens issued by the NRF.
package nrf

import (
	"context"
	"fmt"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	Nnrf_NFManagement "github.com/free5gc/openapi/nrf/NFManagement"
	"github.com/free5gc/openapi/oauth"
)

// Registration is the NF instance of the AF at the NRF.
type Registration struct {
	nrfURI string
	nfID   string
	api    *Nnrf_NFManagement.APIClient
	oauth2 bool
}

// Register registers the AF at the NRF as an NF of type AF.
func Register(ctx context.Context, nrfURI, nfID, ipv4 string) (*Registration, error) {
	cfg := Nnrf_NFManagement.NewConfiguration()
	cfg.SetBasePath(nrfURI)
	api := Nnrf_NFManagement.NewAPIClient(cfg)

	profile := models.NrfNfManagementNfProfile{
		NfInstanceId:  nfID,
		NfType:        models.NrfNfManagementNfType_AF,
		NfStatus:      models.NrfNfManagementNfStatus_REGISTERED,
		Ipv4Addresses: []string{ipv4},
	}
	rsp, err := api.NFInstanceIDDocumentApi.RegisterNFInstance(ctx,
		&Nnrf_NFManagement.RegisterNFInstanceRequest{NfInstanceID: &nfID, NrfNfManagementNfProfile: &profile})
	if err != nil {
		return nil, err
	}
	// free5GC: the NRF tells in its answer whether OAuth2 is required.
	oauth2, _ := rsp.NrfNfManagementNfProfile.CustomInfo["oauth2"].(bool)
	return &Registration{nrfURI: nrfURI, nfID: nfID, api: api, oauth2: oauth2}, nil
}

// NfID returns the NF instance ID of the AF.
func (r *Registration) NfID() string { return r.nfID }

// OAuth2 tells whether the NRF requires access tokens.
func (r *Registration) OAuth2() bool { return r.oauth2 }

// TokenCtx returns ctx with an access token for scope at the NF type target,
// or ctx itself when the NRF does not require OAuth2. The token is cached
// and renewed by free5gc/openapi.
func (r *Registration) TokenCtx(ctx context.Context, target models.NrfNfManagementNfType, scope string) (
	context.Context, error,
) {
	if !r.oauth2 {
		return ctx, nil
	}
	tokenCtx, pd, err := oauth.GetTokenCtx(models.NrfNfManagementNfType_AF, target, r.nfID, r.nrfURI, scope)
	if err != nil {
		return nil, err
	}
	if pd != nil {
		return nil, fmt.Errorf("access token for %s: %d %s", scope, pd.Status, pd.Cause)
	}
	return context.WithValue(ctx, openapi.ContextOAuth2, tokenCtx.Value(openapi.ContextOAuth2)), nil
}

// Deregister removes the AF from the NRF.
func (r *Registration) Deregister(ctx context.Context) error {
	tokenCtx, err := r.TokenCtx(ctx, models.NrfNfManagementNfType_NRF, string(models.ServiceName_NNRF_NFM))
	if err != nil {
		return err
	}
	_, err = r.api.NFInstanceIDDocumentApi.DeregisterNFInstance(tokenCtx,
		&Nnrf_NFManagement.DeregisterNFInstanceRequest{NfInstanceID: &r.nfID})
	return err
}
