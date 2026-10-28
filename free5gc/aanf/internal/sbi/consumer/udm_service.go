package consumer

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/florianoneto07/akma-free5gc/free5gc/aanf/internal/logger"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	Nnrf_NFDiscovery "github.com/free5gc/openapi/nrf/NFDiscovery"
	"github.com/free5gc/openapi/oauth"
	Nudm_UEContextManagement "github.com/free5gc/openapi/udm/UEContextManagement"
)

type nudmService struct {
	consumer *Consumer

	mu     sync.Mutex
	udmUri string // apiRoot of the UDM discovered at the NRF
}

// TriggerAuth asks the UDM for a primary (re-)authentication of supi with
// Nudm_UECM_AuthTrigger (TS 29.503 cl. 5.3.2.16), which gives a new K_AKMA
// (TS 33.535 cl. 6.4.4). It returns nil when the UDM accepted the request.
func (s *nudmService) TriggerAuth(supi string) error {
	uri, err := s.discoverUdm()
	if err != nil {
		return err
	}
	ctx, err := s.tokenCtx(models.ServiceName_NUDM_UECM, models.NrfNfManagementNfType_UDM)
	if err != nil {
		return err
	}

	cfg := Nudm_UEContextManagement.NewConfiguration()
	cfg.SetBasePath(uri)
	// TS 29.500 table 5.2.2.2-1: the NF type of the consumer first.
	cfg.SetUserAgent("AANF-" + s.consumer.Context().NfId)
	client := Nudm_UEContextManagement.NewAPIClient(cfg)

	var req Nudm_UEContextManagement.AuthTriggerRequest
	req.SetUeId(supi)
	req.SetAuthTriggerInfo(models.AuthTriggerInfo{Supi: supi})
	if _, err = client.TriggerThePrimaryReAuthenticationApi.AuthTrigger(ctx, &req); err != nil {
		var apiError openapi.GenericOpenAPIError
		if !errors.As(err, &apiError) {
			// The UDM may have moved: discover it again next time.
			s.mu.Lock()
			s.udmUri = ""
			s.mu.Unlock()
			return fmt.Errorf("Nudm_UECM_AuthTrigger at %s: %w", uri, err)
		}
		if v, ok := apiError.Model().(Nudm_UEContextManagement.AuthTriggerError); ok {
			return fmt.Errorf("%d %s (%s)", apiError.ErrorStatus, v.ProblemDetails.Cause, v.ProblemDetails.Detail)
		}
		return fmt.Errorf("%d", apiError.ErrorStatus)
	}
	return nil
}

// discoverUdm returns the apiRoot of a UDM that offers nudm-uecm, discovered
// at the NRF (TS 29.510 cl. 5.3.2.2) once and then kept.
func (s *nudmService) discoverUdm() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.udmUri != "" {
		return s.udmUri, nil
	}

	ctx, err := s.tokenCtx(models.ServiceName_NNRF_DISC, models.NrfNfManagementNfType_NRF)
	if err != nil {
		return "", err
	}
	cfg := Nnrf_NFDiscovery.NewConfiguration()
	cfg.SetBasePath(s.consumer.Context().NrfUri)
	client := Nnrf_NFDiscovery.NewAPIClient(cfg)

	target := models.NrfNfManagementNfType_UDM
	requester := models.NrfNfManagementNfType_AANF
	param := Nnrf_NFDiscovery.SearchNFInstancesRequest{
		TargetNfType:    &target,
		RequesterNfType: &requester,
		ServiceNames:    []models.ServiceName{models.ServiceName_NUDM_UECM},
	}
	res, err := client.NFInstancesStoreApi.SearchNFInstances(ctx, &param)
	if err != nil {
		return "", fmt.Errorf("UDM discovery: %w", err)
	}
	_, uri, err := openapi.GetServiceNfProfileAndUri(res.SearchResult.NfInstances, models.ServiceName_NUDM_UECM)
	if err != nil {
		return "", fmt.Errorf("UDM discovery: %w", err)
	}
	logger.AkmaLog.Infof("UDM for Nudm_UECM_AuthTrigger: %s (discovered at the NRF)", uri)
	s.udmUri = uri
	return uri, nil
}

// tokenCtx returns a context with an access token of the NRF for scope when
// OAuth2 is required (TS 33.501 cl. 13.4.1), and context.Background
// otherwise.
func (s *nudmService) tokenCtx(scope models.ServiceName, target models.NrfNfManagementNfType) (
	context.Context, error,
) {
	self := s.consumer.Context()
	if !self.RequiresOAuth2() {
		return context.Background(), nil
	}
	ctx, _, err := oauth.GetTokenCtx(models.NrfNfManagementNfType_AANF, target, self.NfId, self.NrfUri,
		string(scope))
	if err != nil {
		return nil, fmt.Errorf("access token for %s: %w", scope, err)
	}
	return ctx, nil
}
