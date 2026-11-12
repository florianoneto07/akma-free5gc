package consumer

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"

	aanf_context "github.com/florianoneto07/akma-free5gc/free5gc/aanf/internal/context"
	"github.com/florianoneto07/akma-free5gc/free5gc/aanf/internal/logger"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	Nnrf_NFManagement "github.com/free5gc/openapi/nrf/NFManagement"
)

// aanfInfoKey is the key of the single entry of aanfInfoList (TS 29.510:
// map key of at most 32 characters).
const aanfInfoKey = "1"

// registerRetryInterval is the wait between registration attempts.
var registerRetryInterval = 2 * time.Second

type nnrfService struct {
	consumer *Consumer

	nfMngmntMu      sync.RWMutex
	nfMngmntClients map[string]*Nnrf_NFManagement.APIClient
}

func (s *nnrfService) getNFManagementClient(uri string) *Nnrf_NFManagement.APIClient {
	if uri == "" {
		return nil
	}
	s.nfMngmntMu.RLock()
	client, ok := s.nfMngmntClients[uri]
	s.nfMngmntMu.RUnlock()
	if ok {
		return client
	}

	self := s.consumer.Context()
	configuration := Nnrf_NFManagement.NewConfiguration()
	configuration.SetBasePath(uri)
	// TS 29.500 table 5.2.2.2-1 and cl. 5.2.3.2.21.
	configuration.SetUserAgent(openapi.NfAgent(models.NrfNfManagementNfType_AANF, self.NfId))
	if info := openapi.NfPeerInfo(self.NfId, ""); info != "" {
		configuration.AddDefaultHeader(openapi.HeaderNfPeerInfo, info)
	}
	client = Nnrf_NFManagement.NewAPIClient(configuration)

	s.nfMngmntMu.Lock()
	defer s.nfMngmntMu.Unlock()
	s.nfMngmntClients[uri] = client
	return client
}

// RegisterNFInstance registers the AAnF profile at the NRF
// (Nnrf_NFManagement_NFRegister), retrying until it succeeds or ctx ends.
func (s *nnrfService) RegisterNFInstance(ctx context.Context) (
	resourceNrfUri string, retrieveNfInstanceID string, err error,
) {
	aanfContext := s.consumer.Context()
	client := s.getNFManagementClient(aanfContext.NrfUri)
	if client == nil {
		return "", "", errors.New("nrfUri not configured")
	}
	nfProfile := BuildNfProfile(aanfContext)

	request := &Nnrf_NFManagement.RegisterNFInstanceRequest{
		NfInstanceID:             &aanfContext.NfId,
		NrfNfManagementNfProfile: &nfProfile,
	}
	for {
		select {
		case <-ctx.Done():
			return "", "", errors.Errorf("Context Cancel before RegisterNFInstance")
		default:
		}
		res, errReg := client.NFInstanceIDDocumentApi.RegisterNFInstance(ctx, request)
		if errReg != nil || res == nil {
			logger.ConsumerLog.Errorf("AANF register to NRF Error[%v]", errReg)
			select {
			case <-ctx.Done():
				return "", "", errors.Errorf("Context Cancel before RegisterNFInstance")
			case <-time.After(registerRetryInterval):
			}
			continue
		}
		nf := res.NrfNfManagementNfProfile

		// The NRF of free5GC tells in the "oauth2" custom information
		// whether NF service consumers use OAuth2 access tokens. It is read
		// both on creation (201) and on update (200).
		oauth2 := false
		if nf.CustomInfo != nil {
			if v, ok := nf.CustomInfo["oauth2"].(bool); ok {
				oauth2 = v
				logger.MainLog.Infoln("OAuth2 setting receive from NRF:", oauth2)
			}
		}
		aanfContext.SetOAuth2Required(oauth2)
		if oauth2 && aanfContext.NrfCertPem == "" {
			logger.CfgLog.Error("OAuth2 enable but no nrfCertPem provided in config.")
		}
		// The heart-beat interval of the NRF (TS 29.510 table 6.1.6.2.2-1).
		aanfContext.SetHeartBeat(nf.HeartBeatTimer)

		if res.Location == "" {
			// 200 OK: the profile was updated (NFUpdate).
			return "", aanfContext.NfId, nil
		}
		// 201 Created (NFRegister).
		resourceUri := res.Location
		if i := strings.Index(resourceUri, "/nnrf-nfm/"); i >= 0 {
			resourceNrfUri = resourceUri[:i]
		}
		retrieveNfInstanceID = resourceUri[strings.LastIndex(resourceUri, "/")+1:]
		return resourceNrfUri, retrieveNfInstanceID, nil
	}
}

// SendDeregisterNFInstance deregisters the AAnF at the NRF
// (Nnrf_NFManagement_NFDeregister).
func (s *nnrfService) SendDeregisterNFInstance() (*models.ProblemDetails, error) {
	logger.ConsumerLog.Infof("[AANF] Send Deregister NFInstance")

	aanfContext := s.consumer.Context()
	ctx, pd, err := aanfContext.GetTokenCtx(models.ServiceName_NNRF_NFM, models.NrfNfManagementNfType_NRF)
	if err != nil {
		return pd, err
	}

	client := s.getNFManagementClient(aanfContext.NrfUri)
	if client == nil {
		return nil, errors.New("nrfUri not configured")
	}
	request := &Nnrf_NFManagement.DeregisterNFInstanceRequest{
		NfInstanceID: &aanfContext.NfId,
	}

	_, err = client.NFInstanceIDDocumentApi.DeregisterNFInstance(ctx, request)
	if apiErr, ok := err.(openapi.GenericOpenAPIError); ok {
		if deregNfError, okDeg := apiErr.Model().(Nnrf_NFManagement.DeregisterNFInstanceError); okDeg {
			return &deregNfError.ProblemDetails, err
		}
		return nil, err
	}
	return nil, err
}

// SendHeartBeat sends the heart-beat of the AAnF: the NFUpdate service
// operation with a "replace" of nfStatus by REGISTERED, without If-Match
// (TS 29.510 cl. 5.2.2.3.2). It returns the HTTP status of the answer, 0
// without one. A new heart-beat interval in the answer is kept.
func (s *nnrfService) SendHeartBeat(ctx context.Context) (int, error) {
	self := s.consumer.Context()
	tokenCtx, _, err := self.GetTokenCtx(models.ServiceName_NNRF_NFM, models.NrfNfManagementNfType_NRF)
	if err != nil {
		return 0, errors.Wrap(err, "access token for nnrf-nfm")
	}
	if tok := tokenCtx.Value(openapi.ContextOAuth2); tok != nil {
		ctx = context.WithValue(ctx, openapi.ContextOAuth2, tok)
	}
	client := s.getNFManagementClient(self.NrfUri)
	if client == nil {
		return 0, errors.New("nrfUri not configured")
	}
	request := &Nnrf_NFManagement.UpdateNFInstanceRequest{
		NfInstanceID: &self.NfId,
		PatchItem: []models.PatchItem{{
			Op: models.PatchOperation_REPLACE, Path: "/nfStatus", Value: models.NrfNfManagementNfStatus_REGISTERED,
		}},
	}
	rsp, err := client.NFInstanceIDDocumentApi.UpdateNFInstance(ctx, request)
	if err != nil {
		var apiErr openapi.GenericOpenAPIError
		if errors.As(err, &apiErr) {
			return apiErr.ErrorStatus, err
		}
		return 0, err
	}
	// "200 OK" along with the full NF Profile, or "204 No Content".
	if rsp != nil && rsp.NrfNfManagementNfProfile.HeartBeatTimer > 0 {
		self.SetHeartBeat(rsp.NrfNfManagementNfProfile.HeartBeatTimer)
	}
	return http.StatusNoContent, nil
}

// RunHeartBeat sends the heart-beat at the interval of the NRF until ctx ends
// (TS 29.510 cl. 5.2.2.3.2: "Each NF that has previously registered in NRF
// shall contact the NRF periodically"). The clause does not say what to do
// with "404 Not Found": the NRF no longer has the profile, so the AAnF
// registers again.
func (s *nnrfService) RunHeartBeat(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(s.consumer.Context().HeartBeat()):
		}
		status, err := s.SendHeartBeat(ctx)
		switch {
		case err == nil:
			logger.ConsumerLog.Infof("Heart-beat sent to the NRF, next in %s", s.consumer.Context().HeartBeat())
		case status == http.StatusNotFound:
			logger.ConsumerLog.Warnf("Heart-beat: the NRF does not have the profile (404); registering again")
			if _, _, regErr := s.RegisterNFInstance(ctx); regErr != nil {
				logger.ConsumerLog.Errorf("AANF register to NRF Error[%v]", regErr)
			}
		case ctx.Err() != nil:
			return
		default:
			logger.ConsumerLog.Warnf("Heart-beat failed: %v", err)
		}
	}
}

// BuildNfProfile returns the NF profile of the AAnF (TS 29.510 NFProfile):
// NF type AANF, the naanf-akma service and, when Routing Indicators are
// configured, an AanfInfo carrying them as strings (TS 29.510 table
// 6.1.6.2.73-1). Without Routing Indicators the AAnF serves any of them.
func BuildNfProfile(c *aanf_context.AANFContext) models.NrfNfManagementNfProfile {
	profile := models.NrfNfManagementNfProfile{
		NfInstanceId: c.NfId,
		NfType:       models.NrfNfManagementNfType_AANF,
		NfStatus:     models.NrfNfManagementNfStatus_REGISTERED,
		// The heart-beat interval proposed (TS 29.510 table 6.1.6.2.2-1).
		HeartBeatTimer: c.HeartBeatTimer,
		Fqdn:           c.Fqdn,
		Ipv4Addresses:  []string{c.RegisterIPv4},
		PlmnList:       append([]models.PlmnId(nil), c.PlmnList...),
	}
	for _, nfService := range c.NfService {
		profile.NfServices = append(profile.NfServices, nfService)
	}
	if len(c.RoutingIndicators) > 0 {
		profile.AanfInfoList = map[string]models.AanfInfo{
			aanfInfoKey: {RoutingIndicators: append([]string(nil), c.RoutingIndicators...)},
		}
	}
	return profile
}
