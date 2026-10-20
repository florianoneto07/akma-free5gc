package consumer

import (
	"context"
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

	configuration := Nnrf_NFManagement.NewConfiguration()
	configuration.SetBasePath(uri)
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

// BuildNfProfile returns the NF profile of the AAnF (TS 29.510 NFProfile):
// NF type AANF, the naanf-akma service and, when Routing Indicators are
// configured, an AanfInfo carrying them as strings (TS 29.510 table
// 6.1.6.2.73-1). Without Routing Indicators the AAnF serves any of them.
func BuildNfProfile(c *aanf_context.AANFContext) models.NrfNfManagementNfProfile {
	profile := models.NrfNfManagementNfProfile{
		NfInstanceId:  c.NfId,
		NfType:        models.NrfNfManagementNfType_AANF,
		NfStatus:      models.NrfNfManagementNfStatus_REGISTERED,
		Ipv4Addresses: []string{c.RegisterIPv4},
		PlmnList:      append([]models.PlmnId(nil), c.PlmnList...),
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
