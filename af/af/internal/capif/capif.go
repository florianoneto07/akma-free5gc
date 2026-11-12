// Package capif makes the AF an API invoker of CAPIF (TS 23.222; TS 29.222;
// TS 33.122). Outside the operator network, the AF onboards at the CAPIF
// core function, discovers the AKMA API of the NEF, obtains its security
// method and the access tokens with which it requests K_AF through the NEF
// (TS 29.522 cl. 7.2; TS 33.535 cl. 6.3).
//
// The log never carries the onboarding credential, the onboarding secret,
// the private key or an access token.
package capif

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/florianoneto07/akma-free5gc/af/af/internal/config"
	"github.com/florianoneto07/akma-free5gc/af/af/internal/logger"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/capif/AEFSecurity"
	"github.com/free5gc/openapi/capif/APIInvokerManagement"
	"github.com/free5gc/openapi/capif/DiscoverService"
	"github.com/free5gc/openapi/capif/Security"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/openapi/sbitls"
)

const (
	// AkmaAPI is the AKMA API of the NEF (TS 29.522 cl. 5.14), version 1.
	AkmaAPI        = "3gpp-akma"
	akmaAPIVersion = "v1"
	// renewBefore: the access token is renewed this long before the end of
	// its lifetime, so that no expired token reaches the AEF (TS 33.122
	// Annex C.5).
	renewBefore = 30 * time.Second
	// requestTimeout bounds each request to the CAPIF core function and to
	// the AEF.
	requestTimeout = 10 * time.Second
)

// errUnknownInvoker: the CAPIF core function no longer knows the API
// invoker; it was offboarded, or the CAPIF core function restarted.
var errUnknownInvoker = errors.New("API invoker unknown at the CAPIF core function")

// Invoker is the AF as API invoker. It is a TokenSource of the client of
// the NEF.
type Invoker struct {
	cfg  config.Capif
	info string
	pool *x509.CertPool
	crl  *sbitls.CrlChecker

	mu      sync.Mutex
	st      *state
	ccf     *http.Client
	apiRoot string
	aefID   string
	token   string
	expiry  time.Time

	// now returns the current time; tests replace it.
	now func() time.Time
}

// Start makes the AF ready to request K_AF through the NEF: it onboards at
// the CAPIF core function unless its state says it is onboarded, discovers
// the AKMA API, obtains the security method for the AEF and asks the AEF to
// check its authentication (TS 33.122 cl. 6.1, 6.3 and 6.5.2.3). info is
// the API invoker information given at onboarding.
func Start(ctx context.Context, cfg config.Capif, info string) (*Invoker, error) {
	ca, err := os.ReadFile(cfg.CcfCA)
	if err != nil {
		return nil, fmt.Errorf("ccfCa: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("ccfCa: no PEM certificate in %s", cfg.CcfCA)
	}
	i := &Invoker{cfg: cfg, info: info, pool: pool, crl: sbitls.NewCrlChecker(logger.CapifLog), now: time.Now}
	st, err := loadState(cfg.State)
	if err != nil {
		return nil, err
	}
	if st != nil && st.CcfURI != cfg.CcfURI {
		logger.CapifLog.Infof("State of the CCF %s set aside: the CCF is now %s", st.CcfURI, cfg.CcfURI)
		st = nil
	}
	if st != nil {
		if err := i.use(st); err != nil {
			return nil, err
		}
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if err := i.setUp(ctx); err != nil {
		return nil, err
	}
	return i, nil
}

// ID returns the API invoker ID.
func (i *Invoker) ID() string {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.st == nil {
		return ""
	}
	return i.st.APIInvokerID
}

// APIRoot returns the apiRoot of the AKMA API, discovered at the CAPIF core
// function.
func (i *Invoker) APIRoot() string {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.apiRoot
}

// use takes the state of an onboarding: the client certificate of
// CAPIF-1e and the onboarding secret.
func (i *Invoker) use(st *state) error {
	cert, err := tls.X509KeyPair([]byte(st.Certificate), []byte(st.PrivateKey))
	if err != nil {
		return fmt.Errorf("state %s: %w", i.cfg.State, err)
	}
	if i.cfg.AefCA != "" {
		// CAPIF-2e: the certificate of the onboarding at the AEF, and the
		// CA of the AEF (TS 33.122 cl. 6.5.2.3 step 5).
		if err = sbitls.Init(sbitls.Config{KeyPair: &cert, CA: i.cfg.AefCA, Logger: logger.CapifLog}); err != nil {
			return fmt.Errorf("aefCa: %w", err)
		}
		// A session with the certificate of an earlier onboarding is of
		// another API invoker.
		openapi.CloseIdleConnections()
	}
	i.st = st
	i.ccf = i.httpClient(&cert)
	return nil
}

// forget drops the onboarding and its state file.
func (i *Invoker) forget() {
	i.st, i.ccf, i.token = nil, nil, ""
	if err := removeState(i.cfg.State); err != nil {
		logger.CapifLog.Warnf("%v", err)
	}
}

// httpClient returns a client of CAPIF-1e: TLS 1.3, or TLS 1.2 with only
// ECDHE and AEAD cipher suites (TS 33.210 cl. 6.2), the CA of the CAPIF core
// function and its CRL (TS 33.310 cl. 6.3.1) and, after onboarding, the client
// certificate (TS 33.122 cl. 6.3.1.1).
func (i *Invoker) httpClient(cert *tls.Certificate) *http.Client {
	tc := &tls.Config{
		RootCAs:          i.pool,
		VerifyConnection: i.crl.VerifyConnection,
		MinVersion:       tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
	}
	if cert != nil {
		tc.Certificates = []tls.Certificate{*cert}
	}
	return &http.Client{
		Timeout:   requestTimeout,
		Transport: &http.Transport{TLSClientConfig: tc, ForceAttemptHTTP2: true},
	}
}

// setUp onboards when needed, then prepares the use of the AKMA API. When
// the CAPIF core function no longer knows the API invoker, the AF onboards
// again, once. i.mu is held.
func (i *Invoker) setUp(ctx context.Context) error {
	for again := false; ; again = true {
		if i.st == nil {
			if err := i.onboard(ctx); err != nil {
				return err
			}
		}
		err := i.prepare(ctx)
		if errors.Is(err, errUnknownInvoker) && !again {
			logger.CapifLog.Warnf("The CCF no longer knows API invoker %s: onboarding again", i.st.APIInvokerID)
			i.forget()
			continue
		}
		return err
	}
}

// onboard onboards the AF at the CAPIF core function (Onboard_API_Invoker,
// TS 29.222 cl. 5.5.2.2; TS 33.122 cl. 6.1): TLS with server authentication
// only, the onboarding credential as bearer (TS 29.222 cl. 5.5.2.2.2 NOTE 4)
// and the public key of a new ECDSA P-256 key pair.
func (i *Invoker) onboard(ctx context.Context) error {
	cred, err := os.ReadFile(i.cfg.Credential)
	if err != nil {
		return fmt.Errorf("credential: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}

	cfg := APIInvokerManagement.NewConfiguration()
	cfg.SetBasePath(i.cfg.CcfURI)
	cfg.SetHTTPClient(i.httpClient(nil))
	ctx = context.WithValue(ctx, openapi.ContextAccessToken, strings.TrimSpace(string(cred)))
	rsp, err := APIInvokerManagement.NewAPIClient(cfg).OnboardedAPIInvokersCollectionApi.CreateOnboardedAPIInvoker(ctx,
		&APIInvokerManagement.CreateOnboardedAPIInvokerRequest{
			APIInvokerEnrolmentDetails: &models.CapifApiInvokerEnrolmentDetails{
				OnboardingInformation: &models.CapifOnboardingInformation{
					ApiInvokerPublicKey: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})),
				},
				NotificationDestination: i.cfg.NotificationDestination,
				ApiInvokerInformation:   i.info,
				SupportedFeatures:       "0",
			},
		})
	if err != nil {
		return fmt.Errorf("onboarding at the CCF: %w", describe(err))
	}
	if rsp.Accepted {
		return errors.New("onboarding at the CCF: 202 Accepted; onboarding with approval is not supported")
	}
	d := rsp.APIInvokerEnrolmentDetails
	if d.ApiInvokerId == "" || d.OnboardingInformation == nil || d.OnboardingInformation.ApiInvokerCertificate == "" ||
		d.OnboardingInformation.OnboardingSecret == "" {
		return errors.New("onboarding at the CCF: no API invoker ID, certificate or onboarding secret")
	}
	st := &state{
		CcfURI:           i.cfg.CcfURI,
		APIInvokerID:     d.ApiInvokerId,
		Certificate:      d.OnboardingInformation.ApiInvokerCertificate,
		PrivateKey:       string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})),
		OnboardingSecret: d.OnboardingInformation.OnboardingSecret,
	}
	if err := i.checkCertificate(st, &key.PublicKey); err != nil {
		return err
	}
	if err := i.use(st); err != nil {
		return err
	}
	if err := saveState(i.cfg.State, st); err != nil {
		return err
	}
	logger.CapifLog.Infof("Onboarded at the CCF as API invoker %s", st.APIInvokerID)
	return nil
}

// checkCertificate checks the certificate of the onboarding: issued by the
// CA of the CAPIF core function for client authentication, for the public
// key of the AF, with the API invoker ID as CN (TS 29.222
// table 8.4.4.2.5-1).
func (i *Invoker) checkCertificate(st *state, pub *ecdsa.PublicKey) error {
	block, _ := pem.Decode([]byte(st.Certificate))
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("onboarding at the CCF: the API invoker certificate is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("onboarding at the CCF: %w", err)
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     i.pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return fmt.Errorf("onboarding at the CCF: API invoker certificate: %w", err)
	}
	if !pub.Equal(cert.PublicKey) || cert.Subject.CommonName != st.APIInvokerID {
		return errors.New("onboarding at the CCF: the certificate is not the one of this API invoker")
	}
	return nil
}

// prepare discovers the AKMA API (Discover_Service_API, TS 29.222
// cl. 5.2.2.2), obtains the security method for its AEF
// (Obtain_Security_Method, cl. 5.6.2.2) and asks the AEF to check the
// authentication of the API invoker (Initiate_Authentication, cl. 6.2.2.2;
// TS 33.122 cl. 6.5.2.3 step 5).
func (i *Invoker) prepare(ctx context.Context) error {
	id := i.st.APIInvokerID
	api, version := AkmaAPI, akmaAPIVersion

	dcfg := DiscoverService.NewConfiguration()
	dcfg.SetBasePath(i.cfg.CcfURI)
	dcfg.SetHTTPClient(i.ccf)
	drsp, err := DiscoverService.NewAPIClient(dcfg).AllPublishedServiceAPIsCollectionApi.GetPubServAPIs(ctx,
		&DiscoverService.GetPubServAPIsRequest{ApiInvokerId: &id, ApiName: &api, ApiVersion: &version})
	if err != nil {
		if status(err) == http.StatusForbidden {
			return errUnknownInvoker
		}
		return fmt.Errorf("discovery of %s at the CCF: %w", AkmaAPI, describe(err))
	}
	apiRoot, aefID, err := chooseAEF(drsp.DiscoveredAPIs.ServiceAPIDescriptions, i.cfg.APIScheme)
	if err != nil {
		return err
	}
	logger.CapifLog.Infof("%s discovered at %s, AEF %s", AkmaAPI, apiRoot, aefID)

	scfg := Security.NewConfiguration()
	scfg.SetBasePath(i.cfg.CcfURI)
	scfg.SetHTTPClient(i.ccf)
	srsp, err := Security.NewAPIClient(scfg).IndividualTrustedAPIInvokerStoreApi.CreateSecIndTrustedAPIInv(ctx,
		&Security.CreateSecIndTrustedAPIInvRequest{
			ApiInvokerId: &id,
			ServiceSecurity: &models.CapifServiceSecurity{
				SecurityInfo: []models.CapifSecurityInformation{{
					AefId:               aefID,
					PrefSecurityMethods: []models.CapifSecurityMethod{models.CapifSecurityMethod_OAUTH},
				}},
				NotificationDestination: i.cfg.NotificationDestination,
				SupportedFeatures:       "0",
			},
		})
	if err != nil {
		if status(err) == http.StatusNotFound {
			return errUnknownInvoker
		}
		return fmt.Errorf("security method at the CCF: %w", describe(err))
	}
	oauth := false
	for _, s := range srsp.ServiceSecurity.SecurityInfo {
		oauth = oauth || (s.AefId == aefID && s.SelSecurityMethod == models.CapifSecurityMethod_OAUTH)
	}
	if !oauth {
		return fmt.Errorf("the CCF selected no OAUTH security method for AEF %s", aefID)
	}
	logger.CapifLog.Infof("Security method OAUTH at AEF %s", aefID)

	acfg := AEFSecurity.NewConfiguration()
	acfg.SetBasePath(apiRoot)
	acfg.SetHTTPClient(&http.Client{Timeout: requestTimeout})
	if _, err := AEFSecurity.NewAPIClient(acfg).CheckAuthenticationRequestApi.CheckAuthReq(ctx,
		&AEFSecurity.CheckAuthReqRequest{CheckAuthenticationReq: &models.CapifCheckAuthenticationReq{
			ApiInvokerId:      id,
			SupportedFeatures: "0",
		}}); err != nil {
		return fmt.Errorf("check-authentication at the NEF %s: %w", apiRoot, describe(err))
	}
	logger.CapifLog.Infof("The NEF has the authentication data of API invoker %s", id)
	i.apiRoot, i.aefID, i.token = apiRoot, aefID, ""
	return nil
}

// TokenCtx returns ctx with an access token of the CAPIF core function for
// the AKMA API at the AEF, for the client of the NEF.
func (i *Invoker) TokenCtx(ctx context.Context, _ models.NrfNfManagementNfType, _ string) (context.Context, error) {
	tok, err := i.accessToken(ctx)
	if err != nil {
		return nil, err
	}
	return context.WithValue(ctx, openapi.ContextAccessToken, tok), nil
}

// Invalidate drops the access token, which the AEF refused: "the API
// Invoker shall return to the CAPIF Core Function" (TS 33.122 Annex C.4.1).
func (i *Invoker) Invalidate() {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.token = ""
}

// accessToken returns the access token, requested at the first use, kept
// only in memory and renewed renewBefore before the end of expires_in
// (TS 33.122 Annex C.4.1 and C.5). When the CAPIF core function no longer
// knows the API invoker, the AF onboards again, once.
func (i *Invoker) accessToken(ctx context.Context) (string, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.token != "" && i.now().Before(i.expiry.Add(-renewBefore)) {
		return i.token, nil
	}
	for again := false; ; again = true {
		if i.st == nil {
			if err := i.setUp(ctx); err != nil {
				return "", err
			}
		}
		tok, err := i.requestToken(ctx)
		if errors.Is(err, errUnknownInvoker) && !again {
			logger.CapifLog.Warnf("The CCF no longer knows API invoker %s: onboarding again", i.st.APIInvokerID)
			i.forget()
			continue
		}
		return tok, err
	}
}

// requestToken obtains an access token (Obtain_Authorization, TS 29.222
// cl. 5.6.2.3; TS 33.122 Annex C.3): client credentials with the onboarding
// secret, over TLS with the client certificate, for the AKMA API at the AEF.
func (i *Invoker) requestToken(ctx context.Context) (string, error) {
	id := i.st.APIInvokerID
	cfg := Security.NewConfiguration()
	cfg.SetBasePath(i.cfg.CcfURI)
	cfg.SetHTTPClient(i.ccf)
	rsp, err := Security.NewAPIClient(cfg).IndividualTrustedAPIInvokerStoreApi.GetOAuthIndAPIInv(ctx,
		&Security.GetOAuthIndAPIInvRequest{SecurityId: &id, AccessTokenReq: &models.CapifAccessTokenReq{
			GrantType:    "client_credentials",
			ClientId:     id,
			ClientSecret: i.st.OnboardingSecret,
			Scope:        "3gpp#" + i.aefID + ":" + AkmaAPI,
		}})
	if err != nil {
		var apiErr openapi.GenericOpenAPIError
		if errors.As(err, &apiErr) {
			if e, ok := apiErr.ErrorModel.(models.CapifAccessTokenErr); ok {
				// RFC 6749 cl. 5.2: the client is not known.
				if string(e.Error) == "invalid_client" {
					return "", errUnknownInvoker
				}
				return "", fmt.Errorf("access token: the CCF answered %d %s", apiErr.ErrorStatus, e.Error)
			}
		}
		return "", fmt.Errorf("access token: %w", describe(err))
	}
	t := rsp.AccessTokenRsp
	if t.AccessToken == "" || !strings.EqualFold(t.TokenType, "Bearer") {
		return "", errors.New("access token: the CCF gave no bearer token")
	}
	i.token, i.expiry = t.AccessToken, i.now().Add(time.Duration(t.ExpiresIn)*time.Second)
	logger.CapifLog.Infof("Access token obtained, expires in %d s", t.ExpiresIn)
	return t.AccessToken, nil
}

// Close offboards the AF from the CAPIF core function when the
// configuration asks for it (Offboard_API_Invoker, TS 29.222 cl. 5.5.2.3;
// TS 33.122 cl. 6.8), and deletes its state (step 5).
func (i *Invoker) Close(ctx context.Context) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if !i.cfg.OffboardOnExit || i.st == nil {
		return
	}
	id := i.st.APIInvokerID
	cfg := APIInvokerManagement.NewConfiguration()
	cfg.SetBasePath(i.cfg.CcfURI)
	cfg.SetHTTPClient(i.ccf)
	_, err := APIInvokerManagement.NewAPIClient(cfg).IndividualOnboardedAPIInvokerDocumentApi.
		DeleteIndOnboardedAPIInvoker(ctx, &APIInvokerManagement.DeleteIndOnboardedAPIInvokerRequest{OnboardingId: &id})
	if err != nil && status(err) != http.StatusNotFound {
		logger.CapifLog.Warnf("Offboarding from the CCF: %v", describe(err))
		return
	}
	i.forget()
	logger.CapifLog.Infof("Offboarded from the CCF")
}

// status returns the HTTP status of an error of the openapi clients, or 0.
func status(err error) int {
	var apiErr openapi.GenericOpenAPIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorStatus
	}
	return 0
}

// describe gives the status, the cause and the detail of an error of the
// openapi clients.
func describe(err error) error {
	var apiErr openapi.GenericOpenAPIError
	if !errors.As(err, &apiErr) {
		return err
	}
	var pd models.ProblemDetails
	switch m := apiErr.ErrorModel.(type) {
	case APIInvokerManagement.OperationError:
		pd = m.ProblemDetails
	case DiscoverService.OperationError:
		pd = m.ProblemDetails
	case Security.OperationError:
		pd = m.ProblemDetails
	case AEFSecurity.OperationError:
		pd = m.ProblemDetails
	}
	return fmt.Errorf("answer %d %s %s", apiErr.ErrorStatus, pd.Cause, pd.Detail)
}
