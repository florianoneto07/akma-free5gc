package sbi

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/florianoneto07/akma-free5gc/free5gc/ccf/internal/credential"
	"github.com/florianoneto07/akma-free5gc/free5gc/ccf/internal/jws"
	"github.com/florianoneto07/akma-free5gc/free5gc/ccf/internal/logger"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/capif/APIInvokerManagement"
	"github.com/free5gc/openapi/capif/DiscoverService"
	"github.com/free5gc/openapi/capif/PublishService"
	"github.com/free5gc/openapi/capif/Security"
	"github.com/free5gc/openapi/models"
)

func ptr[T any](v T) *T { return &v }

func status(t *testing.T, err error) (int, openapi.GenericOpenAPIError) {
	t.Helper()
	var apiErr openapi.GenericOpenAPIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected an API error, got %v", err)
	}
	return apiErr.ErrorStatus, apiErr
}

func problem(t *testing.T, apiErr openapi.GenericOpenAPIError) models.ProblemDetails {
	t.Helper()
	switch m := apiErr.ErrorModel.(type) {
	case APIInvokerManagement.OperationError:
		return m.ProblemDetails
	case DiscoverService.OperationError:
		return m.ProblemDetails
	case PublishService.OperationError:
		return m.ProblemDetails
	case Security.OperationError:
		return m.ProblemDetails
	}
	t.Fatalf("no ProblemDetails in %T", apiErr.ErrorModel)
	return models.ProblemDetails{}
}

// invoker is an onboarded API invoker of the tests.
type invoker struct {
	details models.CapifApiInvokerEnrolmentDetails
	cert    tls.Certificate
}

func (tc *testCCF) credential(t *testing.T, profile string, validity time.Duration) string {
	t.Helper()
	tok, err := credential.Issue(tc.ctx.CredentialKey(), "ccf", profile, time.Now(), validity)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func (tc *testCCF) invokerAPI(cert *tls.Certificate) *APIInvokerManagement.APIClient {
	cfg := APIInvokerManagement.NewConfiguration()
	cfg.SetBasePath(tc.external.URL)
	cfg.SetHTTPClient(tc.client(cert, 0, false))
	return APIInvokerManagement.NewAPIClient(cfg)
}

func (tc *testCCF) discoverAPI(cert *tls.Certificate) *DiscoverService.APIClient {
	cfg := DiscoverService.NewConfiguration()
	cfg.SetBasePath(tc.external.URL)
	cfg.SetHTTPClient(tc.client(cert, 0, false))
	return DiscoverService.NewAPIClient(cfg)
}

func (tc *testCCF) securityAPI(cert *tls.Certificate) *Security.APIClient {
	cfg := Security.NewConfiguration()
	cfg.SetBasePath(tc.external.URL)
	cfg.SetHTTPClient(tc.client(cert, 0, false))
	return Security.NewAPIClient(cfg)
}

func (tc *testCCF) internalSecurityAPI() *Security.APIClient {
	cfg := Security.NewConfiguration()
	cfg.SetBasePath(tc.internal.URL)
	cfg.SetHTTPClient(&http.Client{})
	return Security.NewAPIClient(cfg)
}

func (tc *testCCF) publishAPI() *PublishService.APIClient {
	cfg := PublishService.NewConfiguration()
	cfg.SetBasePath(tc.internal.URL)
	cfg.SetHTTPClient(&http.Client{})
	return PublishService.NewAPIClient(cfg)
}

// akmaAPI is 3gpp-akma as the NEF publishes it.
func akmaAPI() models.CapifServiceApiDescription {
	return models.CapifServiceApiDescription{
		ApiName:           "3gpp-akma",
		Description:       "AKMA API of the NEF",
		SupportedFeatures: "0",
		AefProfiles: []models.CapifAefProfile{{
			AefId: "nef-aef",
			Versions: []models.CapifVersion{{
				ApiVersion: "v1",
				CustOperations: []models.CapifCustomOperation{{
					CommType:   models.CapifCommunicationType_REQUEST_RESPONSE,
					CustOpName: "retrieve",
					Operations: []models.CapifOperation{models.CapifOperation_POST},
				}},
			}},
			Protocol:        models.CapifProtocol_HTTP_1_1,
			DataFormat:      models.CapifDataFormat_JSON,
			SecurityMethods: []models.CapifSecurityMethod{models.CapifSecurityMethod_OAUTH},
			InterfaceDescriptions: []models.CapifInterfaceDescription{{
				Ipv4Addr:        "192.168.16.130",
				Port:            8000,
				SecurityMethods: []models.CapifSecurityMethod{models.CapifSecurityMethod_OAUTH},
			}},
		}},
	}
}

func (tc *testCCF) publish(t *testing.T) models.CapifServiceApiDescription {
	t.Helper()
	rsp, err := tc.publishAPI().APFPublishedAPIsCollectionApi.CreateAPFPubAPIs(context.Background(),
		&PublishService.CreateAPFPubAPIsRequest{ApfId: ptr("nef-apf"), ServiceAPIDescription: ptr(akmaAPI())})
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if rsp.ServiceAPIDescription.ApiId == "" ||
		rsp.Location != tc.server.internalRoot()+"/published-apis/v1/nef-apf/service-apis/"+rsp.ServiceAPIDescription.ApiId {
		t.Fatalf("publish: %+v", rsp)
	}
	return rsp.ServiceAPIDescription
}

func publicKeyPEM(t *testing.T, pub any) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func enrolment(pub string) *models.CapifApiInvokerEnrolmentDetails {
	return &models.CapifApiInvokerEnrolmentDetails{
		OnboardingInformation:   &models.CapifOnboardingInformation{ApiInvokerPublicKey: pub},
		NotificationDestination: "https://192.168.16.129/capif/notify",
		ApiInvokerInformation:   "AKMA AF af1.akma.example",
		SupportedFeatures:       "0",
	}
}

func (tc *testCCF) onboard(t *testing.T, profile string) invoker {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return tc.onboardWithKey(t, profile, key)
}

func (tc *testCCF) onboardWithKey(t *testing.T, profile string, key interface {
	Public() crypto.PublicKey
}) invoker {
	t.Helper()
	ctx := context.WithValue(context.Background(), openapi.ContextAccessToken, tc.credential(t, profile, time.Hour))
	rsp, err := tc.invokerAPI(nil).OnboardedAPIInvokersCollectionApi.CreateOnboardedAPIInvoker(ctx,
		&APIInvokerManagement.CreateOnboardedAPIInvokerRequest{
			APIInvokerEnrolmentDetails: enrolment(publicKeyPEM(t, key.Public())),
		})
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}
	d := rsp.APIInvokerEnrolmentDetails
	if rsp.Accepted || d.ApiInvokerId == "" || d.OnboardingInformation == nil ||
		d.OnboardingInformation.OnboardingSecret == "" || d.SupportedFeatures != "0" ||
		rsp.Location != tc.server.externalRoot()+"/api-invoker-management/v1/onboardedInvokers/"+d.ApiInvokerId {
		t.Fatalf("onboard: %+v", rsp)
	}
	block, _ := pem.Decode([]byte(d.OnboardingInformation.ApiInvokerCertificate))
	if block == nil {
		t.Fatal("onboard: no certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	// TS 29.222 table 8.4.4.2.5-1: the CN is the API invoker ID; the
	// certificate is issued by the CA of the CCF (TS 33.122 cl. 6.1 step 4).
	if cert.Subject.CommonName != d.ApiInvokerId {
		t.Fatalf("certificate CN %q, API invoker %q", cert.Subject.CommonName, d.ApiInvokerId)
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: tc.caPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("certificate: %v", err)
	}
	checkInvokerCertificate(t, cert)
	return invoker{details: d, cert: tls.Certificate{Certificate: [][]byte{block.Bytes}, PrivateKey: key}}
}

var (
	oidBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtKeyUsage      = asn1.ObjectIdentifier{2, 5, 29, 37}
)

// checkInvokerCertificate checks the TLS entity certificate profile of
// TS 33.310 cl. 6.1.3a and 6.1.1: subject O=<CA organization>, CN=<API
// invoker ID> in UTF8String; key usage digitalSignature, critical; extended
// key usage id-kp-clientAuth, not critical; no other critical extension, so
// no basic constraints; signed with SHA-384 by the P-384 CA.
func checkInvokerCertificate(t *testing.T, cert *x509.Certificate) {
	t.Helper()
	if o := cert.Subject.Organization; len(o) != 1 || o[0] != "AKMA test" {
		t.Fatalf("certificate O %v", o)
	}
	var name []asn1.RawValue
	if rest, err := asn1.Unmarshal(cert.RawSubject, &name); err != nil || len(rest) != 0 {
		t.Fatalf("subject: %v", err)
	}
	for _, rdn := range name {
		var attrs []struct {
			Type  asn1.ObjectIdentifier
			Value asn1.RawValue
		}
		if _, err := asn1.UnmarshalWithParams(rdn.FullBytes, &attrs, "set"); err != nil {
			t.Fatalf("subject: %v", err)
		}
		for _, a := range attrs {
			if a.Value.Tag != asn1.TagUTF8String {
				t.Fatalf("subject attribute %v with tag %d, not UTF8String", a.Type, a.Value.Tag)
			}
		}
	}
	seen := map[string]bool{}
	for _, e := range cert.Extensions {
		seen[e.Id.String()] = true
		switch {
		case e.Id.Equal(oidBasicConstraints):
			t.Fatal("certificate with basic constraints")
		case e.Id.Equal(oidKeyUsage):
			if !e.Critical {
				t.Fatal("key usage not critical")
			}
		case e.Critical:
			t.Fatalf("critical extension %v", e.Id)
		}
	}
	if !seen[oidKeyUsage.String()] || !seen[oidExtKeyUsage.String()] ||
		cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 || cert.SignatureAlgorithm != x509.ECDSAWithSHA384 {
		t.Fatalf("certificate: key usage %v, extensions %v, signature %v", cert.KeyUsage, seen, cert.SignatureAlgorithm)
	}
	// The CRL of the CA of the CCF, and no OCSP responder (TS 33.310 cl. 6.1.3a).
	if !slices.Equal(cert.CRLDistributionPoints, []string{testCrlUri}) || len(cert.OCSPServer) != 0 {
		t.Fatalf("certificate with other revocation data: %v %v", cert.CRLDistributionPoints, cert.OCSPServer)
	}
}

func (tc *testCCF) securityMethod(t *testing.T, inv invoker, methods ...models.CapifSecurityMethod) models.CapifServiceSecurity {
	t.Helper()
	id := inv.details.ApiInvokerId
	rsp, err := tc.securityAPI(&inv.cert).IndividualTrustedAPIInvokerStoreApi.CreateSecIndTrustedAPIInv(
		context.Background(), &Security.CreateSecIndTrustedAPIInvRequest{
			ApiInvokerId: &id,
			ServiceSecurity: &models.CapifServiceSecurity{
				SecurityInfo:            []models.CapifSecurityInformation{{AefId: "nef-aef", PrefSecurityMethods: methods}},
				NotificationDestination: "https://192.168.16.129/capif/notify",
			},
		})
	if err != nil {
		t.Fatalf("security method: %v", err)
	}
	return rsp.ServiceSecurity
}

func (tc *testCCF) token(inv invoker, cert *tls.Certificate, req models.CapifAccessTokenReq,
	ctx context.Context,
) (*Security.GetOAuthIndAPIInvResponse, error) {
	id := inv.details.ApiInvokerId
	return tc.securityAPI(cert).IndividualTrustedAPIInvokerStoreApi.GetOAuthIndAPIInv(ctx,
		&Security.GetOAuthIndAPIInvRequest{SecurityId: &id, AccessTokenReq: &req})
}

func tokenErr(t *testing.T, err error) (int, string) {
	t.Helper()
	code, apiErr := status(t, err)
	e, ok := apiErr.ErrorModel.(models.CapifAccessTokenErr)
	if !ok {
		t.Fatalf("expected AccessTokenErr, got %T %s", apiErr.ErrorModel, apiErr.RawBody)
	}
	return code, e.Error
}

// TestCapifFlow runs the CAPIF procedures of TS 29.222 with the clients of
// the openapi patch: publication (cl. 5.3), onboarding and offboarding
// (cl. 5.5), discovery (cl. 5.2), and the security method, the token and the
// security information of the API invoker (cl. 5.6).
func TestCapifFlow(t *testing.T) {
	var logs bytes.Buffer
	logger.Log.SetOutput(&logs)
	t.Cleanup(func() { logger.Log.SetOutput(io.Discard) })

	tc := newTestCCF(t)
	api := tc.publish(t)
	inv := tc.onboard(t, "af1-external")
	id := inv.details.ApiInvokerId
	if l := inv.details.ApiList; l == nil || len(l.ServiceAPIDescriptions) != 1 ||
		l.ServiceAPIDescriptions[0].ApiId != api.ApiId {
		t.Fatalf("apiList: %+v", inv.details.ApiList)
	}

	// Discovery, with the client certificate (TS 33.122 cl. 6.3.1.1).
	disc, err := tc.discoverAPI(&inv.cert).AllPublishedServiceAPIsCollectionApi.GetPubServAPIs(context.Background(),
		&DiscoverService.GetPubServAPIsRequest{ApiInvokerId: &id, ApiName: ptr("3gpp-akma"), ApiVersion: ptr("v1")})
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if got := disc.DiscoveredAPIs.ServiceAPIDescriptions; len(got) != 1 ||
		got[0].AefProfiles[0].InterfaceDescriptions[0].Ipv4Addr != "192.168.16.130" ||
		got[0].AefProfiles[0].InterfaceDescriptions[0].Port != 8000 {
		t.Fatalf("discover: %+v", got)
	}
	disc, err = tc.discoverAPI(&inv.cert).AllPublishedServiceAPIsCollectionApi.GetPubServAPIs(context.Background(),
		&DiscoverService.GetPubServAPIsRequest{ApiInvokerId: &id, AefId: ptr("other-aef")})
	if err != nil || disc.DiscoveredAPIs.ServiceAPIDescriptions != nil {
		t.Fatalf("discover without match: %v %+v", err, disc)
	}

	// Security method: OAUTH is selected; PSK alone has no common method.
	if sec := tc.securityMethod(t, inv, models.CapifSecurityMethod_PSK); sec.SecurityInfo[0].SelSecurityMethod != "" {
		t.Fatalf("PSK selected: %+v", sec)
	}
	sec := tc.securityMethod(t, inv, models.CapifSecurityMethod_PSK, models.CapifSecurityMethod_OAUTH)
	if sec.SecurityInfo[0].SelSecurityMethod != models.CapifSecurityMethod_OAUTH || sec.SupportedFeatures != "0" {
		t.Fatalf("security method: %+v", sec)
	}

	// Access token with client_secret, then with HTTP Basic.
	secret := inv.details.OnboardingInformation.OnboardingSecret
	before := time.Now()
	tok, err := tc.token(inv, &inv.cert, models.CapifAccessTokenReq{GrantType: "client_credentials", ClientId: id,
		ClientSecret: secret, Scope: "3gpp#nef-aef:3gpp-akma"}, context.Background())
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if tok.AccessTokenRsp.TokenType != "Bearer" || tok.AccessTokenRsp.ExpiresIn != 600 ||
		tok.AccessTokenRsp.Scope != "3gpp#nef-aef:3gpp-akma" {
		t.Fatalf("token: %+v", tok.AccessTokenRsp)
	}
	// ES256 with the "kid" of the token key (TS 33.210 cl. 6.3.3.1).
	var claims models.CapifAccessTokenClaims
	parsed, err := jwt.ParseWithClaims(tok.AccessTokenRsp.AccessToken, &claims, jws.Keyfunc(tc.ctx.TokenPublicKey()),
		jwt.WithValidMethods([]string{jws.Alg}), jwt.WithExpirationRequired())
	if err != nil {
		t.Fatalf("token signature: %v", err)
	}
	if kid, _ := jws.Thumbprint(tc.ctx.TokenPublicKey()); parsed.Header["kid"] != kid || len(parsed.Header) != 3 {
		t.Fatalf("token header: %v", parsed.Header)
	}
	if claims.Iss != id || claims.ClientId != id || claims.Scope != "3gpp#nef-aef:3gpp-akma" ||
		claims.Exp < before.Add(10*time.Minute).Unix() || claims.Exp > time.Now().Add(10*time.Minute).Unix()+1 {
		t.Fatalf("claims: %+v", claims)
	}
	basic := context.WithValue(context.Background(), openapi.ContextBasicAuth,
		openapi.BasicAuth{UserName: id, Password: secret})
	tok2, err := tc.token(inv, &inv.cert, models.CapifAccessTokenReq{GrantType: "client_credentials", ClientId: id}, basic)
	if err != nil || tok2.AccessTokenRsp.Scope != "3gpp#nef-aef:3gpp-akma" {
		t.Fatalf("token with Basic and without scope: %v %+v", err, tok2)
	}

	// Security information of the API invoker, for the NEF.
	info, err := tc.internalSecurityAPI().IndividualTrustedAPIInvokerStoreApi.GetSecIndTrustedAPIInv(
		context.Background(), &Security.GetSecIndTrustedAPIInvRequest{ApiInvokerId: &id,
			AuthenticationInfo: ptr(true), AuthorizationInfo: ptr(true)})
	if err != nil {
		t.Fatalf("invoker information: %v", err)
	}
	item := info.ServiceSecurity.SecurityInfo[0]
	if item.AefId != "nef-aef" || item.SelSecurityMethod != models.CapifSecurityMethod_OAUTH ||
		item.AuthenticationInfo != tc.ctx.CaPEM() ||
		item.AuthorizationInfo != `{"akmaAfIds":["`+testAfId+`","`+testOtherAfId+`"]}` {
		t.Fatalf("invoker information: %+v", item)
	}

	// Offboarding: the certificate is revoked and no longer opens a session,
	// and the security information no longer knows the API invoker.
	if _, err := tc.invokerAPI(&inv.cert).IndividualOnboardedAPIInvokerDocumentApi.DeleteIndOnboardedAPIInvoker(
		context.Background(), &APIInvokerManagement.DeleteIndOnboardedAPIInvokerRequest{OnboardingId: &id}); err != nil {
		t.Fatalf("offboard: %v", err)
	}
	_, err = tc.invokerAPI(&inv.cert).IndividualOnboardedAPIInvokerDocumentApi.DeleteIndOnboardedAPIInvoker(
		context.Background(), &APIInvokerManagement.DeleteIndOnboardedAPIInvokerRequest{OnboardingId: &id})
	var apiErr openapi.GenericOpenAPIError
	if err == nil || errors.As(err, &apiErr) {
		t.Fatalf("offboard again: %v", err)
	}
	_, err = tc.token(inv, &inv.cert, models.CapifAccessTokenReq{GrantType: "client_credentials", ClientId: id,
		ClientSecret: secret}, context.Background())
	if err == nil || errors.As(err, &apiErr) {
		t.Fatalf("token after offboarding: %v", err)
	}
	_, err = tc.internalSecurityAPI().IndividualTrustedAPIInvokerStoreApi.GetSecIndTrustedAPIInv(
		context.Background(), &Security.GetSecIndTrustedAPIInvRequest{ApiInvokerId: &id})
	if code, _ := status(t, err); code != http.StatusNotFound {
		t.Fatalf("invoker information after offboarding: %d", code)
	}

	// Unpublication.
	pub := tc.publishAPI()
	list, err := pub.APFPublishedAPIsCollectionApi.GetAPFPubAPIs(context.Background(),
		&PublishService.GetAPFPubAPIsRequest{ApfId: ptr("nef-apf")})
	if err != nil || len(list.ServiceAPIDescriptions) != 1 {
		t.Fatalf("published APIs: %v %+v", err, list)
	}
	ind := &PublishService.IndAPFPubAPIRequest{ApfId: ptr("nef-apf"), ServiceApiId: &api.ApiId}
	if _, err := pub.IndividualAPFPublishedAPIDocumentApi.DeleteIndAPFPubAPI(context.Background(), ind); err != nil {
		t.Fatalf("unpublish: %v", err)
	}
	_, err = pub.IndividualAPFPublishedAPIDocumentApi.GetIndAPFPubAPI(context.Background(), ind)
	if code, _ := status(t, err); code != http.StatusNotFound {
		t.Fatalf("published API after unpublication: %d", code)
	}

	// No secret, token, credential or private key in the log.
	for _, s := range []string{secret, tok.AccessTokenRsp.AccessToken, tok2.AccessTokenRsp.AccessToken, "PRIVATE KEY"} {
		if strings.Contains(logs.String(), s) {
			t.Fatalf("the log has a secret: %q", s[:8])
		}
	}
	if !strings.Contains(logs.String(), "API invoker "+id+" onboarded, profile af1-external") {
		t.Fatalf("no onboarding in the log:\n%s", logs.String())
	}
}

// TestCapifOnboardingRefused covers the refusals of Onboard_API_Invoker
// (TS 29.222 cl. 5.5.2.2): the credential (TS 33.122 cl. 6.1) and the body
// (table 8.4.4.2.2-1).
func TestCapifOnboardingRefused(t *testing.T) {
	tc := newTestCCF(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub := publicKeyPEM(t, &key.PublicKey)
	onboard := func(cred string, d *models.CapifApiInvokerEnrolmentDetails) error {
		ctx := context.Background()
		if cred != "" {
			ctx = context.WithValue(ctx, openapi.ContextAccessToken, cred)
		}
		_, err := tc.invokerAPI(nil).OnboardedAPIInvokersCollectionApi.CreateOnboardedAPIInvoker(ctx,
			&APIInvokerManagement.CreateOnboardedAPIInvokerRequest{APIInvokerEnrolmentDetails: d})
		return err
	}
	good := tc.credential(t, "af1-external", time.Hour)
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	forged, _ := credential.Issue(otherKey, "ccf", "af1-external", time.Now(), time.Hour)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rs512, _ := jwt.NewWithClaims(jwt.SigningMethodRS512, jwt.RegisteredClaims{Issuer: "ccf", Subject: "af1-external",
		Audience: jwt.ClaimStrings{credential.Audience}, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}).
		SignedString(rsaKey)
	expired, _ := credential.Issue(tc.ctx.CredentialKey(), "ccf", "af1-external", time.Now().Add(-2*time.Hour), time.Hour)
	unknown, _ := credential.Issue(tc.ctx.CredentialKey(), "ccf", "nobody", time.Now(), time.Hour)
	tampered := good[:len(good)-2] + map[bool]string{true: "AA", false: "BB"}[!strings.HasSuffix(good, "AA")]

	for _, c := range []struct {
		name, cred string
	}{
		{"no credential", ""}, {"another key", forged}, {"expired", expired},
		{"unknown profile", unknown}, {"tampered", tampered}, {"RS512", rs512},
	} {
		code, apiErr := status(t, onboard(c.cred, enrolment(pub)))
		if code != http.StatusUnauthorized {
			t.Fatalf("%s: %d %s", c.name, code, apiErr.RawBody)
		}
	}

	rsa1024, _ := rsa.GenerateKey(rand.Reader, 1024)
	withId := enrolment(pub)
	withId.ApiInvokerId = "chosen-by-the-invoker"
	noFeatures := enrolment(pub)
	noFeatures.SupportedFeatures = ""
	noDestination := enrolment(pub)
	noDestination.NotificationDestination = "not a uri"
	for _, c := range []struct {
		name  string
		d     *models.CapifApiInvokerEnrolmentDetails
		cause string
	}{
		{"apiInvokerId present", withId, "OPTIONAL_IE_INCORRECT"},
		{"no supportedFeatures", noFeatures, "MANDATORY_IE_MISSING"},
		{"bad notificationDestination", noDestination, "MANDATORY_IE_INCORRECT"},
		{"RSA 1024", enrolment(publicKeyPEM(t, &rsa1024.PublicKey)), "MANDATORY_IE_INCORRECT"},
		{"not PEM", enrolment("abc"), "MANDATORY_IE_INCORRECT"},
	} {
		code, apiErr := status(t, onboard(good, c.d))
		if pd := problem(t, apiErr); code != http.StatusBadRequest || pd.Cause != c.cause {
			t.Fatalf("%s: %d %+v", c.name, code, pd)
		}
	}

	// The 401 carries a Bearer challenge (RFC 6750 cl. 3; RFC 9110 cl. 15.5.2).
	req, _ := http.NewRequest(http.MethodPost, tc.external.URL+"/api-invoker-management/v1/onboardedInvokers",
		strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tampered)
	rsp, err := tc.client(nil, 0, false).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = rsp.Body.Close()
	if rsp.StatusCode != 401 || rsp.Header.Get("WWW-Authenticate") != `Bearer error="invalid_token"` ||
		rsp.Header.Get("Content-Type") != "application/problem+json" {
		t.Fatalf("401: %d %v", rsp.StatusCode, rsp.Header)
	}
}

// TestCapifClientCertificate covers the operations that need the client
// certificate of the API invoker (TS 33.122 cl. 6.3.1.1).
func TestCapifClientCertificate(t *testing.T) {
	tc := newTestCCF(t)
	tc.publish(t)
	a := tc.onboard(t, "af1-external")
	b := tc.onboard(t, "af1-external")
	idA, idB := a.details.ApiInvokerId, b.details.ApiInvokerId

	discover := func(cert *tls.Certificate, id string) error {
		_, err := tc.discoverAPI(cert).AllPublishedServiceAPIsCollectionApi.GetPubServAPIs(context.Background(),
			&DiscoverService.GetPubServAPIsRequest{ApiInvokerId: &id})
		return err
	}
	if code, _ := status(t, discover(nil, idA)); code != http.StatusForbidden {
		t.Fatalf("discover without certificate: %d", code)
	}
	if code, _ := status(t, discover(&b.cert, idA)); code != http.StatusForbidden {
		t.Fatalf("discover with another certificate: %d", code)
	}
	_, err := tc.invokerAPI(&b.cert).IndividualOnboardedAPIInvokerDocumentApi.DeleteIndOnboardedAPIInvoker(
		context.Background(), &APIInvokerManagement.DeleteIndOnboardedAPIInvokerRequest{OnboardingId: &idA})
	if code, _ := status(t, err); code != http.StatusForbidden {
		t.Fatalf("offboard another invoker: %d", code)
	}
	_, err = tc.securityAPI(nil).IndividualTrustedAPIInvokerStoreApi.CreateSecIndTrustedAPIInv(context.Background(),
		&Security.CreateSecIndTrustedAPIInvRequest{ApiInvokerId: &idB, ServiceSecurity: &models.CapifServiceSecurity{
			SecurityInfo: []models.CapifSecurityInformation{{AefId: "nef-aef",
				PrefSecurityMethods: []models.CapifSecurityMethod{models.CapifSecurityMethod_OAUTH}}},
			NotificationDestination: "https://192.168.16.129/capif/notify",
		}})
	if code, _ := status(t, err); code != http.StatusForbidden {
		t.Fatalf("security method without certificate: %d", code)
	}

	// Query parameters: a feature the CCF does not support, an unknown
	// parameter, and no api-invoker-id.
	for _, c := range []struct{ query, cause string }{
		{"api-invoker-id=" + idA + "&api-ids=x", "INVALID_QUERY_PARAM"},
		{"api-invoker-id=" + idA + "&foo=1", "INVALID_QUERY_PARAM"},
		{"api-name=3gpp-akma", "MANDATORY_QUERY_PARAM_MISSING"},
	} {
		rsp, err := tc.client(&a.cert, 0, false).Get(tc.external.URL + "/service-apis/v1/allServiceAPIs?" + c.query)
		if err != nil {
			t.Fatal(err)
		}
		var pd models.ProblemDetails
		_ = json.NewDecoder(rsp.Body).Decode(&pd)
		_ = rsp.Body.Close()
		if rsp.StatusCode != 400 || pd.Cause != c.cause {
			t.Fatalf("%s: %d %+v", c.query, rsp.StatusCode, pd)
		}
	}
}

// TestCapifTokenRefused covers the refusals of Obtain_Authorization
// (TS 29.222 cl. 5.6.2.3.2, table 8.5.5.3-1; RFC 6749 cl. 5.2).
func TestCapifTokenRefused(t *testing.T) {
	tc := newTestCCF(t)
	tc.publish(t)
	inv := tc.onboard(t, "af1-external")
	fresh := tc.onboard(t, "af1-external")
	tc.securityMethod(t, inv, models.CapifSecurityMethod_OAUTH)
	id, secret := inv.details.ApiInvokerId, inv.details.OnboardingInformation.OnboardingSecret
	other := tc.onboard(t, "other")

	cases := []struct {
		name   string
		inv    invoker
		cert   *tls.Certificate
		req    models.CapifAccessTokenReq
		ctx    context.Context
		status int
		code   string
	}{
		{"wrong secret", inv, &inv.cert, models.CapifAccessTokenReq{GrantType: "client_credentials", ClientId: id,
			ClientSecret: "wrong"}, nil, 400, "invalid_client"},
		{"wrong secret with Basic", inv, &inv.cert, models.CapifAccessTokenReq{GrantType: "client_credentials",
			ClientId: id}, context.WithValue(context.Background(), openapi.ContextBasicAuth,
			openapi.BasicAuth{UserName: id, Password: "wrong"}), 401, "invalid_client"},
		{"no client certificate", inv, nil, models.CapifAccessTokenReq{GrantType: "client_credentials", ClientId: id,
			ClientSecret: secret}, nil, 400, "invalid_client"},
		{"certificate of another invoker", inv, &fresh.cert, models.CapifAccessTokenReq{
			GrantType: "client_credentials", ClientId: id, ClientSecret: secret}, nil, 400, "invalid_client"},
		{"password grant", inv, &inv.cert, models.CapifAccessTokenReq{GrantType: "password", ClientId: id,
			ClientSecret: secret}, nil, 400, "unsupported_grant_type"},
		{"API outside the profile", inv, &inv.cert, models.CapifAccessTokenReq{GrantType: "client_credentials",
			ClientId: id, ClientSecret: secret, Scope: "3gpp#nef-aef:3gpp-traffic-influence"}, nil, 400, "invalid_scope"},
		{"another AEF", inv, &inv.cert, models.CapifAccessTokenReq{GrantType: "client_credentials", ClientId: id,
			ClientSecret: secret, Scope: "3gpp#other-aef:3gpp-akma"}, nil, 400, "invalid_scope"},
		{"malformed scope", inv, &inv.cert, models.CapifAccessTokenReq{GrantType: "client_credentials", ClientId: id,
			ClientSecret: secret, Scope: "nef-aef:3gpp-akma"}, nil, 400, "invalid_scope"},
		{"no security method", fresh, &fresh.cert, models.CapifAccessTokenReq{GrantType: "client_credentials",
			ClientId: fresh.details.ApiInvokerId, ClientSecret: fresh.details.OnboardingInformation.OnboardingSecret},
			nil, 400, "unauthorized_client"},
	}
	for _, c := range cases {
		ctx := c.ctx
		if ctx == nil {
			ctx = context.Background()
		}
		_, err := tc.token(c.inv, c.cert, c.req, ctx)
		if code, e := tokenErr(t, err); code != c.status || e != c.code {
			t.Fatalf("%s: %d %s", c.name, code, e)
		}
	}

	// The profile "other" has no API published with OAUTH.
	tc.securityMethod(t, other, models.CapifSecurityMethod_OAUTH)
	_, err := tc.token(other, &other.cert, models.CapifAccessTokenReq{GrantType: "client_credentials",
		ClientId: other.details.ApiInvokerId, ClientSecret: other.details.OnboardingInformation.OnboardingSecret},
		context.Background())
	if code, e := tokenErr(t, err); code != 400 || e != "invalid_scope" {
		t.Fatalf("nothing to grant: %d %s", code, e)
	}

	// Raw request: Basic challenge on 401 and no-store on the errors.
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {id}}
	req, _ := http.NewRequest(http.MethodPost, tc.external.URL+"/capif-security/v1/securities/"+id+"/token",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(id, "wrong")
	rsp, err := tc.client(&inv.cert, 0, false).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = rsp.Body.Close()
	if rsp.StatusCode != 401 || rsp.Header.Get("WWW-Authenticate") != `Basic realm="capif-security"` ||
		rsp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("401: %d %v", rsp.StatusCode, rsp.Header)
	}
}

// TestCapifPublishRefused covers the refusals of Publish_Service_API
// (TS 29.222 cl. 5.3.2.2, tables 8.2.4.2.2-1 to 8.2.4.2.4-1).
func TestCapifPublishRefused(t *testing.T) {
	tc := newTestCCF(t)
	pub := tc.publishAPI()
	create := func(apf string, d models.CapifServiceApiDescription) (int, string) {
		_, err := pub.APFPublishedAPIsCollectionApi.CreateAPFPubAPIs(context.Background(),
			&PublishService.CreateAPFPubAPIsRequest{ApfId: &apf, ServiceAPIDescription: &d})
		code, apiErr := status(t, err)
		return code, problem(t, apiErr).Cause
	}
	if code, _ := create("other-apf", akmaAPI()); code != http.StatusForbidden {
		t.Fatalf("unknown APF: %d", code)
	}
	otherAef := akmaAPI()
	otherAef.AefProfiles[0].AefId = "other-aef"
	noMethods := akmaAPI()
	noMethods.AefProfiles[0].SecurityMethods = nil
	noMethods.AefProfiles[0].InterfaceDescriptions[0].SecurityMethods = nil
	both := akmaAPI()
	both.AefProfiles[0].DomainName = "nef.example"
	withId := akmaAPI()
	withId.ApiId = "chosen"
	for _, c := range []struct {
		name  string
		d     models.CapifServiceApiDescription
		cause string
	}{
		{"AEF of another provider", otherAef, "MANDATORY_IE_INCORRECT"},
		{"no security method", noMethods, "MANDATORY_IE_MISSING"},
		{"domainName and interfaceDescriptions", both, "MANDATORY_IE_INCORRECT"},
		{"apiId present", withId, "OPTIONAL_IE_INCORRECT"},
	} {
		if code, cause := create("nef-apf", c.d); code != http.StatusBadRequest || cause != c.cause {
			t.Fatalf("%s: %d %s", c.name, code, cause)
		}
	}

	// Publishing again replaces the previous publication.
	first := tc.publish(t)
	second := tc.publish(t)
	list, err := pub.APFPublishedAPIsCollectionApi.GetAPFPubAPIs(context.Background(),
		&PublishService.GetAPFPubAPIsRequest{ApfId: ptr("nef-apf")})
	if err != nil || len(list.ServiceAPIDescriptions) != 1 || list.ServiceAPIDescriptions[0].ApiId != second.ApiId ||
		first.ApiId == second.ApiId {
		t.Fatalf("published again: %v %+v", err, list)
	}
}

// TestCapifRoutes covers the answers to requests outside the operations.
func TestCapifRoutes(t *testing.T) {
	tc := newTestCCF(t)
	c := tc.client(nil, 0, false)
	for _, x := range []struct {
		method, url string
		status      int
		cause       string
		allow       string
	}{
		{"GET", tc.external.URL + "/api-invoker-management/v1/onboardedInvokers", 405, "", "POST"},
		{"GET", tc.external.URL + "/api-invoker-management/v2/onboardedInvokers", 400, "INVALID_API", ""},
		{"GET", tc.external.URL + "/api-invoker-management/v1/unknown", 404, "RESOURCE_URI_STRUCTURE_NOT_FOUND", ""},
		// The APIs of the API provider are not served on CAPIF-1e.
		{"GET", tc.external.URL + "/published-apis/v1/nef-apf/service-apis", 404, "", ""},
		{"POST", tc.internal.URL + "/capif-security/v1/trustedInvokers/x", 405, "", "GET"},
	} {
		req, _ := http.NewRequest(x.method, x.url, nil)
		client := c
		if strings.HasPrefix(x.url, tc.internal.URL) {
			client = &http.Client{}
		}
		rsp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var pd models.ProblemDetails
		_ = json.NewDecoder(rsp.Body).Decode(&pd)
		_ = rsp.Body.Close()
		if rsp.StatusCode != x.status || pd.Cause != x.cause || rsp.Header.Get("Allow") != x.allow {
			t.Fatalf("%s %s: %d %q %q", x.method, x.url, rsp.StatusCode, pd.Cause, rsp.Header.Get("Allow"))
		}
	}
}

// TestCapifTLS checks TLS 1.2 and HTTP/2 by ALPN on CAPIF-1e (TS 33.210
// cl. 6.2; RFC 9113 cl. 3.2).
func TestCapifTLS(t *testing.T) {
	tc := newTestCCF(t)
	url := tc.external.URL + "/service-apis/v1/allServiceAPIs"
	rsp, err := tc.client(nil, tls.VersionTLS12, false).Get(url)
	if err != nil {
		t.Fatalf("TLS 1.2: %v", err)
	}
	_ = rsp.Body.Close()
	if rsp.TLS.Version != tls.VersionTLS12 || rsp.Proto != "HTTP/1.1" {
		t.Fatalf("TLS 1.2: %x %s", rsp.TLS.Version, rsp.Proto)
	}
	rsp, err = tc.client(nil, 0, true).Get(url)
	if err != nil {
		t.Fatalf("HTTP/2: %v", err)
	}
	_ = rsp.Body.Close()
	if rsp.TLS.Version != tls.VersionTLS13 || rsp.Proto != "HTTP/2.0" {
		t.Fatalf("HTTP/2: %x %s", rsp.TLS.Version, rsp.Proto)
	}
	// No OCSP stapling: the lab has no OCSP responder.
	if rsp.TLS.OCSPResponse != nil {
		t.Fatal("OCSP response stapled")
	}
	// A TLS 1.2 client without ECDHE and AEAD suites is refused.
	weak := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: tc.caPool,
		MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA}}}}
	if rsp, err := weak.Get(url); err == nil {
		_ = rsp.Body.Close()
		t.Fatal("a TLS 1.2 suite without ECDHE was accepted")
	}
}

// TestCapifInvokerKeys covers the public keys of the API invokers (TS 33.310
// cl. 6.1.1): ECDSA P-256 or P-384, RSA of 2048 to 4096 bits with a public
// exponent of at least 65537.
func TestCapifInvokerKeys(t *testing.T) {
	tc := newTestCCF(t)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	tc.onboardWithKey(t, "af1-external", p384)
	rsa2048, _ := rsa.GenerateKey(rand.Reader, 2048)
	inv := tc.onboardWithKey(t, "af1-external", rsa2048)
	if cert, _ := x509.ParseCertificate(inv.cert.Certificate[0]); cert.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
		t.Fatal("RSA certificate without keyEncipherment")
	}

	p521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	p224, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	rsa1024, _ := rsa.GenerateKey(rand.Reader, 1024)
	// Only the public key goes to the CCF: an odd modulus of the size wanted
	// is enough.
	modulus := func(bits int) *big.Int {
		n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
		return n.SetBit(n, 0, 1)
	}
	cred := context.WithValue(context.Background(), openapi.ContextAccessToken, tc.credential(t, "af1-external", time.Hour))
	for name, pub := range map[string]any{
		"P-521":        &p521.PublicKey,
		"P-224":        &p224.PublicKey,
		"RSA 1024":     &rsa1024.PublicKey,
		"RSA 4100":     &rsa.PublicKey{N: modulus(4100), E: 65537},
		"exponent 3":   &rsa.PublicKey{N: modulus(2048), E: 3},
		"exponent 257": &rsa.PublicKey{N: modulus(2048), E: 257},
	} {
		_, err := tc.invokerAPI(nil).OnboardedAPIInvokersCollectionApi.CreateOnboardedAPIInvoker(cred,
			&APIInvokerManagement.CreateOnboardedAPIInvokerRequest{APIInvokerEnrolmentDetails: enrolment(publicKeyPEM(t, pub))})
		code, apiErr := status(t, err)
		if pd := problem(t, apiErr); code != http.StatusBadRequest || pd.Cause != "MANDATORY_IE_INCORRECT" {
			t.Fatalf("%s: %d %+v", name, code, pd)
		}
	}
}

// closeConn records when the client closes its connection.
type closeConn struct {
	net.Conn
	once   sync.Once
	closed chan struct{}
}

func (c *closeConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

// TestCapifOffboardingTearsDownTLS checks that the CCF ends the TLS session
// after offboarding (TS 33.122 cl. 6.8 step 6), with HTTP/1.1 and HTTP/2.
func TestCapifOffboardingTearsDownTLS(t *testing.T) {
	tc := newTestCCF(t)
	for _, h2 := range []bool{false, true} {
		inv := tc.onboard(t, "af1-external")
		id := inv.details.ApiInvokerId
		var mu sync.Mutex
		var conns []*closeConn
		tr := &http.Transport{
			TLSClientConfig:   &tls.Config{RootCAs: tc.caPool, Certificates: []tls.Certificate{inv.cert}},
			ForceAttemptHTTP2: h2,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}
				cc := &closeConn{Conn: c, closed: make(chan struct{})}
				mu.Lock()
				conns = append(conns, cc)
				mu.Unlock()
				return cc, nil
			},
		}
		client := &http.Client{Transport: tr}

		rsp, err := client.Get(tc.external.URL + "/service-apis/v1/allServiceAPIs?api-invoker-id=" + id)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, rsp.Body)
		_ = rsp.Body.Close()
		req, _ := http.NewRequest(http.MethodDelete, tc.external.URL+"/api-invoker-management/v1/onboardedInvokers/"+id, nil)
		rsp, err = client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = rsp.Body.Close()
		if wantProto := map[bool]string{false: "HTTP/1.1", true: "HTTP/2.0"}[h2]; rsp.StatusCode != http.StatusNoContent ||
			rsp.Proto != wantProto {
			t.Fatalf("HTTP/2 %v: offboard %d %s", h2, rsp.StatusCode, rsp.Proto)
		}
		mu.Lock()
		n := len(conns)
		mu.Unlock()
		if n != 1 {
			t.Fatalf("HTTP/2 %v: %d connections", h2, n)
		}
		select {
		case <-conns[0].closed:
		case <-time.After(5 * time.Second):
			t.Fatalf("HTTP/2 %v: the TLS session was not torn down", h2)
		}
		tr.CloseIdleConnections()
	}
}
