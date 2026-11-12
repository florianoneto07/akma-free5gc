package sbi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"

	"github.com/free5gc/openapi/capif/PublishService"
	"github.com/free5gc/openapi/capif/Security"
	"github.com/free5gc/openapi/models"
)

const (
	testNefId   = "8e73ad07-906c-4952-93ac-cd32bbb076ed"
	testOtherId = "5a6d7127-edf7-4edc-960c-e4105ff023d8"
)

func peerState(t *testing.T, id string) *tls.ConnectionState {
	t.Helper()
	uri, err := url.Parse("urn:uuid:" + id)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{URIs: []*url.URL{uri}}}}
}

// internalAs serves the internal interface as if a TLS client with the
// certificate of an NF instance were asking.
func (tc *testCCF) internalAs(t *testing.T, state *tls.ConnectionState) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.TLS = state
		tc.server.InternalRouter().ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	return server.URL
}

// TestCapifInternalProvider covers the API provider by its certificate on
// CAPIF-3/4 (TS 33.122 cl. 6.6).
func TestCapifInternalProvider(t *testing.T) {
	tc := newTestCCF(t)
	conf := tc.server.Config().Configuration
	conf.Providers[0].NfInstanceId = testNefId
	publish := func(state *tls.ConnectionState) error {
		cfg := PublishService.NewConfiguration()
		cfg.SetBasePath(tc.internalAs(t, state))
		cfg.SetHTTPClient(&http.Client{})
		_, err := PublishService.NewAPIClient(cfg).APFPublishedAPIsCollectionApi.CreateAPFPubAPIs(context.Background(),
			&PublishService.CreateAPFPubAPIsRequest{ApfId: ptr("nef-apf"), ServiceAPIDescription: ptr(akmaAPI())})
		return err
	}
	if err := publish(peerState(t, testNefId)); err != nil {
		t.Fatalf("publication by the NEF: %v", err)
	}
	if code, _ := status(t, publish(peerState(t, testOtherId))); code != http.StatusForbidden {
		t.Fatalf("publication by another NF: %d", code)
	}
	if code, _ := status(t, publish(&tls.ConnectionState{PeerCertificates: []*x509.Certificate{{}}})); code != http.StatusForbidden {
		t.Fatalf("publication with a certificate without an NF instance: %d", code)
	}
}

// TestCapifInvokerInfoOfTheAef covers the items of Obtain_API_Invoker_Info: only
// those of the AEFs of the client.
func TestCapifInvokerInfoOfTheAef(t *testing.T) {
	tc := newTestCCF(t)
	conf := tc.server.Config().Configuration
	conf.Providers[0].NfInstanceId = testNefId
	tc.publish(t)
	inv := tc.onboard(t, "af1-external")
	id := inv.details.ApiInvokerId
	if _, err := tc.securityAPI(&inv.cert).IndividualTrustedAPIInvokerStoreApi.CreateSecIndTrustedAPIInv(context.Background(),
		&Security.CreateSecIndTrustedAPIInvRequest{ApiInvokerId: &id, ServiceSecurity: &models.CapifServiceSecurity{
			NotificationDestination: "https://192.0.2.1/notify",
			SecurityInfo: []models.CapifSecurityInformation{{
				AefId: "nef-aef", PrefSecurityMethods: []models.CapifSecurityMethod{models.CapifSecurityMethod_OAUTH},
			}},
		}}); err != nil {
		t.Fatal(err)
	}
	get := func(state *tls.ConnectionState) (*Security.GetSecIndTrustedAPIInvResponse, error) {
		cfg := Security.NewConfiguration()
		cfg.SetBasePath(tc.internalAs(t, state))
		cfg.SetHTTPClient(&http.Client{})
		return Security.NewAPIClient(cfg).IndividualTrustedAPIInvokerStoreApi.GetSecIndTrustedAPIInv(context.Background(),
			&Security.GetSecIndTrustedAPIInvRequest{ApiInvokerId: &id, AuthenticationInfo: ptr(true)})
	}
	rsp, err := get(peerState(t, testNefId))
	if err != nil || len(rsp.ServiceSecurity.SecurityInfo) != 1 || rsp.ServiceSecurity.SecurityInfo[0].AefId != "nef-aef" {
		t.Fatalf("information for the NEF: %+v, %v", rsp, err)
	}
	_, err = get(peerState(t, testOtherId))
	if code, _ := status(t, err); code != http.StatusForbidden {
		t.Fatalf("information for another NF: %d", code)
	}
	// A provider with other AEFs gets none of the items.
	conf.Providers = append(conf.Providers, conf.Providers[0])
	conf.Providers[1].ApfId, conf.Providers[1].AefIds, conf.Providers[1].NfInstanceId = "other-apf", []string{"other-aef"}, testOtherId
	_, err = get(peerState(t, testOtherId))
	if code, _ := status(t, err); code != http.StatusNotFound {
		t.Fatalf("information for another provider: %d", code)
	}
}

// TestCapifInvokerCertificateCrl checks the CRL distribution point of the
// certificates of the API invokers (TS 33.310 cl. 6.1.3a).
func TestCapifInvokerCertificateCrl(t *testing.T) {
	tc := newTestCCF(t)
	inv := tc.onboard(t, "af1-external")
	block, _ := pem.Decode([]byte(inv.details.OnboardingInformation.ApiInvokerCertificate))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cert.CRLDistributionPoints, []string{testCrlUri}) {
		t.Fatalf("CRL distribution points: %v", cert.CRLDistributionPoints)
	}
}
