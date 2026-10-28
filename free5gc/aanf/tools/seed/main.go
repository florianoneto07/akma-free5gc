// Command seed exercises the Naanf_AKMA API of the AAnF without an AUSF or
// an AF, for tests:
//
//	register  plays the AUSF: derives K_AKMA and the A-KID from K_AUSF and
//	          sends Naanf_AKMA_AnchorKey_Register (TS 33.535 cl. 6.1);
//	retrieve  plays the AF: sends Naanf_AKMA_ApplicationKey_Get
//	          (TS 33.535 cl. 6.2.1) and prints K_AF and its expiry;
//	remove    sends Naanf_AKMA_ContextRemove (TS 33.535 cl. 6.6);
//	discover  queries the NRF for AAnF instances (Nnrf_NFDiscovery) and
//	          prints their profiles;
//	trigger-auth
//	          does what the AAnF does to refresh K_AKMA (TS 33.535
//	          cl. 6.4.4): sends Nudm_UECM_AuthTrigger to the UDM.
//
// With --nrf, register, remove and trigger-auth first obtain an OAuth2 access
// token: the tool registers at the NRF as a temporary NF of type AF (the NRF
// of free5GC only grants tokens to registered NFs) and deregisters on exit.
// discover does the same to obtain a token for nnrf-disc.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/urfave/cli/v2"
	"golang.org/x/oauth2"

	"github.com/florianoneto07/akma-free5gc/shared/akma/afid"
	"github.com/florianoneto07/akma-free5gc/shared/akma/akid"
	"github.com/florianoneto07/akma-free5gc/shared/akma/codec"
	"github.com/florianoneto07/akma-free5gc/shared/akma/derive"
	"github.com/florianoneto07/akma-free5gc/shared/akma/supi"
	"github.com/free5gc/openapi"
	Naanf_AKMA "github.com/free5gc/openapi/aanf/AKMA"
	"github.com/free5gc/openapi/models"
	Nnrf_NFDiscovery "github.com/free5gc/openapi/nrf/NFDiscovery"
	Nnrf_NFManagement "github.com/free5gc/openapi/nrf/NFManagement"
	"github.com/free5gc/openapi/oauth"
	Nudm_UEContextManagement "github.com/free5gc/openapi/udm/UEContextManagement"
)

// seedUserAgent names the tool in its requests to the UDM, as the temporary
// AF it registers at the NRF (TS 29.500 table 5.2.2.2-1).
const seedUserAgent = "AF-seed"

// defaultNfInstanceID is the NF instance ID of the temporary AF profile. It is
// fixed so that the certificate the NRF signs for it (cert/af_<id>.pem) is
// the same file on every run.
const defaultNfInstanceID = "76a7ade7-c7d6-4e09-8d66-2726fd6f2cb9"

func main() {
	aanfFlag := &cli.StringFlag{Name: "aanf", Value: "http://192.168.16.130:8010", Usage: "AAnF apiRoot"}
	nrfFlags := []cli.Flag{
		&cli.StringFlag{Name: "nrf", Usage: "NRF apiRoot; when set, an OAuth2 access token is obtained"},
		&cli.StringFlag{Name: "nf-id", Value: defaultNfInstanceID, Usage: "NF instance ID of the temporary AF profile"},
	}
	app := &cli.App{
		Name:  "seed",
		Usage: "exercise the Naanf_AKMA API of the AAnF in tests",
		Commands: []*cli.Command{
			{
				Name:  "register",
				Usage: "derive K_AKMA and A-KID from K_AUSF and register them (AUSF role)",
				Flags: append([]cli.Flag{
					aanfFlag,
					&cli.StringFlag{Name: "supi", Required: true, Usage: "SUPI, SBI form (imsi-...)"},
					&cli.StringFlag{Name: "k-ausf", Required: true, Usage: "K_AUSF, 64 hexadecimal characters"},
					&cli.StringFlag{Name: "rid", Required: true, Usage: "Routing Indicator, 1 to 4 digits"},
					&cli.StringFlag{Name: "mcc", Required: true},
					&cli.StringFlag{Name: "mnc", Required: true},
					// Negative tests: the AAnF must reject these.
					&cli.StringFlag{Name: "gpsi", Usage: "also send this gpsi (test: AKMA_GPSI_Support is not supported)"},
					&cli.StringFlag{Name: "k-akma", Usage: "send this kAkma instead of the derived one (test)"},
				}, nrfFlags...),
				Action: register,
			},
			{
				Name:  "retrieve",
				Usage: "request K_AF for an A-KID (AF role)",
				Flags: []cli.Flag{
					aanfFlag,
					&cli.StringFlag{Name: "af-id", Required: true, Usage: "AF_ID \"<FQDN>.<Ua* security protocol id>\""},
					&cli.StringFlag{Name: "akid", Required: true, Usage: "A-KID"},
					&cli.BoolFlag{Name: "anon", Usage: "anonymous user access (anonInd)"},
				},
				Action: retrieve,
			},
			{
				Name:  "discover",
				Usage: "discover the AAnF instances at the NRF",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "nrf", Required: true, Usage: "NRF apiRoot"},
					&cli.StringFlag{Name: "nf-id", Value: defaultNfInstanceID, Usage: "NF instance ID of the temporary AF profile"},
					&cli.StringFlag{Name: "requester", Value: "AUSF", Usage: "requester-nf-type"},
					&cli.StringFlag{Name: "routing-indicator", Usage: "routing-indicator query parameter"},
				},
				Action: discover,
			},
			{
				Name:  "remove",
				Usage: "remove the AKMA context of a SUPI",
				Flags: append([]cli.Flag{
					aanfFlag,
					&cli.StringFlag{Name: "supi", Required: true},
				}, nrfFlags...),
				Action: remove,
			},
			{
				Name:  "trigger-auth",
				Usage: "ask the UDM for a primary authentication of a SUPI (AAnF role, Nudm_UECM_AuthTrigger)",
				Flags: append([]cli.Flag{
					&cli.StringFlag{Name: "udm", Value: "http://127.0.0.3:8000", Usage: "UDM apiRoot"},
					&cli.StringFlag{Name: "supi", Required: true, Usage: "SUPI, SBI form (imsi-...)"},
					// Negative tests: the request is sent as given.
					&cli.StringFlag{Name: "method", Usage: "send with this HTTP method (test)"},
					&cli.StringFlag{Name: "body", Usage: "send this JSON body instead of {\"supi\": ...} (test)"},
				}, nrfFlags...),
				Action: triggerAuth,
			},
		},
	}
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, "seed:", err)
		os.Exit(1)
	}
}

func akmaClient(apiRoot string) *Naanf_AKMA.APIClient {
	cfg := Naanf_AKMA.NewConfiguration()
	cfg.SetBasePath(apiRoot)
	return Naanf_AKMA.NewAPIClient(cfg)
}

// tokenContext returns a context with an access token for naanf-akma when
// --nrf is set, and a function that deregisters the temporary AF profile.
func tokenContext(c *cli.Context) (context.Context, func(), error) {
	return tokenContextFor(c, models.NrfNfManagementNfType_AANF, models.ServiceName_NAANF_AKMA)
}

// tokenContextFor is tokenContext for another target NF type and scope.
func tokenContextFor(c *cli.Context, target models.NrfNfManagementNfType, scope models.ServiceName) (
	context.Context, func(), error,
) {
	nrfURI := c.String("nrf")
	if nrfURI == "" {
		return context.Background(), func() {}, nil
	}
	nfID := c.String("nf-id")
	cfg := Nnrf_NFManagement.NewConfiguration()
	cfg.SetBasePath(nrfURI)
	nrf := Nnrf_NFManagement.NewAPIClient(cfg)

	profile := models.NrfNfManagementNfProfile{
		NfInstanceId: nfID,
		NfType:       models.NrfNfManagementNfType_AF,
		NfStatus:     models.NrfNfManagementNfStatus_REGISTERED,
	}
	rsp, err := nrf.NFInstanceIDDocumentApi.RegisterNFInstance(context.Background(),
		&Nnrf_NFManagement.RegisterNFInstanceRequest{NfInstanceID: &nfID, NrfNfManagementNfProfile: &profile})
	if err != nil {
		return nil, nil, fmt.Errorf("temporary registration at the NRF: %w", err)
	}
	fmt.Fprintf(os.Stderr, "registered at the NRF as AF %s\n", nfID)
	cleanup := func() {
		ctx, _, err := oauth.GetTokenCtx(models.NrfNfManagementNfType_AF, models.NrfNfManagementNfType_NRF,
			nfID, nrfURI, string(models.ServiceName_NNRF_NFM))
		if err != nil {
			ctx = context.Background()
		}
		if _, err := nrf.NFInstanceIDDocumentApi.DeregisterNFInstance(ctx,
			&Nnrf_NFManagement.DeregisterNFInstanceRequest{NfInstanceID: &nfID}); err != nil {
			fmt.Fprintf(os.Stderr, "deregistration at the NRF failed: %v\n", err)
			return
		}
		fmt.Fprintf(os.Stderr, "deregistered AF %s from the NRF\n", nfID)
	}

	oauth2, _ := rsp.NrfNfManagementNfProfile.CustomInfo["oauth2"].(bool)
	if !oauth2 {
		fmt.Fprintln(os.Stderr, "the NRF does not require OAuth2; no access token requested")
		return context.Background(), cleanup, nil
	}
	ctx, _, err := oauth.GetTokenCtx(models.NrfNfManagementNfType_AF, target, nfID, nrfURI, string(scope))
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("access token request: %w", err)
	}
	fmt.Fprintf(os.Stderr, "access token obtained for scope %s\n", scope)
	return ctx, cleanup, nil
}

func register(c *cli.Context) error {
	p, err := supi.FromSBI(c.String("supi"))
	if err != nil {
		return err
	}
	kAusf, err := codec.ParseHexKey(c.String("k-ausf"))
	if err != nil {
		return fmt.Errorf("--k-ausf: %w", err)
	}
	rid, err := akid.ParseRID(c.String("rid"))
	if err != nil {
		return fmt.Errorf("--rid: %w", err)
	}
	hn, err := akid.NewHomeNetwork(c.String("mcc"), c.String("mnc"))
	if err != nil {
		return err
	}
	kAkma, err := derive.KAkma(kAusf, p)
	if err != nil {
		return err
	}
	id, err := derive.AKID(kAusf, p, rid, hn)
	if err != nil {
		return err
	}
	aKId, err := id.Format(akid.DefaultOptions())
	if err != nil {
		return err
	}

	ctx, cleanup, err := tokenContext(c)
	if err != nil {
		return err
	}
	defer cleanup()

	info := models.AkmaKeyInfo{Supi: c.String("supi"), AKId: aKId, KAkma: codec.HexKey(kAkma), Gpsi: c.String("gpsi")}
	if c.IsSet("k-akma") {
		info.KAkma = c.String("k-akma")
	}
	req := &Naanf_AKMA.RegisterAKMAKeyRequest{}
	req.SetAkmaKeyInfo(info)
	if _, err := akmaClient(c.String("aanf")).RegisterTheAKMARelatedKeyMaterialApi.RegisterAKMAKey(ctx, req); err != nil {
		return describe(err)
	}
	fmt.Println("registered")
	fmt.Println("a-kid:", aKId)
	return nil
}

func retrieve(c *cli.Context) error {
	af, err := afid.Parse(c.String("af-id"))
	if err != nil {
		return fmt.Errorf("--af-id: %w", err)
	}
	req := &Naanf_AKMA.GetAKMAAPPKeyMaterialRequest{}
	req.SetAkmaAfKeyRequest(models.AkmaAfKeyRequest{
		AfId: af.Transport(), AKId: c.String("akid"), AnonInd: c.Bool("anon"),
	})
	rsp, err := akmaClient(c.String("aanf")).RetrieveTheAKMAApplicationKeyMaterialCollectionApi.
		GetAKMAAPPKeyMaterial(context.Background(), req)
	if err != nil {
		return describe(err)
	}
	if rsp.NoContent {
		fmt.Println("204 No Content")
		return nil
	}
	d := rsp.AkmaAfKeyData
	kaf, err := codec.ParseHexKey(d.Kaf)
	if err != nil {
		return fmt.Errorf("kaf in the response: %w", err)
	}
	fmt.Println("kaf:", d.Kaf)
	fmt.Println("kaf (base64):", codec.Base64Key(kaf))
	if d.Expiry != nil {
		fmt.Printf("expiry: %s (in %s)\n", d.Expiry.Format(time.RFC3339), time.Until(*d.Expiry).Round(time.Second))
	}
	if d.Supi != "" {
		fmt.Println("supi:", d.Supi)
	}
	return nil
}

func discover(c *cli.Context) error {
	ctx, cleanup, err := tokenContextFor(c, models.NrfNfManagementNfType_NRF, models.ServiceName_NNRF_DISC)
	if err != nil {
		return err
	}
	defer cleanup()

	cfg := Nnrf_NFDiscovery.NewConfiguration()
	cfg.SetBasePath(c.String("nrf"))
	target := models.NrfNfManagementNfType_AANF
	requester := models.NrfNfManagementNfType(strings.ToUpper(c.String("requester")))
	query := &Nnrf_NFDiscovery.SearchNFInstancesRequest{TargetNfType: &target, RequesterNfType: &requester}
	if ri := c.String("routing-indicator"); ri != "" {
		if _, err := akid.ParseRID(ri); err != nil {
			return fmt.Errorf("--routing-indicator: %w", err)
		}
		query.RoutingIndicator = &ri
	}
	rsp, err := Nnrf_NFDiscovery.NewAPIClient(cfg).NFInstancesStoreApi.SearchNFInstances(ctx, query)
	if err != nil {
		return fmt.Errorf("discovery: %w", err)
	}
	out, err := json.MarshalIndent(rsp.SearchResult.NfInstances, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}

func remove(c *cli.Context) error {
	ctx, cleanup, err := tokenContext(c)
	if err != nil {
		return err
	}
	defer cleanup()

	req := &Naanf_AKMA.RemoveContextRequest{}
	req.SetCtxRemove(models.CtxRemove{Supi: c.String("supi")})
	if _, err := akmaClient(c.String("aanf")).RemoveTheAKMAApplicationKeyMaterialDeletionApi.RemoveContext(ctx, req); err != nil {
		return describe(err)
	}
	fmt.Println("removed")
	return nil
}

func triggerAuth(c *cli.Context) error {
	ctx, cleanup, err := tokenContextFor(c, models.NrfNfManagementNfType_UDM, models.ServiceName_NUDM_UECM)
	if err != nil {
		return err
	}
	defer cleanup()

	if c.IsSet("method") || c.IsSet("body") {
		return rawTriggerAuth(ctx, c)
	}
	cfg := Nudm_UEContextManagement.NewConfiguration()
	cfg.SetBasePath(c.String("udm"))
	cfg.SetUserAgent(seedUserAgent)
	req := &Nudm_UEContextManagement.AuthTriggerRequest{}
	req.SetUeId(c.String("supi"))
	req.SetAuthTriggerInfo(models.AuthTriggerInfo{Supi: c.String("supi")})
	_, err = Nudm_UEContextManagement.NewAPIClient(cfg).TriggerThePrimaryReAuthenticationApi.AuthTrigger(ctx, req)
	if err != nil {
		var apiErr openapi.GenericOpenAPIError
		if !errors.As(err, &apiErr) {
			return err
		}
		msg := fmt.Sprintf("UDM answered %d", apiErr.ErrorStatus)
		if v, ok := apiErr.Model().(Nudm_UEContextManagement.AuthTriggerError); ok && v.ProblemDetails.Cause != "" {
			msg += " (" + v.ProblemDetails.Cause + "; " + v.ProblemDetails.Detail + ")"
		}
		return errors.New(msg)
	}
	fmt.Println("accepted (204)")
	return nil
}

// rawTriggerAuth sends trigger-auth with --method and --body as given, over
// HTTP/1.1, and prints the status and the body of the answer.
func rawTriggerAuth(ctx context.Context, c *cli.Context) error {
	method := http.MethodPost
	if c.IsSet("method") {
		method = strings.ToUpper(c.String("method"))
	}
	body := fmt.Sprintf(`{"supi":%q}`, c.String("supi"))
	if c.IsSet("body") {
		body = c.String("body")
	}
	uri := c.String("udm") + "/nudm-uecm/v1/" + c.String("supi") + "/registrations/trigger-auth"
	req, err := http.NewRequestWithContext(context.Background(), method, uri, strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", seedUserAgent)
	if tok, err := bearer(ctx); err != nil {
		return err
	} else if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	rsp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer rsp.Body.Close()
	out, _ := io.ReadAll(rsp.Body)
	fmt.Printf("%d %s\n", rsp.StatusCode, strings.TrimSpace(string(out)))
	if allow := rsp.Header.Get("Allow"); allow != "" {
		fmt.Println("allow:", allow)
	}
	return nil
}

// bearer returns the access token that tokenContextFor put in ctx, or "".
func bearer(ctx context.Context) (string, error) {
	ts, ok := ctx.Value(openapi.ContextOAuth2).(oauth2.TokenSource)
	if !ok {
		return "", nil
	}
	tok, err := ts.Token()
	if err != nil {
		return "", err
	}
	return tok.AccessToken, nil
}

// describe renders an error answer of the AAnF as "status cause".
func describe(err error) error {
	var apiErr openapi.GenericOpenAPIError
	if !errors.As(err, &apiErr) {
		return err
	}
	msg := fmt.Sprintf("AAnF answered %d", apiErr.ErrorStatus)
	if opErr, ok := apiErr.Model().(Naanf_AKMA.OperationError); ok {
		pd := opErr.ProblemDetails
		parts := []string{}
		if pd.Cause != "" {
			parts = append(parts, pd.Cause)
		}
		if pd.Detail != "" {
			parts = append(parts, pd.Detail)
		}
		for _, ip := range pd.InvalidParams {
			parts = append(parts, ip.Param+": "+ip.Reason)
		}
		if len(parts) > 0 {
			msg += " (" + strings.Join(parts, "; ") + ")"
		}
	}
	return errors.New(msg)
}
