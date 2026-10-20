package sbi

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/free5gc/openapi"
	Naanf_AKMA "github.com/free5gc/openapi/aanf/AKMA"
	"github.com/free5gc/openapi/models"
)

// The client added to free5gc/openapi by patches/openapi (used by the AUSF
// and the AF) against the AAnF server.
func TestOpenapiClient(t *testing.T) {
	e := newEnv(t)
	cfg := Naanf_AKMA.NewConfiguration()
	cfg.SetBasePath(e.ts.URL)
	client := Naanf_AKMA.NewAPIClient(cfg)
	ctx := context.Background()

	reg := &Naanf_AKMA.RegisterAKMAKeyRequest{}
	reg.SetAkmaKeyInfo(models.AkmaKeyInfo{Supi: e.v.Supi, AKId: e.v.AKID["base64"], KAkma: e.v.KAkma})
	rsp, err := client.RegisterTheAKMARelatedKeyMaterialApi.RegisterAKMAKey(ctx, reg)
	if err != nil || rsp.AkmaKeyInfo.AKId != e.v.AKID["base64"] {
		t.Fatalf("RegisterAKMAKey: %+v, %v", rsp, err)
	}

	get := &Naanf_AKMA.GetAKMAAPPKeyMaterialRequest{}
	get.SetAkmaAfKeyRequest(models.AkmaAfKeyRequest{AfId: afLocal, AKId: e.v.AKID["base64"]})
	data, err := client.RetrieveTheAKMAApplicationKeyMaterialCollectionApi.GetAKMAAPPKeyMaterial(ctx, get)
	if err != nil || data.NoContent || data.AkmaAfKeyData.Kaf != e.v.KAf || data.AkmaAfKeyData.Expiry == nil {
		t.Fatalf("GetAKMAAPPKeyMaterial: %+v, %v", data, err)
	}

	rm := &Naanf_AKMA.RemoveContextRequest{}
	rm.SetCtxRemove(models.CtxRemove{Supi: e.v.Supi})
	if _, err := client.RemoveTheAKMAApplicationKeyMaterialDeletionApi.RemoveContext(ctx, rm); err != nil {
		t.Fatalf("RemoveContext: %v", err)
	}

	// Errors carry the ProblemDetails of the AAnF.
	_, err = client.RetrieveTheAKMAApplicationKeyMaterialCollectionApi.GetAKMAAPPKeyMaterial(ctx, get)
	assertProblem(t, err, http.StatusForbidden, "K_AKMA_NOT_PRESENT")
	_, err = client.RemoveTheAKMAApplicationKeyMaterialDeletionApi.RemoveContext(ctx, rm)
	assertProblem(t, err, http.StatusNotFound, "AKMA_CONTEXT_NOT_FOUND")
}

func assertProblem(t *testing.T, err error, status int, cause string) {
	t.Helper()
	var apiErr openapi.GenericOpenAPIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v, want GenericOpenAPIError", err)
	}
	opErr, ok := apiErr.Model().(Naanf_AKMA.OperationError)
	if apiErr.ErrorStatus != status || !ok || opErr.ProblemDetails.Cause != cause {
		t.Errorf("status %d model %+v, want %d %s", apiErr.ErrorStatus, apiErr.Model(), status, cause)
	}
}
