// Package aanf requests K_AF from the AAnF with
// Naanf_AKMA_ApplicationKey_Get (TS 33.535 cl. 6.2.1 step 2; TS 29.535
// cl. 4.2.2.3), using the Naanf_AKMA client of the patched free5gc/openapi.
package aanf

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/florianoneto07/akma-free5gc/shared/akma/afid"
	"github.com/florianoneto07/akma-free5gc/shared/akma/codec"
	"github.com/florianoneto07/akma-free5gc/shared/akma/kdf"
	"github.com/free5gc/openapi"
	Naanf_AKMA "github.com/free5gc/openapi/aanf/AKMA"
	"github.com/free5gc/openapi/models"
)

// causeKAkmaNotPresent is the application error of TS 29.535 table
// 5.1.7.3-1 for an A-KID without K_AKMA.
const causeKAkmaNotPresent = "K_AKMA_NOT_PRESENT"

var (
	// ErrKeyNotAvailable reports that the AAnF has no K_AKMA for the A-KID.
	ErrKeyNotAvailable = errors.New("aanf: K_AKMA not present for the A-KID")
	// ErrUnavailable reports any other failure to obtain K_AF: the AAnF did
	// not authorize the AF, answered with another error or was not reached.
	ErrUnavailable = errors.New("aanf: K_AF not obtained")
)

// Key is the AKMA Application Key material of one A-KID.
type Key struct {
	KAf    kdf.Key
	Expiry time.Time
	Supi   string // never sent to the UE
}

// Client requests K_AF from the AAnF.
type Client struct {
	api       *Naanf_AKMA.APIClient
	anonymous bool
}

// New returns a client of the AAnF at apiRoot. With anonymous, the requests
// carry anonInd: the AAnF answers without the SUPI
// (Naanf_AKMA_ApplicationKey_AnonUser_Get, TS 33.535 cl. 6.2.2).
func New(apiRoot string, anonymous bool) *Client {
	cfg := Naanf_AKMA.NewConfiguration()
	cfg.SetBasePath(apiRoot)
	return &Client{api: Naanf_AKMA.NewAPIClient(cfg), anonymous: anonymous}
}

// ApplicationKey requests the K_AF of aKid for the AF_ID id: one AF has an
// AF_ID per Ua* security protocol, and so per profile and TLS cipher suite
// (TS 33.220 H.3). The afId is sent in transport form and the aKId exactly
// as received from the UE.
func (c *Client) ApplicationKey(ctx context.Context, id afid.AfID, aKid string) (Key, error) {
	req := &Naanf_AKMA.GetAKMAAPPKeyMaterialRequest{}
	req.SetAkmaAfKeyRequest(models.AkmaAfKeyRequest{AfId: id.Transport(), AKId: aKid, AnonInd: c.anonymous})
	rsp, err := c.api.RetrieveTheAKMAApplicationKeyMaterialCollectionApi.GetAKMAAPPKeyMaterial(ctx, req)
	if err != nil {
		return Key{}, classify(err)
	}
	if rsp.NoContent {
		// Allowed by TS 29.535 cl. 4.2.2.3.2; the AAnF of this repository
		// never sends it.
		return Key{}, fmt.Errorf("%w: 204 No Content", ErrUnavailable)
	}
	d := rsp.AkmaAfKeyData
	kaf, err := codec.ParseHexKey(d.Kaf)
	if err != nil {
		return Key{}, fmt.Errorf("%w: kaf: %v", ErrUnavailable, err)
	}
	if d.Expiry == nil {
		return Key{}, fmt.Errorf("%w: expiry missing", ErrUnavailable)
	}
	return Key{KAf: kaf, Expiry: *d.Expiry, Supi: d.Supi}, nil
}

// classify maps an error answer of the AAnF to ErrKeyNotAvailable or
// ErrUnavailable.
func classify(err error) error {
	var apiErr openapi.GenericOpenAPIError
	if !errors.As(err, &apiErr) {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	cause := ""
	if opErr, ok := apiErr.Model().(Naanf_AKMA.OperationError); ok {
		cause = opErr.ProblemDetails.Cause
	}
	if apiErr.ErrorStatus == 403 && cause == causeKAkmaNotPresent {
		return ErrKeyNotAvailable
	}
	if cause != "" {
		return fmt.Errorf("%w: AAnF answered %d %s", ErrUnavailable, apiErr.ErrorStatus, cause)
	}
	return fmt.Errorf("%w: AAnF answered %d", ErrUnavailable, apiErr.ErrorStatus)
}
