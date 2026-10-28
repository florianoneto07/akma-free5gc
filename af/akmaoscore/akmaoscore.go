// Package akmaoscore holds what the AF and the UE share in the OSCORE
// profile of the Ua* reference point (TS 33.535 Annex D): the payloads of
// the Application Session Establishment in CBOR (D.3.5), the A-KID in CBOR,
// and the security context from K_AF (D.3.3).
//
// TS 33.535 leaves several points open; this package takes these choices:
//   - the request is the array of D.3.5, without the "CoAP Security protocol
//     identifier" that D.3.2 lists and D.3.5 does not encode;
//   - HPLMN-ID is the MCC followed by the MNC, the Home Network Identifier
//     of TS 23.003 cl. 2.2B;
//   - OSC-INP is a byte string with the CBOR map inside, and only the
//     default values are accepted: the response has no way to tell the UE
//     that the AF used others;
//   - the Master Secret is HKDF-SHA-256 with an empty salt, K_AF as input
//     key material, "AKMA-OSCORE" as info and 32 octets of output.
package akmaoscore

import (
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"fmt"
	"regexp"
	"slices"

	"github.com/florianoneto07/akma-free5gc/af/cbor"
	"github.com/florianoneto07/akma-free5gc/af/oscore"
	"github.com/florianoneto07/akma-free5gc/shared/akma/akid"
	"github.com/florianoneto07/akma-free5gc/shared/akma/kdf"
)

const (
	// Path is the AKMA resource of the AF (D.3.2 step 1).
	Path = "/akma"
	// NonceSize is the length of N1 and N2.
	NonceSize = 16
	// MinNonceSize and MaxNonceSize bound the N1 the AF accepts.
	MinNonceSize = 8
	MaxNonceSize = 64
	// SenderIDSize is the length of AF-SID and UE-SID.
	SenderIDSize = 4
	// MasterSecretLabel is the info of the HKDF of the Master Secret
	// (D.3.3).
	MasterSecretLabel = "AKMA-OSCORE"
	// MasterSecretSize is the length of the Master Secret.
	MasterSecretSize = 32
	// DefaultPort is the port of the coap URI scheme (RFC 7252 cl. 6.1).
	DefaultPort = 5683
)

// Request is the payload of the Application Session Establishment Request
// (D.3.2 step 1; D.3.5).
type Request struct {
	AKID  string // A-KID in text, as the AAnF knows it
	N1    []byte
	AFSID []byte // Sender ID of the AF, chosen by the UE
	// OSCInput is the content of OSC-INP, the CBOR map; nil when absent.
	OSCInput []byte
}

// Response is the payload of the Application Session Establishment
// Response (D.3.2 step 3; D.3.5).
type Response struct {
	N2    []byte
	UESID []byte // Sender ID of the UE, chosen by the AF
}

// ErrPayload reports a payload that is not the one of D.3.5.
var ErrPayload = errors.New("akmaoscore: malformed payload")

// ErrOSCInput reports an OSC-INP with values other than the defaults.
var ErrOSCInput = errors.New("akmaoscore: OSC-INP with values other than the defaults")

var hplmnPattern = regexp.MustCompile(`^[0-9]{5,6}$`)

// Marshal encodes the request: [A-KID, N1, AF-SID, ? OSC-INP], with
// A-KID = [RID, A-TID, HPLMN-ID].
func (r Request) Marshal(o akid.Options) ([]byte, error) {
	a, err := akid.Parse(r.AKID, o)
	if err != nil {
		return nil, err
	}
	hn, err := akid.ParseDomain(a.Realm)
	if err != nil {
		return nil, err
	}
	items := []cbor.Value{
		cbor.ArrayValue(cbor.TextValue(string(a.RID)), cbor.BytesValue(a.ATID[:]), cbor.TextValue(hn.MCC+hn.MNC)),
		cbor.BytesValue(r.N1), cbor.BytesValue(r.AFSID),
	}
	if r.OSCInput != nil {
		items = append(items, cbor.BytesValue(r.OSCInput))
	}
	return cbor.Encode(cbor.ArrayValue(items...))
}

// ParseRequest decodes and checks a request, and writes the A-KID in text
// with o.
func ParseRequest(b []byte, o akid.Options) (Request, error) {
	v, err := cbor.Decode(b)
	if err != nil {
		return Request{}, fmt.Errorf("%w: %v", ErrPayload, err)
	}
	if v.Kind != cbor.Array || len(v.A) < 3 || len(v.A) > 4 {
		return Request{}, fmt.Errorf("%w: not an array of 3 or 4 items", ErrPayload)
	}
	k := v.A[0]
	if k.Kind != cbor.Array || len(k.A) != 3 || k.A[0].Kind != cbor.Text || k.A[1].Kind != cbor.Bytes ||
		k.A[2].Kind != cbor.Text {
		return Request{}, fmt.Errorf("%w: A-KID is not [tstr, bstr, tstr]", ErrPayload)
	}
	rid, err := akid.ParseRID(k.A[0].S)
	if err != nil {
		return Request{}, fmt.Errorf("%w: RID: %v", ErrPayload, err)
	}
	if len(k.A[1].B) != len(kdf.Key{}) {
		return Request{}, fmt.Errorf("%w: A-TID of %d octets", ErrPayload, len(k.A[1].B))
	}
	hplmn := k.A[2].S
	if !hplmnPattern.MatchString(hplmn) {
		return Request{}, fmt.Errorf("%w: HPLMN-ID %q is not MCC and MNC", ErrPayload, hplmn)
	}
	hn, err := akid.NewHomeNetwork(hplmn[:3], hplmn[3:])
	if err != nil {
		return Request{}, fmt.Errorf("%w: HPLMN-ID: %v", ErrPayload, err)
	}
	var atid kdf.Key
	copy(atid[:], k.A[1].B)
	text, err := akid.AKID{RID: rid, ATID: atid, Realm: hn.Domain()}.Format(o)
	if err != nil {
		return Request{}, fmt.Errorf("%w: A-KID: %v", ErrPayload, err)
	}
	for i, name := range []string{"N1", "AF-SID"} {
		if v.A[1+i].Kind != cbor.Bytes {
			return Request{}, fmt.Errorf("%w: %s is not a byte string", ErrPayload, name)
		}
	}
	r := Request{AKID: text, N1: v.A[1].B, AFSID: v.A[2].B}
	if len(r.N1) < MinNonceSize || len(r.N1) > MaxNonceSize {
		return Request{}, fmt.Errorf("%w: N1 of %d octets", ErrPayload, len(r.N1))
	}
	if len(r.AFSID) > oscore.MaxIDSize {
		return Request{}, fmt.Errorf("%w: AF-SID of %d octets", ErrPayload, len(r.AFSID))
	}
	if len(v.A) == 4 {
		if v.A[3].Kind != cbor.Bytes {
			return Request{}, fmt.Errorf("%w: OSC-INP is not a byte string", ErrPayload)
		}
		r.OSCInput = v.A[3].B
		if err := checkOSCInput(r.OSCInput); err != nil {
			return Request{}, err
		}
	}
	return r, nil
}

// Labels of OSC-INP (D.3.5; RFC 9203 cl. 3.2.1) and the defaults of
// TS 33.220 P.3.3. RFC 9203 names the HKDF by an HMAC algorithm of COSE:
// HKDF SHA-256 is HMAC 256/256, 5 (RFC 9053 cl. 3.1).
const (
	labelVersion   = 1
	labelHKDF      = 3
	labelAlg       = 4
	labelSalt      = 5
	labelContextID = 6
	hkdfSHA256     = 5
)

func checkOSCInput(b []byte) error {
	m, err := cbor.Decode(b)
	if err != nil || m.Kind != cbor.Map {
		return fmt.Errorf("%w: OSC-INP is not a CBOR map", ErrPayload)
	}
	for _, p := range m.M {
		label, ok := p.Key.Int()
		n, isInt := p.Value.Int()
		switch {
		case !ok:
			return fmt.Errorf("%w: label of OSC-INP", ErrOSCInput)
		case label == labelVersion && isInt && n == oscore.Version,
			label == labelHKDF && isInt && n == hkdfSHA256,
			label == labelAlg && isInt && n == oscore.AlgAESCCM16_64_128:
		default:
			// Another value, a salt, an ID Context or another label.
			return fmt.Errorf("%w: label %d", ErrOSCInput, label)
		}
	}
	return nil
}

// Marshal encodes the response: [N2, UE-SID].
func (r Response) Marshal() []byte {
	return cbor.MustEncode(cbor.ArrayValue(cbor.BytesValue(r.N2), cbor.BytesValue(r.UESID)))
}

// ParseResponse decodes a response.
func ParseResponse(b []byte) (Response, error) {
	v, err := cbor.Decode(b)
	if err != nil {
		return Response{}, fmt.Errorf("%w: %v", ErrPayload, err)
	}
	if v.Kind != cbor.Array || len(v.A) != 2 || v.A[0].Kind != cbor.Bytes || v.A[1].Kind != cbor.Bytes {
		return Response{}, fmt.Errorf("%w: not [bstr, bstr]", ErrPayload)
	}
	r := Response{N2: v.A[0].B, UESID: v.A[1].B}
	if len(r.N2) < MinNonceSize || len(r.N2) > MaxNonceSize || len(r.UESID) > oscore.MaxIDSize {
		return Response{}, fmt.Errorf("%w: N2 of %d octets, UE-SID of %d", ErrPayload, len(r.N2), len(r.UESID))
	}
	return r, nil
}

// MasterSecret is OMS = HKDF(K_AF, "AKMA-OSCORE") (D.3.3): HKDF-SHA-256
// (RFC 5869) with an empty salt and 32 octets of output.
func MasterSecret(kaf kdf.Key) []byte {
	oms, err := hkdf.Key(sha256.New, kaf[:], nil, MasterSecretLabel, MasterSecretSize)
	if err != nil {
		panic(err) // only for an output length beyond 255 hash lengths
	}
	return oms
}

// Context derives the security context of the UE (ue true) or of the AF
// from K_AF and the two payloads as sent (D.3.3): the Master Salt is the
// request payload followed by the response payload; the Sender ID of the UE
// is UE-SID and the one of the AF is AF-SID; no ID Context.
func Context(kaf kdf.Key, reqPayload, rspPayload []byte, afSID, ueSID []byte, ue bool) (*oscore.Context, error) {
	p := oscore.Params{
		MasterSecret: MasterSecret(kaf),
		MasterSalt:   append(slices.Clone(reqPayload), rspPayload...),
		SenderID:     afSID, RecipientID: ueSID,
	}
	if ue {
		p.SenderID, p.RecipientID = ueSID, afSID
	}
	return oscore.Derive(p)
}
