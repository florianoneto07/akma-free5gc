package context

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/florianoneto07/akma-free5gc/free5gc/aanf/internal/logger"
	"github.com/florianoneto07/akma-free5gc/free5gc/aanf/pkg/factory"
	"github.com/florianoneto07/akma-free5gc/shared/akma/afid"
	"github.com/florianoneto07/akma-free5gc/shared/akma/akid"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/openapi/oauth"
)

// AANFContext holds the NF-level state of the AAnF.
type AANFContext struct {
	NfId              string
	RegisterIPv4      string
	BindingIPv4       string
	SBIPort           int
	UriScheme         models.UriScheme
	Url               string
	NrfUri            string
	NrfCertPem        string
	NfService         map[models.ServiceName]models.NrfNfManagementNfService
	PlmnList          []models.PlmnId
	RoutingIndicators []string

	// OAuth2Required is learned from the NRF at registration (free5GC NRF
	// "oauth2" custom info). The access to Naanf_AKMA may be authorized with
	// OAuth2 based on local configuration (TS 29.535 cl. 5.1.9).
	OAuth2Required bool

	KafLifetime time.Duration
	// KakmaRefresh is the age of K_AKMA after which the AAnF asks the UDM
	// for its refresh (TS 33.535 cl. 6.4.4); 0 disables it.
	KakmaRefresh time.Duration
	AKidOptions  akid.Options
	AfPolicy     *AfPolicy
	NefPolicy    *NefPolicy
	Store        *Store

	mu sync.RWMutex
}

var self *AANFContext

// GetSelf returns the AAnF context created by Init.
func GetSelf() *AANFContext {
	return self
}

// Init builds the AAnF context from cfg and makes it the current one.
func Init(cfg *factory.Config) error {
	c, err := New(cfg)
	if err != nil {
		return err
	}
	self = c
	logger.AkmaLog.Infof("Routing Indicators %v; K_AF lifetime %s; AF_IDs authorized by local policy: %v",
		c.RoutingIndicators, c.KafLifetime, c.AfPolicy.AfIds())
	if ids := c.NefPolicy.AfIds(); len(ids) > 0 {
		logger.AkmaLog.Infof("AF_IDs accepted from a NEF: %v", ids)
	}
	if c.KakmaRefresh > 0 {
		logger.AkmaLog.Infof("K_AKMA refresh requested from the UDM when a K_AF is asked for a K_AKMA older than %s "+
			"(TS 33.535 cl. 6.4.4)", c.KakmaRefresh)
	}
	return nil
}

// New builds an AAnF context from cfg.
func New(cfg *factory.Config) (*AANFContext, error) {
	configuration := cfg.Configuration
	sbi := configuration.Sbi

	c := &AANFContext{
		NfId:              cfg.GetNfInstanceId(),
		NrfUri:            configuration.NrfUri,
		NrfCertPem:        configuration.NrfCertPem,
		RegisterIPv4:      factory.AanfSbiDefaultIPv4,
		SBIPort:           factory.AanfSbiDefaultPort,
		UriScheme:         models.UriScheme_HTTP,
		PlmnList:          append([]models.PlmnId(nil), configuration.PlmnSupportList...),
		RoutingIndicators: append([]string(nil), configuration.RoutingIndicators...),
		Store:             NewStore(),
	}
	if sbi != nil {
		if sbi.RegisterIPv4 != "" {
			c.RegisterIPv4 = sbi.RegisterIPv4
		}
		if sbi.Port != 0 {
			c.SBIPort = sbi.Port
		}
		if sbi.Scheme == "https" {
			c.UriScheme = models.UriScheme_HTTPS
		}
		c.BindingIPv4 = os.Getenv(sbi.BindingIPv4)
		if c.BindingIPv4 == "" {
			c.BindingIPv4 = sbi.BindingIPv4
		}
	}
	c.Url = string(c.UriScheme) + "://" + c.RegisterIPv4 + ":" + strconv.Itoa(c.SBIPort)

	lifetime, err := configuration.Akma.GetKafLifetime()
	if err != nil {
		return nil, err
	}
	c.KafLifetime = lifetime
	if c.KakmaRefresh, err = configuration.Akma.GetKakmaRefresh(); err != nil {
		return nil, err
	}

	if c.AKidOptions, err = akidOptions(configuration.Akma.AKid); err != nil {
		return nil, err
	}
	if c.AfPolicy, err = NewAfPolicy(configuration.Akma.AuthorizedAfs); err != nil {
		return nil, err
	}
	if c.NefPolicy, err = NewNefPolicy(configuration.Akma.AuthorizedNefs); err != nil {
		return nil, err
	}

	c.NfService = map[models.ServiceName]models.NrfNfManagementNfService{
		models.ServiceName_NAANF_AKMA: c.nfService(),
	}
	return c, nil
}

// nfService builds the naanf-akma NF service published at the NRF.
func (c *AANFContext) nfService() models.NrfNfManagementNfService {
	return models.NrfNfManagementNfService{
		ServiceInstanceId: c.NfId,
		ServiceName:       models.ServiceName_NAANF_AKMA,
		Versions: []models.NfServiceVersion{{
			ApiVersionInUri: "v1",
			ApiFullVersion:  factory.AanfApiFullVersion,
		}},
		Scheme:          c.UriScheme,
		NfServiceStatus: models.NfServiceStatus_REGISTERED,
		IpEndPoints: []models.IpEndPoint{{
			Ipv4Address: c.RegisterIPv4,
			Transport:   models.NrfNfManagementTransportProtocol_TCP,
			Port:        int32(c.SBIPort),
		}},
		// Consumers of Naanf_AKMA (TS 29.535 table 4.2.2.1-1). The NRF only
		// grants an access token to these NF types.
		AllowedNfTypes: []models.NrfNfManagementNfType{
			models.NrfNfManagementNfType_AUSF,
			models.NrfNfManagementNfType_NEF,
			models.NrfNfManagementNfType_AF,
		},
	}
}

func akidOptions(f *factory.AKidFormat) (akid.Options, error) {
	o := akid.DefaultOptions()
	if f == nil {
		return o, nil
	}
	switch f.AtidEncoding {
	case "", "base64":
		o.Encoding = akid.EncodingBase64
	case "base64url":
		o.Encoding = akid.EncodingBase64URL
	case "hex":
		o.Encoding = akid.EncodingHex
	default:
		return o, fmt.Errorf("invalid akma.aKid.atidEncoding %q", f.AtidEncoding)
	}
	if f.AtidLabel != "" {
		o.Label = f.AtidLabel
	}
	if len(f.AcceptLabels) > 0 {
		o.AcceptLabels = append([]string(nil), f.AcceptLabels...)
	}
	return o, nil
}

// SetOAuth2Required records whether OAuth2 is required, as learned from the NRF.
func (c *AANFContext) SetOAuth2Required(v bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.OAuth2Required = v
}

// RequiresOAuth2 reports whether the NRF asked for OAuth2 access tokens.
func (c *AANFContext) RequiresOAuth2() bool {
	return c.oauth2Required()
}

func (c *AANFContext) oauth2Required() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.OAuth2Required
}

// GetTokenCtx returns a context carrying an access token for serviceName,
// or a plain context when OAuth2 is not required.
func (c *AANFContext) GetTokenCtx(serviceName models.ServiceName, targetNF models.NrfNfManagementNfType) (
	context.Context, *models.ProblemDetails, error,
) {
	if !c.oauth2Required() {
		return context.TODO(), nil, nil
	}
	return oauth.GetTokenCtx(models.NrfNfManagementNfType_AANF, targetNF,
		c.NfId, c.NrfUri, string(serviceName))
}

// AuthorizationCheck verifies the OAuth2 access token in the Authorization
// header value when OAuth2 is required.
func (c *AANFContext) AuthorizationCheck(token string, serviceName models.ServiceName) error {
	if !c.oauth2Required() {
		logger.UtilLog.Debugf("AuthorizationCheck: OAuth2 not required")
		return nil
	}
	return VerifyAccessToken(token, string(serviceName), c.NrfCertPem, c.NfId, time.Now())
}

// VerifyAccessToken verifies an "Authorization: Bearer" value as the NF
// Service Producer of TS 33.501 cl. 13.4.1.1.2 step 2. oauth.VerifyOAuth of
// free5GC checks the RS512 signature with the NRF certificate and the scope;
// the expiration time and the audience are checked here:
//   - "exp" must be in the future;
//   - "aud" must contain the NF instance ID of this AAnF or the NF type AANF
//     (TS 29.510 table 6.3.5.2.4-1). The NRF of free5GC v1.4.5 issues an
//     empty audience; patches/nrf/0003 makes it fill the claim.
func VerifyAccessToken(authorization, serviceName, nrfCertPem, nfId string, now time.Time) error {
	fields := strings.Fields(authorization)
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") {
		return errors.New("authorization header is not a Bearer token")
	}
	if err := oauth.VerifyOAuth(authorization, serviceName, nrfCertPem); err != nil {
		return err
	}
	// The signature has just been verified by oauth.VerifyOAuth.
	claims := &models.NrfAccessTokenAccessTokenClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(fields[1], claims); err != nil {
		return fmt.Errorf("access token claims: %w", err)
	}
	if claims.Exp == 0 || now.Unix() >= int64(claims.Exp) {
		return errors.New("access token expired or without expiration time")
	}
	if !audienceAccepted(claims.Aud, nfId) {
		return errors.New("access token audience does not match this AAnF")
	}
	return nil
}

func audienceAccepted(aud any, nfId string) bool {
	match := func(s string) bool {
		return s != "" && (s == nfId || strings.EqualFold(s, string(models.NrfNfManagementNfType_AANF)))
	}
	switch a := aud.(type) {
	case string:
		return match(a)
	case []any:
		for _, v := range a {
			if s, ok := v.(string); ok && match(s) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// AfPolicy is the local policy that authorizes AFs to obtain K_AF
// (TS 33.535 cl. 6.2.1 step 2). Each authorized AF_ID is bound to the source
// addresses of the AF allowed to request it, so that an AF cannot obtain the
// K_AF of another AF_ID.
type AfPolicy struct {
	sources map[string]map[netip.Addr]struct{}
}

// NewAfPolicy builds the policy from the configuration.
func NewAfPolicy(afs []factory.AuthorizedAf) (*AfPolicy, error) {
	p := &AfPolicy{sources: make(map[string]map[netip.Addr]struct{})}
	for i, af := range afs {
		id, err := afid.Parse(af.AfId)
		if err != nil {
			return nil, fmt.Errorf("akma.authorizedAfs[%d]: %w", i, err)
		}
		set := p.sources[id.Transport()]
		if set == nil {
			set = make(map[netip.Addr]struct{})
			p.sources[id.Transport()] = set
		}
		for j, s := range af.SourceAddresses {
			addr, err := netip.ParseAddr(strings.TrimSpace(s))
			if err != nil {
				return nil, fmt.Errorf("akma.authorizedAfs[%d].sourceAddresses[%d]: %w", i, j, err)
			}
			set[addr.Unmap()] = struct{}{}
		}
	}
	return p, nil
}

// AfIds returns the authorized AF_IDs, in transport form, sorted.
func (p *AfPolicy) AfIds() []string {
	ids := make([]string, 0, len(p.sources))
	for id := range p.sources {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// Authorize reports whether the AF at remote may obtain K_AF for id.
func (p *AfPolicy) Authorize(id afid.AfID, remote netip.Addr) bool {
	set, ok := p.sources[id.Transport()]
	if !ok {
		return false
	}
	_, ok = set[remote.Unmap()]
	return ok
}

// NefPolicy is the local policy for the K_AF requests that a NEF relays for
// AFs outside the operator network (TS 33.535 cl. 6.3 step 3, processed as
// in cl. 6.2.1 step 2). The NEF is recognized by its source address, the
// implicit authentication between NFs that TS 33.501 cl. 13.3.2.1 allows
// when TLS is not used (this AAnF serves the SBI without TLS), together with
// an access token when OAuth2 is required. Each NEF has the list of AF_IDs
// accepted from it.
type NefPolicy struct {
	afIds map[netip.Addr]map[string]struct{}
}

// NewNefPolicy builds the policy from the configuration.
func NewNefPolicy(nefs []factory.AuthorizedNef) (*NefPolicy, error) {
	p := &NefPolicy{afIds: make(map[netip.Addr]map[string]struct{})}
	for i, nef := range nefs {
		ids := make([]string, 0, len(nef.AfIds))
		for j, s := range nef.AfIds {
			id, err := afid.Parse(s)
			if err != nil {
				return nil, fmt.Errorf("akma.authorizedNefs[%d].afIds[%d]: %w", i, j, err)
			}
			ids = append(ids, id.Transport())
		}
		for j, s := range nef.SourceAddresses {
			addr, err := netip.ParseAddr(strings.TrimSpace(s))
			if err != nil {
				return nil, fmt.Errorf("akma.authorizedNefs[%d].sourceAddresses[%d]: %w", i, j, err)
			}
			set := p.afIds[addr.Unmap()]
			if set == nil {
				set = make(map[string]struct{})
				p.afIds[addr.Unmap()] = set
			}
			for _, id := range ids {
				set[id] = struct{}{}
			}
		}
	}
	return p, nil
}

// IsNef reports whether remote is the source address of an authorized NEF.
func (p *NefPolicy) IsNef(remote netip.Addr) bool {
	_, ok := p.afIds[remote.Unmap()]
	return ok
}

// Authorize reports whether the NEF at remote may obtain K_AF for id.
func (p *NefPolicy) Authorize(id afid.AfID, remote netip.Addr) bool {
	_, ok := p.afIds[remote.Unmap()][id.Transport()]
	return ok
}

// AfIds returns the AF_IDs accepted from any NEF, in transport form, sorted.
func (p *NefPolicy) AfIds() []string {
	seen := make(map[string]struct{})
	for _, set := range p.afIds {
		for id := range set {
			seen[id] = struct{}{}
		}
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
