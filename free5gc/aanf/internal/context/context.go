package context

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

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
	Fqdn              string // FQDN in the NF profile, required with https
	BindingIPv4       string
	SBIPort           int
	UriScheme         models.UriScheme
	Url               string
	NrfUri            string
	NrfCertPem        string
	NfService         map[models.ServiceName]models.NrfNfManagementNfService
	PlmnList          []models.PlmnId
	RoutingIndicators []string
	// HeartBeatTimer is the heart-beat interval, in seconds, proposed in the
	// registration (TS 29.510 table 6.1.6.2.2-1).
	HeartBeatTimer int32

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
	// heartBeat is the heart-beat interval that the NRF gave
	// (TS 29.510 cl. 5.2.2.3.2).
	heartBeat time.Duration
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
		HeartBeatTimer:    factory.AanfDefaultHeartBeatTimer,
		Store:             NewStore(),
	}
	if configuration.HeartBeatTimer > 0 {
		c.HeartBeatTimer = int32(configuration.HeartBeatTimer)
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
		c.Fqdn = sbi.Fqdn
		c.BindingIPv4 = os.Getenv(sbi.BindingIPv4)
		if c.BindingIPv4 == "" {
			c.BindingIPv4 = sbi.BindingIPv4
		}
	}
	host := c.RegisterIPv4
	if c.Fqdn != "" {
		host = c.Fqdn
	}
	c.Url = string(c.UriScheme) + "://" + host + ":" + strconv.Itoa(c.SBIPort)

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
		// The scopes of each NF type (TS 29.535 table 5.1.9-1; TS 29.510
		// table 6.1.6.2.3-1 NOTE 11): the AUSF stores and removes, the NEF and
		// the AF get K_AF, and the SUPI with it (TS 33.535 cl. 6.2.1 step 8
		// and cl. 6.3 step 4).
		AllowedOperationsPerNfType: map[string][]string{
			string(models.NrfNfManagementNfType_AUSF): {
				string(models.ServiceName_NAANF_AKMA), oauth.ScopeNaanfAkmaAnchorKey,
			},
			string(models.NrfNfManagementNfType_NEF): keyGetScopes(),
			string(models.NrfNfManagementNfType_AF):  keyGetScopes(),
		},
	}
}

func keyGetScopes() []string {
	return []string{
		string(models.ServiceName_NAANF_AKMA), oauth.ScopeNaanfAkmaApplicationKey, oauth.ScopeNaanfAkmaSupiAccess,
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

// SetHeartBeat records the heart-beat interval that the NRF gave, in
// seconds; a value not above 0 keeps the one proposed (TS 29.510
// cl. 5.2.2.3.2: the NRF returns it in the answer to the registration and,
// when it changes, in the answer to the next heart-beat).
func (c *AANFContext) SetHeartBeat(seconds int32) {
	if seconds <= 0 {
		seconds = c.HeartBeatTimer
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.heartBeat = time.Duration(seconds) * time.Second
}

// HeartBeat returns the heart-beat interval: the one of the NRF, or the one
// proposed before any answer.
func (c *AANFContext) HeartBeat() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.heartBeat > 0 {
		return c.heartBeat
	}
	return time.Duration(c.HeartBeatTimer) * time.Second
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

// AuthorizationCheck verifies the OAuth2 access token of a request, when
// OAuth2 is required: the checks of the NF Service Producer (TS 33.501
// cl. 13.4.1.1.2) with the TLS client of the request, and the scopes of the
// operation besides the one of the service (TS 29.535 table 5.1.9-1). Without
// OAuth2, the grant is nil.
func (c *AANFContext) AuthorizationCheck(token string, peer *tls.ConnectionState, scopes ...string) (*oauth.Grant, error) {
	if !c.oauth2Required() {
		logger.UtilLog.Debugf("AuthorizationCheck: OAuth2 not required")
		return nil, nil
	}
	grant, err := oauth.Verify(token, string(models.ServiceName_NAANF_AKMA), c.NrfCertPem, peer)
	if err != nil {
		return nil, err
	}
	for _, scope := range scopes {
		if !grant.Has(scope) {
			return nil, oauth.InsufficientScope(scope)
		}
	}
	return grant, nil
}

// nfInstanceId normalizes an NF instance ID of the configuration.
func nfInstanceId(s string) (string, error) {
	id, err := uuid.Parse(strings.TrimSpace(s))
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

// AfPolicy is the local policy that authorizes AFs to obtain K_AF
// (TS 33.535 cl. 6.2.1 step 2). Each authorized AF_ID is bound to the NF
// instances of the AF, the ones of their client certificates (TS 33.501
// cl. 13.1.0), so that an AF cannot obtain the K_AF of another AF_ID.
type AfPolicy struct {
	instances map[string]map[string]struct{}
}

// NewAfPolicy builds the policy from the configuration.
func NewAfPolicy(afs []factory.AuthorizedAf) (*AfPolicy, error) {
	p := &AfPolicy{instances: make(map[string]map[string]struct{})}
	for i, af := range afs {
		id, err := afid.Parse(af.AfId)
		if err != nil {
			return nil, fmt.Errorf("akma.authorizedAfs[%d]: %w", i, err)
		}
		set := p.instances[id.Transport()]
		if set == nil {
			set = make(map[string]struct{})
			p.instances[id.Transport()] = set
		}
		for j, s := range af.NfInstanceIds {
			instance, err := nfInstanceId(s)
			if err != nil {
				return nil, fmt.Errorf("akma.authorizedAfs[%d].nfInstanceIds[%d]: %w", i, j, err)
			}
			set[instance] = struct{}{}
		}
	}
	return p, nil
}

// AfIds returns the authorized AF_IDs, in transport form, sorted.
func (p *AfPolicy) AfIds() []string {
	ids := make([]string, 0, len(p.instances))
	for id := range p.instances {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// Listed reports whether the policy has id, for any NF instance.
func (p *AfPolicy) Listed(id afid.AfID) bool {
	_, ok := p.instances[id.Transport()]
	return ok
}

// Authorize reports whether an NF instance may obtain K_AF for id.
func (p *AfPolicy) Authorize(id afid.AfID, instance string) bool {
	_, ok := p.instances[id.Transport()][instance]
	return ok
}

// NefPolicy is the local policy for the K_AF requests that a NEF relays for
// AFs outside the operator network (TS 33.535 cl. 6.3 step 3, processed as
// in cl. 6.2.1 step 2). The NEF is the NF instance of its client certificate
// (TS 33.501 cl. 13.1.0), with an access token when OAuth2 is required. Each
// NEF has the list of AF_IDs accepted from it.
type NefPolicy struct {
	afIds map[string]map[string]struct{}
}

// NewNefPolicy builds the policy from the configuration.
func NewNefPolicy(nefs []factory.AuthorizedNef) (*NefPolicy, error) {
	p := &NefPolicy{afIds: make(map[string]map[string]struct{})}
	for i, nef := range nefs {
		ids := make([]string, 0, len(nef.AfIds))
		for j, s := range nef.AfIds {
			id, err := afid.Parse(s)
			if err != nil {
				return nil, fmt.Errorf("akma.authorizedNefs[%d].afIds[%d]: %w", i, j, err)
			}
			ids = append(ids, id.Transport())
		}
		for j, s := range nef.NfInstanceIds {
			instance, err := nfInstanceId(s)
			if err != nil {
				return nil, fmt.Errorf("akma.authorizedNefs[%d].nfInstanceIds[%d]: %w", i, j, err)
			}
			set := p.afIds[instance]
			if set == nil {
				set = make(map[string]struct{})
				p.afIds[instance] = set
			}
			for _, id := range ids {
				set[id] = struct{}{}
			}
		}
	}
	return p, nil
}

// IsNef reports whether an NF instance is an authorized NEF.
func (p *NefPolicy) IsNef(instance string) bool {
	_, ok := p.afIds[instance]
	return ok
}

// Authorize reports whether the NEF instance may obtain K_AF for id.
func (p *NefPolicy) Authorize(id afid.AfID, instance string) bool {
	_, ok := p.afIds[instance][id.Transport()]
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
