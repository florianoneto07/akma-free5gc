package context

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/florianoneto07/akma-free5gc/free5gc/ccf/internal/jws"
	"github.com/florianoneto07/akma-free5gc/free5gc/ccf/pkg/factory"
	"github.com/free5gc/openapi/models"
)

// CCFContext is the state of the CAPIF core function: the onboarded API
// invokers with their security contexts, and the published service APIs. It
// is kept in memory, as the AAnF keeps its AKMA contexts.
type CCFContext struct {
	cfg *factory.Config

	caCert              *x509.Certificate
	caPEM               string
	caKey               crypto.Signer
	tokenKey            *ecdsa.PrivateKey
	credentialKey       *ecdsa.PrivateKey
	tokenLifetime       time.Duration
	invokerCertLifetime time.Duration

	mu       sync.RWMutex
	invokers map[string]*Invoker
	apis     map[string]*PublishedAPI

	// The CRL of the CA of the CCF (TS 33.310 cl. 6.1a).
	crlEntries []x509.RevocationListEntry
	crlNumber  *big.Int
	crlNext    time.Time

	// Now returns the current time; tests replace it.
	Now func() time.Time
}

// Invoker is the profile of an onboarded API invoker (TS 23.222 cl. 8.1.3).
type Invoker struct {
	// Id is the API invoker ID; it is also the onboardingId of its resource
	// and the securityId of its access tokens (TS 29.222 cl. 5.6.2.3.2).
	Id string
	// Profile is the invoker profile named by the onboarding credential.
	Profile                 string
	PublicKey               string
	Certificate             string
	Serial                  *big.Int
	Secret                  string
	NotificationDestination string
	Information             string
	// Security is the security context of Obtain_Security_Method, nil
	// before it.
	Security *SecurityContext
}

// SecurityContext is the "Individual trusted API invoker" resource.
type SecurityContext struct {
	Items []models.CapifSecurityInformation
	// Aefs holds the API exposing function of each item, resolved from its
	// aefId or its interfaceDetails; "" when no published AEF matches.
	Aefs                    []string
	NotificationDestination string
}

// PublishedAPI is an "Individual APF published API" resource.
type PublishedAPI struct {
	ApfId       string
	Description models.CapifServiceApiDescription
}

var self *CCFContext

// Init builds the context of the running CCF and signs its CRL.
func Init(cfg *factory.Config) error {
	c, err := New(cfg)
	if err != nil {
		return err
	}
	if err = c.StartCrl(); err != nil {
		return err
	}
	self = c
	return nil
}

// StartCrl takes the revocations of a previous run and signs the CRL. The
// certificates of the API invokers name it (TS 33.310 cl. 6.1.3a).
func (c *CCFContext) StartCrl() error {
	path := c.cfg.Configuration.Ca.CrlFile
	if path == "" {
		return nil
	}
	if err := c.loadCrl(path); err != nil {
		return fmt.Errorf("ca.crlFile: %w", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.signCrl(); err != nil {
		return fmt.Errorf("ca.crlFile: %w", err)
	}
	return nil
}

// GetSelf returns the context of the running CCF.
func GetSelf() *CCFContext {
	return self
}

// New loads the keys and certificates of the configuration.
func New(cfg *factory.Config) (*CCFContext, error) {
	c := &CCFContext{
		cfg:      cfg,
		invokers: map[string]*Invoker{},
		apis:     map[string]*PublishedAPI{},
		Now:      time.Now,
	}
	conf := cfg.Configuration
	var err error
	if c.caCert, c.caPEM, err = loadCertificate(conf.Ca.Certificate); err != nil {
		return nil, fmt.Errorf("ca.certificate: %w", err)
	}
	if !c.caCert.IsCA {
		return nil, fmt.Errorf("ca.certificate: not a CA certificate")
	}
	if len(c.caCert.Subject.Organization) == 0 {
		// The certificates of the API invokers take the organization of the
		// CA (TS 33.310 cl. 6.1.1, subject name format).
		return nil, fmt.Errorf("ca.certificate: no organization (O) in the subject")
	}
	if c.caKey, err = loadCAKey(conf.Ca.Key, c.caCert); err != nil {
		return nil, fmt.Errorf("ca.key: %w", err)
	}
	if c.tokenKey, err = loadES256Key(conf.Token.Key); err != nil {
		return nil, fmt.Errorf("token.key: %w", err)
	}
	if c.credentialKey, err = loadES256Key(conf.CredentialKey); err != nil {
		return nil, fmt.Errorf("credentialKey: %w", err)
	}
	if c.tokenLifetime, err = conf.Token.GetLifetime(); err != nil {
		return nil, err
	}
	if c.invokerCertLifetime, err = conf.Ca.GetInvokerCertLifetime(); err != nil {
		return nil, err
	}
	return c, nil
}

// Config returns the configuration of the CCF.
func (c *CCFContext) Config() *factory.Config {
	return c.cfg
}

// CaPEM returns the certificate of the CA of the CCF, in PEM.
func (c *CCFContext) CaPEM() string {
	return c.caPEM
}

// CaPool returns a pool with the CA of the CCF, which issues the client
// certificates of the API invokers.
func (c *CCFContext) CaPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(c.caCert)
	return pool
}

// CredentialKey returns the key of the onboarding credentials.
func (c *CCFContext) CredentialKey() *ecdsa.PrivateKey {
	return c.credentialKey
}

// TokenPublicKey returns the public key that checks the access tokens.
func (c *CCFContext) TokenPublicKey() *ecdsa.PublicKey {
	return &c.tokenKey.PublicKey
}

// utf8Attribute is an AttributeTypeAndValue (RFC 5280 cl. 4.1.2.4) with a
// UTF8String value.
type utf8Attribute struct {
	Type  asn1.ObjectIdentifier
	Value string `asn1:"utf8"`
}

// utf8RDNSET is a RelativeDistinguishedName; encoding/asn1 encodes a slice
// type whose name ends in "SET" as a SET OF.
type utf8RDNSET []utf8Attribute

var (
	oidOrganization = asn1.ObjectIdentifier{2, 5, 4, 10}
	oidCommonName   = asn1.ObjectIdentifier{2, 5, 4, 3}
)

// subjectName returns the DER name O=<org>, CN=<cn>. TS 33.310 cl. 6.1.1:
// "(C=<country>), O=<Organization Name>, CN=<Some distinguishing name>.
// Organization and CN shall be in UTF8 format."
func subjectName(org []string, cn string) ([]byte, error) {
	var name []utf8RDNSET
	for _, o := range org {
		name = append(name, utf8RDNSET{{Type: oidOrganization, Value: o}})
	}
	name = append(name, utf8RDNSET{{Type: oidCommonName, Value: cn}})
	return asn1.Marshal(name)
}

// randomSecret returns 32 random octets in base64url without padding.
func randomSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Onboard creates the profile of a new API invoker of the invoker profile
// profile: the API invoker ID, the client certificate of pub (TS 33.122
// cl. 6.1 step 4; CN = API invoker ID, TS 29.222 table 8.4.4.2.5-1) and the
// onboarding secret. The certificate follows the TLS entity certificate
// profile of TS 33.310 cl. 6.1.3a, which TS 33.122 cl. 6.3.1.1 requires on
// CAPIF-1e: key usage digitalSignature, critical; extended key usage
// id-kp-clientAuth, not critical; the CRL distribution point of the CA of the
// CCF; no other critical extension (cl. 6.1.1).
func (c *CCFContext) Onboard(profile, publicKeyPEM string, pub crypto.PublicKey,
	notificationDestination, information string,
) (Invoker, error) {
	id := uuid.New().String()
	now := c.Now()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return Invoker{}, err
	}
	subject, err := subjectName(c.caCert.Subject.Organization, id)
	if err != nil {
		return Invoker{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		RawSubject:   subject,
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(c.invokerCertLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if uri := c.cfg.Configuration.Ca.CrlUri; uri != "" {
		tmpl.CRLDistributionPoints = []string{uri}
	}
	if _, ok := pub.(*rsa.PublicKey); ok {
		tmpl.KeyUsage |= x509.KeyUsageKeyEncipherment
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.caCert, pub, c.caKey)
	if err != nil {
		return Invoker{}, err
	}
	secret, err := randomSecret()
	if err != nil {
		return Invoker{}, err
	}
	inv := &Invoker{
		Id:                      id,
		Profile:                 profile,
		PublicKey:               publicKeyPEM,
		Certificate:             string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		Serial:                  serial,
		Secret:                  secret,
		NotificationDestination: notificationDestination,
		Information:             information,
	}
	c.mu.Lock()
	c.invokers[id] = inv
	c.mu.Unlock()
	return copyInvoker(inv), nil
}

func copyInvoker(inv *Invoker) Invoker {
	out := *inv
	if inv.Security != nil {
		sc := *inv.Security
		sc.Items = slices.Clone(inv.Security.Items)
		sc.Aefs = slices.Clone(inv.Security.Aefs)
		out.Security = &sc
	}
	return out
}

// Invoker returns the profile of an API invoker.
func (c *CCFContext) Invoker(id string) (Invoker, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	inv, ok := c.invokers[id]
	if !ok {
		return Invoker{}, false
	}
	return copyInvoker(inv), true
}

// Offboard deletes the profile of an API invoker with its certificate, its
// security context and its onboarding secret (TS 33.122 cl. 6.8 step 3), and
// revokes the certificate.
func (c *CCFContext) Offboard(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	inv, ok := c.invokers[id]
	if !ok {
		return false
	}
	delete(c.invokers, id)
	c.revoke(inv.Serial)
	return true
}

// SetSecurityContext stores the security context of an API invoker,
// replacing the previous one.
func (c *CCFContext) SetSecurityContext(id string, sc SecurityContext) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	inv, ok := c.invokers[id]
	if !ok {
		return false
	}
	sc.Items = slices.Clone(sc.Items)
	sc.Aefs = slices.Clone(sc.Aefs)
	inv.Security = &sc
	return true
}

// Publish stores a service API published by apfId and assigns its API
// identifier. A service API with the same name published before by the same
// APF for one of the same AEFs is replaced. It returns the stored
// description and the API identifiers it replaced.
func (c *CCFContext) Publish(apfId string, d models.CapifServiceApiDescription) (
	models.CapifServiceApiDescription, []string,
) {
	aefs := map[string]bool{}
	for _, p := range d.AefProfiles {
		aefs[p.AefId] = true
	}
	d.ApiId = uuid.New().String()

	c.mu.Lock()
	defer c.mu.Unlock()
	var replaced []string
	for id, api := range c.apis {
		if api.ApfId != apfId || api.Description.ApiName != d.ApiName {
			continue
		}
		for _, p := range api.Description.AefProfiles {
			if aefs[p.AefId] {
				replaced = append(replaced, id)
				delete(c.apis, id)
				break
			}
		}
	}
	slices.Sort(replaced)
	c.apis[d.ApiId] = &PublishedAPI{ApfId: apfId, Description: d}
	return d, replaced
}

// PublishedAPI returns a service API published by apfId.
func (c *CCFContext) PublishedAPI(apfId, apiId string) (models.CapifServiceApiDescription, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	api, ok := c.apis[apiId]
	if !ok || api.ApfId != apfId {
		return models.CapifServiceApiDescription{}, false
	}
	return api.Description, true
}

// Unpublish deletes a service API published by apfId.
func (c *CCFContext) Unpublish(apfId, apiId string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	api, ok := c.apis[apiId]
	if !ok || api.ApfId != apfId {
		return false
	}
	delete(c.apis, apiId)
	return true
}

// PublishedAPIs returns the service APIs published by apfId, or by every APF
// when apfId is empty, ordered by API identifier.
func (c *CCFContext) PublishedAPIs(apfId string) []models.CapifServiceApiDescription {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := []models.CapifServiceApiDescription{}
	for _, api := range c.apis {
		if apfId == "" || api.ApfId == apfId {
			out = append(out, api.Description)
		}
	}
	slices.SortFunc(out, func(a, b models.CapifServiceApiDescription) int {
		if a.ApiId < b.ApiId {
			return -1
		}
		if a.ApiId > b.ApiId {
			return 1
		}
		return 0
	})
	return out
}

// IssueToken signs an access token for the API invoker id with the granted
// scope, and returns it with its lifetime in seconds. The claims carry iss
// and client_id with the API invoker ID and exp as a NumericDate (TS 29.222
// table 8.5.4.2.8-1; TS 33.122 C.2.2; RFC 7519 cl. 4.1.4); the JWS is ES256
// with "kid" (TS 33.210 cl. 6.3.3.1).
func (c *CCFContext) IssueToken(id, scope string) (string, int32, error) {
	claims := models.CapifAccessTokenClaims{
		Iss:      id,
		ClientId: id,
		Scope:    scope,
		Exp:      c.Now().Add(c.tokenLifetime).Unix(),
	}
	token, err := jws.Sign(claims, c.tokenKey)
	if err != nil {
		return "", 0, err
	}
	return token, int32(c.tokenLifetime / time.Second), nil
}
