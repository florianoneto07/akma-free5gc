/*
 * CCF Configuration Factory
 */

package factory

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/google/uuid"

	"github.com/florianoneto07/akma-free5gc/shared/akma/afid"
)

const (
	CcfDefaultConfigPath = "./config/ccfcfg.yaml"
	CcfDefaultPort       = 8020
	// CcfApiFullVersion is the version of the TS29222_*.yaml files implemented
	// (TS 29.222 V19.8.0).
	CcfApiFullVersion = "1.4.0"
	// CcfDefaultTokenLifetime is used when token.lifetime is not configured.
	CcfDefaultTokenLifetime = 10 * time.Minute
	// CcfDefaultInvokerCertLifetime is used when ca.invokerCertLifetime is not
	// configured.
	CcfDefaultInvokerCertLifetime = 365 * 24 * time.Hour
)

type Config struct {
	Info          *Info          `yaml:"info" valid:"required"`
	Configuration *Configuration `yaml:"configuration" valid:"required"`
	Logger        *Logger        `yaml:"logger" valid:"required"`
	sync.RWMutex
}

func (c *Config) Validate() (bool, error) {
	if configuration := c.Configuration; configuration != nil {
		if err := configuration.validate(); err != nil {
			return false, err
		}
	}

	result, err := govalidator.ValidateStruct(c)
	return result, appendInvalid(err)
}

type Info struct {
	Version     string `yaml:"version,omitempty" valid:"required,in(1.0.0)"`
	Description string `yaml:"description,omitempty" valid:"type(string)"`
}

type Configuration struct {
	// CcfName is the issuer of the onboarding credentials.
	CcfName string `yaml:"ccfName" valid:"required"`
	// Capif1e is the interface of the API invokers (TS 23.222 cl. 6.4.3),
	// served over HTTPS (TS 29.222 cl. 7.3; TS 33.122 cl. 6.1, 6.3.1.1).
	Capif1e *Capif1e `yaml:"capif1e" valid:"required"`
	// Internal is the interface of the API provider functions, CAPIF-3/4
	// (TS 23.222 cl. 6.4.6, 6.4.7), with mutual TLS (TS 33.122 cl. 6.6).
	Internal *Internal `yaml:"internal" valid:"required"`
	// Ca signs the certificates of the API invokers (TS 33.122 cl. 6.1 step 4).
	Ca *Ca `yaml:"ca" valid:"required"`
	// Token signs the access tokens (TS 29.222 cl. 5.6.2.3.2; TS 33.122
	// Annex C).
	Token *Token `yaml:"token" valid:"required"`
	// CredentialKey signs and checks the onboarding credentials (TS 33.122
	// cl. 6.1): an ECDSA P-256 private key, for ES256.
	CredentialKey string `yaml:"credentialKey" valid:"required"`
	// Providers are the API provider domain functions, fixed by
	// configuration instead of Register_API_Provider.
	Providers []Provider `yaml:"providers" valid:"optional"`
	// InvokerProfiles are the AFs that may onboard; the onboarding credential
	// names the profile.
	InvokerProfiles []InvokerProfile `yaml:"invokerProfiles" valid:"optional"`
}

type Listener struct {
	BindingIPv4 string `yaml:"bindingIPv4" valid:"required"`
	Port        int    `yaml:"port" valid:"required"`
}

type Capif1e struct {
	Listener    `yaml:",inline"`
	Certificate string `yaml:"certificate" valid:"required"`
	Key         string `yaml:"key" valid:"required"`
}

// Internal is the listener of CAPIF-3/4. With Certificate, its server has
// mutual TLS with the CA of the operator in Ca, by the name in Fqdn; without
// it, it is http.
type Internal struct {
	Listener    `yaml:",inline"`
	Fqdn        string `yaml:"fqdn,omitempty" valid:"optional"` // required with TLS
	Certificate string `yaml:"certificate,omitempty" valid:"optional"`
	Key         string `yaml:"key,omitempty" valid:"optional"`
	Ca          string `yaml:"ca,omitempty" valid:"optional"`
}

// Tls tells whether the interface has TLS.
func (i *Internal) Tls() bool {
	return i.Certificate != ""
}

// ApiRoot returns the apiRoot of the interface.
func (i *Internal) ApiRoot() string {
	if !i.Tls() {
		return "http://" + i.Addr()
	}
	return "https://" + net.JoinHostPort(i.Fqdn, strconv.Itoa(i.Port))
}

type Ca struct {
	Certificate string `yaml:"certificate" valid:"required"`
	// Key is an ECDSA P-384 or P-521 private key: the CA signs P-384 keys
	// (TS 33.310 cl. 6.1.1).
	Key string `yaml:"key" valid:"required"`
	// InvokerCertLifetime is a Go duration ("8760h").
	InvokerCertLifetime string `yaml:"invokerCertLifetime,omitempty" valid:"optional"`
	// CrlUri is the CRL distribution point of the certificates of the API
	// invokers (TS 33.310 cl. 6.1.3a).
	CrlUri string `yaml:"crlUri,omitempty" valid:"optional"`
	// CrlFile is where the CCF writes the CRL of this CA, in DER.
	CrlFile string `yaml:"crlFile,omitempty" valid:"optional"`
}

type Token struct {
	// Key is an ECDSA P-256 private key: the tokens are signed with ES256
	// (TS 33.210 cl. 6.3.3.1).
	Key string `yaml:"key" valid:"required"`
	// Lifetime is a Go duration ("10m").
	Lifetime string `yaml:"lifetime,omitempty" valid:"optional"`
}

// Provider is an API provider domain: its API publishing function and the
// API exposing functions whose APIs it publishes.
type Provider struct {
	Name   string   `yaml:"name" valid:"required"`
	ApfId  string   `yaml:"apfId" valid:"required"`
	AefIds []string `yaml:"aefIds" valid:"required"`
	// NfInstanceId is the NF instance of the client certificate of the
	// provider on CAPIF-3/4, with TLS.
	NfInstanceId string `yaml:"nfInstanceId,omitempty" valid:"optional"`
}

// InvokerProfile lists the APIs an AF may use and the AF_IDs the NEF accepts
// from it (TS 33.535 cl. 6.3 step 2).
type InvokerProfile struct {
	Name  string   `yaml:"name" valid:"required"`
	Apis  []string `yaml:"apis" valid:"required"`
	AfIds []string `yaml:"afIds" valid:"optional"`
}

type Logger struct {
	Enable       bool   `yaml:"enable" valid:"type(bool)"`
	Level        string `yaml:"level" valid:"required,in(trace|debug|info|warn|error|fatal|panic)"`
	ReportCaller bool   `yaml:"reportCaller" valid:"type(bool)"`
}

// scopeToken is an identifier that may appear in an OAuth2 scope: the
// delimiters of TS 29.222 table 8.5.4.2.6-1 and spaces are prohibited.
var scopeToken = regexp.MustCompile(`^[^#:,; ]+$`)

func (c *Configuration) validate() error {
	if c.Capif1e != nil {
		if err := c.Capif1e.Listener.validate("capif1e"); err != nil {
			return err
		}
	}
	if c.Internal != nil {
		if err := c.Internal.validate(); err != nil {
			return err
		}
	}
	if c.Ca != nil {
		if _, err := c.Ca.GetInvokerCertLifetime(); err != nil {
			return err
		}
	}
	if c.Token != nil {
		if _, err := c.Token.GetLifetime(); err != nil {
			return err
		}
	}
	apfIds := map[string]bool{}
	aefOwner := map[string]string{}
	for i, p := range c.Providers {
		if !scopeToken.MatchString(p.ApfId) {
			return fmt.Errorf("invalid providers[%d].apfId: no '#', ':', ',', ';' or space", i)
		}
		if apfIds[p.ApfId] {
			return fmt.Errorf("providers[%d]: apfId %q repeated", i, p.ApfId)
		}
		apfIds[p.ApfId] = true
		if len(p.AefIds) == 0 {
			return fmt.Errorf("providers[%d]: at least one aefId is required", i)
		}
		for j, aef := range p.AefIds {
			if !scopeToken.MatchString(aef) {
				return fmt.Errorf("invalid providers[%d].aefIds[%d]: no '#', ':', ',', ';' or space", i, j)
			}
			if owner, ok := aefOwner[aef]; ok {
				return fmt.Errorf("providers[%d].aefIds[%d]: aefId %q also in provider %q", i, j, aef, owner)
			}
			aefOwner[aef] = p.Name
		}
		if c.Internal != nil && c.Internal.Tls() {
			if err := uuid.Validate(p.NfInstanceId); err != nil {
				return fmt.Errorf("invalid providers[%d].nfInstanceId: with TLS on the internal interface, "+
					"the NF instance of the certificate of the provider", i)
			}
		}
	}
	names := map[string]bool{}
	for i, p := range c.InvokerProfiles {
		if names[p.Name] {
			return fmt.Errorf("invokerProfiles[%d]: name %q repeated", i, p.Name)
		}
		names[p.Name] = true
		if len(p.Apis) == 0 {
			return fmt.Errorf("invokerProfiles[%d]: at least one API is required", i)
		}
		for j, api := range p.Apis {
			if !scopeToken.MatchString(api) {
				return fmt.Errorf("invalid invokerProfiles[%d].apis[%d]: no '#', ':', ',', ';' or space", i, j)
			}
		}
		for j, id := range p.AfIds {
			if _, err := afid.Parse(id); err != nil {
				return fmt.Errorf("invalid invokerProfiles[%d].afIds[%d]: expected \"<FQDN>.<10 hex>\"", i, j)
			}
		}
	}
	return nil
}

func (i *Internal) validate() error {
	if err := i.Listener.validate("internal"); err != nil {
		return err
	}
	if (i.Certificate == "") != (i.Key == "") || (i.Certificate == "") != (i.Ca == "") {
		return errors.New("invalid internal: certificate, key and ca go together")
	}
	// With TLS, the URIs go by name (TS 29.510 table 6.1.6.2.2-1 NOTE 1, as
	// in the SBI): no URIs by IP address.
	if i.Tls() && i.Fqdn == "" {
		return errors.New("invalid internal: fqdn is required with TLS")
	}
	return nil
}

func (l Listener) validate(name string) error {
	ip := net.ParseIP(l.BindingIPv4)
	if ip == nil || ip.To4() == nil || ip.IsUnspecified() {
		return fmt.Errorf("invalid %s.bindingIPv4: an IPv4 address of this host, not 0.0.0.0", name)
	}
	if l.Port <= 0 || l.Port > 65535 {
		return fmt.Errorf("invalid %s.port", name)
	}
	return nil
}

// Addr returns host:port of the listener.
func (l Listener) Addr() string {
	return net.JoinHostPort(l.BindingIPv4, strconv.Itoa(l.Port))
}

// GetInvokerCertLifetime returns the validity of the certificates of the API
// invokers.
func (a *Ca) GetInvokerCertLifetime() (time.Duration, error) {
	if a == nil || a.InvokerCertLifetime == "" {
		return CcfDefaultInvokerCertLifetime, nil
	}
	d, err := time.ParseDuration(a.InvokerCertLifetime)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("invalid ca.invokerCertLifetime %q: expected a positive duration", a.InvokerCertLifetime)
	}
	return d, nil
}

// GetLifetime returns the lifetime of the access tokens.
func (t *Token) GetLifetime() (time.Duration, error) {
	if t == nil || t.Lifetime == "" {
		return CcfDefaultTokenLifetime, nil
	}
	d, err := time.ParseDuration(t.Lifetime)
	if err != nil || d < time.Second {
		return 0, fmt.Errorf("invalid token.lifetime %q: expected a duration of at least 1s", t.Lifetime)
	}
	return d, nil
}

// Profile returns the invoker profile with the given name.
func (c *Config) Profile(name string) (InvokerProfile, bool) {
	c.RLock()
	defer c.RUnlock()
	for _, p := range c.Configuration.InvokerProfiles {
		if p.Name == name {
			return p, true
		}
	}
	return InvokerProfile{}, false
}

// ProviderOf returns the API provider domain of an NF instance.
func (c *Config) ProviderOf(nfInstanceId string) (Provider, bool) {
	c.RLock()
	defer c.RUnlock()
	for _, p := range c.Configuration.Providers {
		if strings.EqualFold(p.NfInstanceId, nfInstanceId) {
			return p, true
		}
	}
	return Provider{}, false
}

// Provider returns the API provider domain of the API publishing function
// apfId.
func (c *Config) Provider(apfId string) (Provider, bool) {
	c.RLock()
	defer c.RUnlock()
	for _, p := range c.Configuration.Providers {
		if p.ApfId == apfId {
			return p, true
		}
	}
	return Provider{}, false
}

func appendInvalid(err error) error {
	var errs govalidator.Errors
	if err == nil {
		return nil
	}
	var verrs govalidator.Errors
	if !errors.As(err, &verrs) {
		return err
	}
	for _, e := range verrs.Errors() {
		errs = append(errs, fmt.Errorf("invalid %w", e))
	}
	return error(errs)
}

func (c *Config) SetLogEnable(enable bool) {
	c.Lock()
	defer c.Unlock()
	if c.Logger == nil {
		c.Logger = &Logger{Enable: enable, Level: "info"}
	} else {
		c.Logger.Enable = enable
	}
}

func (c *Config) SetLogLevel(level string) {
	c.Lock()
	defer c.Unlock()
	if c.Logger == nil {
		c.Logger = &Logger{Level: level}
	} else {
		c.Logger.Level = level
	}
}

func (c *Config) SetLogReportCaller(reportCaller bool) {
	c.Lock()
	defer c.Unlock()
	if c.Logger == nil {
		c.Logger = &Logger{Level: "info", ReportCaller: reportCaller}
	} else {
		c.Logger.ReportCaller = reportCaller
	}
}

func (c *Config) GetLogEnable() bool {
	c.RLock()
	defer c.RUnlock()
	if c.Logger == nil {
		return false
	}
	return c.Logger.Enable
}

func (c *Config) GetLogLevel() string {
	c.RLock()
	defer c.RUnlock()
	if c.Logger == nil {
		return "info"
	}
	return c.Logger.Level
}

func (c *Config) GetLogReportCaller() bool {
	c.RLock()
	defer c.RUnlock()
	if c.Logger == nil {
		return false
	}
	return c.Logger.ReportCaller
}
