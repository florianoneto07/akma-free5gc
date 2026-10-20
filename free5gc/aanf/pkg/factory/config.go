/*
 * AAnF Configuration Factory
 */

package factory

import (
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/google/uuid"

	"github.com/florianoneto07/akma-free5gc/free5gc/aanf/internal/logger"
	"github.com/florianoneto07/akma-free5gc/shared/akma/afid"
	"github.com/free5gc/openapi/models"
)

const (
	AanfDefaultConfigPath         = "./config/aanfcfg.yaml"
	AanfDefaultNfInstanceIdEnvVar = "AANF_NF_INSTANCE_ID"
	AanfSbiDefaultIPv4            = "127.0.0.1"
	AanfSbiDefaultPort            = 8010
	AanfAkmaResUriPrefix          = "/naanf-akma/v1"
	// AanfApiFullVersion is the version of TS29535_Naanf_AKMA.yaml implemented.
	AanfApiFullVersion = "1.2.0"
	// AanfDefaultKafLifetime is used when akma.kafLifetime is not configured.
	// The lifetime of K_AF is operator policy (TS 33.535 cl. 4.4.0, 5.2).
	AanfDefaultKafLifetime = time.Hour
)

type Config struct {
	Info          *Info          `yaml:"info" valid:"required"`
	Configuration *Configuration `yaml:"configuration" valid:"required"`
	Logger        *Logger        `yaml:"logger" valid:"required"`
	sync.RWMutex
}

func (c *Config) Validate() (bool, error) {
	govalidator.TagMap["scheme"] = func(str string) bool {
		return str == "https" || str == "http"
	}

	if configuration := c.Configuration; configuration != nil {
		if result, err := configuration.validate(); err != nil {
			return result, err
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
	NfInstanceId    string          `yaml:"nfInstanceId,omitempty" valid:"optional,uuidv4"`
	Sbi             *Sbi            `yaml:"sbi,omitempty" valid:"required"`
	ServiceNameList []string        `yaml:"serviceNameList,omitempty" valid:"required"`
	NrfUri          string          `yaml:"nrfUri,omitempty" valid:"url,required"`
	NrfCertPem      string          `yaml:"nrfCertPem,omitempty" valid:"optional"`
	PlmnSupportList []models.PlmnId `yaml:"plmnSupportList,omitempty" valid:"required"`
	// RoutingIndicators published in AanfInfo (TS 29.510). Empty means the
	// AAnF serves any Routing Indicator. Quote them in YAML: each digit is
	// significant ("0000" is not "0", TS 23.003 cl. 2.2B).
	RoutingIndicators []string `yaml:"routingIndicators,omitempty" valid:"optional"`
	Akma              *Akma    `yaml:"akma,omitempty" valid:"required"`
}

// Akma holds the AKMA-specific settings of the AAnF.
type Akma struct {
	// KafLifetime is the K_AF lifetime as a Go duration ("1h", "30m").
	KafLifetime string `yaml:"kafLifetime,omitempty" valid:"optional"`
	// AuthorizedAfs is the local policy that authorizes AFs to obtain K_AF
	// (TS 33.535 cl. 6.2.1 step 2).
	AuthorizedAfs []AuthorizedAf `yaml:"authorizedAfs,omitempty" valid:"optional"`
	// AuthorizedNefs is the local policy for the K_AF requests that a NEF
	// relays for AFs outside the operator network (TS 33.535 cl. 6.3 step 3).
	AuthorizedNefs []AuthorizedNef `yaml:"authorizedNefs,omitempty" valid:"optional"`
	// RoamingStatusSubscription enables the ROAMING_STATUS subscription of
	// TS 33.535 cl. 6.2.1 step 5. Not implemented: it must stay false.
	RoamingStatusSubscription bool `yaml:"roamingStatusSubscription" valid:"optional"`
	// AKid sets the A-KID format; no specification fixes the A-TID encoding.
	AKid *AKidFormat `yaml:"aKid,omitempty" valid:"optional"`
}

// AuthorizedAf binds an AF identifier to the source addresses the AF uses,
// so that an AF cannot request the K_AF of another AF_ID.
type AuthorizedAf struct {
	AfId            string   `yaml:"afId" valid:"required"`
	SourceAddresses []string `yaml:"sourceAddresses" valid:"required"`
}

// AuthorizedNef binds the source addresses of a NEF to the AF_IDs of the
// external AFs whose K_AF the NEF may request.
type AuthorizedNef struct {
	SourceAddresses []string `yaml:"sourceAddresses" valid:"required"`
	AfIds           []string `yaml:"afIds" valid:"required"`
}

// AKidFormat configures the textual form of the A-KID.
type AKidFormat struct {
	AtidEncoding string   `yaml:"atidEncoding,omitempty" valid:"optional,in(base64|base64url|hex)"`
	AtidLabel    string   `yaml:"atidLabel,omitempty" valid:"optional"`
	AcceptLabels []string `yaml:"acceptLabels,omitempty" valid:"optional"`
}

type Logger struct {
	Enable       bool   `yaml:"enable" valid:"type(bool)"`
	Level        string `yaml:"level" valid:"required,in(trace|debug|info|warn|error|fatal|panic)"`
	ReportCaller bool   `yaml:"reportCaller" valid:"type(bool)"`
}

var ridPattern = regexp.MustCompile(`^[0-9]{1,4}$`)

func (c *Configuration) validate() (bool, error) {
	if c.NfInstanceId == "" {
		c.NfInstanceId = uuid.New().String()
	}

	if sbi := c.Sbi; sbi != nil {
		if result, err := sbi.validate(); err != nil {
			return result, err
		}
	}

	if len(c.ServiceNameList) != 1 || c.ServiceNameList[0] != string(models.ServiceName_NAANF_AKMA) {
		return false, errors.New("invalid serviceNameList: should be [naanf-akma]")
	}

	for i, plmnId := range c.PlmnSupportList {
		if !govalidator.StringMatches(plmnId.Mcc, "^[0-9]{3}$") ||
			!govalidator.StringMatches(plmnId.Mnc, "^[0-9]{2,3}$") {
			return false, fmt.Errorf("invalid plmnSupportList[%d]: MCC 3 digits, MNC 2 or 3 digits", i)
		}
	}

	for i, rid := range c.RoutingIndicators {
		if !ridPattern.MatchString(rid) {
			return false, fmt.Errorf("invalid routingIndicators[%d]: 1 to 4 decimal digits", i)
		}
	}

	if c.Akma != nil {
		if err := c.Akma.validate(); err != nil {
			return false, err
		}
	}

	result, err := govalidator.ValidateStruct(c)
	return result, appendInvalid(err)
}

func (a *Akma) validate() error {
	if a.RoamingStatusSubscription {
		return errors.New("akma.roamingStatusSubscription: the ROAMING_STATUS subscription " +
			"is not implemented in this version and must be false")
	}
	if _, err := a.GetKafLifetime(); err != nil {
		return err
	}
	for i, af := range a.AuthorizedAfs {
		if _, err := afid.Parse(af.AfId); err != nil {
			return fmt.Errorf("invalid akma.authorizedAfs[%d].afId: expected \"<FQDN>.<10 hex>\"", i)
		}
		if len(af.SourceAddresses) == 0 {
			return fmt.Errorf("akma.authorizedAfs[%d]: at least one source address is required", i)
		}
		for j, addr := range af.SourceAddresses {
			if net.ParseIP(addr) == nil {
				return fmt.Errorf("invalid akma.authorizedAfs[%d].sourceAddresses[%d]", i, j)
			}
		}
	}
	for i, nef := range a.AuthorizedNefs {
		if len(nef.SourceAddresses) == 0 {
			return fmt.Errorf("akma.authorizedNefs[%d]: at least one source address is required", i)
		}
		for j, addr := range nef.SourceAddresses {
			if net.ParseIP(addr) == nil {
				return fmt.Errorf("invalid akma.authorizedNefs[%d].sourceAddresses[%d]", i, j)
			}
		}
		if len(nef.AfIds) == 0 {
			return fmt.Errorf("akma.authorizedNefs[%d]: at least one AF_ID is required", i)
		}
		for j, id := range nef.AfIds {
			if _, err := afid.Parse(id); err != nil {
				return fmt.Errorf("invalid akma.authorizedNefs[%d].afIds[%d]: expected \"<FQDN>.<10 hex>\"", i, j)
			}
		}
	}
	return nil
}

// GetKafLifetime returns the configured K_AF lifetime.
func (a *Akma) GetKafLifetime() (time.Duration, error) {
	if a == nil || a.KafLifetime == "" {
		return AanfDefaultKafLifetime, nil
	}
	d, err := time.ParseDuration(a.KafLifetime)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("invalid akma.kafLifetime %q: expected a positive duration", a.KafLifetime)
	}
	return d, nil
}

func (c *Config) GetNfInstanceId() string {
	c.RLock()
	defer c.RUnlock()

	nfInstanceId := os.Getenv(AanfDefaultNfInstanceIdEnvVar)
	if nfInstanceId == "" {
		return c.Configuration.NfInstanceId
	}
	if err := uuid.Validate(nfInstanceId); err != nil {
		logger.CfgLog.Errorf("Env var \"%s\" is not a valid uuid, fallback on configuration nfInstanceId",
			AanfDefaultNfInstanceIdEnvVar)
		return c.Configuration.NfInstanceId
	}
	return nfInstanceId
}

type Sbi struct {
	Scheme       string `yaml:"scheme" valid:"scheme"`
	RegisterIPv4 string `yaml:"registerIPv4,omitempty" valid:"host,required"` // IP that is registered at NRF.
	BindingIPv4  string `yaml:"bindingIPv4,omitempty" valid:"host,required"`  // IP used to run the server in the node.
	Port         int    `yaml:"port,omitempty" valid:"port,required"`
	Tls          *Tls   `yaml:"tls,omitempty" valid:"optional"`
}

func (s *Sbi) validate() (bool, error) {
	if tls := s.Tls; tls != nil {
		if result, err := govalidator.ValidateStruct(tls); err != nil {
			return result, err
		}
	}
	result, err := govalidator.ValidateStruct(s)
	return result, appendInvalid(err)
}

type Tls struct {
	Pem string `yaml:"pem,omitempty" valid:"type(string),minstringlength(1),required"`
	Key string `yaml:"key,omitempty" valid:"type(string),minstringlength(1),required"`
}

func appendInvalid(err error) error {
	var errs govalidator.Errors

	if err == nil {
		return nil
	}

	es := err.(govalidator.Errors).Errors()
	for _, e := range es {
		errs = append(errs, fmt.Errorf("invalid %w", e))
	}

	return error(errs)
}

func (c *Config) GetSbiScheme() string {
	c.RLock()
	defer c.RUnlock()
	return c.Configuration.Sbi.Scheme
}

func (c *Config) GetSbiBindingAddr() string {
	c.RLock()
	defer c.RUnlock()
	return net.JoinHostPort(c.Configuration.Sbi.BindingIPv4, fmt.Sprint(c.Configuration.Sbi.Port))
}

func (c *Config) GetCertPemPath() string {
	c.RLock()
	defer c.RUnlock()
	if c.Configuration.Sbi.Tls == nil {
		return ""
	}
	return c.Configuration.Sbi.Tls.Pem
}

func (c *Config) GetCertKeyPath() string {
	c.RLock()
	defer c.RUnlock()
	if c.Configuration.Sbi.Tls == nil {
		return ""
	}
	return c.Configuration.Sbi.Tls.Key
}

func (c *Config) GetLogEnable() bool {
	c.RLock()
	defer c.RUnlock()
	return c.Logger != nil && c.Logger.Enable
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
	return c.Logger != nil && c.Logger.ReportCaller
}

func (c *Config) SetLogEnable(enable bool) {
	c.Lock()
	defer c.Unlock()
	if c.Logger == nil {
		c.Logger = &Logger{Level: "info"}
	}
	c.Logger.Enable = enable
}

func (c *Config) SetLogLevel(level string) {
	c.Lock()
	defer c.Unlock()
	if c.Logger == nil {
		c.Logger = &Logger{Enable: true}
	}
	c.Logger.Level = level
}

func (c *Config) SetLogReportCaller(reportCaller bool) {
	c.Lock()
	defer c.Unlock()
	if c.Logger == nil {
		c.Logger = &Logger{Enable: true, Level: "info"}
	}
	c.Logger.ReportCaller = reportCaller
}
