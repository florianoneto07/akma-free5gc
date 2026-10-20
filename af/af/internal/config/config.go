// Package config reads the configuration of the AF (afcfg.yaml).
package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"gopkg.in/yaml.v2"

	"github.com/florianoneto07/akma-free5gc/af/uastar"
	"github.com/florianoneto07/akma-free5gc/shared/akma/afid"
)

// KafExpiry is the policy of the AF when a K_AF expires (TS 33.535
// cl. 6.4.2: "based on its policy").
type KafExpiry string

const (
	// KafExpiryRefetch requests the K_AF again from the AAnF.
	KafExpiryRefetch KafExpiry = "refetch"
	// KafExpiryReject rejects the UE with the cause KAF_EXPIRED.
	KafExpiryReject KafExpiry = "reject"
)

// Defaults of the optional fields.
const (
	DefaultPath          = "/ua/v1/session"
	DefaultNonceLifetime = 300 * time.Second
	DefaultAanfTimeout   = 5 * time.Second
)

// Config is the content of afcfg.yaml.
type Config struct {
	Configuration Configuration `yaml:"configuration"`
	Logger        Logger        `yaml:"logger"`
}

// Configuration holds the AF parameters.
type Configuration struct {
	// FQDN of the AF: the only name accepted in the Host header field, the
	// second part of the realm and the FQDN of the AF_ID.
	FQDN string `yaml:"fqdn"`
	// UaStarID is the Ua* security protocol identifier, ten hexadecimal
	// digits: FF00000001, the private-range identifier of the simplified Ua*
	// protocol (TS 33.220 H.2 NOTE 2).
	UaStarID string `yaml:"uaStarId"`
	// Listen is the address of the Ua* server.
	Listen string `yaml:"listen"`
	// Path of the protected resource.
	Path string `yaml:"path,omitempty"`
	// RealmPrefix is the first part of the realm; uastar.RealmPrefix when
	// absent.
	RealmPrefix string `yaml:"realmPrefix,omitempty"`
	// Qop lists the qop values offered in the challenge.
	Qop []string `yaml:"qop,omitempty"`
	// NonceLifetime is a Go duration ("300s").
	NonceLifetime string `yaml:"nonceLifetime,omitempty"`
	// KafExpiry is "refetch" or "reject".
	KafExpiry KafExpiry `yaml:"kafExpiry,omitempty"`
	// AanfURI is the apiRoot of the AAnF, locally configured (TS 33.535
	// cl. 6.7). The AF is then inside the operator network.
	AanfURI string `yaml:"aanfUri,omitempty"`
	// NefURI is the apiRoot of the NEF. The AF is then outside the operator
	// network and requests K_AF through the NEF (TS 33.535 cl. 6.3). Exactly
	// one of aanfUri and nefUri is set.
	NefURI string `yaml:"nefUri,omitempty"`
	// NrfURI is the NRF at which the AF registers and that issues the access
	// token of the NEF API. Without CAPIF, TS 29.522 cl. 6 leaves the token
	// issuer to local configuration. Required with nefUri.
	NrfURI string `yaml:"nrfUri,omitempty"`
	// NfInstanceID identifies the AF at the NRF; a random UUID when absent.
	NfInstanceID string `yaml:"nfInstanceId,omitempty"`
	// Anonymous requests anonymous user access: the K_AF comes without the
	// SUPI (TS 33.535 cl. 6.2.2).
	Anonymous bool `yaml:"anonymous,omitempty"`
	// ClockOffset shifts the clock of the AF, a Go duration ("2h", "-2h").
	// Test only: it simulates an AF whose clock disagrees with the AAnF's.
	ClockOffset string `yaml:"clockOffset,omitempty"`
}

// Logger holds the log settings, as in the free5GC configurations.
type Logger struct {
	Enable       bool   `yaml:"enable"`
	Level        string `yaml:"level"`
	ReportCaller bool   `yaml:"reportCaller"`
}

// Settings is the validated configuration.
type Settings struct {
	AfID          afid.AfID
	FQDN          string
	Listen        string
	Path          string
	Realm         string
	Qop           []string
	NonceLifetime time.Duration
	KafExpiry     KafExpiry
	AanfURI       string
	NefURI        string
	NrfURI        string
	NfInstanceID  string
	Anonymous     bool
	ClockOffset   time.Duration
	Logger        Logger
}

// Load reads and validates path.
func Load(path string) (*Settings, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.UnmarshalStrict(raw, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c.Settings()
}

// Settings validates the configuration and applies the defaults.
func (c Config) Settings() (*Settings, error) {
	cf := c.Configuration
	var errs []error

	ua, err := parseUaStarID(cf.UaStarID)
	if err != nil {
		errs = append(errs, err)
	}
	if !isHostname(cf.FQDN) {
		errs = append(errs, fmt.Errorf("fqdn: %q is not a DNS name", cf.FQDN))
	}
	id, err := afid.New(cf.FQDN, ua)
	if err != nil {
		errs = append(errs, fmt.Errorf("fqdn: %w", err))
	}
	if _, _, err := net.SplitHostPort(cf.Listen); err != nil {
		errs = append(errs, fmt.Errorf("listen: %w", err))
	}
	switch {
	case cf.AanfURI != "" && cf.NefURI != "":
		errs = append(errs, errors.New("aanfUri and nefUri: set only one of them"))
	case cf.NefURI != "":
		if !isAPIRoot(cf.NefURI) {
			errs = append(errs, fmt.Errorf("nefUri: %q is not an http(s) apiRoot", cf.NefURI))
		}
		if !isAPIRoot(cf.NrfURI) {
			errs = append(errs, fmt.Errorf("nrfUri: %q is not an http(s) apiRoot (required with nefUri)", cf.NrfURI))
		}
	case !isAPIRoot(cf.AanfURI):
		errs = append(errs, fmt.Errorf("aanfUri: %q is not an http(s) apiRoot", cf.AanfURI))
	}
	nfID := cf.NfInstanceID
	if nfID == "" {
		nfID = uuid.New().String()
	} else if _, err := uuid.Parse(nfID); err != nil {
		errs = append(errs, fmt.Errorf("nfInstanceId: %q is not a UUID", nfID))
	}

	s := &Settings{
		AfID: id, FQDN: cf.FQDN, Listen: cf.Listen, Path: cf.Path, Qop: cf.Qop,
		NonceLifetime: DefaultNonceLifetime, KafExpiry: cf.KafExpiry, AanfURI: strings.TrimRight(cf.AanfURI, "/"),
		NefURI: strings.TrimRight(cf.NefURI, "/"), NrfURI: strings.TrimRight(cf.NrfURI, "/"),
		NfInstanceID: nfID, Anonymous: cf.Anonymous, Logger: c.Logger,
	}
	if s.Path == "" {
		s.Path = DefaultPath
	}
	if !strings.HasPrefix(s.Path, "/") {
		errs = append(errs, fmt.Errorf("path: %q must start with /", s.Path))
	}
	prefix := cf.RealmPrefix
	if prefix == "" {
		prefix = uastar.RealmPrefix
	}
	if strings.ContainsAny(prefix, "@\"") {
		errs = append(errs, fmt.Errorf("realmPrefix: %q must not contain @ or \"", prefix))
	}
	s.Realm = uastar.Realm(prefix, cf.FQDN)
	if len(s.Qop) == 0 {
		s.Qop = []string{uastar.QopAuth}
	}
	for _, q := range s.Qop {
		if q != uastar.QopAuth && q != uastar.QopAuthInt {
			errs = append(errs, fmt.Errorf("qop: %q is neither auth nor auth-int", q))
		}
	}
	if cf.NonceLifetime != "" {
		d, err := time.ParseDuration(cf.NonceLifetime)
		if err != nil || d <= 0 {
			errs = append(errs, fmt.Errorf("nonceLifetime: %q is not a positive duration", cf.NonceLifetime))
		}
		s.NonceLifetime = d
	}
	if cf.ClockOffset != "" {
		d, err := time.ParseDuration(cf.ClockOffset)
		if err != nil {
			errs = append(errs, fmt.Errorf("clockOffset: %q is not a duration", cf.ClockOffset))
		}
		s.ClockOffset = d
	}
	switch s.KafExpiry {
	case "":
		s.KafExpiry = KafExpiryRefetch
	case KafExpiryRefetch, KafExpiryReject:
	default:
		errs = append(errs, fmt.Errorf("kafExpiry: %q is neither refetch nor reject", s.KafExpiry))
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return s, nil
}

func isAPIRoot(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

func parseUaStarID(s string) (afid.UaStarID, error) {
	var id afid.UaStarID
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(id) {
		return id, fmt.Errorf("uaStarId: %q is not ten hexadecimal digits", s)
	}
	copy(id[:], b)
	return id, nil
}

// isHostname reports whether s is an ASCII DNS name: dot-separated labels of
// letters, digits and hyphens, 1 to 63 characters each, not starting or
// ending with a hyphen. The FQDN is compared with the Host header field, so
// it carries no port (TS 33.220 cl. 4.5.2 prerequisite (3)).
func isHostname(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
