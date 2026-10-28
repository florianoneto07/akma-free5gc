// Package config reads the configuration of the AF (afcfg.yaml).
package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"gopkg.in/yaml.v2"

	"github.com/florianoneto07/akma-free5gc/af/akmatls"
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
	// UaStarID is the Ua* security protocol identifier of the digest-http
	// profile, ten hexadecimal digits; FF00000001, the private-range
	// identifier of the simplified Ua* protocol (TS 33.220 H.2 NOTE 2), when
	// absent. The other profiles have the identifiers of TS 33.220 H.3.
	UaStarID string `yaml:"uaStarId,omitempty"`
	// Profiles are the Ua* servers of the AF, one per profile and port.
	Profiles []Profile `yaml:"profiles,omitempty"`
	// Listen is the address of a digest-http profile, when there is no
	// profiles list: the configuration of earlier versions.
	Listen string `yaml:"listen,omitempty"`
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

// Profile is one Ua* server of the AF.
type Profile struct {
	// Type is digest-tls (TS 24.109 K.2), psk-tls13 (K.3.3), psk-tls12
	// (K.3.2), psk-dtls13 or psk-dtls12 (TS 33.535 Annex C, CoAP inside),
	// oscore (TS 33.535 Annex D) or digest-http (the simplified Ua*, test
	// only).
	Type string `yaml:"type"`
	// Listen is a TCP address, or a UDP address for the DTLS and OSCORE
	// profiles.
	Listen string `yaml:"listen"`
	// Certificate and Key are the PEM files of the certificate of the AF
	// and its private key, for digest-tls. A relative path is relative to
	// the configuration file.
	Certificate string `yaml:"certificate,omitempty"`
	Key         string `yaml:"key,omitempty"`
}

// Logger holds the log settings, as in the free5GC configurations.
type Logger struct {
	Enable       bool   `yaml:"enable"`
	Level        string `yaml:"level"`
	ReportCaller bool   `yaml:"reportCaller"`
}

// Settings is the validated configuration.
type Settings struct {
	// AfID is the AF_ID of the digest-http profile.
	AfID          afid.AfID
	FQDN          string
	Profiles      []Profile
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
	s, err := c.Settings()
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(path)
	for i, p := range s.Profiles {
		if p.Certificate != "" && !filepath.IsAbs(p.Certificate) {
			s.Profiles[i].Certificate = filepath.Join(dir, p.Certificate)
		}
		if p.Key != "" && !filepath.IsAbs(p.Key) {
			s.Profiles[i].Key = filepath.Join(dir, p.Key)
		}
	}
	return s, nil
}

// Settings validates the configuration and applies the defaults.
func (c Config) Settings() (*Settings, error) {
	cf := c.Configuration
	var errs []error

	ua := afid.UaStarDigest
	if cf.UaStarID != "" {
		var err error
		if ua, err = parseUaStarID(cf.UaStarID); err != nil {
			errs = append(errs, err)
		}
	}
	if !isHostname(cf.FQDN) {
		errs = append(errs, fmt.Errorf("fqdn: %q is not a DNS name", cf.FQDN))
	}
	id, err := afid.New(cf.FQDN, ua)
	if err != nil {
		errs = append(errs, fmt.Errorf("fqdn: %w", err))
	}
	profiles, err := checkProfiles(cf)
	if err != nil {
		errs = append(errs, err)
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
		AfID: id, FQDN: cf.FQDN, Profiles: profiles, Path: cf.Path, Qop: cf.Qop,
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

// checkProfiles validates the profiles. Without a list, listen is a
// digest-http profile.
func checkProfiles(cf Configuration) ([]Profile, error) {
	if len(cf.Profiles) == 0 {
		if _, _, err := net.SplitHostPort(cf.Listen); err != nil {
			return nil, fmt.Errorf("listen: %w", err)
		}
		return []Profile{{Type: akmatls.ProfileDigestHTTP, Listen: cf.Listen}}, nil
	}
	if cf.Listen != "" {
		return nil, errors.New("listen: give the address in profiles, not here")
	}
	var errs []error
	seen := map[string]bool{}
	for i, p := range cf.Profiles {
		where := fmt.Sprintf("profiles[%d]", i)
		switch p.Type {
		case akmatls.ProfileDigestTLS:
			if p.Certificate == "" || p.Key == "" {
				errs = append(errs, fmt.Errorf("%s: %s needs certificate and key", where, p.Type))
			}
		case akmatls.ProfilePSKTLS13, akmatls.ProfilePSKTLS12, akmatls.ProfilePSKDTLS13, akmatls.ProfilePSKDTLS12,
			akmatls.ProfileOSCORE, akmatls.ProfileDigestHTTP:
			if p.Certificate != "" || p.Key != "" {
				errs = append(errs, fmt.Errorf("%s: %s takes no certificate", where, p.Type))
			}
		default:
			errs = append(errs, fmt.Errorf("%s: type %q is not digest-tls, psk-tls13, psk-tls12, psk-dtls13, "+
				"psk-dtls12, oscore or digest-http", where, p.Type))
		}
		if _, _, err := net.SplitHostPort(p.Listen); err != nil {
			errs = append(errs, fmt.Errorf("%s: listen: %w", where, err))
		} else if key := transport(p.Type) + p.Listen; seen[key] {
			errs = append(errs, fmt.Errorf("%s: listen %s already used", where, p.Listen))
		} else {
			seen[key] = true
		}
	}
	return cf.Profiles, errors.Join(errs...)
}

// transport names the transport of a profile: a TCP and a UDP server may
// share an address and port.
func transport(profile string) string {
	if akmatls.IsUDP(profile) {
		return "udp/"
	}
	return "tcp/"
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
