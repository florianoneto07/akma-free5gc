package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func base() Config {
	return Config{Configuration: Configuration{
		FQDN: "af1.akma.example", UaStarID: "FF00000001", Listen: "192.168.16.129:8080",
		AanfURI: "http://192.168.16.130:8010/",
	}}
}

func TestDefaults(t *testing.T) {
	s, err := base().Settings()
	if err != nil {
		t.Fatal(err)
	}
	if s.AfID.Transport() != "af1.akma.example.FF00000001" || s.Realm != "3GPP-bootstrapping-akma@af1.akma.example" ||
		len(s.Profiles) != 1 || s.Profiles[0] != (Profile{Type: "digest-http", Listen: "192.168.16.129:8080"}) ||
		s.Path != DefaultPath || len(s.Qop) != 1 || s.Qop[0] != "auth" || s.NonceLifetime != DefaultNonceLifetime ||
		s.KafExpiry != KafExpiryRefetch || s.AanfURI != "http://192.168.16.130:8010" {
		t.Fatalf("settings %+v", s)
	}
}

func TestInvalid(t *testing.T) {
	for name, mutate := range map[string]func(*Configuration){
		"fqdn with port":        func(c *Configuration) { c.FQDN = "af1.akma.example:8080" },
		"fqdn empty label":      func(c *Configuration) { c.FQDN = "af1..example" },
		"fqdn non ascii":        func(c *Configuration) { c.FQDN = "äf1.example" },
		"ua* id short":          func(c *Configuration) { c.UaStarID = "FF0000" },
		"listen without port":   func(c *Configuration) { c.Listen = "192.168.16.129" },
		"aanfUri":               func(c *Configuration) { c.AanfURI = "192.168.16.130:8010" },
		"qop":                   func(c *Configuration) { c.Qop = []string{"auth-conf"} },
		"nonceLifetime":         func(c *Configuration) { c.NonceLifetime = "-1s" },
		"kafExpiry":             func(c *Configuration) { c.KafExpiry = "renew" },
		"realmPrefix with @":    func(c *Configuration) { c.RealmPrefix = "a@b" },
		"path":                  func(c *Configuration) { c.Path = "ua" },
		"clockOffset":           func(c *Configuration) { c.ClockOffset = "two hours" },
		"no aanfUri nor nefUri": func(c *Configuration) { c.AanfURI = "" },
		"aanfUri and nefUri":    func(c *Configuration) { c.NefURI = "http://192.168.16.130:8000" },
		"nefUri without nrfUri": func(c *Configuration) {
			c.AanfURI, c.NefURI = "", "http://192.168.16.130:8000"
		},
		"nefUri not an apiRoot": func(c *Configuration) {
			c.AanfURI, c.NefURI, c.NrfURI = "", "192.168.16.130:8000", "http://127.0.0.10:8000"
		},
		"nfInstanceId": func(c *Configuration) { c.NfInstanceID = "af1" },
		"listen and profiles": func(c *Configuration) {
			c.Profiles = []Profile{{Type: "psk-tls13", Listen: "192.168.16.129:8444"}}
		},
		"profile type": func(c *Configuration) {
			c.Listen, c.Profiles = "", []Profile{{Type: "psk-tls", Listen: "192.168.16.129:8444"}}
		},
		"profile listen": func(c *Configuration) {
			c.Listen, c.Profiles = "", []Profile{{Type: "psk-tls13", Listen: "8444"}}
		},
		"profile port twice": func(c *Configuration) {
			c.Listen, c.Profiles = "", []Profile{{Type: "psk-tls13", Listen: ":8444"}, {Type: "psk-tls12", Listen: ":8444"}}
		},
		"DTLS port twice": func(c *Configuration) {
			c.Listen, c.Profiles = "", []Profile{{Type: "psk-dtls13", Listen: ":5684"}, {Type: "psk-dtls12", Listen: ":5684"}}
		},
		"OSCORE and DTLS on one port": func(c *Configuration) {
			c.Listen, c.Profiles = "", []Profile{{Type: "oscore", Listen: ":5683"}, {Type: "psk-dtls13", Listen: ":5683"}}
		},
		"OSCORE with a certificate": func(c *Configuration) {
			c.Listen, c.Profiles = "", []Profile{{Type: "oscore", Listen: ":5683", Certificate: "c.pem", Key: "c.key"}}
		},
		"digest-tls without certificate": func(c *Configuration) {
			c.Listen, c.Profiles = "", []Profile{{Type: "digest-tls", Listen: ":8443"}}
		},
		"psk with certificate": func(c *Configuration) {
			c.Listen, c.Profiles = "", []Profile{{Type: "psk-tls12", Listen: ":8445", Certificate: "a.pem", Key: "a.key"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := base()
			mutate(&c.Configuration)
			if _, err := c.Settings(); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// The AF outside the operator network: NEF, NRF and an NF instance ID.
func TestExternal(t *testing.T) {
	c := base()
	c.Configuration.AanfURI = ""
	c.Configuration.NefURI = "http://192.168.16.130:8000/"
	c.Configuration.NrfURI = "http://127.0.0.10:8000"
	c.Configuration.Anonymous = true
	s, err := c.Settings()
	if err != nil {
		t.Fatal(err)
	}
	if s.NefURI != "http://192.168.16.130:8000" || s.NrfURI != "http://127.0.0.10:8000" || s.AanfURI != "" ||
		!s.Anonymous || len(s.NfInstanceID) != 36 {
		t.Fatalf("settings %+v", s)
	}
	c.Configuration.NfInstanceID = "b6f417f0-06fa-4c38-b291-33066f5a5fe8"
	if s, err = c.Settings(); err != nil || s.NfInstanceID != c.Configuration.NfInstanceID {
		t.Fatalf("settings %+v, %v", s, err)
	}
}

func TestClockOffset(t *testing.T) {
	c := base()
	c.Configuration.ClockOffset = "-2h"
	s, err := c.Settings()
	if err != nil || s.ClockOffset != -2*time.Hour {
		t.Fatalf("settings %+v, %v", s, err)
	}
}

// The sample configuration: the three profiles of TS 24.109 Annex K, and no
// digest-http, a test profile off by default.
func TestSampleConfig(t *testing.T) {
	s, err := Load("../../../config/afcfg.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if s.AfID.Transport() != "af1.akma.example.FF00000001" || len(s.Profiles) != 6 ||
		s.NonceLifetime != 300*time.Second || s.KafExpiry != KafExpiryRefetch || !s.Logger.Enable {
		t.Fatalf("settings %+v", s)
	}
	cert, _ := filepath.Abs("../../../build/cert/af1.akma.example.pem")
	want := []Profile{
		{Type: "digest-tls", Listen: "192.168.16.129:8443", Certificate: cert,
			Key: strings.TrimSuffix(cert, ".pem") + ".key"},
		{Type: "psk-tls13", Listen: "192.168.16.129:8444"},
		{Type: "psk-tls12", Listen: "192.168.16.129:8445"},
		{Type: "psk-dtls13", Listen: "192.168.16.129:5684"},
		{Type: "psk-dtls12", Listen: "192.168.16.129:5685"},
		{Type: "oscore", Listen: "192.168.16.129:5683"},
	}
	for i, p := range s.Profiles {
		if p.Certificate != "" {
			p.Certificate, _ = filepath.Abs(p.Certificate)
			p.Key, _ = filepath.Abs(p.Key)
		}
		if p != want[i] {
			t.Errorf("profile %d: %+v, want %+v", i, p, want[i])
		}
	}
}

// Without profiles, listen is a digest-http profile with uaStarId, the
// configuration of earlier versions; uaStarId defaults to FF00000001.
func TestListenOnly(t *testing.T) {
	c := base()
	c.Configuration.UaStarID = ""
	s, err := c.Settings()
	if err != nil {
		t.Fatal(err)
	}
	if s.AfID.Transport() != "af1.akma.example.FF00000001" || len(s.Profiles) != 1 || s.Profiles[0].Type != "digest-http" {
		t.Fatalf("settings %+v", s)
	}
}

// The configuration of the AF outside the operator network.
func TestSampleExternalConfig(t *testing.T) {
	s, err := Load("../../../config/afcfg-external.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if s.AfID.Transport() != "af1.akma.example.FF00000001" || len(s.Profiles) != 6 ||
		s.Profiles[1].Listen != "192.168.16.129:8454" || s.Profiles[3].Listen != "192.168.16.129:5694" ||
		s.Profiles[5] != (Profile{Type: "oscore", Listen: "192.168.16.129:5693"}) ||
		s.NefURI != "http://192.168.16.130:8000" || s.NrfURI != "http://127.0.0.10:8000" || s.AanfURI != "" {
		t.Fatalf("settings %+v", s)
	}
}

func TestUnknownField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "afcfg.yaml")
	raw := "configuration:\n  fqdn: af1.akma.example\n  uaStarID: FF00000001\n"
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "uaStarID") {
		t.Fatalf("err = %v", err)
	}
}

// A TCP and a UDP server may share an address and port.
func TestTCPAndUDPOnOnePort(t *testing.T) {
	c := base()
	c.Configuration.Listen = ""
	c.Configuration.Profiles = []Profile{{Type: "psk-tls13", Listen: ":5684"}, {Type: "psk-dtls13", Listen: ":5684"}}
	if _, err := c.Settings(); err != nil {
		t.Fatal(err)
	}
}
