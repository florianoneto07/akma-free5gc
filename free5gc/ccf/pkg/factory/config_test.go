package factory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sample = `info:
  version: 1.0.0
  description: CCF test configuration

configuration:
  ccfName: ccf
  capif1e:
    bindingIPv4: 192.168.16.130
    port: 8020
    certificate: cert/ccf.pem
    key: cert/ccf.key
  internal:
    bindingIPv4: 127.0.0.1
    port: 8020
  ca:
    certificate: cert/ccf-ca.pem
    key: cert/ccf-ca.key
    invokerCertLifetime: 8760h
  token:
    key: cert/ccf-token.key
    lifetime: 10m
  credentialKey: cert/ccf-credential.key
  providers:
    - name: nef
      apfId: nef-apf
      aefIds:
        - nef-aef
  invokerProfiles:
    - name: af1-external
      apis:
        - 3gpp-akma
      afIds:
        - af1.akma.example.FF00000001

logger:
  enable: true
  level: info
  reportCaller: false
`

func readSample(t *testing.T, text string) (*Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ccfcfg.yaml")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return ReadConfig(path)
}

func TestConfig(t *testing.T) {
	cfg, err := readSample(t, sample)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Configuration.Capif1e.Addr() != "192.168.16.130:8020" || cfg.Configuration.Internal.Addr() != "127.0.0.1:8020" {
		t.Fatalf("addresses: %+v", cfg.Configuration)
	}
	if p, ok := cfg.Profile("af1-external"); !ok || p.Apis[0] != "3gpp-akma" {
		t.Fatalf("profile: %+v", p)
	}
	if p, ok := cfg.Provider("nef-apf"); !ok || p.AefIds[0] != "nef-aef" {
		t.Fatalf("provider: %+v", p)
	}
	if d, _ := cfg.Configuration.Token.GetLifetime(); d.Minutes() != 10 {
		t.Fatalf("token lifetime: %v", d)
	}

	for name, change := range map[string][2]string{
		"0.0.0.0":           {"bindingIPv4: 192.168.16.130", "bindingIPv4: 0.0.0.0"},
		"apfId with ':'":    {"apfId: nef-apf", "apfId: nef:apf"},
		"aefId with space":  {"- nef-aef", "- nef aef"},
		"API with '#'":      {"- 3gpp-akma", "- 3gpp#akma"},
		"bad AF_ID":         {"- af1.akma.example.FF00000001", "- af1.akma.example"},
		"short token":       {"lifetime: 10m", "lifetime: 500ms"},
		"unknown attribute": {"ccfName: ccf", "ccfName: ccf\n  extra: 1"},
		"no credential key": {"credentialKey: cert/ccf-credential.key", ""},
	} {
		if _, err := readSample(t, strings.Replace(sample, change[0], change[1], 1)); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	withTls := strings.Replace(sample, "    bindingIPv4: 127.0.0.1\n    port: 8020\n",
		"    bindingIPv4: 127.0.0.1\n    port: 8020\n    fqdn: ccf.example\n"+
			"    certificate: cert/sba/ccf-internal.pem\n    key: cert/sba/ccf-internal.key\n    ca: cert/sba/sba-ca.pem\n", 1)
	if _, err := readSample(t, withTls); err == nil {
		t.Fatal("TLS on the internal interface without the NF instance of the provider: accepted")
	}
	withInstance := strings.Replace(withTls, "      apfId: nef-apf\n",
		"      apfId: nef-apf\n      nfInstanceId: 8e73ad07-906c-4952-93ac-cd32bbb076ed\n", 1)
	tlsCfg, err := readSample(t, withInstance)
	if err != nil {
		t.Fatal(err)
	}
	if got := tlsCfg.Configuration.Internal.ApiRoot(); got != "https://ccf.example:8020" {
		t.Fatalf("apiRoot with TLS: %s", got)
	}
	if got := cfg.Configuration.Internal.ApiRoot(); got != "http://127.0.0.1:8020" {
		t.Fatalf("apiRoot without TLS: %s", got)
	}
	if p, ok := tlsCfg.ProviderOf("8E73AD07-906C-4952-93AC-CD32BBB076ED"); !ok || p.ApfId != "nef-apf" {
		t.Fatalf("provider of an NF instance: %+v", p)
	}
	if _, err := readSample(t, strings.Replace(withInstance, "    ca: cert/sba/sba-ca.pem\n", "", 1)); err == nil {
		t.Fatal("internal.certificate without internal.ca: accepted")
	}
	// With TLS, no apiRoot by IP address.
	if _, err := readSample(t, strings.Replace(withInstance, "    fqdn: ccf.example\n", "", 1)); err == nil {
		t.Fatal("TLS on the internal interface without fqdn: accepted")
	}
	twoProviders := strings.Replace(sample, "  invokerProfiles:",
		"    - name: other\n      apfId: other-apf\n      aefIds:\n        - nef-aef\n  invokerProfiles:", 1)
	if _, err := readSample(t, twoProviders); err == nil {
		t.Fatal("an AEF in two providers: accepted")
	}
}
