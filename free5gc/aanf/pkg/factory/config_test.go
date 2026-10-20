package factory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const baseConfig = `info:
  version: 1.0.0
  description: AANF test configuration
configuration:
  sbi:
    scheme: http
    registerIPv4: 192.168.16.130
    bindingIPv4: 192.168.16.130
    port: 8010
  serviceNameList:
    - naanf-akma
  nrfUri: http://127.0.0.10:8000
  nrfCertPem: cert/nrf.pem
  plmnSupportList:
    - mcc: "208"
      mnc: "93"
  routingIndicators: [%RIDS%]
  akma:
    kafLifetime: %LIFETIME%
    roamingStatusSubscription: %ROAMING%
    authorizedAfs:
      - afId: %AFID%
        sourceAddresses: [%ADDR%]
    authorizedNefs:
      - sourceAddresses: [%NEFADDR%]
        afIds: [%NEFAFIDS%]
logger:
  enable: true
  level: info
  reportCaller: false
`

type params map[string]string

func writeConfig(t *testing.T, p params) string {
	t.Helper()
	defaults := params{
		"RIDS":     `"0000", "012"`,
		"LIFETIME": "30m",
		"ROAMING":  "false",
		"AFID":     "af1.akma.example.FF00000001",
		"ADDR":     "192.168.16.129",
		"NEFADDR":  "192.168.16.130",
		"NEFAFIDS": "af1.akma.example.FF00000001",
	}
	s := baseConfig
	for k, v := range defaults {
		if pv, ok := p[k]; ok {
			v = pv
		}
		s = strings.ReplaceAll(s, "%"+k+"%", v)
	}
	path := filepath.Join(t.TempDir(), "aanfcfg.yaml")
	if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadConfig(t *testing.T) {
	cfg, err := ReadConfig(writeConfig(t, nil))
	if err != nil {
		t.Fatalf("ReadConfig: %v", err)
	}
	c := cfg.Configuration
	if got := strings.Join(c.RoutingIndicators, ","); got != "0000,012" {
		t.Errorf("routingIndicators = %q, want 0000,012", got)
	}
	if d, _ := c.Akma.GetKafLifetime(); d != 30*time.Minute {
		t.Errorf("kafLifetime = %v", d)
	}
	if c.NfInstanceId == "" {
		t.Error("nfInstanceId not generated")
	}
	if cfg.GetSbiBindingAddr() != "192.168.16.130:8010" {
		t.Errorf("binding addr = %s", cfg.GetSbiBindingAddr())
	}
}

// Every digit of a Routing Indicator is significant (TS 23.003 cl. 2.2B). An
// unquoted 0000 must still be read as the string "0000", not as 0.
func TestRoutingIndicatorLeadingZerosKept(t *testing.T) {
	cfg, err := ReadConfig(writeConfig(t, params{"RIDS": "0000, 012"}))
	if err != nil {
		t.Fatalf("ReadConfig: %v", err)
	}
	if got := strings.Join(cfg.Configuration.RoutingIndicators, ","); got != "0000,012" {
		t.Errorf("routingIndicators = %q, want 0000,012", got)
	}
}

func TestDefaultKafLifetime(t *testing.T) {
	cfg, err := ReadConfig(writeConfig(t, params{"LIFETIME": `""`}))
	if err != nil {
		t.Fatalf("ReadConfig: %v", err)
	}
	if d, _ := cfg.Configuration.Akma.GetKafLifetime(); d != AanfDefaultKafLifetime {
		t.Errorf("kafLifetime = %v, want %v", d, AanfDefaultKafLifetime)
	}
}

func TestInvalidConfigs(t *testing.T) {
	cases := map[string]params{
		"rid too long":             {"RIDS": `"12345"`},
		"rid not digits":           {"RIDS": `"01a"`},
		"roaming subscription on":  {"ROAMING": "true"},
		"lifetime not a duration":  {"LIFETIME": "soon"},
		"lifetime not positive":    {"LIFETIME": "-1m"},
		"afId without Ua* id":      {"AFID": "af1.akma.example"},
		"afId with 9 hex digits":   {"AFID": "af1.akma.example.FF0000001"},
		"source address not an IP": {"ADDR": "af1.akma.example"},
		"no source address":        {"ADDR": ""},
		"NEF address not an IP":    {"NEFADDR": "nef.example"},
		"NEF without address":      {"NEFADDR": ""},
		"NEF without AF_ID":        {"NEFAFIDS": ""},
		"NEF AF_ID without Ua* id": {"NEFAFIDS": "af1.akma.example"},
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ReadConfig(writeConfig(t, p)); err == nil {
				t.Error("invalid configuration accepted")
			}
		})
	}
}

// The sample configuration of the repository is valid.
func TestSampleConfig(t *testing.T) {
	cfg, err := ReadConfig("../../../config/aanfcfg.yaml")
	if err != nil {
		t.Fatalf("free5gc/config/aanfcfg.yaml: %v", err)
	}
	c := cfg.Configuration
	if c.NfInstanceId != "b6f417f0-06fa-4c38-b291-33066f5a5fe7" {
		t.Errorf("nfInstanceId = %s", c.NfInstanceId)
	}
	if strings.Join(c.RoutingIndicators, ",") != "0000" || len(c.Akma.AuthorizedAfs) != 1 ||
		len(c.Akma.AuthorizedNefs) != 1 || c.Sbi.Port != 8010 {
		t.Errorf("configuration = %+v", c)
	}
}
