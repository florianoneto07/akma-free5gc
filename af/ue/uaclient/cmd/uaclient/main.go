// Command uaclient establishes an application session with the AF over a
// Ua* profile (-profile): HTTP Digest inside TLS (digest-tls, TS 24.109
// K.2); TLS 1.3 or TLS 1.2 with K_AF as pre-shared key (psk-tls13 and
// psk-tls12, K.3); DTLS 1.3 or DTLS 1.2 with K_AF as pre-shared key and
// CoAP inside (psk-dtls13 and psk-dtls12, TS 33.535 Annex C); the PSK
// profiles in a client built with wolfSSL; CoAP protected by OSCORE with a
// context from K_AF (oscore, Annex D); or the simplified Ua* protocol of
// package uastar (digest-http, test only). The A-KID and K_AF
// come from the AKMA key service of the ME of UERANSIM (-me-socket), from
// nr-cli for tests (-nr-cli, -ue), from a shared/akma vector (-vector) or
// from the command line. K_AF is never printed.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/florianoneto07/akma-free5gc/af/akmatls"
	"github.com/florianoneto07/akma-free5gc/af/ue/uaclient"
	"github.com/florianoneto07/akma-free5gc/shared/akma/afid"
	"github.com/florianoneto07/akma-free5gc/shared/akma/codec"
	"github.com/florianoneto07/akma-free5gc/shared/akma/kdf"
)

// defaultPorts are the ports of the profiles in af/config/afcfg.yaml.
var defaultPorts = map[string]string{
	akmatls.ProfileDigestHTTP: "8080",
	akmatls.ProfileDigestTLS:  "8443",
	akmatls.ProfilePSKTLS13:   "8444",
	akmatls.ProfilePSKTLS12:   "8445",
	akmatls.ProfilePSKDTLS13:  "5684",
	akmatls.ProfilePSKDTLS12:  "5685",
	akmatls.ProfileOSCORE:     "5683",
}

const profiles = "digest-tls, psk-tls13, psk-tls12, psk-dtls13, psk-dtls12, oscore or digest-http"

func main() {
	var (
		fqdn      = flag.String("fqdn", "af1.akma.example", "FQDN of the AF (sent in Host, checked in the realm)")
		profile   = flag.String("profile", akmatls.ProfileDigestHTTP, "Ua* profile: "+profiles)
		connect   = flag.String("connect", "192.168.16.129", "address of the AF, with the port of the profile when absent")
		caFile    = flag.String("ca", "", "certificate of the CA of the AF, PEM (digest-tls)")
		reconnect = flag.Bool("reconnect", false, "a new TLS connection or DTLS association for each request, resuming the previous session; oscore: a new POST /akma for each request")
		rekey     = flag.Bool("rekey", false, "oscore: renew the security context before each request (RFC 8613 Appendix B.2)")
		tls12     = flag.Bool("tls12", false, "digest-tls: TLS 1.2 only")
		pskKEOnly = flag.Bool("psk-ke-only", false, "psk-tls13, psk-dtls13: offer psk_ke and not psk_dhe_ke (test only; the AF refuses it)")
		path      = flag.String("path", "/ua/v1/session", "protected resource")
		aKid      = flag.String("akid", "", "A-KID")
		kafHex    = flag.String("kaf", "", "K_AF, 64 hexadecimal characters")
		kafB64    = flag.String("kaf-base64", "", "K_AF in base64")
		kafFile   = flag.String("kaf-file", "", "file holding K_AF, 64 hexadecimal characters")
		vector    = flag.String("vector", "", "take A-KID and K_AF from this vector of -vectors")
		vectors   = flag.String("vectors", "shared/akma/testdata/vectors.json", "vectors file of shared/akma")
		qop       = flag.String("qop", "auth", "qop: auth or auth-int")
		count     = flag.Int("n", 1, "number of requests in the session")
		userAgent = flag.String("user-agent", uaclient.DefaultUserAgent, "User-Agent")
		bind      = flag.String("bind", "", "source address, e.g. the address of the PDU session on uesimtun0")
		meSocket  = flag.String("me-socket", "", "AKMA key service of the ME: take A-KID and K_AF from it")
		nrCli     = flag.String("nr-cli", "", "nr-cli of UERANSIM: take A-KID and K_AF from the ME (test only, akmaCliKaf)")
		ue        = flag.String("ue", "", "UE node name for nr-cli (e.g. imsi-208930000000001)")
		uaStarID  = flag.String("ua-star-id", "FF00000001", "Ua* security protocol identifier of digest-http")
	)
	flag.Parse()
	o := options{
		fqdn: *fqdn, connect: *connect, path: *path, aKid: *aKid, kafHex: *kafHex, kafB64: *kafB64, kafFile: *kafFile,
		vector: *vector, vectors: *vectors, qop: *qop, userAgent: *userAgent, count: *count,
		bind: *bind, meSocket: *meSocket, nrCli: *nrCli, ue: *ue, uaStarID: *uaStarID,
		profile: *profile, caFile: *caFile, reconnect: *reconnect, pskKEOnly: *pskKEOnly, tls12: *tls12,
		rekey: *rekey,
	}
	if err := run(o); err != nil {
		msg := err.Error()
		if !strings.HasPrefix(msg, "uaclient:") {
			msg = "uaclient: " + msg
		}
		fmt.Fprintln(os.Stderr, msg)
		os.Exit(1)
	}
}

type options struct {
	fqdn, connect, path, aKid, kafHex, kafB64, kafFile, vector, vectors, qop, userAgent string
	count                                                                               int
	bind, meSocket, nrCli, ue, uaStarID, profile, caFile                                string
	reconnect, pskKEOnly, tls12, rekey                                                  bool
}

// session is a Digest or a PSK session.
type session interface {
	Establish(ctx context.Context) (uaclient.Result, error)
}

func run(o options) error {
	keys, err := keySource(o)
	if err != nil {
		return err
	}
	if _, _, err := net.SplitHostPort(o.connect); err != nil {
		port, ok := defaultPorts[o.profile]
		if !ok {
			return fmt.Errorf("-profile %q is not %s", o.profile, profiles)
		}
		o.connect = net.JoinHostPort(o.connect, port)
	}
	var s session
	switch o.profile {
	case akmatls.ProfileDigestHTTP, akmatls.ProfileDigestTLS:
		cfg := uaclient.Config{
			FQDN: o.fqdn, Connect: o.connect, Path: o.path, Keys: keys, Qop: o.qop, UserAgent: o.userAgent,
			LocalAddr: o.bind, Reconnect: o.reconnect,
		}
		if cfg.UaStarID, err = parseUaStarID(o.uaStarID); err != nil {
			return err
		}
		if o.profile == akmatls.ProfileDigestTLS {
			if cfg.TLS, err = k2Config(o); err != nil {
				return err
			}
		}
		if s, err = uaclient.NewSession(cfg); err != nil {
			return err
		}
	case akmatls.ProfilePSKTLS13, akmatls.ProfilePSKTLS12:
		ps, err := uaclient.NewPSKSession(uaclient.PSKConfig{
			Profile: o.profile, FQDN: o.fqdn, Connect: o.connect, Path: o.path, UserAgent: o.userAgent,
			LocalAddr: o.bind, Keys: keys, Reconnect: o.reconnect, OfferPSKKEOnly: o.pskKEOnly,
		})
		if err != nil {
			return err
		}
		defer ps.Close()
		s = ps
	case akmatls.ProfilePSKDTLS13, akmatls.ProfilePSKDTLS12:
		ds, err := uaclient.NewDTLSSession(uaclient.PSKConfig{
			Profile: o.profile, FQDN: o.fqdn, Connect: o.connect, Path: o.path, LocalAddr: o.bind, Keys: keys,
			Reconnect: o.reconnect, OfferPSKKEOnly: o.pskKEOnly,
		})
		if err != nil {
			return err
		}
		defer ds.Close()
		s = ds
	case akmatls.ProfileOSCORE:
		oc, err := uaclient.NewOSCORESession(uaclient.PSKConfig{
			Profile: o.profile, FQDN: o.fqdn, Connect: o.connect, Path: o.path, LocalAddr: o.bind, Keys: keys,
			Reconnect: o.reconnect, Renew: o.rekey,
		})
		if err != nil {
			return err
		}
		defer oc.Close()
		s = oc
	default:
		return fmt.Errorf("-profile %q is not %s", o.profile, profiles)
	}
	from := ""
	if o.bind != "" {
		from = " from " + o.bind
	}
	fmt.Printf("AF %s at %s%s, profile %s\n", o.fqdn, o.connect, from, o.profile)
	for i := 0; i < o.count; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		r, err := s.Establish(ctx)
		cancel()
		if err != nil {
			return err
		}
		fmt.Println(describe(o.profile, r))
	}
	return nil
}

// describe reports a successful response. The A-KID is printed: it is not
// a key.
func describe(profile string, r uaclient.Result) string {
	tlsState := ""
	if r.TLSVersion != 0 {
		tlsState = fmt.Sprintf("; %s, cipher suite %04X", versionName(r.TLSVersion), r.CipherSuite)
		switch {
		case profile == akmatls.ProfileDigestTLS:
			tlsState += fmt.Sprintf(", resumed %t", r.Resumed)
		case r.TLSVersion == tls.VersionTLS12 || r.TLSVersion == dtls12:
			tlsState += fmt.Sprintf(", resumed %t", r.Resumed)
		case r.Resumed:
			// wolfSSL reports an offered (D)TLS 1.3 ticket as resumed:
			// the AF log tells whether the AF accepted it.
			tlsState += ", session ticket offered"
		}
	}
	auth := "AF authenticated by rspauth"
	switch {
	case profile == akmatls.ProfileOSCORE:
		auth = "AF authenticated by the OSCORE context from K_AF"
		if r.IDContext != nil {
			tlsState = fmt.Sprintf("; context renewed, ID Context %x", r.IDContext)
		}
	case akmatls.IsDTLS(profile):
		auth = "AF authenticated by the DTLS handshake with K_AF"
	case r.NC == "":
		auth = "AF authenticated by the TLS handshake with K_AF"
	}
	nc := ""
	if r.NC != "" {
		nc = " (nc " + r.NC + ")"
	}
	return fmt.Sprintf("session established%s: %s; A-KID %s; AF_ID %s%s; K_AF valid until %s", nc, auth,
		r.AKid, r.AfID, tlsState, r.KafExpiry.Format(time.RFC3339))
}

// DTLS versions, as wolfSSL gives them.
const (
	dtls12 = 0xFEFD
	dtls13 = 0xFEFC
)

func versionName(v uint16) string {
	switch v {
	case dtls12:
		return "DTLS 1.2"
	case dtls13:
		return "DTLS 1.3"
	}
	return tls.VersionName(v)
}

// keySource returns where the A-KID and K_AF come from. An explicit key or
// vector takes precedence over the ME, so that a test can present an earlier
// A-KID and K_AF from the namespace of the UE; and an explicit -nr-cli (test
// only) over the -me-socket that ue-netns.sh always passes.
func keySource(o options) (uaclient.KeySource, error) {
	var kaf kdf.Key
	var err error
	aKid := o.aKid
	fixed := true
	switch {
	case o.kafHex != "":
		kaf, err = codec.ParseHexKey(o.kafHex)
	case o.kafB64 != "":
		kaf, err = parseBase64Key(o.kafB64)
	case o.kafFile != "":
		var raw []byte
		if raw, err = os.ReadFile(o.kafFile); err == nil {
			kaf, err = codec.ParseHexKey(strings.TrimSpace(string(raw)))
		}
	case o.vector != "":
		aKid, kaf, err = fromVector(o.vectors, o.vector)
	case o.nrCli != "":
		if o.ue == "" {
			return nil, errors.New("-ue is required with -nr-cli")
		}
		fixed = false
	case o.meSocket != "":
		fixed = false
	default:
		return nil, errors.New("give -me-socket, -nr-cli, -vector, -kaf, -kaf-base64 or -kaf-file")
	}
	if err != nil {
		return nil, err
	}
	if fixed {
		if aKid == "" {
			return nil, errors.New("-akid is required")
		}
		return func(context.Context, afid.UaStarID) (string, kdf.Key, error) { return aKid, kaf, nil }, nil
	}
	return func(ctx context.Context, id afid.UaStarID) (string, kdf.Key, error) {
		var aKid string
		var kaf kdf.Key
		var err error
		if o.nrCli != "" {
			aKid, kaf, err = uaclient.FromME(ctx, o.nrCli, o.ue, o.fqdn, id.String())
		} else {
			aKid, kaf, err = uaclient.FromKeyService(ctx, o.meSocket, o.fqdn, id.String())
		}
		if err == nil {
			fmt.Printf("ME: K_AF derived for AF_ID %s.%s\n", o.fqdn, id)
		}
		return aKid, kaf, err
	}, nil
}

// k2Config returns the TLS configuration of digest-tls: the certificate of
// the AF must chain to -ca and name the FQDN of the AF (TS 33.222
// cl. 5.3.1.3).
func k2Config(o options) (*tls.Config, error) {
	if o.caFile == "" {
		return nil, errors.New("-ca is required with -profile digest-tls")
	}
	pem, err := os.ReadFile(o.caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s: no PEM certificate", o.caFile)
	}
	cfg := akmatls.ClientConfig(o.fqdn, pool)
	cfg.ClientSessionCache = tls.NewLRUClientSessionCache(1)
	if o.tls12 {
		cfg.MaxVersion = tls.VersionTLS12
	}
	return cfg, nil
}

func parseUaStarID(s string) (afid.UaStarID, error) {
	var id afid.UaStarID
	a, err := afid.Parse("x." + s)
	if err != nil {
		return id, fmt.Errorf("-ua-star-id: %q is not ten hexadecimal digits", s)
	}
	return a.Protocol, nil
}

func fromVector(path, name string) (string, kdf.Key, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", kdf.Key{}, err
	}
	var doc struct {
		Vectors []struct {
			Name string `json:"name"`
			AKid struct {
				Base64 string `json:"base64"`
			} `json:"a_kid"`
			KAf string `json:"k_af"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return "", kdf.Key{}, err
	}
	for _, v := range doc.Vectors {
		if v.Name == name {
			k, err := codec.ParseHexKey(v.KAf)
			return v.AKid.Base64, k, err
		}
	}
	return "", kdf.Key{}, fmt.Errorf("vector %q not in %s", name, path)
}

func parseBase64Key(s string) (kdf.Key, error) {
	var k kdf.Key
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != len(k) {
		return k, errors.New("-kaf-base64: not 32 octets in base64")
	}
	copy(k[:], b)
	return k, nil
}
