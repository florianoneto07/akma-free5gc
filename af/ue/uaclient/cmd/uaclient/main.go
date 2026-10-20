// Command uaclient establishes an application session with the AF over the
// simplified Ua* protocol of package uastar. The A-KID and K_AF come
// from the ME of UERANSIM through nr-cli (-nr-cli, -ue), from a shared/akma
// vector (-vector) or from the command line. K_AF is never printed.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/florianoneto07/akma-free5gc/af/ue/uaclient"
	"github.com/florianoneto07/akma-free5gc/shared/akma/codec"
	"github.com/florianoneto07/akma-free5gc/shared/akma/kdf"
)

func main() {
	var (
		fqdn      = flag.String("fqdn", "af1.akma.example", "FQDN of the AF (sent in Host, checked in the realm)")
		connect   = flag.String("connect", "192.168.16.129:8080", "address of the AF")
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
		nrCli     = flag.String("nr-cli", "", "nr-cli of UERANSIM: take A-KID and K_AF from the ME")
		ue        = flag.String("ue", "", "UE node name for nr-cli (e.g. imsi-208930000000001)")
		uaStarID  = flag.String("ua-star-id", "FF00000001", "Ua* security protocol identifier")
	)
	flag.Parse()
	o := options{
		fqdn: *fqdn, connect: *connect, path: *path, aKid: *aKid, kafHex: *kafHex, kafB64: *kafB64, kafFile: *kafFile,
		vector: *vector, vectors: *vectors, qop: *qop, userAgent: *userAgent, count: *count,
		bind: *bind, nrCli: *nrCli, ue: *ue, uaStarID: *uaStarID,
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
	bind, nrCli, ue, uaStarID                                                           string
}

func run(o options) error {
	var kaf kdf.Key
	var err error
	aKid := o.aKid
	// An explicit key or vector takes precedence over the ME, so that a test
	// can present an earlier A-KID and K_AF from the namespace of the UE.
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
			return errors.New("-ue is required with -nr-cli")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		aKid, kaf, err = uaclient.FromME(ctx, o.nrCli, o.ue, o.fqdn, o.uaStarID)
		cancel()
		if err == nil {
			fmt.Printf("ME: K_AF derived for AF_ID %s.%s\n", o.fqdn, o.uaStarID)
		}
	default:
		err = errors.New("give -nr-cli, -vector, -kaf, -kaf-base64 or -kaf-file")
	}
	if err != nil {
		return err
	}
	if aKid == "" {
		return errors.New("-akid is required")
	}
	s, err := uaclient.NewSession(uaclient.Config{
		FQDN: o.fqdn, Connect: o.connect, Path: o.path, AKID: aKid, KAf: kaf, Qop: o.qop, UserAgent: o.userAgent,
		LocalAddr: o.bind,
	})
	if err != nil {
		return err
	}
	from := ""
	if o.bind != "" {
		from = " from " + o.bind
	}
	fmt.Printf("AF %s at %s%s, A-KID %s\n", o.fqdn, o.connect, from, aKid)
	for i := 0; i < o.count; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		r, err := s.Establish(ctx)
		cancel()
		if err != nil {
			return err
		}
		fmt.Printf("session established (nc %s): AF authenticated by rspauth; K_AF valid until %s\n",
			r.NC, r.KafExpiry.Format(time.RFC3339))
	}
	return nil
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
