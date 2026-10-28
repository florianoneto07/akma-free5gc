package profile

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/florianoneto07/akma-free5gc/af/af/internal/config"
	"github.com/florianoneto07/akma-free5gc/af/akmatls"
	"github.com/florianoneto07/akma-free5gc/af/coap"
	"github.com/florianoneto07/akma-free5gc/af/oscore"
	"github.com/florianoneto07/akma-free5gc/af/ue/uaclient"
	"github.com/florianoneto07/akma-free5gc/shared/akma/afid"
	"github.com/florianoneto07/akma-free5gc/shared/akma/kdf"
)

func oscoreSession(t *testing.T, addr string, src uaclient.KeySource, mod func(*uaclient.PSKConfig)) *uaclient.OSCORESession {
	t.Helper()
	cfg := uaclient.PSKConfig{Profile: akmatls.ProfileOSCORE, FQDN: fqdn, Connect: addr, Path: config.DefaultPath,
		Keys: src}
	if mod != nil {
		mod(&cfg)
	}
	s, err := uaclient.NewOSCORESession(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func ctx5(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// TS 33.535 Annex D: POST /akma once, then requests protected with the
// context; a renewal by RFC 8613 Appendix B.2; a new POST for each request
// with Reconnect.
func TestOSCOREProfile(t *testing.T) {
	addr, k := startAF(t, akmatls.ProfileOSCORE, time.Hour)
	s := oscoreSession(t, addr, ue(theAKid), nil)
	for i := range 3 {
		r, err := s.Establish(ctx5(t))
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		if r.AKid != theAKid || r.AfID != fqdn+".0100000008" || r.IDContext != nil {
			t.Fatalf("request %d: %+v", i, r)
		}
	}
	if got := k.list(); !slices.Equal(got, []string{fqdn + ".0100000008"}) {
		t.Fatalf("AAnF asked for %v", got)
	}

	renew := oscoreSession(t, addr, ue(theAKid), func(c *uaclient.PSKConfig) { c.Renew = true })
	var last []byte
	for i := range 2 {
		r, err := renew.Establish(ctx5(t))
		if err != nil {
			t.Fatalf("renewal %d: %v", i, err)
		}
		if len(r.IDContext) != 16 || string(r.IDContext) == string(last) {
			t.Fatalf("renewal %d: ID Context %x", i, r.IDContext)
		}
		last = r.IDContext
	}

	again := oscoreSession(t, addr, ue(theAKid), func(c *uaclient.PSKConfig) { c.Reconnect = true })
	for range 2 {
		if _, err := again.Establish(ctx5(t)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestOSCORERefused(t *testing.T) {
	addr, _ := startAF(t, akmatls.ProfileOSCORE, time.Hour)
	var rej *uaclient.RejectedError
	unknown := "rid0000.atidCMNGM3f5wGdrrXvlGa0krmGw1U/8S0poB5Gito498cI=@5gc.mnc093.mcc208.3gppnetwork.org"
	if _, err := oscoreSession(t, addr, ue(unknown), nil).Establish(ctx5(t)); !errors.As(err, &rej) ||
		rej.CoAP != "4.03" || rej.Cause != "AKMA_KEY_NOT_AVAILABLE" {
		t.Fatalf("unknown A-KID: %v", err)
	}
	// A UE with the K_AF of another AF_ID: the AF cannot decrypt the
	// request (RFC 8613 cl. 8.2).
	other := func(context.Context, afid.UaStarID) (string, kdf.Key, error) {
		return theAKid, kafOf(fqdn + ".0100000007"), nil
	}
	var ue *oscore.UnprotectedError
	if _, err := oscoreSession(t, addr, other, nil).Establish(ctx5(t)); !errors.As(err, &ue) ||
		ue.Code != coap.BadRequest || ue.Diagnostic != "Decryption failed" {
		t.Fatalf("other K_AF: %v", err)
	}
}

// TS 33.535 cl. 6.4.2: at the expiry of K_AF the AF drops the context; the
// next request gets 4.01, and the UE establishes a new one, with a K_AF the
// AF requests again (policy refetch).
func TestOSCOREExpiry(t *testing.T) {
	addr, k := startAF(t, akmatls.ProfileOSCORE, 1500*time.Millisecond)
	s := oscoreSession(t, addr, ue(theAKid), nil)
	if _, err := s.Establish(ctx5(t)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second)
	if _, err := s.Establish(ctx5(t)); err != nil {
		t.Fatalf("after the expiry: %v", err)
	}
	if n := len(k.list()); n != 2 {
		t.Fatalf("AAnF asked %d times, want 2", n)
	}
}

// An independent client: coap-client of libcoap, given in LIBCOAP_CLIENT,
// with the request and the context computed by af/scripts/oscore-check.py,
// which shares no code with the AF.
func TestLibcoapClient(t *testing.T) {
	client := os.Getenv("LIBCOAP_CLIENT")
	if client == "" {
		t.Skip("LIBCOAP_CLIENT not set")
	}
	addr, _ := startAF(t, akmatls.ProfileOSCORE, time.Hour)
	kaf := kafOf(fqdn + ".0100000008")
	run := func(extra ...string) string {
		args := append([]string{"-I", "../../../scripts/oscore-check.py", "--coap-client", client, "--af", addr,
			"--fqdn", fqdn, "--akid", theAKid, "--kaf", hex.EncodeToString(kaf[:]), "--dir", t.TempDir()}, extra...)
		out, err := exec.Command("python3", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("oscore-check.py: %v\n%s", err, out)
		}
		return string(out)
	}
	if out := run(); !strings.Contains(out, `"aKid":"`+theAKid+`"`) {
		t.Fatalf("protected GET: %s", out)
	}
	if out := run("--osc-inp-alg", "11"); !strings.Contains(out, "4.00") || !strings.Contains(out, "OSC_INP_NOT_SUPPORTED") {
		t.Fatalf("OSC-INP with another algorithm: %s", out)
	}
}
