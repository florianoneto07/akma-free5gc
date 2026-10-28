//go:build wolfssl

package profile

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/florianoneto07/akma-free5gc/af/af/internal/config"
	"github.com/florianoneto07/akma-free5gc/af/af/internal/server"
	"github.com/florianoneto07/akma-free5gc/af/akmatls"
	"github.com/florianoneto07/akma-free5gc/af/ue/uaclient"
	"github.com/florianoneto07/akma-free5gc/shared/akma/afid"
	"github.com/florianoneto07/akma-free5gc/shared/akma/kdf"
)

// establisher is a PSK TLS or DTLS session of the client.
type establisher interface {
	Establish(context.Context) (uaclient.Result, error)
	Close()
}

func session(t *testing.T, typ, addr string, src uaclient.KeySource, mod func(*uaclient.PSKConfig)) establisher {
	t.Helper()
	cfg := uaclient.PSKConfig{Profile: typ, FQDN: fqdn, Connect: addr, Path: config.DefaultPath, Keys: src}
	if mod != nil {
		mod(&cfg)
	}
	var s establisher
	var err error
	if akmatls.IsDTLS(typ) {
		s, err = uaclient.NewDTLSSession(cfg)
	} else {
		s, err = uaclient.NewPSKSession(cfg)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// short is a context for the handshakes that must fail: a DTLS peer drops a
// record it cannot decrypt, and the client waits until its deadline.
func short(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// TS 24.109 K.3.3 and K.3.2: the session over each PSK profile, with the
// AF_ID of TS 33.220 H.3, and resumed on a new connection.
func TestPSKProfiles(t *testing.T) {
	for _, tc := range []struct{ typ, afID string }{
		{akmatls.ProfilePSKTLS13, fqdn + ".0100000007"},
		{akmatls.ProfilePSKTLS12, fqdn + ".010001D001"},
		{akmatls.ProfilePSKDTLS13, fqdn + ".0100000009"},
		{akmatls.ProfilePSKDTLS12, fqdn + ".010001D001"},
	} {
		t.Run(tc.typ, func(t *testing.T) {
			addr, k := startAF(t, tc.typ, time.Hour)
			s := session(t, tc.typ, addr, ue(theAKid), func(c *uaclient.PSKConfig) { c.Reconnect = true })
			for i := range 2 {
				r, err := s.Establish(context.Background())
				if err != nil {
					t.Fatalf("request %d: %v", i, err)
				}
				if r.AKid != theAKid || r.AfID != tc.afID || r.NC != "" {
					t.Fatalf("request %d: %+v", i, r)
				}
			}
			// One request to the AAnF: the second connection resumed.
			if got := k.list(); len(got) != 1 || got[0] != tc.afID {
				t.Fatalf("AF_IDs at the AAnF %v, want [%s]", got, tc.afID)
			}
		})
	}
}

func TestPSKRefused(t *testing.T) {
	for _, typ := range []string{akmatls.ProfilePSKTLS13, akmatls.ProfilePSKTLS12, akmatls.ProfilePSKDTLS13,
		akmatls.ProfilePSKDTLS12} {
		t.Run(typ, func(t *testing.T) {
			addr, _ := startAF(t, typ, time.Hour)
			// A-KID unknown to the AAnF.
			if _, err := session(t, typ, addr, ue("rid0000.other@5gc.mnc093.mcc208.3gppnetwork.org"), nil).
				Establish(short(t)); err == nil {
				t.Error("unknown A-KID accepted")
			}
			// K_AF of another AF_ID.
			wrong := func(context.Context, afid.UaStarID) (string, kdf.Key, error) {
				return theAKid, kafOf(fqdn + ".FF00000001"), nil
			}
			if _, err := session(t, typ, addr, wrong, nil).Establish(short(t)); err == nil {
				t.Error("wrong K_AF accepted")
			}
		})
	}
	for _, typ := range []string{akmatls.ProfilePSKTLS13, akmatls.ProfilePSKDTLS13} {
		addr, _ := startAF(t, typ, time.Hour)
		s := session(t, typ, addr, ue(theAKid), func(c *uaclient.PSKConfig) { c.OfferPSKKEOnly = true })
		if _, err := s.Establish(short(t)); err == nil {
			t.Errorf("%s: psk_ke accepted (TS 33.210 cl. 6.2.2)", typ)
		}
	}
}

// TS 33.535 cl. 6.4.2: the AF closes the TLS session when K_AF expires; the
// next one gets a new K_AF from the AAnF (policy refetch).
func TestPSKExpiry(t *testing.T) {
	for _, typ := range []string{akmatls.ProfilePSKTLS13, akmatls.ProfilePSKDTLS13} {
		t.Run(typ, func(t *testing.T) {
			addr, k := startAF(t, typ, 1500*time.Millisecond)
			s := session(t, typ, addr, ue(theAKid), nil)
			if _, err := s.Establish(context.Background()); err != nil {
				t.Fatal(err)
			}
			time.Sleep(2 * time.Second)
			if _, err := s.Establish(context.Background()); err != nil {
				t.Fatal(err)
			}
			if n := len(k.list()); n != 2 {
				t.Fatalf("%d requests to the AAnF, want 2", n)
			}
		})
	}
}

func TestStartErrors(t *testing.T) {
	c := config.Config{Configuration: config.Configuration{
		FQDN: fqdn, AanfURI: "http://127.0.0.1:1",
		Profiles: []config.Profile{{Type: akmatls.ProfileDigestTLS, Listen: "127.0.0.1:0", Certificate: "none.pem",
			Key: "none.key"}},
	}}
	s, err := c.Settings()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Start(s.Profiles[0], s, server.New(s, &keys{})); err == nil || !strings.Contains(err.Error(), "none.pem") {
		t.Fatalf("err = %v", err)
	}
}
