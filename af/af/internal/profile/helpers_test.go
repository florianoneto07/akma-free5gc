package profile

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/florianoneto07/akma-free5gc/af/af/internal/aanf"
	"github.com/florianoneto07/akma-free5gc/af/af/internal/config"
	"github.com/florianoneto07/akma-free5gc/af/af/internal/server"
	"github.com/florianoneto07/akma-free5gc/af/akmatls"
	"github.com/florianoneto07/akma-free5gc/af/ue/uaclient"
	"github.com/florianoneto07/akma-free5gc/shared/akma/afid"
	"github.com/florianoneto07/akma-free5gc/shared/akma/kdf"
)

const (
	fqdn    = "af1.akma.example"
	theAKid = "rid0000.atidiz1FN8DkMGyxwtfTVYsKUsWnzOJdBOLlQEiQlK2gHNA=@5gc.mnc093.mcc208.3gppnetwork.org"
)

// keys plays the AAnF: one K_AF per AF_ID, as the KDF gives (TS 33.535 A.4).
type keys struct {
	mu     sync.Mutex
	asked  []string
	expiry time.Duration
}

func kafOf(afID string) kdf.Key {
	var k kdf.Key
	copy(k[:], afID)
	return k
}

func (k *keys) ApplicationKey(_ context.Context, id afid.AfID, aKid string) (aanf.Key, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.asked = append(k.asked, id.Transport())
	if aKid != theAKid {
		return aanf.Key{}, aanf.ErrKeyNotAvailable
	}
	return aanf.Key{KAf: kafOf(id.Transport()), Expiry: time.Now().Add(k.expiry)}, nil
}

func (k *keys) list() []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]string(nil), k.asked...)
}

// ue is the key service of the ME for one A-KID.
func ue(aKid string) uaclient.KeySource {
	return func(_ context.Context, id afid.UaStarID) (string, kdf.Key, error) {
		return aKid, kafOf(fqdn + "." + id.String()), nil
	}
}

func startAF(t *testing.T, typ string, expiry time.Duration) (string, *keys) {
	t.Helper()
	var addr string
	if akmatls.IsUDP(typ) {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr = pc.LocalAddr().String()
		pc.Close()
	} else {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr = l.Addr().String()
		l.Close()
	}
	c := config.Config{Configuration: config.Configuration{
		FQDN: fqdn, AanfURI: "http://127.0.0.1:1", Profiles: []config.Profile{{Type: typ, Listen: addr}},
	}}
	s, err := c.Settings()
	if err != nil {
		t.Fatal(err)
	}
	k := &keys{expiry: expiry}
	r, err := Start(s.Profiles[0], s, server.New(s, k))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Shutdown(context.Background()) })
	return addr, k
}
