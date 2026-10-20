package uaclient

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/florianoneto07/akma-free5gc/shared/akma/codec"
)

const kafHex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"

func TestParseAkmaKaf(t *testing.T) {
	out := "a-kid: " + testAKid + "\naf-id: af1.akma.example.FF00000001\nk-af: " + kafHex + "\n"
	aKid, kaf, err := ParseAkmaKaf(out)
	if err != nil {
		t.Fatal(err)
	}
	if aKid != testAKid || codec.HexKey(kaf) != kafHex {
		t.Fatalf("got %s %s", aKid, codec.HexKey(kaf))
	}
	// A quoted value, as a YAML dumper may write it.
	if aKid, _, err := ParseAkmaKaf(`a-kid: "` + testAKid + `"` + "\nk-af: '" + kafHex + "'"); err != nil || aKid != testAKid {
		t.Fatalf("quoted: %s, %v", aKid, err)
	}
	for _, bad := range []string{"k-af: " + kafHex, "a-kid: x\nk-af: 12", ""} {
		if _, _, err := ParseAkmaKaf(bad); !errors.Is(err, ErrME) {
			t.Errorf("%q: err = %v", bad, err)
		}
	}
}

// fakeNrCli writes a script that records its arguments and answers like
// nr-cli, or fails like nr-cli when the UE refuses the command.
func fakeNrCli(t *testing.T, answer string, exit int) (path, argsFile string) {
	t.Helper()
	dir := t.TempDir()
	argsFile = filepath.Join(dir, "args")
	path = filepath.Join(dir, "nr-cli")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + argsFile + "\ncat <<'EOF'\n" + answer + "\nEOF\nexit " +
		string(rune('0'+exit)) + "\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path, argsFile
}

func TestFromME(t *testing.T) {
	nrCli, argsFile := fakeNrCli(t, "a-kid: "+testAKid+"\naf-id: af1.akma.example.FF00000001\nk-af: "+kafHex, 0)
	aKid, kaf, err := FromME(context.Background(), nrCli, "imsi-208930000000001", "af1.akma.example", "FF00000001")
	if err != nil {
		t.Fatal(err)
	}
	if aKid != testAKid || codec.HexKey(kaf) != kafHex {
		t.Fatalf("got %s", aKid)
	}
	args, _ := os.ReadFile(argsFile)
	if got := strings.TrimSpace(string(args)); got != "imsi-208930000000001\n-e\nakma-kaf af1.akma.example FF00000001" {
		t.Fatalf("nr-cli arguments:\n%s", got)
	}
}

func TestFromMERefused(t *testing.T) {
	nrCli, _ := fakeNrCli(t, "ERROR: No AKMA key material: no successful primary authentication", 1)
	_, _, err := FromME(context.Background(), nrCli, "imsi-208930000000001", "af1.akma.example", "FF00000001")
	if !errors.Is(err, ErrME) || !strings.Contains(err.Error(), "No AKMA key material") {
		t.Fatalf("err = %v", err)
	}
}

// TestLocalAddr: the connection leaves from the given address, as from the
// address of the PDU session.
func TestLocalAddr(t *testing.T) {
	var remote string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remote, _, _ = net.SplitHostPort(r.RemoteAddr)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()
	s, err := NewSession(Config{
		FQDN: "af1.akma.example", Connect: ts.Listener.Addr().String(), Path: "/ua/v1/session", LocalAddr: "127.0.0.2",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = s.Establish(context.Background())
	if remote != "127.0.0.2" {
		t.Fatalf("request from %s", remote)
	}
	if _, err := NewSession(Config{FQDN: "x", Connect: "127.0.0.1:1", Path: "/", LocalAddr: "uesimtun0"}); err == nil {
		t.Fatal("interface name accepted as address")
	}
}
