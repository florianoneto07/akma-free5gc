package uaclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/florianoneto07/akma-free5gc/shared/akma/codec"
	"github.com/florianoneto07/akma-free5gc/shared/akma/kdf"
)

// ErrME reports a failure to obtain the A-KID and K_AF from the ME.
var ErrME = errors.New("uaclient: no AKMA key material from the ME")

// FromME asks the ME of UERANSIM, through nr-cli, for the A-KID and the K_AF
// of the AF (TS 33.535 cl. 6.2.1 step 1: "The UE may derive KAF before
// sending the message"). ue is the node name given to nr-cli (the SUPI, as
// "imsi-208930000000001"). K_AKMA never leaves the ME; K_AF travels only on
// the pipe from nr-cli, never on a command line.
func FromME(ctx context.Context, nrCli, ue, fqdn, uaStarID string) (string, kdf.Key, error) {
	cmd := exec.CommandContext(ctx, nrCli, ue, "-e", "akma-kaf "+fqdn+" "+uaStarID)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String() + " " + stdout.String())
		return "", kdf.Key{}, fmt.Errorf("%w: nr-cli: %v: %s", ErrME, err, msg)
	}
	return ParseAkmaKaf(stdout.String())
}

// ParseAkmaKaf reads the answer of the akma-kaf command of nr-cli: YAML
// lines "a-kid: ...", "af-id: ..." and "k-af: ..." (64 hexadecimal
// characters).
func ParseAkmaKaf(out string) (string, kdf.Key, error) {
	fields := make(map[string]string)
	for _, line := range strings.Split(out, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		fields[strings.TrimSpace(key)] = strings.Trim(strings.TrimSpace(value), `"'`)
	}
	aKid := fields["a-kid"]
	if aKid == "" {
		return "", kdf.Key{}, fmt.Errorf("%w: a-kid missing in the nr-cli answer", ErrME)
	}
	kaf, err := codec.ParseHexKey(fields["k-af"])
	if err != nil {
		return "", kdf.Key{}, fmt.Errorf("%w: k-af: %v", ErrME, err)
	}
	return aKid, kaf, nil
}
