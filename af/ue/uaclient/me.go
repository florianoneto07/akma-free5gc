package uaclient

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"

	"github.com/florianoneto07/akma-free5gc/shared/akma/codec"
	"github.com/florianoneto07/akma-free5gc/shared/akma/kdf"
)

// ErrME reports a failure to obtain the A-KID and K_AF from the ME.
var ErrME = errors.New("uaclient: no AKMA key material from the ME")

// ErrNotAuthorized reports that the AKMA key service of the ME refused the
// AF_ID to this application (TS 33.535 cl. 4.4.3).
var ErrNotAuthorized = errors.New("uaclient: application not authorized for this AF_ID by the ME")

// FromKeyService asks the AKMA key service of the ME, on the Unix socket at
// path, for the A-KID and the K_AF of the AF (TS 33.535 cl. 6.2.1 step 1).
// The ME gives an application only the K_AF of its own AF_IDs
// (cl. 4.4.3); K_AKMA never leaves the ME.
func FromKeyService(ctx context.Context, path, fqdn, uaStarID string) (string, kdf.Key, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return "", kdf.Key{}, fmt.Errorf("%w: key service: %v", ErrME, err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	}
	if _, err := fmt.Fprintf(conn, "KAF %s %s\n", fqdn, uaStarID); err != nil {
		return "", kdf.Key{}, fmt.Errorf("%w: key service: %v", ErrME, err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return "", kdf.Key{}, fmt.Errorf("%w: key service: %v", ErrME, err)
	}
	return ParseKeyService(line)
}

// ParseKeyService reads an answer of the AKMA key service of the ME:
// "OK a-kid=<A-KID> af-id=<AF_ID> k-af=<64 hexadecimal characters>" or
// "ERR <cause>".
func ParseKeyService(line string) (string, kdf.Key, error) {
	line = strings.TrimSpace(line)
	if cause, ok := strings.CutPrefix(line, "ERR "); ok {
		if cause == "NOT_AUTHORIZED" {
			return "", kdf.Key{}, ErrNotAuthorized
		}
		return "", kdf.Key{}, fmt.Errorf("%w: key service: %s", ErrME, cause)
	}
	rest, ok := strings.CutPrefix(line, "OK ")
	if !ok {
		return "", kdf.Key{}, fmt.Errorf("%w: key service: unexpected answer", ErrME)
	}
	fields := make(map[string]string)
	for _, f := range strings.Fields(rest) {
		if k, v, ok := strings.Cut(f, "="); ok {
			fields[k] = v
		}
	}
	aKid := fields["a-kid"]
	if aKid == "" {
		return "", kdf.Key{}, fmt.Errorf("%w: a-kid missing in the key service answer", ErrME)
	}
	kaf, err := codec.ParseHexKey(fields["k-af"])
	if err != nil {
		return "", kdf.Key{}, fmt.Errorf("%w: k-af: %v", ErrME, err)
	}
	return aKid, kaf, nil
}

// FromME asks the ME of UERANSIM, through nr-cli, for the A-KID and the K_AF
// of the AF (TS 33.535 cl. 6.2.1 step 1: "The UE may derive KAF before
// sending the message"). ue is the node name given to nr-cli (the SUPI, as
// "imsi-208930000000001"). K_AKMA never leaves the ME; K_AF travels only on
// the pipe from nr-cli, never on a command line. Test only: the ME answers
// akma-kaf only with akmaCliKaf in its configuration; applications use
// FromKeyService.
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
