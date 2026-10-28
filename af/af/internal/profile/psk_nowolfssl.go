//go:build !wolfssl

package profile

import (
	"context"
	"fmt"
	"net"

	"github.com/florianoneto07/akma-free5gc/af/af/internal/config"
	"github.com/florianoneto07/akma-free5gc/af/af/internal/server"
)

// Built is false: this AF has no PSK profiles.
const Built = false

func pskListener(p config.Profile, _ *config.Settings, _ *server.Server, _ net.Listener) (net.Listener,
	func(context.Context, net.Conn) context.Context, func(), error) {
	return nil, nil, nil, fmt.Errorf("profile %s needs an AF built with wolfSSL (af/scripts/build-wolfssl.sh, "+
		"then af/scripts/build-af.sh)", p.Type)
}

func startDTLS(p config.Profile, _ *config.Settings, _ *server.Server) (func(), error) {
	return nil, fmt.Errorf("profile %s needs an AF built with wolfSSL (af/scripts/build-wolfssl.sh, "+
		"then af/scripts/build-af.sh)", p.Type)
}
