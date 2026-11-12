package capif

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/free5gc/openapi/models"
)

// chooseAEF returns the apiRoot and the AEF of the first AEF profile of the
// AKMA API that offers OAUTH (TS 33.122 cl. 6.5.2.3). The security methods
// of an interface take precedence over those of its profile (TS 29.222
// table 8.2.4.2.3-1). The apiRoot is built from the interface description,
// or else from the domain name (TS 29.222 cl. 5.2.2.2.2 NOTE), as
// TS 29.501 cl. 4.4.1 describes it, with scheme.
func chooseAEF(apis []models.CapifServiceApiDescription, scheme string) (apiRoot, aefID string, err error) {
	oauth := func(methods []models.CapifSecurityMethod) bool {
		return slices.Contains(methods, models.CapifSecurityMethod_OAUTH)
	}
	for _, api := range apis {
		if api.ApiName != AkmaAPI {
			continue
		}
		for _, p := range api.AefProfiles {
			for _, in := range p.InterfaceDescriptions {
				methods := in.SecurityMethods
				if len(methods) == 0 {
					methods = p.SecurityMethods
				}
				if !oauth(methods) {
					continue
				}
				root, err := interfaceAPIRoot(scheme, in)
				if err != nil {
					return "", "", fmt.Errorf("AEF %s: %w", p.AefId, err)
				}
				return root, p.AefId, nil
			}
			if len(p.InterfaceDescriptions) == 0 && p.DomainName != "" && oauth(p.SecurityMethods) {
				return strings.TrimRight(scheme+"://"+p.DomainName, "/"), p.AefId, nil
			}
		}
	}
	return "", "", fmt.Errorf("no %s with the OAUTH security method at the CCF", AkmaAPI)
}

// interfaceAPIRoot builds "<scheme>://<address>[:<port>][<apiPrefix>]" from
// an interface description (TS 29.222 table 8.2.4.2.3-1, NOTE 2).
func interfaceAPIRoot(scheme string, in models.CapifInterfaceDescription) (string, error) {
	var host string
	switch {
	case in.Ipv4Addr != "":
		host = in.Ipv4Addr
	case in.Ipv6Addr != "":
		host = in.Ipv6Addr
	case in.Fqdn != "":
		host = in.Fqdn
	default:
		return "", errors.New("interface description without address")
	}
	if in.Port != 0 {
		host = net.JoinHostPort(host, strconv.Itoa(int(in.Port)))
	} else if in.Ipv6Addr != "" {
		host = "[" + host + "]"
	}
	if in.ApiPrefix != "" && !strings.HasPrefix(in.ApiPrefix, "/") {
		return "", fmt.Errorf("apiPrefix %q does not start with /", in.ApiPrefix)
	}
	u := url.URL{Scheme: scheme, Host: host, Path: in.ApiPrefix}
	return strings.TrimRight(u.String(), "/"), nil
}
