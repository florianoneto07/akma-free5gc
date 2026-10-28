package uaclient

import (
	"errors"
	"fmt"
)

// PSKConfig describes sessions with the AF authenticated with K_AF: TLS or
// DTLS with K_AF as pre-shared key (TS 24.109 K.3; TS 33.222 cl. 5.4;
// TS 33.535 Annex C), or OSCORE with a context from K_AF (Annex D).
type PSKConfig struct {
	// Profile is akmatls.ProfilePSKTLS13, ProfilePSKTLS12, ProfilePSKDTLS13,
	// ProfilePSKDTLS12 or ProfileOSCORE.
	Profile   string
	FQDN      string // sent in server_name and Host, and the FQDN of the AF_ID
	Connect   string // host:port to connect to
	Path      string
	UserAgent string // default DefaultUserAgent
	LocalAddr string
	// Keys gives the A-KID and K_AF: in TLS 1.3 for 01 00 00 00 07 before
	// the ClientHello; in TLS 1.2 for 01 00 01 and the cipher suite chosen
	// by the AF, after the ServerHello (TS 33.222 cl. 5.4.0.2 NOTE 0).
	Keys KeySource
	// Reconnect opens a new connection for each request, which offers the
	// session of the previous one; with OSCORE, a new POST /akma for each
	// request.
	Reconnect bool
	// OfferPSKKEOnly offers psk_ke and not psk_dhe_ke in TLS 1.3, which
	// TS 33.210 cl. 6.2.2 forbids. Test only.
	OfferPSKKEOnly bool
	// Renew renews the OSCORE context before each request (RFC 8613
	// Appendix B.2; TS 33.535 D.3.4).
	Renew bool
}

// ErrNotPSK reports a handshake that the AF did not complete with the
// AKMA PSK.
var ErrNotPSK = errors.New("uaclient: the AF did not select the AKMA pre-shared key")

// ErrNoWolfSSL reports a client built without wolfSSL.
var ErrNoWolfSSL = errors.New("uaclient: the PSK profiles need a client built with wolfSSL " +
	"(af/scripts/build-wolfssl.sh, then af/scripts/build-af.sh)")

func (c PSKConfig) check() error {
	if c.Keys == nil {
		return errors.New("uaclient: Keys is required")
	}
	if c.FQDN == "" || c.Connect == "" {
		return errors.New("uaclient: FQDN and Connect are required")
	}
	if len(c.Path) == 0 || c.Path[0] != '/' {
		return fmt.Errorf("uaclient: path %q must start with /", c.Path)
	}
	return nil
}
