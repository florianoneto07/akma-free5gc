// Package akmatls holds what the AF and the UE share in the TLS profiles of
// the Ua* reference point (TS 33.535 Annex B; TS 24.109 Annex K; TS 33.222
// cl. 5.3 and 5.4): the names of all the Ua* profiles, the Ua* security
// protocol identifiers of TS 33.220 H.3,
// the PSK identity, and the crypto/tls configuration of the shared key-based
// UE authentication with certificate-based AF authentication (K.2). The PSK
// handshakes themselves are in package wolftls.
package akmatls

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"strings"
	"time"

	"github.com/florianoneto07/akma-free5gc/shared/akma/afid"
)

// Profiles of the Ua* server of the AF and of the client.
const (
	// ProfileDigestTLS is K.2: HTTP Digest inside TLS, the AF
	// authenticated by its certificate (TS 24.109 K.2).
	ProfileDigestTLS = "digest-tls"
	// ProfilePSKTLS13 is K.3 with TLS 1.3 (TS 24.109 K.3.3).
	ProfilePSKTLS13 = "psk-tls13"
	// ProfilePSKTLS12 is K.3 with TLS 1.2 (TS 24.109 K.3.2).
	ProfilePSKTLS12 = "psk-tls12"
	// ProfilePSKDTLS13 is DTLS 1.3 with K_AF as PSK, CoAP inside (TS 33.535
	// Annex C).
	ProfilePSKDTLS13 = "psk-dtls13"
	// ProfilePSKDTLS12 is DTLS 1.2 with K_AF as PSK, with the procedure of
	// TLS 1.2, CoAP inside.
	ProfilePSKDTLS12 = "psk-dtls12"
	// ProfileOSCORE is CoAP protected by OSCORE with a security context from
	// K_AF (TS 33.535 Annex D), over UDP.
	ProfileOSCORE = "oscore"
	// ProfileDigestHTTP is the simplified Ua* protocol of package uastar,
	// HTTP Digest without TLS. Test only.
	ProfileDigestHTTP = "digest-http"
)

// UaStarTLS returns the Ua* security protocol identifier 01 00 01 yy zz of
// a TLS cipher suite: K.2 with TLS 1.2 or 1.3, and K.3 with TLS 1.2
// (TS 33.220 H.3). K.3 with TLS 1.3 has the fixed afid.UaStarTLS13.
func UaStarTLS(cipherSuite uint16) afid.UaStarID {
	id := afid.UaStarID{0x01, 0x00, 0x01}
	binary.BigEndian.PutUint16(id[3:], cipherSuite)
	return id
}

// UaStarDTLS13 is the Ua* security protocol identifier of DTLS 1.3,
// 01 00 00 00 09: the one TS 33.220 H.3 gives to the DTLS of its Annex O,
// which TS 33.535 Annex C takes over for AKMA.
var UaStarDTLS13 = afid.UaStarID{0x01, 0x00, 0x00, 0x00, 0x09}

// UaStarOSCORE is the Ua* security protocol identifier of OSCORE,
// 01 00 00 00 08: the one TS 33.220 H.3 gives to the OSCORE of its Annex
// P, which TS 33.535 Annex D follows (D.1).
var UaStarOSCORE = afid.UaStarID{0x01, 0x00, 0x00, 0x00, 0x08}

// IsDTLS reports whether profile runs over DTLS.
func IsDTLS(profile string) bool { return profile == ProfilePSKDTLS13 || profile == ProfilePSKDTLS12 }

// IsUDP reports whether profile runs over UDP: DTLS or OSCORE.
func IsUDP(profile string) bool { return IsDTLS(profile) || profile == ProfileOSCORE }

// IdentityHint is the psk_identity_hint of the AF in TLS 1.2 (TS 24.109
// K.3.2 d)) and the prefix of the PSK identity.
const IdentityHint = "3GPP-AKMA"

// identityPrefix is the name space and the separator of the PSK identity.
// TS 24.109 K.3.3 1) d) gives ";" for TLS 1.3; K.3.2 e) gives no separator
// for TLS 1.2, and the same one is used.
const identityPrefix = IdentityHint + ";"

// ErrIdentity reports a PSK identity outside the AKMA name space.
var ErrIdentity = errors.New("akmatls: PSK identity is not 3GPP-AKMA;<A-KID>")

// Identity returns the PSK identity of an A-KID: "3GPP-AKMA;<A-KID>".
func Identity(aKid string) string {
	return identityPrefix + aKid
}

// ParseIdentity returns the A-KID of a PSK identity.
func ParseIdentity(s string) (string, error) {
	aKid, ok := strings.CutPrefix(s, identityPrefix)
	if !ok || aKid == "" {
		return "", ErrIdentity
	}
	return aKid, nil
}

// SessionLifetime is the longest a TLS session may be resumed: 24 hours
// (TS 33.222 cl. 5.3.1.5 and 5.4.1.4).
const SessionLifetime = 24 * time.Hour

// TLS12CipherSuites are the TLS 1.2 cipher suites of K.2: ECDHE with
// AES-GCM, the two mandatory and the two recommended ones of TS 33.210
// cl. 6.2.3. A server negotiates the ones of its certificate type.
var TLS12CipherSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
}

// curves are P-256 (mandatory), x25519 and P-384 (TS 33.210 cl. 6.2.2 and
// 6.2.3).
var curves = []tls.CurveID{tls.CurveP256, tls.X25519, tls.CurveP384}

// ServerConfig returns the K.2 configuration of the AF: TLS 1.2 and 1.3,
// the cipher suites and groups of TS 33.210 cl. 6.2, and session tickets
// accepted for SessionLifetime from their issue.
func ServerConfig(cert tls.Certificate) *tls.Config {
	cfg := &tls.Config{
		MinVersion:       tls.VersionTLS12,
		CipherSuites:     TLS12CipherSuites,
		CurvePreferences: curves,
		Certificates:     []tls.Certificate{cert},
	}
	boundTickets(cfg, SessionLifetime, time.Now)
	return cfg
}

// ClientConfig returns the K.2 configuration of the UE: the certificate of
// the AF must chain to roots and match serverName, the FQDN of the AF
// (TS 33.222 cl. 5.3.1.3, RFC 2818 cl. 3.1). No client certificate is sent.
func ClientConfig(serverName string, roots *x509.CertPool) *tls.Config {
	return &tls.Config{
		ServerName:       serverName,
		RootCAs:          roots,
		MinVersion:       tls.VersionTLS12,
		CipherSuites:     TLS12CipherSuites,
		CurvePreferences: curves,
	}
}

// ticketStamp marks the issue time that boundTickets keeps in a ticket.
const ticketStamp = "akma-issued:"

// boundTickets makes cfg refuse a session ticket older than lifetime.
// crypto/tls accepts tickets for seven days. The issue time goes in
// SessionState.Extra. When crypto/tls wraps the state of a resumed TLS 1.2
// session again, it keeps the original time internally but drops Extra:
// that ticket gets no time and is refused, so the session is never resumed
// beyond lifetime.
func boundTickets(cfg *tls.Config, lifetime time.Duration, now func() time.Time) {
	cfg.WrapSession = func(cs tls.ConnectionState, ss *tls.SessionState) ([]byte, error) {
		if !(cs.DidResume && cs.Version <= tls.VersionTLS12) {
			ss.Extra = append(ss.Extra, binary.BigEndian.AppendUint64([]byte(ticketStamp), uint64(now().Unix())))
		}
		return cfg.EncryptTicket(cs, ss)
	}
	cfg.UnwrapSession = func(identity []byte, cs tls.ConnectionState) (*tls.SessionState, error) {
		ss, err := cfg.DecryptTicket(identity, cs)
		if err != nil || ss == nil {
			return nil, err
		}
		for _, e := range ss.Extra {
			if v, ok := strings.CutPrefix(string(e), ticketStamp); ok && len(v) == 8 {
				issued := time.Unix(int64(binary.BigEndian.Uint64([]byte(v))), 0)
				if age := now().Sub(issued); age >= 0 && age <= lifetime {
					return ss, nil
				}
			}
		}
		return nil, nil
	}
}
