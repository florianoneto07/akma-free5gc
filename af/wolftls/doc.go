// Copyright 2026 Floriano Neto.
// Licensed under the GNU General Public License v3.0 or later; see COPYING.

// Package wolftls runs TLS 1.2 and TLS 1.3 with an external pre-shared key
// over a net.Conn, with wolfSSL: the transport of the shared key-based
// profiles of TS 24.109 K.3 and TS 33.222 cl. 5.4. crypto/tls has neither the
// PSK cipher suites of TS 33.210 cl. 6.2.3 nor external PSKs in TLS 1.3.
//
// The package needs cgo, the build tag wolfssl and the static library built
// by af/scripts/build-wolfssl.sh. Like wolfSSL, it is licensed under the GNU
// General Public License v3.0 or later, and so is any binary built with the
// tag.
//
// What the package enforces, whatever the caller asks:
//   - TLS 1.2 or TLS 1.3 only, one version per Server or Client;
//   - TLS 1.3: the PSK only with (EC)DHE, psk_dhe_ke (TS 33.210 cl. 6.2.2),
//     and no early data;
//   - TLS 1.2: ECDHE_PSK with AES-GCM (TS 33.210 cl. 6.2.3, RFC 5489),
//     Extended Master Secret and the renegotiation_info extension;
//   - groups P-256, x25519 and P-384, no finite field DH;
//   - the server name (SNI) sent by the client and required by the server;
//   - resumption by session tickets only, each bound to the expiry of the
//     key of its full handshake.
package wolftls
