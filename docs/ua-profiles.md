# Ua\* profiles of the test AF

The test AF and the Ua\* client implement the TLS profiles of TS 24.109 Annex K, which TS 33.535 Annex B adapts to AKMA from the GBA profiles of TS 33.222, the DTLS profile of TS 33.535 Annex C, with CoAP inside, and the OSCORE profile of TS 33.535 Annex D. Each profile runs on its own port of the AF.

| Profile | Specification | How the UE authenticates | Ua\* identifier (TS 33.220 H.3) |
|---|---|---|---|
| `digest-tls` | TS 24.109 K.2; TS 33.222 cl. 5.3 | HTTP Digest keyed with K_AF inside TLS 1.3 or 1.2; the AF authenticates with its certificate | `01 00 01 yy zz`, `yy zz` the cipher suite of the connection |
| `psk-tls13` | TS 24.109 K.3.3; TS 33.222 cl. 5.4.0.2 | TLS 1.3 with K_AF as external pre-shared key | `01 00 00 00 07` |
| `psk-tls12` | TS 24.109 K.3.2; TS 33.222 cl. 5.4.0.1 | TLS 1.2 `ECDHE_PSK` with K_AF | `01 00 01 D0 01` |
| `psk-dtls13` | TS 33.535 Annex C | DTLS 1.3 with K_AF as external pre-shared key; CoAP inside | `01 00 00 00 09` |
| `psk-dtls12` | TS 33.535 C.1.1; TS 33.210 cl. 6.2.1 | DTLS 1.2 `ECDHE_PSK` with K_AF, the procedure of TLS 1.2; CoAP inside | `01 00 01 D0 01` |
| `oscore` | TS 33.535 Annex D; TS 33.220 Annex P | CoAP protected by OSCORE (RFC 8613) with a security context from K_AF | `01 00 00 00 08` |
| `digest-http` | none: test only | the simplified Ua\* of [ua-star.md](ua-star.md), without TLS | `FF 00 00 00 01` (private range) |

The AF_ID is the FQDN of the AF followed by the identifier, `<FQDN>.<10 hex digits>` in the APIs. Each profile, and in K.2 and TLS 1.2 each cipher suite, has its own AF_ID and so its own K_AF. The AAnF, the NEF and the key service of the UE must authorize every AF_ID that the AF can use.

## 1. K.2: Digest inside TLS

1. The UE opens TLS with the AF, checks that the certificate of the AF matches the FQDN of the AF (RFC 2818 cl. 3.1) and sends no certificate.
2. The UE sends the request with the product token `3gpp-akma` in `User-Agent`. The AF answers `401` with a Digest challenge whose realm is `3GPP-bootstrapping-akma@<FQDN>`.
3. The UE checks that the realm names the AF it opened TLS with. Only then does it ask the ME for K_AF, for the AF_ID with the cipher suite of the connection, and send the A-KID as `username` with base64(K_AF) as password.
4. The AF asks the AAnF for K_AF with the same AF_ID, checks the Digest and proves K_AF back with `rspauth`.

The Digest is the one of [ua-star.md](ua-star.md) (RFC 7616 with SHA-256). With the ECDSA certificate of the example, the AF_IDs are `0100011301`, `0100011302` and `0100011303` in TLS 1.3 and `010001C02B` and `010001C02C` in TLS 1.2.

## 2. PSK profiles

- **TLS 1.3.** The UE asks the ME for the K_AF of `<FQDN>.0100000007` before the `ClientHello`, and offers the identity `3GPP-AKMA;<A-KID>` with `psk_key_exchange_modes` set to `psk_dhe_ke` only: TS 33.210 cl. 6.2.2 forbids `psk_ke`. The AF reads the A-KID from the identity, asks the AAnF for the K_AF of the same AF_ID and uses it as the external PSK, with SHA-256 (RFC 8446 cl. 4.2.11) and `TLS_AES_128_GCM_SHA256`. No early data.
- **TLS 1.2.** The AF selects `TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256` (RFC 8442, mandatory in TS 33.210 cl. 6.2.3) and sends the hint `3GPP-AKMA`. The UE then asks the ME for the K_AF of `<FQDN>.010001D001`, the identifier of that cipher suite, and sends the identity `3GPP-AKMA;<A-KID>`. K_AF is the PSK of RFC 5489. Extended Master Secret and `renegotiation_info` are on; renegotiation itself is never accepted.

K_AF, the full 32 octets, is the PSK: the specifications only say that the PSK is derived from K_AF. If the AF cannot get K_AF, it refuses the identity and the handshake fails: TLS has no way to carry a cause. Once the handshake is done, the UE sends `GET /ua/v1/session` without HTTP authentication and gets the A-KID and the expiry of K_AF.

The AF requires the `server_name` of the client to be its FQDN. In both versions the client also offers other authentication methods, as TS 33.222 cl. 5.4.0 asks, but it trusts no certificate in these profiles: if the AF picked one, the handshake would fail. K.2 is the profile with a certificate.

## 3. DTLS profiles

TS 33.535 Annex C applies the TLS 1.3 procedure of section 2 to DTLS 1.3, with the identifier `01 00 00 00 09` that TS 33.220 H.3 gives to DTLS. TS 33.210 cl. 6.2.1 also requires DTLS 1.2 from whoever supports DTLS. Annex C does not describe it and H.3 has no identifier for it, so this repository runs DTLS 1.2 with the procedure and identifier of TLS 1.2 (`01 00 01 D0 01`). DTLS 1.2 and DTLS 1.3 thus never share a K_AF (RFC 8446 Appendix E.7).

- **Cookies.** The AF answers a first ClientHello with a HelloRetryRequest (DTLS 1.3, RFC 9147 cl. 5.1) or a HelloVerifyRequest (DTLS 1.2) carrying a cookie bound to the address of the client. It asks the AAnF for K_AF only once the client has sent the cookie back, so a forged source address never makes the AF query the AAnF.
- **Application protocol.** Annex C leaves it open; the AF serves CoAP (RFC 7252), `coaps` on UDP 5684 (DTLS 1.3) and 5685 (DTLS 1.2). The UE sends a confirmable `GET coaps://<FQDN>/ua/v1/session` with `Uri-Host`; the AF answers `2.05 Content` in the acknowledgement, with the JSON of the PSK TLS profiles. Errors: `4.04` for another host or path, `4.05`, `4.02` for an unknown critical option, `4.03` with `KAF_EXPIRED`.
- **Cipher suites.** Those of TS 33.210 cl. 6.2, as in TLS. RFC 7252 cl. 9.1.3.1 asks CoAP in PSK mode to support `TLS_PSK_WITH_AES_128_CCM_8`, a suite without ECDHE; TS 33.535 C.2.1 applies TS 33.210, which forbids it, and so does this repository.
- **Datagrams.** One UDP socket at the AF, one association per client address; MTU 1200 for what the AF sends, while it reads datagrams of up to 17584 octets (a `ClientHello` with a post-quantum key share passes 1700); CoAP retransmission per RFC 7252 cl. 4.8. No connection ID: if the NAT mapping of the UE changes, a new handshake resumes the session.

## 4. OSCORE profile

TS 33.535 Annex D follows the OSCORE profile of GBA, TS 33.220 Annex P, with the AF in the role of the NAF. Over CoAP on UDP 5683, without DTLS:

1. The UE asks the ME for the K_AF of `<FQDN>.0100000008` and sends a confirmable `POST coap://<FQDN>/akma` with `Content-Format` 60 (CBOR) and the payload `[A-KID, N1, AF-SID]` of D.3.5. The A-KID goes as `[RID, A-TID, HPLMN-ID]`: the RID in text, the 32 octets of the A-TID, and the MCC followed by the MNC.
2. The AF rebuilds the A-KID in text, asks the AAnF for the K_AF of `<FQDN>.0100000008`, and answers `2.01 Created` with `[N2, UE-SID]`.
3. Both derive the security context (D.3.3), then the UE sends `GET /ua/v1/session` protected by OSCORE and gets `2.05` with the JSON of the other profiles.

| Parameter | Value |
|---|---|
| Master Secret | HKDF-SHA-256 with an empty salt, K_AF as input key material, `AKMA-OSCORE` as info, 32 octets |
| Master Salt | the request payload followed by the response payload, as sent |
| Sender ID of the UE / of the AF | UE-SID, chosen by the AF / AF-SID, chosen by the UE; 4 random octets, never equal |
| N1, N2 | 16 random octets |
| AEAD, HKDF, ID Context | AES-CCM-16-64-128, HKDF SHA-256, none |

Annex D leaves several points open, and this repository takes these choices:

- **"CoAP Security protocol identifier".** D.3.2 lists it in the request and D.3.5 does not encode it; the request is the array of D.3.5.
- **HPLMN-ID.** D.3.5 gives it no form. It is the MCC and MNC, the Home Network Identifier of TS 23.003 cl. 2.2B.
- **OSC-INP.** It is a byte string with the CBOR map inside. Only the default values are accepted, because the response has no way to tell the UE that the AF used others.
- **Master Secret.** The HKDF parameters are those of the table above.
- **Errors.** Annex D defines none. A refused `POST` gets a CoAP error with the cause as diagnostic payload: `4.03 AKMA_KEY_NOT_AVAILABLE`, `4.03 KAF_EXPIRED`, `5.03 AANF_UNAVAILABLE`, `4.00 OSC_INP_NOT_SUPPORTED`, `4.15`, `4.04`, `4.05`. A protected request that fails gets the errors of RFC 8613 cl. 8.2.

The AF keeps a context pending until a request verifies with it, and removes a pending one after 60 s. It keeps at most 4 contexts per A-KID and 4096 in all, and removes a context when its K_AF expires. The next request then gets `4.01 Security context not found`, and the client sends a new `POST /akma`, with a new N1. The renewal of RFC 8613 Appendix B.2 runs from the client (`-rekey`): the context gets the ID Context `R2 || R3`.

There is no cookie here: each `POST` makes the AF query the AAnF, as the Digest response of the other profiles does. The `2.01` is smaller than the `POST`, so the AF does not amplify traffic. The A-KID travels in clear in the `POST`, as the PSK identity does in a TLS 1.3 `ClientHello`.

## 5. Session resumption and K_AF expiry

- **PSK profiles.** Resumption by session tickets only, in TLS 1.2 (RFC 5077) and in TLS 1.3. A ticket is valid until the earlier of the expiry of the K_AF of its full handshake and 24 hours (TS 33.222 cl. 5.4.1.4); the AF keeps the A-KID of each ticket. The AF closes a TLS session (`close_notify`) when its K_AF expires; the next handshake follows `kafExpiry`: `refetch` asks the AAnF again, `reject` refuses.
- **K.2.** Tickets are accepted for 24 hours from their issue (TS 33.222 cl. 5.3.1.5). K_AF does not enter TLS here: each Digest request is checked against K_AF and its expiry, as in [ua-star.md](ua-star.md).

## 6. Configuration

In `afcfg.yaml`, one entry per profile:

```yaml
configuration:
  fqdn: af1.akma.example
  profiles:
    - type: digest-tls
      listen: 192.168.16.129:8443
      certificate: ../build/cert/af1.akma.example.pem   # relative to this file
      key: ../build/cert/af1.akma.example.key
    - type: psk-tls13
      listen: 192.168.16.129:8444
    - type: psk-tls12
      listen: 192.168.16.129:8445
    - type: psk-dtls13             # UDP
      listen: 192.168.16.129:5684
    - type: psk-dtls12             # UDP
      listen: 192.168.16.129:5685
    - type: oscore                 # UDP, without wolfSSL too
      listen: 192.168.16.129:5683
    # - type: digest-http          # test only, off by default
    #   listen: 192.168.16.129:8080
  uaStarId: FF00000001             # identifier of digest-http
```

Without `profiles`, a top-level `listen` is a single `digest-http` server, as in earlier versions.

The client picks the profile with `-profile`. Without a port in `-connect`, it uses the one of the example: 8443, 8444, 8445, 5684, 5685, 5683 or 8080.

| Option | |
|---|---|
| `-profile` | `digest-tls`, `psk-tls13`, `psk-tls12`, `psk-dtls13`, `psk-dtls12`, `oscore` or `digest-http` (default) |
| `-ca` | PEM certificate of the CA of the AF, required with `digest-tls` |
| `-tls12` | `digest-tls` in TLS 1.2 only |
| `-reconnect` | a new TLS connection or DTLS association for each request, resuming the previous session; with `oscore`, a new `POST /akma` for each request |
| `-rekey` | `oscore`: renew the context before each request (RFC 8613 Appendix B.2) |
| `-psk-ke-only` | `psk-tls13` or `psk-dtls13` offering `psk_ke` only, which the AF refuses: a negative test |

In TLS 1.3, wolfSSL tells the client that it offered a ticket, not whether the AF took it; the log of the AF says whether the session was resumed.

## 7. Build and licenses

Go's `crypto/tls` does K.2. It has neither the PSK cipher suites of TS 33.210, nor external PSKs in TLS 1.3, nor DTLS, so the PSK profiles use wolfSSL through `af/wolftls`, a cgo binding of this repository:

```bash
af/scripts/build-wolfssl.sh
```

```bash
af/scripts/make-test-ca.sh
```

```bash
af/scripts/build-af.sh
```

`build-wolfssl.sh` downloads wolfSSL 5.9.4, checks the SHA-256 of the archive, builds a static library in `af/build/wolfssl` and checks its options: TLS 1.2 and 1.3, DTLS 1.2 and 1.3 with a settable MTU, PSK, AES-GCM and AES-CCM, SNI, Extended Master Secret, session tickets; no finite field DH, no TLS below 1.2, no early data. `build-af.sh` builds static binaries with the build tag `wolfssl` when the library is there; `AF_WOLFSSL=no` builds without it, and the PSK profiles are then refused.

wolfSSL is licensed under the GNU General Public License v3.0. `af/wolftls` and `af/scripts/build-wolfssl.sh` are under the same license, and so are the AF and client binaries built with the tag. The rest of `af/` is under the Apache License 2.0.

The OSCORE profile does not use wolfSSL. Go has no AES-CCM, so `af/oscore` implements it on `crypto/aes` (RFC 3610), next to OSCORE itself (RFC 8613, Appendix B.2 included). `af/cbor` is the part of CBOR (RFC 8949) the profile needs, and `af/akmaoscore` holds the payloads and the derivations of Annex D. The tests check them against the vectors of RFC 3610 and RFC 8613 Appendix C and the examples of RFC 8949 Appendix A.

## 8. Limitations

- `TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384`, recommended by TS 33.210 cl. 6.2.3, is not in wolfSSL and is not offered.
- The certificate status request extension (OCSP stapling), recommended by TS 33.210 cl. 6.2, is not supported; the test CA has no OCSP responder.
- HTTP/1.1 only.
- One profile per port: a port that negotiates K.2 or K.3 in the same `ClientHello` (TS 33.222 cl. 5.4.0.1 NOTE 3) is not supported.
- The tickets of an AF are sealed with a key of the process: they do not survive a restart.
- No DTLS connection ID (RFC 9147 cl. 9), and the CoAP client takes only piggybacked responses.
- OSCORE: no Observe, no block-wise transfer and no proxy. The contexts of the AF do not survive a restart, and the AF does not start a renewal itself. The address of the UE is not confirmed before the AAnF is queried; the Echo option of RFC 9175 would do it, and Annex D does not have it.
