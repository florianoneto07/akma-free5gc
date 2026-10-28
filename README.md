# akma-free5gc

AKMA (Authentication and Key Management for Applications, 3GPP TS 33.535, Release 19) on top of [free5GC](https://github.com/free5gc/free5gc) v4.2.3 and [UERANSIM](https://github.com/aligungr/UERANSIM) v3.2.6.

After a successful primary authentication, the UE and the network derive K_AKMA and an A-KID from K_AUSF. An application function (AF) then gets a K_AF for that A-KID from the AAnF and uses it to authenticate the UE, without a separate credential. free5GC has no AAnF and none of its NFs do AKMA; this repository adds what is missing.

This is **V2**. See [What's new in V2](#whats-new-in-v2) and [CHANGELOG.md](CHANGELOG.md).

## What is in here

| Part | What it does |
|---|---|
| `free5gc/aanf/` | **AAnF**, the AKMA Anchor Function (TS 33.535 cl. 4.2.1, Naanf_AKMA of TS 29.535). A new NF with the same layout as the free5GC NFs. It installs as a binary in `bin/` and a file in `config/`, and changes no file of free5GC |
| `free5gc/patches/` | Patches for free5GC: NRF, UDM, AUSF, AMF, NEF, `openapi` (Naanf_AKMA, and the primary authentication triggered by the home network), configuration, `run.sh` and the Go test bench |
| `af/ue/ueransim/patches/` | Patches for UERANSIM: the ME derives K_AKMA, the A-KID and K_AF; a key service gives each application only the K_AF of its own AF_IDs; `nr-akma-selftest` checks the derivations |
| `af/af/`, `af/uastar/`, `af/ue/uaclient/` | A test AF and a Ua\* client with the profiles of TS 24.109 Annex K: HTTP Digest keyed with K_AF inside TLS (K.2), and TLS 1.3 and TLS 1.2 with K_AF as pre-shared key (K.3); the DTLS profile of TS 33.535 Annex C, DTLS 1.3 and 1.2 with CoAP inside; and the OSCORE profile of Annex D, CoAP protected with a context from K_AF. A simplified Ua\*, HTTP Digest without TLS, stays as a test profile, off by default |
| `af/akmatls/`, `af/wolftls/`, `af/coap/` | The Ua\* identifiers, the PSK identity and the TLS profile of K.2; a cgo binding to wolfSSL for TLS and DTLS with a pre-shared key (GPL-3.0); the part of CoAP that the DTLS and OSCORE profiles use |
| `af/oscore/`, `af/cbor/`, `af/akmaoscore/` | OSCORE (RFC 8613) with AES-CCM, Appendix B.2 included; the part of CBOR (RFC 8949) it needs; the payloads and derivations of TS 33.535 Annex D |
| `shared/akma/` | Go library shared by all of the above: the KDF, the SUPI as KDF parameter, the A-KID, the AF_ID and the key encodings |
| `reference/kdf/` | Independent Python implementation of the KDF that generates the test vectors |
| `af/scripts/e2e.sh` | End-to-end run with negative tests, from the AF host |

## What works

Tested on free5GC v4.2.3 and UERANSIM v3.2.6 (commit `85a0fbf`, the one of the free5GC guide):

| Procedure | TS 33.535 | Notes |
|---|---|---|
| K_AKMA and A-KID derived by the AUSF and by the UE, registered at the AAnF | cl. 6.1 | 5G AKA and EAP-AKA'; the AAnF is discovered at the NRF by Routing Indicator (cl. 6.7) |
| K_AF to an AF inside the operator network | cl. 6.2.1 | the AAnF authorizes the AF by local policy |
| Anonymous user access: K_AF without the SUPI | cl. 6.2.2 | directly and through the NEF |
| K_AF to an AF outside the operator network, through the NEF | cl. 6.3 | `POST /3gpp-akma/v1/retrieve` (TS 29.522 cl. 5.14) |
| AKMA context removal | cl. 6.6 | requested by the `seed` test tool in the role of the OAM |
| Refresh of K_AKMA by the AAnF | cl. 6.4.4; TS 33.501 cl. 6.1.5 | by local policy (`kakmaRefresh`), the AAnF sends `Nudm_UECM_AuthTrigger`; the UDM notifies the AMF, which authenticates the registered UE again and runs the NAS SMC; the UE gets a new A-KID and keeps its PDU session |
| Ua\* between the UE and the AF over the PDU session | cl. 6.2.1 steps 1 and 9; Annexes B, C and D | K.2 in TLS 1.3 and 1.2, PSK TLS 1.3 and 1.2, PSK DTLS 1.3 and 1.2 with CoAP, OSCORE, with session resumption and context renewal; see [docs/ua-profiles.md](docs/ua-profiles.md) |

The derivations agree in four implementations: the Python oracle, `shared/akma`, the KDF that free5GC already uses for K_SEAF, and the patched UERANSIM. `af/scripts/e2e.sh` runs 161 checks against a running core: the flows above, every Ua\* profile from the UE, over TLS, DTLS and OSCORE, OpenSSL as an independent PSK client, libcoap as an independent OSCORE client, the expiry of K_AF in a TLS session, re-authentication, the refresh of K_AKMA, the AAnF down during an authentication, a subscriber without AKMA, the key service of the UE refusing other AF_IDs and other users, the negative cases of the AAnF and NEF APIs and of the TLS profiles, and no key in any log.

## Architecture

```
                     free5GC host                                         AF host
 ┌──────────────────────────────────────────────────────┐
 │  UDM ── akmaInd, Routing Indicator ──▶ AUSF            │
 │                                         │              │
 │                     AnchorKey_Register  │ K_AKMA, A-KID │
 │                                         ▼              │
 │  NRF ◀──── discovery by RID ──────── AAnF ◀───── ApplicationKey_Get ──── AF inside the
 │                                         ▲              │                    operator network
 │                                         │              │
 │                                        NEF ◀──── 3gpp-akma/v1/retrieve ─ AF outside
 └──────────────────────────────────────────────────────┘
   UE (UERANSIM) ─── Ua*: (D)TLS with K_AF, or Digest in TLS (K.2), over the PDU session ───▶ AF
```

Example topology used throughout the documentation:

| Host | Address | Runs |
|---|---|---|
| free5GC host | 192.168.16.130 | free5GC with the AAnF; UERANSIM too, in the one-host setup |
| AF host | 192.168.16.129 | this repository, the AF, the end-to-end script |
| UERANSIM host (optional) | 192.168.16.131 | gNB and UE, as in the free5GC installation guide |

## Quick start

Install free5GC v4.2.3 and UERANSIM with the [free5GC guide](https://free5gc.org/guide/) and check that `TestRegistration` passes. Then follow [docs/install.md](docs/install.md). In short:

1. Clone this repository on the free5GC host as `~/akma-free5gc`, next to `~/free5gc`, and anywhere on the AF host. The folder name matters: the patched `go.mod` files point to `../../../akma-free5gc`.
2. Build and install the AAnF: `free5gc/scripts/build-aanf.sh` and `free5gc/scripts/deploy.sh user@free5gc-host`.
3. On the free5GC host, patch the NFs: `patch-nf.sh nrf|udm|ausf|amf|nef|config|run apply`.
4. Give a subscriber an AKMA subscription: `provision-akma-subscriber.sh imsi-208930000000001 0000`.
5. Patch UERANSIM: `af/scripts/patch-ueransim.sh apply`.
6. Build wolfSSL, a test CA and the AF, and start it: `af/scripts/build-wolfssl.sh`, `af/scripts/make-test-ca.sh`, `af/scripts/build-af.sh` and `af/build/bin/af -c af/config/afcfg.yaml`.
7. Run everything end to end from the AF host: `af/scripts/e2e.sh user@free5gc-host`.

The example configuration files carry the addresses of the example topology. [docs/install.md](docs/install.md) lists every place to change for yours.

## Documentation

| Document | Content |
|---|---|
| [docs/install.md](docs/install.md) | Installation guide, step by step, on one host and with UERANSIM on another host |
| [docs/free5gc-fixes.md](docs/free5gc-fixes.md) | What free5GC has to change for AKMA: for each point, what free5GC does, where the specification says what to do, and how |
| [docs/aanf.md](docs/aanf.md) | The AAnF: configuration, operations, authorization, errors |
| [docs/nef-akma-api.md](docs/nef-akma-api.md) | The AKMA API of the NEF for AFs outside the operator network |
| [docs/ua-profiles.md](docs/ua-profiles.md) | The Ua\* profiles of the test AF and client: K.2 and TLS with a pre-shared key; resumption, K_AF expiry, build and licenses |
| [docs/ua-star.md](docs/ua-star.md) | The simplified Ua\* protocol, the test profile, and the Digest that K.2 shares |
| [docs/testing.md](docs/testing.md) | Unit tests, test vectors and the end-to-end script |
| [docs/3gpp-recommendations.md](docs/3gpp-recommendations.md) | Errors and gaps in the 3GPP specifications, in the fields of a Change Request |
| [docs/ueransim-recommendations.md](docs/ueransim-recommendations.md) | What UERANSIM does against the specifications, and how to fix it |
| [CHANGELOG.md](CHANGELOG.md) | What changed in each version |

## What's new in V2

- **Ua\* profiles of the specifications.** K.2 (HTTP Digest inside TLS), TLS 1.3 and 1.2 with K_AF as pre-shared key, DTLS 1.3 and 1.2 with CoAP, and OSCORE, in the test AF and the Ua\* client; the simplified Ua\* of V1 became a test profile, off by default.
- **Key service of the ME.** UERANSIM gives each application only the K_AF of its own AF_IDs (TS 33.535 cl. 4.4.3).
- **Refresh of K_AKMA.** The AAnF asks the UDM for a new primary authentication (TS 33.535 cl. 6.4.4), with new patches for the UDM, the AMF and `openapi`.
- **Recommendations** to free5GC, 3GPP and UERANSIM (below).
- 161 end-to-end checks instead of 83. Upgrading from V1: [docs/install.md](docs/install.md#12-upgrading-from-v1).

## Recommendations

What this work found in the three projects it builds on, each item with the clause of the specification that says what to do:

- [docs/free5gc-fixes.md](docs/free5gc-fixes.md): twenty changes for free5GC (F1 to F20), with the patches of this repository and a table by free5GC repository, checked again in free5GC v4.3.0;
- [docs/3gpp-recommendations.md](docs/3gpp-recommendations.md): sixteen errors and ten gaps in the 3GPP specifications (A to Z), grouped by working group and checked in the latest published versions;
- [docs/ueransim-recommendations.md](docs/ueransim-recommendations.md): four items for UERANSIM, checked in release v3.3.0 and in `master`.

## Limitations

Read these before you use any of it outside a test bed.

- **No TLS on the SBI.** The SBI runs on h2c, and the NEF–AF interface on plain HTTP. TS 33.535 cl. 4.4.0 and TS 33.501 cl. 12 and 13.1 require protection. The AAnF and the NEF bind each AF_ID to source addresses (local policy). That limits which AF_ID a host can ask for, but it does not authenticate the AF.
- **Ua\* profiles.** K.2 and the two PSK profiles of TS 24.109 Annex K, DTLS (TS 33.535 Annex C) with CoAP, and OSCORE (Annex D). Annex D leaves the form of several fields open, and this repository takes its own choices for them ([docs/ua-profiles.md](docs/ua-profiles.md) section 4). RFC 7252 asks CoAP in PSK mode for `TLS_PSK_WITH_AES_128_CCM_8`, which TS 33.210 forbids; the DTLS profiles follow TS 33.210. wolfSSL has no `TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384`, which TS 33.210 recommends; the certificate of K.2 comes from a test CA, without OCSP. The simplified Ua\* (`FF00000001`), HTTP Digest without TLS, is a test profile, off by default. See [docs/ua-profiles.md](docs/ua-profiles.md).
- **Token issuer of the external AF.** free5GC has no CAPIF, so the AF outside the operator network gets its NEF access token from the NRF. The specified path is the CAPIF Core Function (TS 29.522 cl. 7.2).
- **Applications in the UE.** The key service of the ME tells applications apart by user (uid). The executable is checked on a best-effort basis. K_AKMA never leaves the ME.
- **Not implemented:**
  - the ROAMING_STATUS subscription (TS 33.535 cl. 6.2.1 step 5) and the `RoamingRestriction` feature;
  - GPSI, i.e. the `AKMA_GPSI_Support` feature and the GPSI to the external AF;
  - SUPI types other than IMSI;
  - NFKC in the UE: a non-ASCII AF FQDN is refused there;
  - the per-operation scopes of TS 29.535 table 5.1.9-1;
  - AS key re-keying after the refresh of K_AKMA, and the refresh over non-3GPP access: UERANSIM has no AS security, and the test bed has no non-3GPP access;
  - more than one AAnF;
  - persistence: the AAnF keeps its contexts in memory.
- **Versions.** The patches are for free5GC v4.2.3 (NRF, UDM, AUSF and AMF v1.4.5, NEF v1.2.5, `openapi` v1.2.4 and, for the AMF and the test bench, v1.2.5-0.20260527003827-02dc71b4d94f) and UERANSIM v3.2.6 commit `85a0fbf`. free5GC v4.3.0 and UERANSIM v3.3.0 are out; the patches are not rebased on them yet.
- **Open points in free5GC.** Some fixes are still open, among them the 401 of the NEF without `ProblemDetails` and the token checks of `oauth.VerifyOAuth`. See [docs/free5gc-fixes.md](docs/free5gc-fixes.md).

## Repository layout

```
shared/akma/              Go library: KDF, SUPI, A-KID, AF_ID, encodings; test vectors
shared/crosscheck/        the KDF of shared/akma against the one of free5gc/util
reference/kdf/            Python oracle and vector generator
free5gc/aanf/             the AAnF and the seed test tool
free5gc/config/           aanfcfg.yaml
free5gc/patches/          patches for free5GC, one directory per target
free5gc/scripts/          build, deploy, patch, provision, N6 NAT
af/af/                    the test AF
af/akmatls/               Ua* identifiers, PSK identity, TLS profile of K.2
af/wolftls/               cgo binding to wolfSSL for TLS and DTLS with a pre-shared key (GPL-3.0)
af/coap/                  CoAP messages, confirmable exchange and UDP server (RFC 7252)
af/oscore/                OSCORE (RFC 8613) and AES-CCM (RFC 3610)
af/cbor/                  the part of CBOR (RFC 8949) of the OSCORE profile
af/akmaoscore/            payloads and derivations of TS 33.535 Annex D
af/uastar/                HTTP Digest of K.2 and of the simplified Ua*
af/ue/uaclient/           the Ua* client of the UE
af/ue/ueransim/patches/   patches for UERANSIM (GPL-3.0)
af/config/                AF configurations (inside and outside the operator network)
af/scripts/               build (wolfSSL, test CA, AF), UE namespace, UERANSIM patches, end-to-end run, negative tests, OSCORE check
docs/                     the documentation above
```

## License

Copyright 2026 Floriano Neto.

Apache License 2.0 ([LICENSE](LICENSE)), the license of free5GC. The free5GC patches modify free5GC, which is licensed under the same license.

The patches in `af/ue/ueransim/patches/` modify UERANSIM, which is licensed under the GNU General Public License v3.0. They are distributed under the same license ([COPYING](af/ue/ueransim/patches/COPYING)).

`af/wolftls/` and `af/scripts/build-wolfssl.sh` use wolfSSL, which is licensed under the GNU General Public License v3.0, and are distributed under the same license ([COPYING](af/wolftls/COPYING)). The AF and client binaries built with wolfSSL (build tag `wolfssl`) are covered by it as well.

3GPP specifications are not included. They are cited by number and clause and can be downloaded from [3gpp.org](https://www.3gpp.org/specifications).
