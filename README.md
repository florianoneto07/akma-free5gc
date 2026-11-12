# akma-free5gc

AKMA (Authentication and Key Management for Applications, 3GPP TS 33.535, Release 19) on top of [free5GC](https://github.com/free5gc/free5gc) v4.2.3 and [UERANSIM](https://github.com/aligungr/UERANSIM) v3.2.6.

After a successful primary authentication, the UE and the network derive K_AKMA and an A-KID from K_AUSF. An application function (AF) then gets a K_AF for that A-KID from the AAnF and uses it to authenticate the UE, without a separate credential. free5GC has no AAnF and none of its NFs do AKMA; this repository adds what is missing.

This is **V3**. See [What's new in V3](#whats-new-in-v3) and [CHANGELOG.md](CHANGELOG.md).

## What is in here

| Part | What it does |
|---|---|
| `free5gc/aanf/` | **AAnF**, the AKMA Anchor Function (TS 33.535 cl. 4.2.1, Naanf_AKMA of TS 29.535). A new NF with the same layout as the free5GC NFs. It installs as a binary in `bin/` and a file in `config/`, and changes no file of free5GC |
| `free5gc/ccf/` | **CCF**, a CAPIF Core Function for the AKMA path (TS 29.222, TS 33.122): onboarding of API invokers, publication and discovery of the `3gpp-akma` API of the NEF, security method and access tokens |
| `free5gc/crl/` | A small HTTP service that serves the certificate revocation lists of the test PKI (TS 33.310 cl. 7.1) |
| `free5gc/patches/` | Patches for free5GC: every NF (mutual TLS on the SBI, by name), and for AKMA the NRF, UDM, AUSF, AMF, NEF (the `3gpp-akma` API and CAPIF), `openapi` (Naanf_AKMA, the primary authentication triggered by the home network, CAPIF, TLS and the checks of access tokens), `util`, configuration, `run.sh` and the Go test bench |
| `af/ue/ueransim/patches/` | Patches for UERANSIM: the ME derives K_AKMA, the A-KID and K_AF; a key service gives each application only the K_AF of its own AF_IDs; `nr-akma-selftest` checks the derivations |
| `af/af/`, `af/uastar/`, `af/ue/uaclient/` | A test AF and a Ua\* client with the profiles of TS 24.109 Annex K: HTTP Digest keyed with K_AF inside TLS (K.2), and TLS 1.3 and TLS 1.2 with K_AF as pre-shared key (K.3); the DTLS profile of TS 33.535 Annex C, DTLS 1.3 and 1.2 with CoAP inside; and the OSCORE profile of Annex D, CoAP protected with a context from K_AF. The AF outside the operator network is an API invoker of CAPIF. A simplified Ua\*, HTTP Digest without TLS, stays as a test profile, off by default |
| `af/akmatls/`, `af/wolftls/`, `af/coap/` | The Ua\* identifiers, the PSK identity and the TLS profile of K.2; a cgo binding to wolfSSL for TLS and DTLS with a pre-shared key (GPL-3.0); the part of CoAP that the DTLS and OSCORE profiles use |
| `af/oscore/`, `af/cbor/`, `af/akmaoscore/` | OSCORE (RFC 8613) with AES-CCM, Appendix B.2 included; the part of CBOR (RFC 8949) it needs; the payloads and derivations of TS 33.535 Annex D |
| `shared/akma/` | Go library shared by all of the above: the KDF, the SUPI as KDF parameter, the A-KID, the AF_ID and the key encodings |
| `reference/kdf/` | Independent Python implementation of the KDF that generates the test vectors |
| `free5gc/scripts/make-sba-certs.sh` | The test PKI of the operator: a CA, one certificate per NF in the profile of TS 33.310 cl. 6.1.3c, the certificate that signs the access tokens of the NRF, and the CRL |
| `af/scripts/e2e.sh` | End-to-end run with negative tests, from the AF host |

## What works

Tested on free5GC v4.2.3 and UERANSIM v3.2.6 (commit `85a0fbf`, the one of the free5GC guide):

| Procedure | Specification | Notes |
|---|---|---|
| K_AKMA and A-KID derived by the AUSF and by the UE, registered at the AAnF | TS 33.535 cl. 6.1 | 5G AKA and EAP-AKA'; the AAnF is discovered at the NRF by Routing Indicator, or any AAnF for the default Routing Indicator (cl. 6.7) |
| K_AF to an AF inside the operator network | cl. 6.2.1 | the AAnF authorizes the AF by local policy, on the identity of its client certificate |
| Anonymous user access: K_AF without the SUPI | cl. 6.2.2 | directly and through the NEF |
| K_AF to an AF outside the operator network, through the NEF | cl. 6.3 | `POST /3gpp-akma/v1/retrieve` (TS 29.522 cl. 5.14), with the access token of the CCF |
| CAPIF for the AKMA API | TS 29.522 cl. 7; TS 29.222; TS 33.122 | the NEF publishes `3gpp-akma` at the CCF and checks its tokens; the AF onboards, discovers the NEF, gets the `OAUTH` method and the token; the certificate of an invoker is revoked when it offboards |
| Mutual TLS on the SBI and between the NEF and the AF | TS 33.501 cl. 12 and 13.1; TS 33.310 | every NF, the AAnF, the CCF and the AF, by name, with certificates of the operator CA and CRLs checked at both ends |
| Access tokens of the NRF | TS 33.501 cl. 13.4.1; TS 33.210 cl. 6.3.3; TS 29.510 | `ES256` with `kid` and `x5t#S256`, `iss` and `sub` bound to the certificates; the scopes of each operation of Naanf_AKMA; every producer checks the claims; `Nnrf_AccessToken_RetrieveKey` |
| AKMA context removal | TS 33.535 cl. 6.6 | requested by the `seed` test tool in the role of the OAM |
| Refresh of K_AKMA by the AAnF | cl. 6.4.4; TS 33.501 cl. 6.1.5 | by local policy (`kakmaRefresh`), the AAnF sends `Nudm_UECM_AuthTrigger`; the UDM notifies the AMF, which authenticates the registered UE again and runs the NAS SMC; the UE gets a new A-KID and keeps its PDU session |
| Ua\* between the UE and the AF over the PDU session | cl. 6.2.1 steps 1 and 9; Annexes B, C and D | K.2 in TLS 1.3 and 1.2, PSK TLS 1.3 and 1.2, PSK DTLS 1.3 and 1.2 with CoAP, OSCORE, with session resumption and context renewal; see [docs/ua-profiles.md](docs/ua-profiles.md) |

The derivations agree in four implementations: the Python oracle, `shared/akma`, the KDF that free5GC already uses for K_SEAF, and the patched UERANSIM. `af/scripts/e2e.sh` runs 333 checks against a running core: the flows above, every Ua\* profile from the UE, over TLS, DTLS and OSCORE, OpenSSL as an independent PSK client, libcoap as an independent OSCORE client, Python clients for every port of the SBI and for CAPIF, without the Go code of this repository, the expiry of K_AF in a TLS session, re-authentication, the refresh of K_AKMA, the AAnF down during an authentication, a subscriber without AKMA, the key service of the UE refusing other AF_IDs and other users, the negative cases of the AAnF, NEF and CCF APIs, of the TLS profiles, of the certificates and of the tokens, and no key or secret in any log.

## Architecture

```
                         free5GC host                                              AF host
 ┌────────────────────────────────────────────────────────────────┐
 │  UDM ── akmaInd, Routing Indicator ──▶ AUSF                      │
 │                                         │                        │
 │                     AnchorKey_Register  │ K_AKMA, A-KID          │
 │                                         ▼                        │
 │  NRF ◀──── discovery, tokens ──────── AAnF ◀── ApplicationKey_Get ─── AF inside the
 │                                         ▲                        │       operator network
 │                                         │                        │
 │  CCF ◀── CAPIF-3/4 ── NEF ◀──────────────── 3gpp-akma/v1/retrieve ─── AF outside
 │   ▲                                                              │       (API invoker)
 │   └───────────────── CAPIF-1e: onboarding, discovery, token ───────────── AF outside
 │                                                                  │
 │  CRL service ◀── every end of a TLS connection                   │
 └────────────────────────────────────────────────────────────────┘
   all SBI, CAPIF and NEF–AF links: mutual TLS, by name
   UE (UERANSIM) ─── Ua*: (D)TLS with K_AF, Digest in TLS (K.2) or OSCORE, over the PDU session ───▶ AF
```

Example topology used throughout the documentation:

| Host | Address | Runs |
|---|---|---|
| free5GC host | 192.168.16.130 | free5GC with the AAnF, the CCF and the CRL service; UERANSIM too, in the one-host setup |
| AF host | 192.168.16.129 | this repository, the AF, the end-to-end script |
| UERANSIM host (optional) | 192.168.16.131 | gNB and UE, as in the free5GC installation guide |

## Quick start

Install free5GC v4.2.3 and UERANSIM with the [free5GC guide](https://free5gc.org/guide/) and check that `TestRegistration` passes. Then follow [docs/install.md](docs/install.md), in the order its first page gives. In short:

1. Clone this repository on the free5GC host as `~/akma-free5gc`, next to `~/free5gc`, and anywhere on the AF host. The folder name matters: the patched `go.mod` files point to `../../../akma-free5gc`.
2. Add the names of the SBI to `/etc/hosts` and make the test PKI: `make-sba-certs.sh ~/free5gc/cert/sba free5gc/config/sba-entities.conf` and `make-capif-certs.sh ~/free5gc/cert <address>`.
3. On the free5GC host, prepare `openapi` and `util` and patch every NF: `prepare-openapi.sh`, `prepare-util.sh`, and `patch-nf.sh <nf> apply` for the NRF, AMF, AUSF, UDM, NEF, SMF, UDR, PCF, NSSF, CHF, BSF, the configuration, `run.sh` and the test bench.
4. Build and install the AAnF, `seed` and the CRL service: `free5gc/scripts/build-aanf.sh`, `free5gc/scripts/build-crl.sh` and `free5gc/scripts/deploy.sh user@free5gc-host`; build the CCF with `free5gc/scripts/build-ccf.sh` and copy it.
5. Give a subscriber an AKMA subscription: `provision-akma-subscriber.sh imsi-208930000000001 0000`.
6. Patch UERANSIM: `af/scripts/patch-ueransim.sh apply`.
7. Build wolfSSL, a test CA and the AF, copy the certificate of the AF from the free5GC host, and start it: `af/scripts/build-wolfssl.sh`, `af/scripts/make-test-ca.sh`, `af/scripts/build-af.sh` and `af/build/bin/af -c af/config/afcfg.yaml`.
8. Start free5GC with `./run.sh -crl -aanf -ccf`, or run everything end to end from the AF host: `af/scripts/e2e.sh user@free5gc-host`.

The example configuration files carry the addresses of the example topology. [docs/install.md](docs/install.md) lists every place to change for yours.

## Documentation

| Document | Content |
|---|---|
| [docs/install.md](docs/install.md) | Installation guide, step by step, on one host and with UERANSIM on another host; upgrading from V2 |
| [docs/free5gc-fixes.md](docs/free5gc-fixes.md) | What free5GC has to change for AKMA: for each point, what free5GC does, where the specification says what to do, and how |
| [docs/aanf.md](docs/aanf.md) | The AAnF: configuration, operations, authorization, errors |
| [docs/nef-akma-api.md](docs/nef-akma-api.md) | The AKMA API of the NEF for AFs outside the operator network |
| [docs/capif.md](docs/capif.md) | The CCF, the NEF as API publishing and exposing function, and the AF as API invoker |
| [docs/sbi-tls.md](docs/sbi-tls.md) | Mutual TLS on the SBI: names, the test PKI, revocation, access tokens and the policies by certificate |
| [docs/ua-profiles.md](docs/ua-profiles.md) | The Ua\* profiles of the test AF and client: K.2 and TLS with a pre-shared key; resumption, K_AF expiry, build and licenses |
| [docs/ua-star.md](docs/ua-star.md) | The simplified Ua\* protocol, the test profile, and the Digest that K.2 shares |
| [docs/testing.md](docs/testing.md) | Unit tests, test vectors and the end-to-end script |
| [docs/3gpp-recommendations.md](docs/3gpp-recommendations.md) | Errors and gaps in the 3GPP specifications, in the fields of a Change Request |
| [docs/ueransim-recommendations.md](docs/ueransim-recommendations.md) | What UERANSIM does against the specifications, and how to fix it |
| [CHANGELOG.md](CHANGELOG.md) | What changed in each version |

## What's new in V3

- **Mutual TLS on the SBI.** Every NF of free5GC, the AAnF, the CCF and the AF talk over mutual TLS, by name, with the certificates of a test PKI of the operator and CRLs checked at both ends (TS 33.501 cl. 13.1; TS 33.310). An NF with `https` and no FQDN does not start.
- **Identity in the access tokens and in the policies.** The NRF signs with `ES256`, binds each token to the certificate of the NF that asked, grants the scopes of each operation by NF type, checks every profile of the target type and serves `Nnrf_AccessToken_RetrieveKey`. Every producer checks the claims. The AAnF knows the AF and the NEF by their certificates, without source addresses.
- **CAPIF.** A CAPIF Core Function for the AKMA path: the NEF publishes `3gpp-akma` and accepts only the tokens of the CCF; the AF outside the operator network is an API invoker.
- **The AAnF** sends its heart-beat to the NRF and the headers of TS 29.500; the AUSF and the NEF reuse the result of the search for the AAnF and select any AAnF for the default Routing Indicator.
- **Recommendations** grow: F21 to F31 for free5GC and AA to AP for 3GPP (below).
- 333 end-to-end checks instead of 161. Upgrading from V2: [docs/install.md](docs/install.md#14-upgrading-from-v2).

## Recommendations

What this work found in the three projects it builds on, each item with the clause of the specification that says what to do:

- [docs/free5gc-fixes.md](docs/free5gc-fixes.md): thirty-one changes for free5GC (F1 to F31), with the patches of this repository and a table by free5GC repository, checked again in free5GC v4.3.0;
- [docs/3gpp-recommendations.md](docs/3gpp-recommendations.md): twenty-seven errors and fourteen gaps in the 3GPP specifications (A to Z and AA to AP), grouped by working group and checked in the latest published versions;
- [docs/ueransim-recommendations.md](docs/ueransim-recommendations.md): four items for UERANSIM, checked in release v3.3.0 and in `master`.

## Limitations

Read these before you use any of it outside a test bed.

- **Test PKI.** The CA of the operator and the CA of the CCF are made by scripts, with keys without a password on the free5GC host. Revocation is by CRL over HTTP only, without OCSP; the CRL of the operator is valid for one week and has to be signed again. No automatic enrolment of certificates (TS 33.310 cl. 10).
- **Partial CAPIF.** Only the AKMA path: one CCF, one API provider (the NEF), security method `OAUTH` only, no events, logging or auditing; the CCF keeps its state in memory.
- **Ua\* profiles.** K.2 and the two PSK profiles of TS 24.109 Annex K, DTLS (TS 33.535 Annex C) with CoAP, and OSCORE (Annex D). Annex D leaves the form of several fields open, and this repository takes its own choices for them ([docs/ua-profiles.md](docs/ua-profiles.md) section 4). RFC 7252 asks CoAP in PSK mode for `TLS_PSK_WITH_AES_128_CCM_8`, which TS 33.210 forbids; the DTLS profiles follow TS 33.210. wolfSSL has no `TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384`, which TS 33.210 recommends; the certificate of K.2 comes from a test CA, without OCSP. The simplified Ua\* (`FF00000001`), HTTP Digest without TLS, is a test profile, off by default. See [docs/ua-profiles.md](docs/ua-profiles.md).
- **Applications in the UE.** The key service of the ME tells applications apart by user (uid). The executable is checked on a best-effort basis. K_AKMA never leaves the ME.
- **Not implemented:**
  - the ROAMING_STATUS subscription (TS 33.535 cl. 6.2.1 step 5) and the `RoamingRestriction` feature;
  - GPSI, i.e. the `AKMA_GPSI_Support` feature and the GPSI to the external AF;
  - SUPI types other than IMSI;
  - NFKC in the UE: a non-ASCII AF FQDN is refused there;
  - AS key re-keying after the refresh of K_AKMA, and the refresh over non-3GPP access: UERANSIM has no AS security, and the test bed has no non-3GPP access;
  - more than one AAnF;
  - persistence: the AAnF and the CCF keep their state in memory.
- **free5GC tools.** The web console of free5GC does not talk to the NRF over mutual TLS; the free5GC test bench keeps the SBI on `http`.
- **Versions.** The patches are for free5GC v4.2.3 (NRF, UDM, AUSF and AMF v1.4.5, NEF v1.2.5, `openapi` v1.2.4 and, for the AMF and the test bench, v1.2.5-0.20260527003827-02dc71b4d94f, `util` v1.3.2) and UERANSIM v3.2.6 commit `85a0fbf`. free5GC v4.3.0 and UERANSIM v3.3.0 are out; the patches are not rebased on them yet.
- **Open points in free5GC.** Some fixes are still open, among them the heart-beat of the free5GC NFs, the headers of TS 29.500 in every NF and the event exposure of the roaming status by SUPI. See [docs/free5gc-fixes.md](docs/free5gc-fixes.md).

## Repository layout

```
shared/akma/              Go library: KDF, SUPI, A-KID, AF_ID, encodings; test vectors
shared/crosscheck/        the KDF of shared/akma against the one of free5gc/util
reference/kdf/            Python oracle and vector generator
free5gc/aanf/             the AAnF and the seed test tool
free5gc/ccf/              the CAPIF core function
free5gc/crl/              the service of the certificate revocation lists
free5gc/config/           aanfcfg.yaml, ccfcfg.yaml, crlcfg.yaml, sba-entities.conf
free5gc/patches/          patches for free5GC, one directory per target
free5gc/scripts/          build, deploy, patch, certificates, provision, N6 NAT
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
af/config/                AF configurations (inside the operator network, and outside as API invoker)
af/scripts/               build (wolfSSL, test CA, AF), UE namespace, UERANSIM patches, end-to-end run, negative tests, OSCORE check
docs/                     the documentation above
```

## License

Copyright 2026 Floriano Neto.

Apache License 2.0 ([LICENSE](LICENSE)), the license of free5GC. The free5GC patches modify free5GC, which is licensed under the same license.

The patches in `af/ue/ueransim/patches/` modify UERANSIM, which is licensed under the GNU General Public License v3.0. They are distributed under the same license ([COPYING](af/ue/ueransim/patches/COPYING)).

`af/wolftls/` and `af/scripts/build-wolfssl.sh` use wolfSSL, which is licensed under the GNU General Public License v3.0, and are distributed under the same license ([COPYING](af/wolftls/COPYING)). The AF and client binaries built with wolfSSL (build tag `wolfssl`) are covered by it as well.

3GPP specifications are not included. They are cited by number and clause and can be downloaded from [3gpp.org](https://www.3gpp.org/specifications).
