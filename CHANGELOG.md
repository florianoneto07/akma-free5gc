# Changelog

## V2 — 2026-10-29

Tested on free5GC v4.2.3 and UERANSIM v3.2.6 (commit `85a0fbf`): `af/scripts/e2e.sh` with 161 checks, none failed, also on a clean install that followed only [docs/install.md](docs/install.md). Upgrading from V1: [docs/install.md](docs/install.md#12-upgrading-from-v1).

### Added

- **Ua\* profiles of the specifications**, in the test AF and the Ua\* client ([docs/ua-profiles.md](docs/ua-profiles.md)):
  - HTTP Digest inside TLS 1.3 and 1.2 (TS 24.109 K.2), the AF authenticated by its certificate;
  - TLS 1.3 and TLS 1.2 with K_AF as pre-shared key (K.3), through a cgo binding to wolfSSL (`af/wolftls`, GPL-3.0), with session resumption;
  - DTLS 1.3 and 1.2 with K_AF (TS 33.535 Annex C), with CoAP inside (`af/coap`);
  - OSCORE (TS 33.535 Annex D): `POST /akma` in CBOR and CoAP protected with a context from K_AF, with the renewal of RFC 8613 Appendix B.2 (`af/oscore`, `af/cbor`, `af/akmaoscore`);
  - one AF_ID per profile and cipher suite (TS 33.220 H.3) in the policies of the AAnF, the NEF and the UE.
- **Key service of the ME** (UERANSIM patch `0005`): each application gets only the K_AF of its own AF_IDs (TS 33.535 cl. 4.4.3); `akma-kaf` of `nr-cli` is off by default.
- **Refresh of K_AKMA by the AAnF** (TS 33.535 cl. 6.4.4; TS 33.501 cl. 6.1.5):
  - AAnF: `akma.kakmaRefresh`, off by default; `Nudm_UECM_AuthTrigger` to the UDM it discovers at the NRF;
  - `openapi/0003`: the models and clients of the primary authentication triggered by the home network;
  - `udm/0002`: `trigger-auth` (POST) and the notification to the AMF;
  - `amf/0001` (new): the re-authentication of a registered UE, followed by the NAS SMC;
  - `seed trigger-auth`.
- **End-to-end script:** 161 checks instead of 83: every Ua\* profile from the UE, OpenSSL 4.1 as an independent DTLS 1.3 client and libcoap as an independent OSCORE client (both optional), the expiry of K_AF in TLS sessions, the key service of the ME, the refresh of K_AKMA.
- **Recommendations:** [docs/3gpp-recommendations.md](docs/3gpp-recommendations.md) (new) and [docs/ueransim-recommendations.md](docs/ueransim-recommendations.md) (new); [docs/free5gc-fixes.md](docs/free5gc-fixes.md) grows from F1–F15 to F1–F20, with a table by free5GC repository. All checked again on 28 October 2026 in the latest versions: 3GPP Release 19 and 20, free5GC v4.3.0, UERANSIM v3.3.0.

### Changed

- The simplified Ua\* of V1 (HTTP Digest without TLS) is now the test profile `digest-http`, off by default.
- `af/scripts/build-af.sh` builds with wolfSSL when `af/scripts/build-wolfssl.sh` has run; `af/scripts/make-test-ca.sh` makes the certificate of K.2.
- `free5gc/scripts/build-aanf.sh` prepares `openapi` again when a patch is missing.

## V1 — 2026-10-20

First public version, tested on free5GC v4.2.3 and UERANSIM v3.2.6 (commit `85a0fbf`): `af/scripts/e2e.sh` with 83 checks, none failed, also on a clean install that followed only [docs/install.md](docs/install.md).

- The AAnF (Naanf_AKMA, TS 29.535) and the `seed` test tool.
- Patches for free5GC: NRF (`aanfInfoList`, discovery of the AAnF by Routing Indicator, `aud` of the access token), UDM (AKMA indication and Routing Indicator), AUSF (K_AKMA, A-KID and registration at the AAnF), NEF (`3gpp-akma`), `openapi` (Naanf_AKMA), configuration, `run.sh` and the test bench.
- Patches for UERANSIM: K_AKMA, A-KID and K_AF in the ME; `nr-akma-selftest`.
- A test AF and a Ua\* client with a simplified Ua\* (HTTP Digest keyed with K_AF), directly and through the NEF; anonymous user access; AKMA context removal.
- The KDF in Go (`shared/akma`) and in Python (`reference/kdf`), with test vectors.
- [docs/free5gc-fixes.md](docs/free5gc-fixes.md) with F1 to F15.
