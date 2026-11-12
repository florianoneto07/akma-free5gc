# Changelog

## V3 — 2026-11-12

Tested on free5GC v4.2.3 and UERANSIM v3.2.6 (commit `85a0fbf`): `af/scripts/e2e.sh` with 333 checks, none failed, none skipped, with OpenSSL 4.1 and libcoap as the independent clients. Not yet followed on a clean install. Upgrading from V2: [docs/install.md](docs/install.md#14-upgrading-from-v2).

### Added

- **Mutual TLS on the SBI** ([docs/sbi-tls.md](docs/sbi-tls.md); TS 33.501 cl. 13.1; TS 33.310):
  - a test PKI of the operator (`free5gc/scripts/make-sba-certs.sh`, `free5gc/config/sba-entities.conf`): a CA, one certificate per NF in the profile of TS 33.310 table 6.1.3c.3-1, with the NF instance ID, the FQDN and the NF type, the certificate that signs the access tokens of the NRF (table 6.1.3c.3-2), test certificates and a check of every profile;
  - a CRL service (`free5gc/crl/`, `run.sh -crl`); the CRL is checked at both ends of every connection, and a connection without a valid CRL is refused;
  - `openapi/0005`: the package `sbitls`, with the TLS profile of TS 33.210 cl. 6.2, the CA and the CRL; the SBI client checks the server and presents the certificate of the NF (F21), and builds the URIs by name (F24);
  - `util/0001`: no TLS secrets written to a key log (F22);
  - one `*-sbi-tls` patch per NF, with `sbi.fqdn` and `sbi.tls.ca`, and the configuration over `https` by name (`config/0004`);
  - the AAnF, `seed` and the AF as TLS clients and servers.
- **Identity in the access tokens and in the policies:**
  - `nrf/0005` and `openapi/0006`: tokens in `ES256` with `kid`, `x5t#S256` and `iss` (F23, F26); the NRF checks each request against the certificate of the TLS session (F25); scopes per operation and NF type with `allowedOperationsPerNfType` (F4); every producer checks `iss`, `aud`, `sub`, `exp` and the scope, with the answers of TS 29.500 cl. 6.7.3 (F5, F12);
  - the AAnF knows the AF and the NEF by the NF instance ID of their certificates, without source addresses, and checks the scopes of each operation of Naanf_AKMA;
  - `nrf/0006`: the scope is checked on the registered profiles of the target type, or on the profile of the requested instance (F27), and `Nnrf_AccessToken_RetrieveKey` (F28, with `openapi/0008`).
- **CAPIF** ([docs/capif.md](docs/capif.md); TS 29.522 cl. 7; TS 29.222; TS 33.122):
  - the CCF (`free5gc/ccf/`): onboarding and offboarding of API invokers, publication and discovery of APIs, security method `OAUTH`, access tokens in `ES256`, information on the invokers for the NEF, the CRL of its CA;
  - `openapi/0004` and `0007`: the CAPIF models and clients;
  - `nef/0002` and `nef/0005`: the NEF as API publishing and exposing function, `check-authentication`, the token of the CCF bound to the client certificate of the AF, `allowNrfTokens: false`;
  - the AF outside the operator network as API invoker (`af/config/afcfg-capif.yaml`);
  - `run.sh -ccf`; `free5gc/scripts/build-ccf.sh` and `make-capif-certs.sh`.
- **AAnF:** the heart-beat to the NRF (`heartBeatTimer`, TS 29.510 cl. 5.2.2.3.2; F29); `Server` and `3gpp-Sbi-NF-Peer-Info` in its answers, and an `SBI` log line with the `User-Agent` of each request (TS 29.500; F31).
- **AUSF and NEF** (`ausf/0004`, `nef/0006`): any AAnF for the default Routing Indicator (TS 33.535 cl. 6.7); the result of the search reused during its validity period (TS 29.510 cl. 5.3.2.2.1); `User-Agent` and `3gpp-Sbi-NF-Peer-Info` towards the AAnF. The NEF asks the AAnF with `Naanf_AKMA_ApplicationKey_Get`, also for an anonymous AF (TS 33.535 cl. 6.3 step 3).
- **FQDN required with `https`** in every NF, the AAnF and the internal server of the CCF (TS 29.510 table 6.1.6.2.2-1 NOTE 1): one `*-fqdn-required` patch per NF and `config/0007`.
- **End-to-end script:** 333 checks instead of 161: every port of the SBI with Python clients (`af/scripts/negative/sbi_tls.py`, `sbi_token.py`), the profiles of the certificates, the CRL, the identity in the tokens and in the policies, CAPIF with a second invoker in Python (`af/scripts/negative/capif_api.py`), `retrieve-key`, the heart-beat and the headers of TS 29.500.
- **Recommendations:** [docs/free5gc-fixes.md](docs/free5gc-fixes.md) grows from F1–F20 to F1–F31, and [docs/3gpp-recommendations.md](docs/3gpp-recommendations.md) from A–Z to A–AP.

### Changed

- Every example configuration runs the SBI over `https`, by name; the names resolve through `/etc/hosts`.
- `akma.authorizedAfs` and `akma.authorizedNefs` of the AAnF name the NF instance IDs of the certificates (`nfInstanceIds`) in place of source addresses.
- `af/config/afcfg-external.yaml` and the SSH tunnel to the NRF are gone: the AF outside the operator network gets its token from the CCF.
- `free5gc/scripts/deploy.sh` also installs the CRL service.

## V2 — 2026-10-29

Tested on free5GC v4.2.3 and UERANSIM v3.2.6 (commit `85a0fbf`): `af/scripts/e2e.sh` with 161 checks, none failed, also on a clean install that followed only [docs/install.md](https://github.com/florianoneto07/akma-free5gc/blob/v2.0.0/docs/install.md). Upgrading from V1: [docs/install.md of V2](https://github.com/florianoneto07/akma-free5gc/blob/v2.0.0/docs/install.md#12-upgrading-from-v1).

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

First public version, tested on free5GC v4.2.3 and UERANSIM v3.2.6 (commit `85a0fbf`): `af/scripts/e2e.sh` with 83 checks, none failed, also on a clean install that followed only [docs/install.md](https://github.com/florianoneto07/akma-free5gc/blob/v1.0.0/docs/install.md).

- The AAnF (Naanf_AKMA, TS 29.535) and the `seed` test tool.
- Patches for free5GC: NRF (`aanfInfoList`, discovery of the AAnF by Routing Indicator, `aud` of the access token), UDM (AKMA indication and Routing Indicator), AUSF (K_AKMA, A-KID and registration at the AAnF), NEF (`3gpp-akma`), `openapi` (Naanf_AKMA), configuration, `run.sh` and the test bench.
- Patches for UERANSIM: K_AKMA, A-KID and K_AF in the ME; `nr-akma-selftest`.
- A test AF and a Ua\* client with a simplified Ua\* (HTTP Digest keyed with K_AF), directly and through the NEF; anonymous user access; AKMA context removal.
- The KDF in Go (`shared/akma`) and in Python (`reference/kdf`), with test vectors.
- [docs/free5gc-fixes.md](docs/free5gc-fixes.md) with F1 to F15.
