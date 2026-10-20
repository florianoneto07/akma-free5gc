# akma-free5gc

AKMA (Authentication and Key Management for Applications, 3GPP TS 33.535, Release 19) on top of [free5GC](https://github.com/free5gc/free5gc) v4.2.3 and [UERANSIM](https://github.com/aligungr/UERANSIM) v3.2.6.

After a successful primary authentication, the UE and the network derive K_AKMA and an A-KID from K_AUSF. An application function (AF) then gets a K_AF for that A-KID from the AAnF and uses it to authenticate the UE, without a separate credential. free5GC has no AAnF and none of its NFs do AKMA; this repository adds what is missing.

## What is in here

| Part | What it does |
|---|---|
| `free5gc/aanf/` | **AAnF**, the AKMA Anchor Function (TS 33.535 cl. 4.2.1, Naanf_AKMA of TS 29.535). A new NF with the same layout as the free5GC NFs. It installs as a binary in `bin/` and a file in `config/`, and changes no file of free5GC |
| `free5gc/patches/` | Patches for free5GC: NRF, UDM, AUSF, NEF, `openapi` (Naanf_AKMA models and client), configuration, `run.sh` and the Go test bench |
| `af/ue/ueransim/patches/` | Patches for UERANSIM: the ME derives K_AKMA, the A-KID and K_AF, `nr-cli` hands A-KID and K_AF to an application, and `nr-akma-selftest` checks the derivations |
| `af/af/`, `af/uastar/`, `af/ue/uaclient/` | A test AF and a Ua\* client, with a simplified Ua\* protocol: HTTP Digest (RFC 7616) keyed with K_AF, without TLS |
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
| Ua\* between the UE and the AF over the PDU session | cl. 6.2.1 steps 1 and 9 | simplified protocol, see the limitations |

The derivations agree in four implementations: the Python oracle, `shared/akma`, the KDF that free5GC already uses for K_SEAF, and the patched UERANSIM. `af/scripts/e2e.sh` runs 83 checks against a running core: the flows above, re-authentication, the AAnF down during an authentication, a subscriber without AKMA, the negative cases of the AAnF and NEF APIs, and no key in any log.

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
   UE (UERANSIM) ─── Ua*: A-KID, HTTP Digest keyed with K_AF, over the PDU session ───▶ AF
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
3. On the free5GC host, patch the NFs: `patch-nf.sh nrf|udm|ausf|nef|config|run apply`.
4. Give a subscriber an AKMA subscription: `provision-akma-subscriber.sh imsi-208930000000001 0000`.
5. Patch UERANSIM: `af/scripts/patch-ueransim.sh apply`.
6. Build and start the AF: `af/scripts/build-af.sh` and `af/build/bin/af -c af/config/afcfg.yaml`.
7. Run everything end to end from the AF host: `af/scripts/e2e.sh user@free5gc-host`.

The example configuration files carry the addresses of the example topology. [docs/install.md](docs/install.md) lists every place to change for yours.

## Documentation

| Document | Content |
|---|---|
| [docs/install.md](docs/install.md) | Installation guide, step by step, on one host and with UERANSIM on another host |
| [docs/free5gc-fixes.md](docs/free5gc-fixes.md) | What free5GC has to change for AKMA: for each point, what free5GC does, where the specification says what to do, and how |
| [docs/aanf.md](docs/aanf.md) | The AAnF: configuration, operations, authorization, errors |
| [docs/nef-akma-api.md](docs/nef-akma-api.md) | The AKMA API of the NEF for AFs outside the operator network |
| [docs/ua-star.md](docs/ua-star.md) | The simplified Ua\* protocol of the test AF and client |
| [docs/testing.md](docs/testing.md) | Unit tests, test vectors and the end-to-end script |

## Limitations

Read these before you use any of it outside a test bed.

- **No TLS.** The SBI runs on h2c, and the NEF–AF interface on plain HTTP. TS 33.535 cl. 4.4.0 and TS 33.501 cl. 12 and 13.1 require protection. The AAnF and the NEF bind each AF_ID to source addresses (local policy). That limits which AF_ID a host can ask for, but it does not authenticate the AF.
- **Simplified Ua\*.** The test AF and client use the HTTP Digest of TS 24.109 K.2 without the TLS tunnel, under the private-range Ua\* identifier `FF00000001`. It is not one of the normative profiles (TS 33.535 Annex B, TS 24.109 Annex K). See [docs/ua-star.md](docs/ua-star.md).
- **Token issuer of the external AF.** free5GC has no CAPIF, so the AF outside the operator network gets its NEF access token from the NRF. The specified path is the CAPIF Core Function (TS 29.522 cl. 7.2).
- **`nr-cli` as the application interface of the UE.** It hands the K_AF of any AF to any local process. K_AKMA never leaves the ME.
- **Not implemented:**
  - the ROAMING_STATUS subscription (TS 33.535 cl. 6.2.1 step 5) and the `RoamingRestriction` feature;
  - GPSI, i.e. the `AKMA_GPSI_Support` feature and the GPSI to the external AF;
  - SUPI types other than IMSI;
  - NFKC in the UE: a non-ASCII AF FQDN is refused there;
  - the per-operation scopes of TS 29.535 table 5.1.9-1;
  - more than one AAnF;
  - persistence: the AAnF keeps its contexts in memory.
- **Versions.** The patches are for free5GC v4.2.3 (NRF, UDM and AUSF v1.4.5, NEF v1.2.5, `openapi` v1.2.4) and UERANSIM v3.2.6 commit `85a0fbf`. Other versions need the patches rebased.
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
af/uastar/                the simplified Ua* protocol (HTTP Digest)
af/ue/uaclient/           the Ua* client of the UE
af/ue/ueransim/patches/   patches for UERANSIM (GPL-3.0)
af/config/                AF configurations (inside and outside the operator network)
af/scripts/               build, UE namespace, UERANSIM patches, end-to-end run, negative tests
docs/                     the documentation above
```

## License

Copyright 2026 Floriano Neto.

Apache License 2.0 ([LICENSE](LICENSE)), the license of free5GC. The free5GC patches modify free5GC, which is licensed under the same license.

The patches in `af/ue/ueransim/patches/` modify UERANSIM, which is licensed under the GNU General Public License v3.0. They are distributed under the same license ([COPYING](af/ue/ueransim/patches/COPYING)).

3GPP specifications are not included. They are cited by number and clause and can be downloaded from [3gpp.org](https://www.3gpp.org/specifications).
