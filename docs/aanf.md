# AAnF — AKMA Anchor Function

TS 33.535 cl. 4.2.1: the AAnF is the AKMA anchor function in the HPLMN. It stores K_AKMA and the A-KID that the AUSF sends after the primary authentication. It derives and hands K_AF to each authorized AF, and deletes the context on request. Its service is Naanf_AKMA (TS 29.535).

The AAnF here is a new NF with the layout of the free5GC v4.2.3 NFs (`cmd`, `pkg/factory`, `pkg/service`, `internal/context`, `internal/sbi/{processor,consumer}`). It runs on the free5GC host and changes no file of free5GC.

| File | Content |
|---|---|
| `free5gc/aanf/cmd/main.go` | entry point (`-c` configuration, `-l` log) |
| `free5gc/aanf/pkg/factory/` | reading and validation of `aanfcfg.yaml` |
| `free5gc/aanf/pkg/service/init.go` | life cycle: context, SBI server, registration at the NRF and deregistration |
| `free5gc/aanf/internal/context/context.go` | NF context, token checks, AF and NEF policies |
| `free5gc/aanf/internal/context/akma_context.go` | storage of the AKMA contexts |
| `free5gc/aanf/internal/sbi/` | SBI server (mutual TLS, or h2c with `http`), routes, protocol errors, the headers of TS 29.500, the three operations, Nnrf_NFManagement with the heart-beat, the client of the UDM |
| `free5gc/aanf/internal/util/problem.go` | `ProblemDetails` |
| `free5gc/aanf/tools/seed/` | test tool that plays the AUSF, the AF and the OAM, as a TLS client with the certificate of each role |
| `free5gc/config/aanfcfg.yaml` | example configuration |
| `free5gc/scripts/{prepare-openapi,build-aanf,run-aanf,deploy}.sh` | preparation, build, run, deployment |
| `free5gc/scripts/make-sba-certs.sh` | the certificate of the AAnF and of its consumers ([sbi-tls.md](sbi-tls.md)) |

On the free5GC host:

| Path | Origin |
|---|---|
| `~/free5gc/bin/aanf` | new file, static binary |
| `~/free5gc/config/aanfcfg.yaml` | new file |
| `~/free5gc/log/aanf/` | created by `run-aanf.sh` (log, output, pid). With `./run.sh -aanf` the log goes to the `free5gc.log` of the other NFs |
| `~/free5gc/cert/sba/aanf.pem`, `aanf.key` | made by `make-sba-certs.sh`; the NRF no longer makes certificates |

Dependencies: `free5gc/openapi` v1.2.4 with the patches of `free5gc/patches/openapi/` (Naanf_AKMA, the TLS of the SBI, the checks of the access tokens, `retrieve-key`), `free5gc/util` v1.3.2, `shared/akma`.

## 1. Configuration

On top of the fields that all free5GC NFs have (`sbi`, `serviceNameList`, `nrfUri`, `nrfCertPem`, `plmnSupportList`, `logger`). The SBI port is **8010**: the free5GC NFs use 8000, and none of them uses 8010. `nrfUri` is the name of the NRF, `https://nrf.5gc.mnc093.mcc208.3gppnetwork.org:8000`, and `nrfCertPem` its token signing certificate, `cert/sba/nrf-token.pem`.

| Field | Example | Rule | Specification |
|---|---|---|---|
| `nfInstanceId` | fixed UUID v4 | the one of the certificate of the AAnF, in `sba-entities.conf`; without it, a new one at each start, which the NRF refuses with TLS | TS 33.310 cl. 6.1.3c.3 |
| `sbi.scheme` | `https` | `https`, mutual TLS; `http` is h2c, without TLS | TS 33.501 cl. 13.1.0 |
| `sbi.fqdn` | `aanf.5gc.mnc093.mcc208.3gppnetwork.org` | required with `https`: the AAnF does not start without it | TS 29.510 table 6.1.6.2.2-1 NOTE 1 |
| `sbi.tls.pem`, `sbi.tls.key`, `sbi.tls.ca` | `cert/sba/aanf.pem`, `…/aanf.key`, `…/sba-ca.pem` | the certificate of the AAnF and the CA of the operator, which checks the peers | TS 33.310 cl. 6.1.3c |
| `heartBeatTimer` | `60` | seconds, 0 to 3600; the interval proposed to the NRF at registration, whose answer prevails; 0 or absent, the default of 60 s (section 10) | TS 29.510 cl. 5.2.2.3.2 |
| `serviceNameList` | `[naanf-akma]` | the only accepted value | TS 29.535 cl. 5.1.1 |
| `routingIndicators` | `["0000"]` | strings of 1 to 4 digits; empty means any RID. `0000` without quotes is still read as `"0000"` | TS 29.510 `AanfInfo`; TS 23.003 cl. 2.2B |
| `akma.kafLifetime` | `1h` | positive Go duration; default `1h` | operator policy, TS 33.535 cl. 5.2 |
| `akma.kakmaRefresh` | `0` | Go duration; `0` or absent, the default, turns it off. With a value, a K_AF request for a K_AKMA registered longer ago makes the AAnF ask the UDM for a new primary authentication (section 8) | operator policy, TS 33.535 cl. 6.4.4 |
| `akma.authorizedAfs[].afId` | `af1.akma.example.FF00000001` | transport form `<FQDN>.<10 hex digits>` | TS 29.522 `AfId` |
| `akma.authorizedAfs[].nfInstanceIds` | `[2170454b-…]` | at least one: the NF instance IDs of the client certificates of the AF | local policy, section 4; TS 33.501 cl. 13.1.0 |
| `akma.authorizedNefs[].nfInstanceIds` | `[8e73ad07-…]` | at least one: the NF instance ID of the certificate of the NEF | section 5 |
| `akma.authorizedNefs[].afIds` | `[af1.akma.example.FF00000001]` | at least one AF_ID in transport form: the external AFs accepted from that NEF | TS 33.535 cl. 6.3 step 3 |
| `akma.roamingStatusSubscription` | `false` | `true` stops the start: not implemented | TS 33.535 cl. 6.2.1 step 5 |
| `akma.aKid` | `atidEncoding`, `atidLabel`, `acceptLabels` | default: base64, writes `atid`, accepts `atid` and `akid` | see section 2.4 |

## 2. Operations

TS 29.535 table 5.1.4.1-1: three custom operations, all `POST` on `{apiRoot}/naanf-akma/v1/`.

### 2.1 `register-anchorkey` — Naanf_AKMA_AnchorKey_Register

TS 29.535 cl. 4.2.2.2.2; TS 33.535 cl. 6.1 steps 4 and 5. Body `AkmaKeyInfo`; answer 200 with the stored `AkmaKeyInfo`.

- `supi`, `aKId` and `kAkma` are mandatory. Table 5.1.6.2.2-1, NOTE: without the `AKMA_GPSI_Support` feature, *"only the supi attribute shall be present"*. A missing one gives 400 `MANDATORY_IE_MISSING`, with `invalidParams`.
- `gpsi` present gives 400 `OPTIONAL_IE_INCORRECT`. The specification gives no cause for an attribute that should not be there; this is the closest one in TS 29.500 table 5.2.7.2-1.
- An `aKId` that is not in the NAI format of TS 29.522, or a `kAkma` that is not 64 hex digits, gives 400 `MANDATORY_IE_INCORRECT`.
- `supi` is only checked for being non-empty. The `Supi` pattern of TS 29.571 accepts any non-empty string, and the AAnF does not put the SUPI into the KDF.

### 2.2 `retrieve-applicationkey` — Naanf_AKMA_ApplicationKey_Get and _AnonUser_Get

TS 29.535 cl. 4.2.2.3.2; TS 33.535 cl. 6.2.1 and 6.2.2. Body `AkmaAfKeyRequest`. The checks follow the order of cl. 6.2.1:

1. format: `afId` and `aKId` present and well formed (400);
2. step 2, authorization of the AF by local policy (section 4), or of the NEF (section 5): 403 without `cause`;
3. step 2, K_AKMA present for the A-KID: otherwise 403 `K_AKMA_NOT_PRESENT`;
4. step 7, K_AF: reused if the context already has a valid one derived from the current K_AKMA; otherwise derived (TS 33.535 A.4) and stored with its expiry;
5. step 8, answer 200 with `kaf` (64 lowercase hex digits) and `expiry` (RFC 3339, UTC, in seconds). `supi` too, except when `anonInd` is `true` (TS 29.535 table 5.1.4.3.2-2 NOTE 2). `gpsi` is never sent.

What the AAnF never answers:

- **204.** TS 29.535 cl. 4.2.2.3.2 has a 204 for *"requested AKMA Application Key information … does not exist"*. Without K_AKMA the answer is 403 `K_AKMA_NOT_PRESENT` (same clause), and with K_AKMA a K_AF can always be derived, so no case is left for the 204.
- **`ROAMING_AKMA_SERVICE_DENIED`.** The roaming status is not subscribed, and the `RoamingRestriction` feature is not supported.

`notifUri` is ignored. TS 29.522 table 5.14.5.3.2-1 ties it to `RoamingRestriction`. No implicit subscription is created.

### 2.3 `remove-context` — Naanf_AKMA_ContextRemove

TS 29.535 cl. 4.2.2.4.2; TS 33.535 cl. 6.6.1. Body `CtxRemove` with `supi`, mandatory in this release (table 5.1.6.2.3-1 NOTE). It deletes the SUPI, the A-KID, K_AKMA and the K_AFs handed out, and answers 204. Without a context, it answers 404 `AKMA_CONTEXT_NOT_FOUND`. The consumer named by the specification is the OAM (TS 29.535 cl. 4.2.1.3.2 and table 4.2.2.1-1); `seed remove` plays it.

### 2.4 Features and the A-KID format

TS 29.535 cl. 5.1.8; TS 29.500 cl. 6.6. The AAnF supports neither optional feature (`AKMA_GPSI_Support`, `RoamingRestriction`). When the consumer sends `suppFeat`, the answer has `suppFeat: "0"`, the empty intersection. Without `suppFeat` in the request, the answer has none.

The A-KID is `rid<RID>.atid<A-TID>@5gc.mnc<MNC>.mcc<MCC>.3gppnetwork.org` (TS 33.535 cl. 6.1; TS 29.522 table 5.14.5.4.2-1). No specification fixes how the 256-bit A-TID is written as text. The default is base64 with padding (RFC 4648 cl. 4, 44 characters), by analogy with the GBA B-TID, `base64encode(RAND)` (TS 33.220 cl. 4.5.2). The text of table 5.14.5.4.2-1 says `atid`, and the example in the same table says `akid`. The AAnF writes `atid` and accepts both. `kAkma` and `kaf` are 64 hex digits, as `Kausf` in TS 29.503.

## 3. Storage

In memory (`internal/context/akma_context.go`), lost when the AAnF restarts. Indexed by SUPI and by A-KID, under a mutex.

| Rule | Specification |
|---|---|
| The AAnF keeps the latest pair sent by the AUSF. The new pair replaces the old one, and the old A-KID no longer identifies a K_AKMA | TS 33.535 cl. 6.1 step 4 and NOTE 1a |
| K_AFs already handed out stay in the context until they expire | cl. 5.2 |
| A K_AF is derived only when the context has no valid one for the AF from the current K_AKMA; the stored expiry is returned until it is reached | cl. 6.2.1 step 7; cl. 5.2 NOTE |
| A-KIDs are compared by content: RID as a string (`"0000"` is not `"000"`), A-TID as octets, realm without case | TS 23.003 cl. 2.2B; the realm is a domain name |
| A-TID collision between SUPIs: the index keeps the latest registration | cl. 6.1 NOTE 2 leaves detection and handling open |
| Deleted keys are overwritten with zeros (best effort) | — |

## 4. Authorization

**Access tokens.** TS 29.535 cl. 5.1.9: access *"may be authorized"* with OAuth2, by local configuration; the NRF tells the AAnF whether OAuth2 is on. The token is checked as TS 33.501 cl. 13.4.1.1.2 step 2 says, with the checks of `openapi/0006` that every NF uses ([sbi-tls.md](sbi-tls.md), section 5): `ES256` with the signing certificate of the NRF, `kid` and `x5t#S256`, `iss`, `aud` (the `nfInstanceId` of the AAnF or `AANF`), `sub` equal to the client certificate of the session, `exp`, and the scopes of the operation (TS 29.535 table 5.1.9-1):

| Operation | Scopes required |
|---|---|
| `register-anchorkey`, `remove-context` | `naanf-akma` and `naanf-akma:anchorkey` |
| `retrieve-applicationkey` | `naanf-akma` and `naanf-akma:applicationkeyget`; the answer has `supi` only with `naanf-akma:applicationkeyget:supi-access` |

The AAnF registers the scopes of each NF type in `allowedOperationsPerNfType`, and the NRF only grants those (TS 29.510 table 6.1.6.2.3-1 NOTE 11): `naanf-akma:anchorkey` to the AUSF, `applicationkeyget` and `supi-access` to the NEF and to the AF. A missing or invalid token gives 401, with `WWW-Authenticate: Bearer` (or `error="invalid_token"`) and `ProblemDetails`; a token for another producer or of another client gives 403 `ACCESS_TOKEN_CLAIM_MISMATCH`; a missing scope gives 403 with `error="insufficient_scope"` (TS 29.500 cl. 6.7.3). `register-anchorkey` and `remove-context` always need the token when OAuth2 is on.

**`retrieve-applicationkey`: local policy by certificate.** TS 33.535 cl. 6.2.1 step 2: the AAnF checks the request *"based on the configured local policy or based on the authorization information available in the signalling (i.e., Oauth2.0 token)"*. An AF inside the operator network does not need to reach the NRF, so the request may come without a token, and the local policy applies. The identity of the consumer is the NF instance ID in the URI of its client certificate, and its type the `nfTypes` of the certificate (TS 33.310 cl. 6.1.3c.3; TS 33.501 cl. 13.1.0):

- each authorized AF_ID is bound to the NF instance IDs of the AF that may ask for it, and the certificate has to be of type `AF`;
- the source address is only logged;
- the FQDN is compared exactly, since it goes into the KDF.

An AF outside the policy, or an AF_ID asked with the certificate of another AF, gets 403 without `cause`: no cause is defined for it. With `sbi.scheme: http`, as in the free5GC test bench, there is no certificate, and the policy is only the list of AF_IDs.

## 5. Requests relayed by a NEF

TS 33.535 cl. 6.3 step 3: through the NEF, the AAnF handles the request as in cl. 6.2.1. The specification has no separate step for recognizing the NEF. The AAnF knows it by its certificate, with `akma.authorizedNefs`:

```yaml
configuration:
  akma:
    authorizedNefs:
      - nfInstanceIds:
          - 8e73ad07-906c-4952-93ac-cd32bbb076ed # the certificate of the NEF
        afIds:
          - af1.akma.example.FF00000001
```

1. If the request has `Authorization`, the token is checked as in section 4. Invalid: 401 or 403.
2. When the certificate is of type `NEF` and its NF instance ID is in an `authorizedNefs` entry, with a valid token or with OAuth2 off, the request is taken as coming from the NEF. The `afId` has to be in the `afIds` of that entry; otherwise 403 without `cause`.
3. In every other case `authorizedAfs` applies (section 4).

Without `authorizedNefs` there is no NEF path. The NEF asks with `Naanf_AKMA_ApplicationKey_Get`, also for an anonymous AF, and gets the SUPI, which it does not pass on (TS 33.535 cl. 6.3 steps 3 and 5).

## 6. Errors

TS 29.535 cl. 5.1.7.1; TS 29.500 table 5.2.7.1-1 and cl. 5.2.7.2. Every error answer carries `ProblemDetails` in `application/problem+json`, and the headers of section 10. Tests in `free5gc/aanf/internal/sbi/api_akma_test.go`.

| Code | When | Cause |
|---|---|---|
| 400 | invalid JSON or wrong type; mandatory attribute missing or wrong; API version other than `v1` | `INVALID_MSG_FORMAT`, `MANDATORY_IE_MISSING`, `MANDATORY_IE_INCORRECT`, `OPTIONAL_IE_INCORRECT`, `INVALID_API` |
| 401 | token missing or invalid (section 4) | `ACCESS_TOKEN_CLAIM_MISSING` when a claim is missing |
| 403 | no K_AKMA; AF or NEF not authorized; token of another producer or client; missing scope | `K_AKMA_NOT_PRESENT`; no cause; `ACCESS_TOKEN_CLAIM_MISMATCH`; no cause, with `insufficient_scope` |
| 404 | no context to remove; unknown operation; path outside the API | `AKMA_CONTEXT_NOT_FOUND`; `RESOURCE_URI_STRUCTURE_NOT_FOUND`; no cause |
| 411 | invalid `Content-Length`, or different from the body received | `INCORRECT_LENGTH` |
| 413 | body above 16 000 000 octets (TS 29.501 cl. 6.2), declared or not | `MAX_JSON_SIZE_EXCEEDED` |
| 415 | `Content-Type` other than `application/json` (parameters such as `charset` accepted) | — |
| 500 | internal failure (panic in a handler, KDF error) | `SYSTEM_FAILURE` |
| 501 | a method other than `POST`: no resource of the API supports one | — |

Not emitted: **429** and **503**, which need overload control (TS 29.500 cl. 6.4); **502** (`INBOUND_SERVER_ERROR`), since the AAnF calls no other server to answer a request. A trailing slash in the path gives 404, without redirection. TS 29.500 only defines `INCORRECT_LENGTH` for *"incorrect value of a Content-length header field"*; the AAnF also uses it when the value does not match the body. A missing `Content-Length` is accepted: HTTP/2 delimits the body by frames.

## 7. Logs

No key is logged, at any level. SUPI, A-KID and AF_ID are logged at `info`, under the `AKMA` category, as free5GC already logs the SUPI. `TestNoKeyInLogs` runs at `trace` level and looks for K_AKMA and K_AF, in hex and in base64, in the log.

| Level | Message |
|---|---|
| info | at start: `Routing Indicators [...]; K_AF lifetime ...; AF_IDs authorized by local policy: [...]`, and `AF_IDs accepted from a NEF: [...]` |
| info | `AKMA context of <SUPI> registered, A-KID <A-KID>`, with `(previous context replaced)` on re-authentication |
| info | `K_AF of <SUPI> provided to AF_ID <AF_ID> for A-KID <A-KID>, expires <time>`, with `, through the NEF at <address>` when relayed |
| info | `K_AKMA not present for A-KID <A-KID>, requested by AF_ID <AF_ID>` |
| info | `AKMA context of <SUPI> removed`, or `... to remove not found` |
| warn | `NF <NF instance ID> at <address> not authorized for AF_ID <AF_ID>`, `NEF <NF instance ID> at <address> not authorized for AF_ID <AF_ID>` |
| info | `K_AF … provided …` ends with `, without the SUPI` when the answer has none (anonymous access, or a token without `supi-access`) |
| info | each request on an `SBI` line: `POST /naanf-akma/v1/<operation>, User-Agent <value>, 3gpp-Sbi-NF-Peer-Info <value>` |
| info, warn | `Heart-beat sent to the NRF, next in <interval>`; `Heart-beat: the NRF does not have the profile (404); registering again`; `Heart-beat failed: <error>` |
| info | with `kakmaRefresh`: `K_AKMA refresh requested from the UDM when a K_AF is asked for a K_AKMA older than <duration> (TS 33.535 cl. 6.4.4)` at start; `K_AKMA of <SUPI> registered <age> ago: refresh requested from the UDM (TS 33.535 cl. 6.4.4)`; `UDM for Nudm_UECM_AuthTrigger: <URI> (discovered at the NRF)`; `Refresh of K_AKMA of <SUPI> accepted by the UDM: new primary authentication requested` |
| warn | `Refresh of K_AKMA of <SUPI> not accepted by the UDM: <status> <cause> (<detail>)` |

## 8. Refresh of K_AKMA

TS 33.535 cl. 6.4.1: *"KAKMA shall be re-keyed by running a successful primary authentication"*. Cl. 6.4.4: *"the AAnF may decide to refresh the KAKMA based on the operator's local authentication policy by sending the Nudm_UECM_AuthTrigger Request message to the UDM"*.

**Policy.** After it hands out a K_AF, the AAnF looks at the age of the K_AKMA of the context. When it was registered longer ago than `akma.kakmaRefresh`, the AAnF asks the UDM for a new primary authentication in the background; the answer to the AF does not wait. It asks once per K_AKMA, and asks again at the first K_AF request after 5 minutes if the K_AKMA did not change. The K_AF already handed out stays valid until it expires (cl. 6.4.2).

**Request.** The AAnF discovers a UDM with `nudm-uecm` at the NRF once (`target-nf-type=UDM`, `requester-nf-type=AANF`) and keeps its URI. With OAuth2 on, it asks the NRF for the `nnrf-disc` and `nudm-uecm` tokens. It sends `POST {apiRoot}/nudm-uecm/v1/{supi}/registrations/trigger-auth` with `{"supi": ...}`, `User-Agent: AANF-<nfInstanceId>` and `3gpp-Sbi-NF-Peer-Info` (TS 29.500 table 5.2.2.2-1). The method is POST, as table 6.2.3.13.4.1-1 of TS 29.503 says; the YAML of the API declares `get`. The UDM and the AMF need the patches `udm/0002` and `amf/0001` ([free5gc-fixes.md](free5gc-fixes.md), F17 to F19).

**Tool.** `seed trigger-auth` sends the same request without waiting for the policy:

```bash
~/akma-tools/seed trigger-auth --nrf https://nrf.5gc.mnc093.mcc208.3gppnetwork.org:8000 --supi imsi-208930000000001
```

It prints `accepted (204)`, or `UDM answered <status> (<cause>; <detail>)`. With `--nrf`, it registers at the NRF as a temporary NF, with the identity of its certificate `seed-af`, for the token. `--method` and `--body` send the request as given, for negative tests.

## 9. Limitations

- No roaming status subscription; no GPSI.
- Contexts in memory, lost on restart; one AAnF only.
- Needs the patched NRF. Without `nrf/0001` and `nrf/0002`, the profile has no `aanfInfoList` and the AAnF cannot be discovered; without `nrf/0003`, tokens come without `aud`; without `nrf/0005`, they are not `ES256` and carry no scopes per operation, and the AAnF refuses them.
- The policies list NF instance IDs: a new certificate of an AF with another NF instance ID needs its entries changed.

## 10. Heart-beat and the headers of TS 29.500

**Heart-beat** (TS 29.510 cl. 5.2.2.3.2: *"Each NF that has previously registered in NRF shall contact the NRF periodically (heart-beat), by invoking the NFUpdate service operation"*). The AAnF proposes `heartBeatTimer` at registration and follows the interval of the answer of the NRF. At each interval it sends `PATCH /nnrf-nfm/v1/nf-instances/{nfInstanceID}` with `[{"op": "replace", "path": "/nfStatus", "value": "REGISTERED"}]`, without `If-Match`, and an `nnrf-nfm` token. The NRF answers 204, or 200 with the profile. The clause does not say what to do with 404: the NRF no longer has the profile, so the AAnF registers again.

**Headers** (TS 29.500 table 5.2.2.2-1 and cl. 5.2.3.2.21; TS 29.535 cl. 5.1.2.3):

- every answer of the AAnF, errors included, carries `Server: AANF-<nfInstanceId>` and `3gpp-Sbi-NF-Peer-Info: srcinst=<AAnF>; dstinst=<consumer>`, with the consumer taken from its client certificate or, without TLS, from the `srcinst` of the request;
- every request of the AAnF, to the NRF and to the UDM, carries `User-Agent: AANF-<nfInstanceId>` and `3gpp-Sbi-NF-Peer-Info`.
