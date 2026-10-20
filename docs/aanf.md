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
| `free5gc/aanf/internal/sbi/` | h2c server, routes, protocol errors, the three operations, Nnrf_NFManagement |
| `free5gc/aanf/internal/util/problem.go` | `ProblemDetails` |
| `free5gc/aanf/tools/seed/` | test tool that plays the AUSF, the AF and the OAM |
| `free5gc/config/aanfcfg.yaml` | example configuration |
| `free5gc/scripts/{prepare-openapi,build-aanf,run-aanf,deploy}.sh` | preparation, build, run, deployment |

On the free5GC host:

| Path | Origin |
|---|---|
| `~/free5gc/bin/aanf` | new file, static binary |
| `~/free5gc/config/aanfcfg.yaml` | new file |
| `~/free5gc/log/aanf/` | created by `run-aanf.sh` (log, output, pid). With `./run.sh -aanf` the log goes to the `free5gc.log` of the other NFs |
| `~/free5gc/cert/aanf.pem`, `cert/aanf_<id>.pem` | created by the NRF when OAuth2 is on |

Dependencies: `free5gc/openapi` v1.2.4 with the Naanf_AKMA patches (`free5gc/patches/openapi/`), `free5gc/util` v1.3.2, `shared/akma`.

## 1. Configuration

On top of the fields that all free5GC NFs have (`sbi`, `serviceNameList`, `nrfUri`, `nrfCertPem`, `plmnSupportList`, `logger`). The SBI port is **8010**: the free5GC NFs use 8000, and none of them uses 8010.

| Field | Example | Rule | Specification |
|---|---|---|---|
| `nfInstanceId` | fixed UUID v4 | optional; without it, a new one at each start. Keep it fixed: with OAuth2 on, each new ID makes the NRF write one more certificate | — |
| `serviceNameList` | `[naanf-akma]` | the only accepted value | TS 29.535 cl. 5.1.1 |
| `routingIndicators` | `["0000"]` | strings of 1 to 4 digits; empty means any RID. `0000` without quotes is still read as `"0000"` | TS 29.510 `AanfInfo`; TS 23.003 cl. 2.2B |
| `akma.kafLifetime` | `1h` | positive Go duration; default `1h` | operator policy, TS 33.535 cl. 5.2 |
| `akma.authorizedAfs[].afId` | `af1.akma.example.FF00000001` | transport form `<FQDN>.<10 hex digits>` | TS 29.522 `AfId` |
| `akma.authorizedAfs[].sourceAddresses` | `[192.168.16.129]` | at least one IP address | local policy, section 4 |
| `akma.authorizedNefs[].sourceAddresses` | `[192.168.16.130]` | at least one IP address: those of the NEF | local policy, section 5 |
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

**`register-anchorkey` and `remove-context`: OAuth2.** TS 29.535 cl. 5.1.9: access *"may be authorized"* with OAuth2, by local configuration. The NRF tells the AAnF whether OAuth2 is on. The token is checked as TS 33.501 cl. 13.4.1.1.2 step 2 says:

| Check | Done by |
|---|---|
| `Bearer` scheme | the AAnF |
| RS512 signature with the NRF certificate | `oauth.VerifyOAuth` of free5GC |
| `scope` contains `naanf-akma` | `oauth.VerifyOAuth`. The finer scopes of TS 29.535 table 5.1.9-1 are not required (TS 33.501 cl. 13.4.1.0 makes additional scopes optional) |
| `exp` in the future | the AAnF; `VerifyOAuth` does not check it (F5) |
| `aud` equal to the `nfInstanceId` of the AAnF or to `AANF`; missing or empty is refused | the AAnF. Needs the NRF fix F3 |

A missing or invalid token gives 401 with `WWW-Authenticate: Bearer` (or `Bearer error="invalid_token"`, RFC 6750 cl. 3) and `ProblemDetails`.

**`retrieve-applicationkey`: local policy.** TS 33.535 cl. 6.2.1 step 2: the AAnF checks the request *"based on the configured local policy or based on the authorization information available in the signalling (i.e., Oauth2.0 token)"*. An AF inside the operator network does not need to reach the NRF, so the local policy applies:

- each authorized AF_ID is bound to the source addresses it may be requested from;
- the address is that of the connection, never `X-Forwarded-For`;
- the FQDN is compared exactly, since it goes into the KDF.

An AF outside the policy, or an AF_ID requested from another address, gets 403 without `cause`: no cause is defined for it.

## 5. Requests relayed by a NEF

TS 33.535 cl. 6.3 step 3: through the NEF, the AAnF handles the request as in cl. 6.2.1. The specification has no separate step for recognizing the NEF. TS 33.501 gives the general mechanisms between NFs:

- cl. 13.3.2.1: without TLS, *"authentication between NFs within one PLMN may be implicit by NDS/IP or physical security"*;
- cl. 13.3.0: without a token, the producer checks the consumer *"based on its local policy"*;
- cl. 13.4.1.1.2: the token, which the NRF only issues after checking the consumer.

The AAnF uses all three, with `akma.authorizedNefs`:

```yaml
configuration:
  akma:
    authorizedNefs:
      - sourceAddresses:
          - 192.168.16.130
        afIds:
          - af1.akma.example.FF00000001
```

1. If the request has `Authorization`, the token is checked as for `register-anchorkey` (section 4): scope `naanf-akma`, `exp`, `aud`. Invalid: 401.
2. With a valid token and the source address in an `authorizedNefs` entry, the request is taken as coming from the NEF. The `afId` has to be in the `afIds` of that entry; otherwise 403 without `cause`.
3. In every other case `authorizedAfs` applies: AF_ID bound to source addresses.

Without `authorizedNefs` there is no NEF path. When the NEF and the AUSF run on the same host, another NF of that host with a `naanf-akma` token could pass for the NEF, but only for the AF_IDs of the list. TLS with NF certificates and per-type scopes (F4 in [free5gc-fixes.md](free5gc-fixes.md)) would close that.

## 6. Errors

TS 29.535 cl. 5.1.7.1; TS 29.500 table 5.2.7.1-1 and cl. 5.2.7.2. Every error answer carries `ProblemDetails` in `application/problem+json`. Tests in `free5gc/aanf/internal/sbi/api_akma_test.go`, over h2c.

| Code | When | Cause |
|---|---|---|
| 400 | invalid JSON or wrong type; mandatory attribute missing or wrong; API version other than `v1` | `INVALID_MSG_FORMAT`, `MANDATORY_IE_MISSING`, `MANDATORY_IE_INCORRECT`, `OPTIONAL_IE_INCORRECT`, `INVALID_API` |
| 401 | token missing or invalid (section 4) | — |
| 403 | no K_AKMA; AF or NEF not authorized | `K_AKMA_NOT_PRESENT`; no cause |
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
| warn | `AF at <address> not authorized for AF_ID <AF_ID>`, `NEF at <address> not authorized for AF_ID <AF_ID>` |

## 8. Limitations

- No TLS on the SBI.
- No roaming status subscription; no GPSI.
- Contexts in memory, lost on restart; one AAnF only.
- Needs the fixed NRF. Without `nrf/0003`, tokens come without `aud` and `register-anchorkey` and `remove-context` answer 401. Without `nrf/0001` and `nrf/0002`, the profile has no `aanfInfoList` and the AAnF cannot be discovered.
