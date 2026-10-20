# AKMA API of the NEF

An AF outside the operator network does not talk to the AAnF. It asks the NEF, which authorizes it, gets K_AF from the AAnF and relays it without the SUPI (TS 33.535 cl. 6.3). The patch `free5gc/patches/nef/0001-akma-api.patch` adds this API to the NEF v1.2.5 of free5GC v4.2.3. Its configuration comes from `free5gc/patches/config/0002-nef-akma.patch`.

## 1. Flow

TS 33.535 cl. 6.3:

1. the AF finds the HPLMN from the A-KID and sends the A-KID and its AF_ID to the NEF;
2. the NEF authorizes the AF, checking the AF_ID too, and selects the AAnF (cl. 6.7);
3. the NEF sends `Naanf_AKMA_ApplicationKey_Get` to the AAnF with the A-KID;
4. the AAnF answers with K_AF, its expiry and the SUPI;
5. the NEF sends the AF the K_AF and the expiry and, by local policy, the GPSI. *"The NEF shall not send the SUPI to the AF."*

TS 29.522 defines the AF-facing side:

- cl. 4.4.23.2: `POST {apiRoot}/3gpp-akma/v1/retrieve`, with `AkmaAfKeyRequest`. A `403` from the AAnF with `K_AKMA_NOT_PRESENT` *"shall"* be relayed to the AF;
- cl. 5.14: the custom operation `Retrieve` (table 5.14.3.1-1), the types `AkmaAfKeyRequest` and `AkmaAfKeyData` (tables 5.14.5.3.2-1 and 5.14.5.3.3-1), the errors (table 5.14.7.3-1) and the `RoamingRestriction` feature (table 5.14.6-1);
- cl. 5.14.7.1: error handling follows TS 29.122 cl. 5.2.6.

```
            AF host                                         free5GC host
  external AF ──(1) registration and token ─────────────▶ NRF 127.0.0.10:8000 (SSH tunnel)
  external AF ──(2) POST /3gpp-akma/v1/retrieve ────────▶ NEF 192.168.16.130:8000
                                                          NEF ──(3) discovery of the AAnF ──▶ NRF
                                                          NEF ──(4) retrieve-applicationkey ──▶ AAnF 192.168.16.130:8010
```

## 2. Access token

- TS 33.501 cl. 13.4.1.1.1: the NRF is the OAuth 2.0 authorization server for the consumer NFs **inside the PLMN**. The external AF is not one of them.
- TS 29.522 cl. 7.2, TS 33.122 cl. 6.5.2.3 and TS 33.501 cl. 12.5: **with CAPIF**, the authorization server is the CAPIF Core Function. The AF, as API invoker, gets the token with `Obtain_Authorization` (TS 29.222 cl. 5.6.2.3.2).
- TS 29.522 cl. 6: **without CAPIF**, *"the access to the NEF Northbound APIs shall be authorized by means of OAuth2 protocol [...] based on local configuration, using the "Client Credentials" authorization grant"*. None of the specifications says who the authorization server is in that case, nor how the AF reaches it.

free5GC has no CAPIF, and its NEF only accepts tokens from the NRF on the AF-facing APIs it already has. The `3gpp-akma` API does the same: the AF registers at the NRF as `nfType: AF` and asks for a `3gpp-akma` token for the NEF. This fits the *"based on local configuration"* of TS 29.522 cl. 6. The specified path for an external AF is CAPIF (F13 in [free5gc-fixes.md](free5gc-fixes.md)).

The NRF listens on a loopback address of the free5GC host. An SSH tunnel gives the AF host the same `nrfUri` as the NFs, without changing the NRF:

```bash
ssh -N -L 127.0.0.10:8000:127.0.0.10:8000 user@192.168.16.130
```

## 3. Request

```
POST /3gpp-akma/v1/retrieve HTTP/1.1
Host: 192.168.16.130:8000
Content-Type: application/json
Authorization: Bearer <token of the NRF, scope 3gpp-akma>

{"afId": "af1.akma.example.FF00000001", "aKId": "rid0000.atid…=@5gc.mnc093.mcc208.3gppnetwork.org"}
```

| Attribute of `AkmaAfKeyRequest` | P | Handling |
|---|---|---|
| `afId` | M | AF_ID in transport form, `<FQDN>.<10 hex digits>` |
| `aKId` | M | A-KID |
| `anonInd` | O | passed to the AAnF; `false` when absent |
| `notifUri` | O | belongs to `RoamingRestriction`, not supported: ignored |
| `suppFeat` | C | no feature supported; the answer has no `suppFeat` |

## 4. Processing, in order

1. **Token.** The OAuth2 middleware of free5GC, for `ServiceName_3GPP_AKMA`. Missing or invalid: 401.
   - The body is that of the existing middleware, `{"error": "..."}` in `application/json`, without `WWW-Authenticate`. TS 29.122 table 5.2.6-1 asks for `ProblemDetails` in `application/problem+json`, and TS 29.500 cl. 6.7.3 and RFC 6750 cl. 3 for `WWW-Authenticate: Bearer` (F12).
   - The middleware checks neither `exp` nor `aud` (F5).
2. **Form of the request** (TS 29.122 table 5.2.6-1, with `ProblemDetails` in `application/problem+json`):
   - a `Content-Type` that is not JSON: 415;
   - a body that is not JSON: 400;
   - `afId` or `aKId` missing: 400, with `invalidParams`;
   - `afId` or `aKId` malformed: 400, with `invalidParams`. The checks use `shared/akma/afid` and `shared/akma/akid`, the same as the AAnF.
3. **Authorization of the AF** (cl. 6.3 step 2). The AF_ID has to be in `akma.authorizedAfs` of the NEF, and the source address of the connection in the `sourceAddresses` of that AF_ID. Otherwise 403 with `ProblemDetails` without `cause`: neither TS 29.522 nor TS 29.122 defines a cause for it.
4. **Selection of the AAnF** (cl. 6.7). The NEF discovers the AAnF at the NRF with `target-nf-type=AANF`, `requester-nf-type=NEF`, `service-names=naanf-akma` and `routing-indicator` set to the RID of the A-KID. No AAnF: 503.
5. **Request to the AAnF** (cl. 6.3 step 3). `POST {apiRoot of the AAnF}/naanf-akma/v1/retrieve-applicationkey` with `afId`, `aKId` and `anonInd`, and a `naanf-akma` token that the NEF gets from the NRF.
6. **Answer to the AF**, as in section 5.

## 5. Answers

| Answer of the AAnF | Answer of the NEF to the AF | Why |
|---|---|---|
| 200 `AkmaAfKeyData` | 200 with `kaf` and `expiry`. **Never** `supi`; no `gpsi` | cl. 6.3 step 5; TS 29.522 cl. 4.4.23.2 and table 5.14.5.3.3-1, NOTE 2 |
| 403 `K_AKMA_NOT_PRESENT` | 403 `K_AKMA_NOT_PRESENT` | TS 29.522 cl. 4.4.23.2: *"shall relay"* |
| 403 without `cause` (the NEF or the AF_ID outside the policy of the AAnF) | 403 without `cause` | cl. 4.4.23.2 only asks for *"a proper error status code"* |
| any other 4xx | 500 `SYSTEM_FAILURE` | the NEF built the request, so a 4xx from the AAnF is a failure of the NEF |
| 5xx, timeout, connection refused | 503 | the AAnF is not available |
| 204 | 204, without a body | see below |

```
HTTP/1.1 200 OK
Content-Type: application/json

{"kaf": "<64 hex digits>", "expiry": "2026-10-20T01:17:28Z"}
```

**The 204.** TS 29.522 table 5.14.3.2.2-2: the NEF answers 204 *"if the requested data does not exist"*. Only the AAnF knows whether the data exists, under the same rule (TS 29.535 cl. 4.2.2.3.2). So the NEF answers 204 when the AAnF answers 204, and relays the answer without a body. The AAnF of this repository never answers 204 ([aanf.md](aanf.md), section 2.2): it answers `403 K_AKMA_NOT_PRESENT`, which the NEF relays. With another AAnF that does answer 204, the NEF follows the table of TS 29.522.

The NEF does not answer 307 or 308: there is a single NEF.

## 6. Anonymous access

TS 33.535 cl. 6.2.2 and TS 29.535 cl. 4.2.2.3.2: with `anonInd: true`, the AAnF answers without `supi`. TS 29.522 table 5.14.5.3.3-1, NOTE 3: with `anonInd: true` in the request of the AF, the answer of the NEF has no `gpsi`. The NEF passes `anonInd` on as it came. Since the NEF never returns `gpsi`, the answer to the AF is the same as in section 5.

## 7. Configuration

**NEF** (`~/free5gc/config/nefcfg.yaml`, after `patch-nf.sh config apply`):

```yaml
configuration:
  sbi:
    registerIPv4: 192.168.16.130 # reachable from the external AF
    bindingIPv4: 192.168.16.130
    port: 8000
  serviceList:
    - serviceName: 3gpp-akma
  akma:
    authorizedAfs: # TS 33.535 cl. 6.3 step 2
      - afId: af1.akma.example.FF00000001
        sourceAddresses:
          - 192.168.16.129
```

The NEF moves from its loopback address to the host address so that the AF host can reach it. The port stays 8000. The patch also authorizes `af3.akma.example.FF00000001`, which the AAnF does not accept, for a negative test of the end-to-end run. Remove it outside a test bed.

**AAnF.** `akma.authorizedNefs` with the address of the NEF and the external AF_IDs accepted from it ([aanf.md](aanf.md), section 5).

**AF** (`af/config/afcfg-external.yaml`):

| Field | Use |
|---|---|
| `nefUri` | the NEF API, `http://192.168.16.130:8000`. Exclusive with `aanfUri`: with it, the AF is external |
| `nrfUri` | the NRF for the registration and the token, `http://127.0.0.10:8000` through the tunnel |
| `nfInstanceId` | the identity of the AF at the NRF; a random UUID when absent |
| `anonymous` | `true` sends `anonInd: true`, to the AAnF or through the NEF. Default `false` |

In external mode, the AF registers at the NRF as `nfType: AF` when it starts, asks for a `3gpp-akma` token for the NEF and renews it before `exp`, and deregisters on shutdown.

## 8. Logs

In the free5GC format, under the `AKMA` category:

| Level | Message |
|---|---|
| info | `K_AF request from AF_ID <afId> for A-KID <aKId>`, with `, anonymous` when it applies |
| info | `K_AF for A-KID <aKId> relayed to AF_ID <afId>, expires <expiry>` |
| warn | AF outside the policy, no AAnF found, error from the AAnF |

The NEF never logs K_AF. It does not log the SUPI either: it does not need it and must not pass it on.

## 9. What the patch changes in the NEF

| File | Change |
|---|---|
| `go.mod`, `go.sum` | `replace` of `openapi` with the patched copy, and of `shared/akma` |
| `pkg/factory/config.go` | the `3gpp-akma` service, the `/3gpp-akma/v1` prefix, the `akma.authorizedAfs` section |
| `internal/sbi/server.go` | the `3gpp-akma` group, behind the OAuth2 middleware |
| `internal/sbi/api_akma.go` (new) | route `POST /retrieve` |
| `internal/sbi/processor/akma.go` (new) | section 4 |
| `internal/sbi/processor/akma_test.go` (new) | the answers of section 5 against a fake NRF and AAnF, `anonInd` passed on, no `supi`, no key in the log |
| `internal/sbi/consumer/aanf_service.go` (new) | discovery of the AAnF and the Naanf_AKMA client |
| `internal/sbi/consumer/consumer.go` | the AAnF consumer |
| `internal/context/akma.go` (new), `nef_context.go` | AF_ID policy |
| `internal/logger/logger.go` | the `AKMA` category |

Like the other clients of the NEF, the AAnF client uses `http.DefaultClient` and the metrics hook of free5GC. That is also what lets the tests fake the NRF and the AAnF with `gock`.
