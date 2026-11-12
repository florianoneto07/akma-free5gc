# AKMA API of the NEF

An AF outside the operator network does not talk to the AAnF. It asks the NEF, which authorizes it, gets K_AF from the AAnF and relays it without the SUPI (TS 33.535 cl. 6.3). The patches of `free5gc/patches/nef/` add this API to the NEF v1.2.5 of free5GC v4.2.3, make the NEF the API publishing and exposing function of CAPIF ([capif.md](capif.md)), and put it on mutual TLS ([sbi-tls.md](sbi-tls.md)). Its configuration comes from the patches of `free5gc/patches/config/`.

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
- cl. 5.14.7.1: error handling follows TS 29.122 cl. 5.2.6;
- cl. 7: CAPIF.

```
            AF host                                              free5GC host
  external AF ──(1) CAPIF-1e: onboarding, discovery, token ────▶ CCF 192.168.16.130:8020
  external AF ──(2) POST /3gpp-akma/v1/retrieve, mutual TLS ───▶ NEF nef.5gc.mnc093.mcc208.3gppnetwork.org:8000
                                                               NEF ──(3) CAPIF-3/4: invoker data ──▶ CCF
                                                               NEF ──(4) discovery of the AAnF ──▶ NRF
                                                               NEF ──(5) retrieve-applicationkey ──▶ AAnF aanf.5gc…:8010
```

## 2. Access token

- TS 33.501 cl. 13.4.1.1.1: the NRF is the OAuth 2.0 authorization server for the consumer NFs **inside the PLMN**. The external AF is not one of them.
- TS 29.522 cl. 7.2, TS 33.122 cl. 6.5.2.3 and TS 33.501 cl. 12.5: **with CAPIF**, the authorization server is the CAPIF Core Function. The AF, as API invoker, gets the token with `Obtain_Authorization` (TS 29.222 cl. 5.6.2.3.2).
- TS 29.522 cl. 6: **without CAPIF**, *"the access to the NEF Northbound APIs shall be authorized by means of OAuth2 protocol [...] based on local configuration, using the "Client Credentials" authorization grant"*. None of the specifications says who the authorization server is in that case (item Y of [3gpp-recommendations.md](3gpp-recommendations.md)).

This repository takes the CAPIF path. The AF onboards at the CCF of this repository, discovers the NEF and asks the CCF for a token with the scope `3gpp#nef-aef:3gpp-akma`. With `allowNrfTokens: false`, the default of the example configuration, `3gpp-akma` accepts only the tokens of the CCF. With `true`, a request without a token of the CCF falls back to the OAuth2 middleware of free5GC and its tokens from the NRF.

## 3. Request

```
POST /3gpp-akma/v1/retrieve HTTP/1.1
Host: nef.5gc.mnc093.mcc208.3gppnetwork.org:8000
Content-Type: application/json
Authorization: Bearer <token of the CCF, scope 3gpp#nef-aef:3gpp-akma>

{"afId": "af1.akma.example.FF00000001", "aKId": "rid0000.atid…=@5gc.mnc093.mcc208.3gppnetwork.org"}
```

Over TLS, the AF presents the client certificate that the CCF issued when it onboarded. HTTP/1.1 and HTTP/2 are negotiated with ALPN.

| Attribute of `AkmaAfKeyRequest` | P | Handling |
|---|---|---|
| `afId` | M | AF_ID in transport form, `<FQDN>.<10 hex digits>` |
| `aKId` | M | A-KID |
| `anonInd` | O | logged; the NEF never sends the SUPI to the AF, with or without it |
| `notifUri` | O | belongs to `RoamingRestriction`, not supported: ignored |
| `suppFeat` | C | no feature supported; the answer has no `suppFeat` |

## 4. Processing, in order

1. **TLS.** The groups of CAPIF-2e (`3gpp-akma` and `aef-security`) only accept client certificates of the CA of the CCF, and the groups of the SBI only those of the CA of the operator. Another CA: 403 without `cause`. The CRL of the CA of the CCF is fetched again after `invokerCrlMaxAge`: the certificate of an invoker that offboarded is refused in the handshake.
2. **Token of the CCF** (TS 29.522 cl. 7.2; TS 33.122 cl. 6.5.2.3 step 7):
   - signature `ES256` with the public key of the CCF (`tokenPublicKey`), `kid` of that key; `exp` not passed; `iss` and `client_id` present and equal; the CN of the client certificate equal to `client_id`. Otherwise 401, `WWW-Authenticate: Bearer error="invalid_token"`;
   - no token, with `allowNrfTokens: false`: 401, `WWW-Authenticate: Bearer`;
   - `scope` with an item for the `aefId` of the NEF and `3gpp-akma`. Otherwise 403, `WWW-Authenticate: Bearer error="insufficient_scope", scope="3gpp#nef-aef:3gpp-akma"`;
   - the data of the invoker, from memory or from the CCF (CAPIF-3/4). The CCF answers 404, because the invoker offboarded or the CCF restarted: 401 `invalid_token`. The CCF is down: 503.
3. **Form of the request** (TS 29.122 table 5.2.6-1, with `ProblemDetails` in `application/problem+json`):
   - a `Content-Type` that is not JSON: 415;
   - a body that is not JSON: 400;
   - `afId` or `aKId` missing: 400, with `invalidParams`;
   - `afId` or `aKId` malformed: 400, with `invalidParams`. The checks use `shared/akma/afid` and `shared/akma/akid`, the same as the AAnF.
4. **Authorization of the AF** (cl. 6.3 step 2). The AF_ID has to be among the AF_IDs that the CCF gives for the invoker (`authorizationInfo`) and in `akma.authorizedAfs` of the NEF. Otherwise 403 with `ProblemDetails` without `cause`: neither TS 29.522 nor TS 29.122 defines a cause for it. In CAPIF mode the source address is not checked: the certificate and the token say who the AF is. `sourceAddresses` is optional with the `capif` section, and required without it.
5. **Selection of the AAnF** (cl. 6.7). The NEF discovers the AAnF at the NRF with `target-nf-type=AANF`, `requester-nf-type=NEF`, `service-names=naanf-akma` and `routing-indicator` set to the RID of the A-KID. With the default Routing Indicator, `0` (TS 23.003 cl. 2.2B), any AAnF of the home network will do, and the search goes without `routing-indicator`. The NEF reuses the result during its validity period (TS 29.510 cl. 5.3.2.2.1); a failure to reach the AAnF found makes the next request search again. No AAnF: 503.
6. **Request to the AAnF** (cl. 6.3 step 3). `POST {apiRoot of the AAnF}/naanf-akma/v1/retrieve-applicationkey` with `afId` and `aKId`, without `anonInd`: `ApplicationKey_AnonUser_Get` is for the AF only (TS 29.535 table 4.2.2.1-1). The NEF uses a token of the NRF with the scopes `naanf-akma`, `naanf-akma:applicationkeyget` and `naanf-akma:applicationkeyget:supi-access`, and sends `User-Agent: NEF-<NF instance ID>` and `3gpp-Sbi-NF-Peer-Info` (TS 29.500).
7. **Answer to the AF**, as in section 5.

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

TS 33.535 cl. 6.2.2 and TS 29.522 table 5.14.5.3.3-1, NOTE 3: with `anonInd: true` in the request of the AF, the answer of the NEF has no `gpsi`. Through the NEF, the anonymity of the AF changes nothing towards the AAnF: the NEF asks with `ApplicationKey_Get` (cl. 6.3 step 3), gets the SUPI, and keeps it to itself (step 5). Since the NEF never returns `supi` or `gpsi`, the answer to the AF is the same as in section 5.

## 7. Configuration

**NEF** (`~/free5gc/config/nefcfg.yaml`, after `patch-nf.sh config apply`):

```yaml
configuration:
  nfInstanceId: 8e73ad07-906c-4952-93ac-cd32bbb076ed # the one of the certificate
  sbi:
    scheme: https
    fqdn: nef.5gc.mnc093.mcc208.3gppnetwork.org
    registerIPv4: 192.168.16.130 # reachable from the external AF
    bindingIPv4: 192.168.16.130
    port: 8000
    tls:
      pem: cert/sba/nef.pem
      key: cert/sba/nef.key
      ca: cert/sba/sba-ca.pem
  serviceList:
    - serviceName: 3gpp-akma
  akma:
    authorizedAfs: # TS 33.535 cl. 6.3 step 2
      - afId: af1.akma.example.FF00000001
  capif: # TS 29.522 cl. 7: the NEF as API publishing and exposing function
    ccfUri: https://ccf.5gc.mnc093.mcc208.3gppnetwork.org:8020
    apfId: nef-apf
    aefId: nef-aef
    tokenPublicKey: cert/ccf-token.pub.pem
    interface: # published for 3gpp-akma
      fqdn: nef.5gc.mnc093.mcc208.3gppnetwork.org
      port: 8000
    invokerInfoLifetime: 10m
    invokerCa: cert/ccf-ca.pem
    invokerCrl: true
    invokerCrlMaxAge: 5s
    allowNrfTokens: false
```

The NEF moves from its loopback address to the host address so that the AF host can reach it. The port stays 8000. The patch also authorizes `af3.akma.example.FF00000001` and `af5.akma.example.FF00000001`, for negative tests of the end-to-end run. Remove them outside a test bed.

**AAnF.** `akma.authorizedNefs` with the NF instance ID of the certificate of the NEF and the external AF_IDs accepted from it ([aanf.md](aanf.md), section 5).

**CCF.** The profile of the invoker lists the AF_IDs that the NEF accepts from it (`invokerProfiles[].afIds`, [capif.md](capif.md)).

**AF** (`af/config/afcfg-capif.yaml`):

| Field | Use |
|---|---|
| `capif.ccfUri` | CAPIF-1e of the CCF, `https://192.168.16.130:8020` |
| `capif.ccfCa`, `capif.credential` | the onboarding information: the CA of the CCF and the onboarding credential |
| `capif.state` | the API invoker ID, its certificate, private key and secret, mode `0600` |
| `capif.apiScheme`, `capif.aefCa` | the scheme of the discovered API and the CA of the certificate of the NEF |
| `capif.offboardOnExit` | `true` offboards on Ctrl-C |
| `anonymous` | `true` sends `anonInd: true`. Default `false` |

## 8. Logs

In the free5GC format, under the `AKMA` and `CAPIF` categories:

| Level | Message |
|---|---|
| info | `K_AF request from AF_ID <afId> for A-KID <aKId>`, with `, anonymous` when it applies |
| info | `AAnF for Routing Indicator <RID>: <apiRoot> (discovered at the NRF)`, `AAnF for the default Routing Indicator: <apiRoot> (discovered at the NRF, any AAnF)`, `… (search result reused)` |
| info | `K_AF for A-KID <aKId> relayed to AF_ID <afId>, expires <expiry>` |
| info | `3gpp-akma published at the CCF as <apiId>`; `check-authentication of API invoker <id>: <n> AF_IDs from the CCF`; `Access token of API invoker <id> accepted for AF_ID <afId>` |
| warn | AF outside the policy, token refused and why, no AAnF found, error from the AAnF, CCF down |

The NEF never logs K_AF or a token. It does not log the SUPI either: it does not pass it on.

## 9. What the patches change in the NEF

| Patch | Change |
|---|---|
| `0001-akma-api` | the `3gpp-akma` service and the `/3gpp-akma/v1/retrieve` route; the processing of section 4; the discovery of the AAnF and the Naanf_AKMA client; the `akma.authorizedAfs` policy; the `AKMA` log category; tests against a fake NRF and AAnF |
| `0002-capif` | the `capif` section; the publication at the CCF and its retries; `aef-security/v1/check-authentication`; the token of the CCF |
| `0003-sbi-tls` | the SBI over mutual TLS, by name; the CA of each group of routes |
| `0004-token-scopes` | the scopes of Naanf_AKMA in the token request; the `nnrf-nfm` token for the right target type, so that the NEF deregisters on shutdown (F14) |
| `0005-capif-tls` | the client certificate of the AF bound to the token and to `check-authentication`; the CA checked against `authenticationInfo`; `invokerCrlMaxAge`; `sourceAddresses` optional |
| `0006-aanf-search-and-headers` | the default Routing Indicator, the reuse of the search, `ApplicationKey_Get` without `anonInd`, the headers of TS 29.500 |
| `0007-fqdn-required` | no start with `https` and without `sbi.fqdn` |
