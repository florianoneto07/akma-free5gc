# What free5GC has to change for AKMA

Base: free5GC v4.2.3 (NRF, UDM, AUSF and AMF v1.4.5, NEF v1.2.5, the other NFs of that release, `openapi` v1.2.4, `util` v1.3.2).

This is the list of what we found in free5GC that has to change for AKMA to work as the specifications say. Each entry has:

- **free5GC today:** what the code does;
- **Specification:** the clause that says what to do, quoted where it matters;
- **How:** what the code should do, following that clause;
- **Here:** the patch that fixes it, or why it is still open.

The AAnF is not in this list: it is a new NF (`free5gc/aanf/`, [aanf.md](aanf.md)). The free5GC NFs only change through the patches in `free5gc/patches/`.

| # | Where | Issue | Here |
|---|---|---|---|
| F1 | NRF | drops `aanfInfoList` | fixed, `nrf/0001` |
| F2 | NRF | refuses discovery of `AANF` by Routing Indicator | fixed, `nrf/0002` |
| F3 | NRF | access token with an empty `aud` | fixed, `nrf/0003` |
| F4 | NRF | no scopes per operation and per consumer type | fixed, `nrf/0005` and the AAnF |
| F5 | `openapi` | `VerifyOAuth` checks neither `exp` nor `aud` | fixed, `openapi/0006`, in every NF and the AAnF |
| F6 | `openapi` | no Naanf_AKMA models or client | fixed, `openapi/0001` and `0002` |
| F7 | UDM | sends neither `akmaInd` nor `routingId` | fixed, `udm/0001` |
| F8 | AUSF | neither derives K_AKMA nor registers at the AAnF | fixed, `ausf/0001` |
| F9 | web console | no `akmaAllowed` and `routingId`; editing drops them | worked around with a script |
| F10 | UDM | `id-translation-result` only maps GPSI to SUPI | open |
| F11 | NEF | no `3gpp-akma` API | fixed, `nef/0001` |
| F12 | NEF | 401 of the OAuth2 middleware without `ProblemDetails` or `WWW-Authenticate` | fixed, `openapi/0006`, in every NF |
| F13 | NEF | AF-facing APIs without CAPIF and without mutual TLS | fixed, the CCF of this repository, `nef/0002`, `nef/0003` and `nef/0005` |
| F14 | NEF | asks for the `nnrf-nfm` token with the wrong target type and does not deregister | fixed, `nef/0004` |
| F15 | NRF | `complexQuery` without `routing-indicator` for `AANF` | open |
| F16 | `openapi` | no models for the primary authentication triggered by the home network | fixed, `openapi/0003` |
| F17 | UDM | no `Nudm_UECM_AuthTrigger` and no `Nudm_UECM_Re-AuthenticationNotification` | fixed, `udm/0002` |
| F18 | AMF | no callback for the re-authentication notification | fixed, `amf/0001` |
| F19 | AMF | does not run the primary authentication the home network asks for | fixed, `amf/0001` |
| F20 | AMF, UDM | the AMF requires an access token on notifications; the UDM sends the deregistration one with the wrong scope | open; the new notification goes without a token |
| F21 | `openapi` | the SBI client neither checks the server nor presents a certificate | fixed, `openapi/0005` |
| F22 | `util` | the NFs write the secrets of the TLS sessions to a file | fixed, `util/0001` |
| F23 | NRF, `openapi` | access tokens in `RS512`, outside the JWS profile | fixed, `nrf/0005` and `openapi/0006` |
| F24 | every NF, `openapi` | profiles without `fqdn`, URIs built from addresses | fixed, the `*-sbi-tls` and `*-fqdn-required` patches and `openapi/0005`; `apiPrefix` still carries the whole URI |
| F25 | NRF, `openapi` | certificates of the NFs outside the profile of TS 33.310 | fixed, `make-sba-certs.sh` and `nrf/0005` |
| F26 | NRF | tokens with an empty `iss`, certificate of the NRF without its NF instance ID | fixed, `nrf/0005` |
| F27 | NRF | the scope of a token is checked on one profile of the target type only | fixed, `nrf/0006` |
| F28 | NRF | no `Nnrf_AccessToken_RetrieveKey` | fixed, `nrf/0006` and `openapi/0008` |
| F29 | every NF, NRF | no heart-beat | done in the AAnF; open in the free5GC NFs and in the NRF |
| F30 | UDM | no `ROAMING_STATUS` event by SUPI | open |
| F31 | every NF, `openapi` | no `User-Agent` with the NF type, no `Server` on error answers, no `3gpp-Sbi-*` headers | partly: the requests of the AUSF and of the NEF to the AAnF, the AAnF, and the token request of every NF (`ausf/0004`, `nef/0006`, `openapi/0008`) |

**Checked against free5GC v4.3.0.** The patches here are for v4.2.3. On 28 October 2026 items F1 to F20 were checked again in free5GC v4.3.0 (30 September 2026: NRF `4522e4a9`, UDM `ba18ef3b`, AUSF `b693e38a`, AMF `9fc0ac3f`, NEF `6cd30f51`, web console `c40b94b6`, `openapi` v1.3.0). All twenty are still there. For F5, the claims model of `openapi` declares `Exp` and `Aud` with the same JSON names as the `jwt.RegisteredClaims` it embeds; the outer fields win, so `golang-jwt/jwt` v5 finds no `exp` or `aud` to check.

On 8 November 2026 items F21 to F31 were checked in the same release, with the SMF at `1c9d7662`, the PCF at `eb57557f`, the UDR at `db69aa0e`, the NSSF at `c1092f6f`, the CHF at `4e06244b`, the BSF at `504e4001` and the new SCP at `04d79c73`, all with `openapi` v1.3.0 and `util` v1.4.0. All eleven are still there:

| Item | In v4.3.0 |
|---|---|
| F21 | `NewHttp2Client` (`client.go`) still sets `InsecureSkipVerify: true` and presents no client certificate; the IMS client of the UDR goes through the same `CallAPI`. With `oauth: true` and `https`, the NRF still requires the client certificate (`configureOAuthMutualTLS`) |
| F22 | `httpwrapper.NewHttp2Server` still sets `KeyLogWriter` when it gets the path, and the NFs and the metrics server get it from `-l` |
| F23 | the NRF still signs with `RS512`, without `kid`; `VerifyOAuth` still accepts `RS512` only |
| F24 | no NF puts its `fqdn` in its own profile; the `Url` of the AUSF still comes from the address; `SearchNFServiceUri` (AMF, UDM) still returns the `fqdn` without scheme or port; the NEF adds the scheme, without the port; `GetNFServiceUri` still prefers `apiPrefix` |
| F25 | `oauth.GenerateCertificate` still makes RSA 2048, 10 years, `C=TW … O=free5gc`; the token request still checks the generated file, not the certificate of the session, and only warns on *"unknown authority"* |
| F26 | `Nrf_NfInstanceID` is still never set: `iss` and the URI of the certificate of the NRF stay empty |
| F27 | `AccessTokenScopeCheck` still checks one profile, from `RestfulAPIGetOne` with `{"nfType": …}` |
| F28 | `api_accesstoken.go` still has `/oauth2/token` only |
| F29 | no NF calls `UpdateNFInstance` on its own profile; the NRF only checks the range of `heartBeatTimer` (1 to 3600 s) and suspends no NF |
| F30 | `CreateEeSubscriptionProcedure` still accepts only `msisdn-`, `extid-`, `extgroupid-` and `anyUE`, with 400 `MANDATORY_IE_INCORRECT` for the rest; the UDM makes no event report: `notifier.go` only has data change and deregistration |
| F31 | no NF calls `SetUserAgent`, and the generated clients send `OpenAPI-Generator/1.0.0/go`; no NF sets `Server`; no NF handles `3gpp-Sbi-*`, and only the generated clients read `3gpp-Sbi-Target-Nf-Id` on 307 and 308. The SCP, new in v4.3.0, does not handle these headers either |

### By repository

One issue or pull request per repository of `github.com/free5gc`:

| Repository | Items | Patches here |
|---|---|---|
| `nrf` | F1, F2, F3, F4, F15, F23, F24, F25, F26, F27, F28, F29, F31 | `nrf/0001` to `0003` (F1 to F3); `nrf/0004` (F24); `nrf/0005` (F4, F23, F25, F26); `nrf/0006` (F27, F28); `nrf/0007` (F24, the FQDN required) |
| `openapi` | F5, F6, F16, F21, F23, F24, F25, F31 | `openapi/0001` to `0003` (F6, F16); `openapi/0004`, the CAPIF models and clients (F13); `openapi/0005` (F21, F24); `openapi/0006` (F5, F12, F23); `openapi/0007` (F13); `openapi/0008` (F28, F31) |
| `util` | F22 | `util/0001` |
| `udm` | F7, F10, F17, F20 (deregistration notification), F24, F29, F30, F31 | `udm/0001`, `udm/0002` (F7, F17); `udm/0003`, `udm/0004` (F24) |
| `ausf` | F8, F24, F29, F31 | `ausf/0001` (F8); `ausf/0002`, `ausf/0005` (F24); `ausf/0003` (F4); `ausf/0004` (F31, towards the AAnF) |
| `amf` | F18, F19, F20 (token check on callbacks), F24, F29, F31 | `amf/0001` (F18, F19); `amf/0002`, `amf/0003` (F24) |
| `nef` | F11, F12, F13, F14, F24, F29, F31 | `nef/0001` (F11); `nef/0002`, `nef/0005` (F13); `nef/0003`, `nef/0007` (F13, F24); `nef/0004` (F4, F14); `nef/0006` (F31, towards the AAnF) |
| `smf`, `pcf`, `udr`, `nssf`, `chf`, `bsf` | F24, F29, F31 | `<nf>/0001`, `<nf>/0002` (F24) |
| `webconsole` | F9 | none; `free5gc/scripts/provision-akma-subscriber.sh` works around it |
| `free5gc` (configuration, `run.sh`, test bench) | the integration changes at the end | `config/`, `run/`, `test/` |

---

## F1 — The NRF drops `aanfInfoList`

- **free5GC today.** `nnrfNFManagementOption` (`internal/context/management_data.go`) copies the `*Info` attributes it knows one by one (`udrInfo`, `udmInfo`, `ausfInfo`…) and drops the rest. The profile of the AAnF loses the Routing Indicators it serves.
- **Specification.** TS 29.510 table 6.1.6.2.2-1: `aanfInfoList` (a map of `AanfInfo`) is part of `NFProfile`. Clause 5.2.2.2.2: attributes the NRF does not understand *"shall be stored as part of the NF's profile data in NRF"*.
- **How.** The NRF stores the whole `NFProfile`, `aanfInfoList` included, and returns it in discovery.
- **Here.** `free5gc/patches/nrf/0001-store-aanf-info-list.patch`.

## F2 — The NRF refuses discovery of `AANF` by Routing Indicator

- **free5GC today.** `validateQueryParameters` (`internal/sbi/processor/nf_discovery.go`) accepts a fixed list of NF types without `AANF` and answers 400. The `routing-indicator` filter only handles AUSF and UDM.
- **Specification.**
  - TS 29.510 table 6.2.3.2.3.1-1: `routing-indicator` *"may be included if the target NF type is "AUSF", "AANF" or "UDM""*.
  - Table 6.1.6.2.73-1 (`AanfInfo`): without `routingIndicators`, *"the AAnf can serve any Routing Indicator"*.
  - TS 33.535 cl. 6.7: the AUSF, the NEF and internal AFs *"shall utilize the NRF to discover the AAnF instance(s) unless AAnF information is available by other means, e.g. locally configured"*, taking the Routing Indicator of the UE into account.
- **How.** Discovery accepts `target-nf-type=AANF`. With `routing-indicator`, it returns the AAnFs whose `aanfInfoList` lists the RID or does not restrict RIDs.
- **Here.** `free5gc/patches/nrf/0002-discover-aanf-by-routing-indicator.patch`.

## F3 — The NRF issues access tokens with an empty `aud`

- **free5GC today.** `access_token.go` copies `targetNfInstanceId` into `aud`. The free5GC clients do not send that field, so `aud` comes out empty.
- **Specification.** TS 29.510 table 6.3.5.2.4-1: `aud` is mandatory and *"shall contain the NF service producer's NF instance ID(s) (if the exact NF instance(s) of the NF service producer is known) or the NF type of NF service producers"*. TS 33.501 cl. 13.4.1.1.2 step 1: the claims include the *"NF type of the NF Service Producer (audience)"*.
- **How.** The NRF puts in `aud` the producer instance when the request names it, and the producer NF type otherwise.
- **Here.** `free5gc/patches/nrf/0003-access-token-audience.patch`. The AAnF requires `aud`, so this patch is needed.

## F4 — The NRF has no scopes per operation and per consumer type

- **free5GC today.** The NRF only issues service scopes (for example `naanf-akma`). It ignores `allowedOperationsPerNfType` and `allowedOperationsPerNfInstance` of `NFService`; no NRF code mentions them.
- **Specification.**
  - TS 33.501 cl. 13.4.1.1.1: the producer may register in its profile an *"additional scope"* with the operations allowed *"per NF type of the NF Service Consumer or per NF instance ID"*.
  - TS 29.510 cl. 6.1.6.2.3, NOTE 11: the NRF *"shall only grant such scope in the access token, if the scope is present in either "allowedOperationsPerNfType", for the specific NF type of the NF Service Consumer, or in "allowedOperationsPerNfInstance""*.
  - TS 29.535 table 5.1.9-1: the scopes of Naanf_AKMA are `naanf-akma`, `naanf-akma:anchorkey`, `naanf-akma:applicationkeyget` and `naanf-akma:applicationkeyget:supi-access`. The last one allows the SUPI in the answer.
- **How.**
  - The AAnF registers in the `naanf-akma` `NFService`, for example, `allowedOperationsPerNfType: {AUSF: [naanf-akma, naanf-akma:anchorkey], NEF: [naanf-akma, naanf-akma:applicationkeyget, naanf-akma:applicationkeyget:supi-access], AF: [...]}`.
  - The NRF only grants a requested scope that is in the list of the consumer type or instance.
  - The AAnF checks the scope of each operation and returns the SUPI only with `supi-access`.
- **Here.** Fixed by `nrf/0005`: the NRF only grants the scopes of `allowedOperationsPerNfType` for the type of the consumer, and refuses a scope outside the list with `400 invalid_scope`. The AAnF registers the lists of [sbi-tls.md](sbi-tls.md) section 5, checks the scopes of each operation, and returns the SUPI only with `supi-access`. The AUSF and the NEF ask for the new scopes (`ausf/0003`, `nef/0004`).

## F5 — `oauth.VerifyOAuth` checks neither `exp` nor `aud`

- **free5GC today.** `oauth.VerifyOAuth` (`openapi` v1.2.4, `oauth/oauth.go`) checks the signature and the scope of the token, but not its expiry (`exp`) or its audience (`aud`). Every free5GC NF that requires a token uses this function, the NEF middleware included.
- **Specification.** TS 33.501 cl. 13.4.1.1.2 step 2: the producer *"checks that the audience claim in the access token matches its own identity or the NF type of NF Service Producer"* and *"checks that the access token has not expired by verifying the expiration time"*. TS 29.522 cl. 7.2, for the NEF with CAPIF: the NEF checks *"whether the NEF identifier in the "token" matches its own published identifier"*.
- **How.** `VerifyOAuth` refuses an expired token and a token whose `aud` is neither the producer instance nor the producer type. The 401 follows TS 29.500 cl. 6.7.3 (F12).
- **Here.** Fixed by `openapi/0006`, in every NF and in the AAnF: the checks of [sbi-tls.md](sbi-tls.md) section 5, with `exp` without tolerance and `aud` equal to the instance or the type of the producer.

## F6 — `openapi` has no Naanf_AKMA models or client

- **free5GC today.** `openapi` v1.2.4 has the `AANF` NF type, the `naanf-akma` service and `AanfInfo`, but no Naanf_AKMA data types and no client.
- **Specification.**
  - TS 29.535 cl. 5.1.6.2: `AkmaKeyInfo` and `CtxRemove`;
  - TS 29.522 cl. 5.14.5.3: `AkmaAfKeyRequest`, `AkmaAfKeyData` and `ServiceDisableNotif`;
  - TS 29.535 Annex A: the API in OpenAPI, which takes precedence for the encoding (A.1).
- **How.** The models and the client are generated from `TS29535_Naanf_AKMA.yaml` and `TS29522_AKMA.yaml` with the same generator free5GC uses for the other APIs.
- **Here.** `free5gc/patches/openapi/0001-naanf-akma-models.patch` and `0002-naanf-akma-client.patch`, written by hand in the style of the generated code. `free5gc/scripts/prepare-openapi.sh` applies them to a local copy of the module, used through `replace` in `go.mod`.

## F7 — The UDM sends neither `akmaInd` nor `routingId`

- **free5GC today.** The UDM v1.4.5 does not fill these two fields of `AuthenticationInfoResult`, although `openapi` has them.
- **Specification.** TS 33.501 cl. 6.1.3.1 step 2 (EAP-AKA') and cl. 6.1.3.2.0 step 2 (5G AKA): *"If a subscriber has an AKMA subscription, the UDM shall include the AKMA indication and Routing indicator in the Nudm_UEAuthentication_Get Response."* TS 29.503 table 6.3.6.2.3-1: `routingId` *"shall be present if the akmaInd is set to "true""*.
- **How.** With `akmaAllowed: true` in the subscription (TS 29.505 table 5.4.2.2-1), the UDM answers with `akmaInd: true` and `routingId` equal to the Routing Indicator of the SUCI.
- **Here.** `free5gc/patches/udm/0001-akma-indication-and-routing-id.patch`. The RID comes from the `routingId` of the subscription in the UDR, which TS 29.505 makes mandatory with `akmaAllowed: true`. It is also there when the UE authenticates with a SUPI, for example after a registration by GUTI.

## F8 — The AUSF neither derives the AKMA material nor registers it at the AAnF

- **free5GC today.** The AUSF v1.4.5 ignores `akmaInd` and `routingId` in the answer of the UDM.
- **Specification.** TS 33.535 cl. 6.1:
  - step 3: with the indication of the UDM, the AUSF *"shall store the KAUSF and generate the AKMA Anchor Key (KAKMA) and the A-KID from KAUSF after the primary authentication procedure is successfully completed"*;
  - step 4: it selects the AAnF (cl. 6.7) and sends SUPI, A-KID and K_AKMA with `Naanf_AKMA_AnchorKey_Register`;
  - *"The AUSF shall use the RID received from the UDM"*.

  Derivations in TS 33.535 A.2 and A.3.
- **How.** The AUSF derives K_AKMA and the A-TID when the primary authentication succeeds, builds the A-KID with the RID of the UDM, and registers them at the AAnF found through the NRF.
- **Here.** `free5gc/patches/ausf/0001-akma-anchor-key-register.patch`. The registration runs apart from the answer to the AMF: the specification does not make the primary authentication wait for it, and an AAnF that is down only shows in the log.

## F9 — The web console has no AKMA subscription data

- **free5GC today.** The web console has no fields for `akmaAllowed` and `routingId`. When you edit a subscriber, it rewrites the document and drops both.
- **Specification.** TS 33.535 cl. 3.1 and 4.2.5: the *"AKMA subscription data"* lives in the UDM. TS 29.505 table 5.4.2.2-1: `akmaAllowed` and `routingId` of `AuthenticationSubscription`; `routingId` *"shall be present if the akmaAllowed is set to "true""*.
- **How.** The web console edits both attributes and keeps them when the rest of the subscriber is edited. With `akmaAllowed: true`, it requires `routingId` (`^[0-9]{1,4}$`).
- **Here.** Worked around by `free5gc/scripts/provision-akma-subscriber.sh`, which writes both attributes in MongoDB.

## F10 — The UDM only maps GPSI to SUPI

- **free5GC today.** `GetIdTranslationResultProcedure` (`internal/sbi/processor/subscriber_data_management.go`) always treats `ueId` as a GPSI and returns the SUPI.
- **Specification.** TS 29.503 cl. 5.2.2.2.10: the consumer (*"e.g. NEF, AAnF"*) gets *"the SUPI/GPSI that corresponds to the provided GPSI/SUPI"*; `ueId` *"shall be a SUPI or GPSI"*. TS 33.535 cl. 6.3 step 5: by local policy, the NEF maps the SUPI to a GPSI with `Nudm_SubscriberDataManagement` to send it to the external AF.
- **How.** With a SUPI in `ueId`, the UDM returns the GPSI of the subscriber (MSISDN or external identifier), taking the AF into account when its parameters come in (`af-id` and others).
- **Here.** Open. The NEF never returns a GPSI, which the specification allows (*"optionally"*).

## F11 — The NEF has no `3gpp-akma` API

- **free5GC today.** The NEF v1.2.5 has nothing for AKMA.
- **Specification.** TS 33.535 cl. 6.3 and 7.3.2; TS 29.522 cl. 4.4.23.2 and 5.14: `POST {apiRoot}/3gpp-akma/v1/retrieve`. The NEF authorizes the AF, gets K_AF from the AAnF with `Naanf_AKMA_ApplicationKey_Get`, and never passes the SUPI to the AF.
- **How.** See [nef-akma-api.md](nef-akma-api.md).
- **Here.** `free5gc/patches/nef/0001-akma-api.patch`, with the configuration in `free5gc/patches/config/0002-nef-akma.patch`.

## F12 — The 401 of the OAuth2 middleware of the NEF has no `ProblemDetails` and no `WWW-Authenticate`

- **free5GC today.** `RouterAuthorizationCheck.Check` (`internal/util/util.go` of the NEF) answers 401 with the body `{"error": "<message>"}` in `application/json` and without the `WWW-Authenticate` header. This holds for every API group of the NEF: the AF-facing ones (`3gpp-traffic-influence`, `3gpp-pfd-management`, `3gpp-akma`) and the SBI ones (`nnef-pfdmanagement`, `nnef-callback`, `nnef-oam`).
- **Specification.**
  - **AF-facing APIs.** TS 29.522 cl. 5.14.7.1 refers to TS 29.122 cl. 5.2.6. TS 29.122 table 5.2.6-1: the 401 carries a `ProblemDetails` body, and NOTE 2 sets the content type `application/problem+json`.
  - **SBI APIs.** TS 29.500 cl. 6.7.3: a producer that refuses a request without a token or with an invalid one *"shall return the HTTP "401 Unauthorized" status code together with the "WWW-Authenticate" header"*, with the `Bearer` scheme, `realm` set to the URI of the API, and `error="invalid_token"` when a token was sent.
  - **RFC 6750 cl. 3:** the `WWW-Authenticate` header in the answer to a request without valid credentials.
- **How.** The 401 carries:
  - `WWW-Authenticate: Bearer realm="<URI of the API>"`, with `error="invalid_token"` when the request had a token;
  - a `ProblemDetails` body (`status: 401` and `detail`) in `application/problem+json`.
- **Here.** Fixed by `openapi/0006`, with the same answers in every NF: `401` with `WWW-Authenticate: Bearer realm="<URI of the API>"` and `ProblemDetails` in `application/problem+json`. Before it, the NEF answered `401` with `{"error":"verify OAuth Authorization header invalid"}` in `application/json`, without `WWW-Authenticate`.

## F13 — The AF-facing APIs of the NEF have no CAPIF and no mutual TLS

- **free5GC today.** free5GC has no CAPIF. The NEF authorizes the AF only with a token from the NRF, and serves the AF-facing APIs on the SBI server, with server-only TLS (`sbi.scheme: https`) or without TLS.
- **Specification.**
  - TS 33.501 cl. 12.2: mutual authentication between NEF and AF *"based on client and server certificates"*, with TLS;
  - TS 33.501 cl. 12.3: TLS *"shall"* protect the interface; support is mandatory;
  - TS 33.501 cl. 12.4: OAuth-based authorization *"shall"* be used;
  - TS 29.522 cl. 6: without CAPIF, OAuth2 authorization with the *"Client Credentials"* grant, *"based on local configuration"*. The specification does not say who the authorization server is in that case;
  - TS 29.522 cl. 7.2 and TS 33.122 cl. 6.5.2.3: with CAPIF, the authorization server is the CAPIF Core Function (CCF). The NEF checks its own identifier, the API name and the scope in the token.
- **How.**
  - TLS with client and server certificates between the NEF and the AF.
  - OAuth2 authorization:
    - with CAPIF, a token from the CCF, obtained with `Obtain_Authorization` (TS 29.222 cl. 5.6.2.3.2);
    - without CAPIF, a token from an authorization server set by local configuration.
  - A CCF for free5GC can be built from the services of TS 29.222:
    - the NEF acts as the API publishing function, publishing `3gpp-akma` with `Publish_Service_API` (cl. 5.3);
    - the NEF also acts as the API exposing function, checking the token as TS 29.522 cl. 7.2 says;
    - the AF acts as the API invoker: it onboards at the CCF (`CAPIF_API_Invoker_Management_API`), discovers the API (`Discover_Service_API`, cl. 5.2) and gets the token at `{apiRoot}/capif-security/v1/securities/{securityId}/token` (cl. 5.6.2.3; TS 33.122 cl. 6.5.2.3).
- **Here.** Fixed with CAPIF and mutual TLS ([capif.md](capif.md), [nef-akma-api.md](nef-akma-api.md)):
  - the CCF of this repository (`free5gc/ccf/`), with the CAPIF models and clients of `openapi/0004` and `0007`;
  - `nef/0002`: the NEF publishes `3gpp-akma` at the CCF and checks its tokens;
  - `nef/0003`: the AF-facing APIs over mutual TLS, with the CA of the CCF for the client certificates of the invokers;
  - `nef/0005`: the client certificate bound to the token and to `check-authentication`, and `allowNrfTokens: false`, so that `3gpp-akma` only accepts the tokens of the CCF.

## F14 — The NEF asks for the `nnrf-nfm` token with the wrong target type

- **free5GC today.** `DeregisterNFInstance` (`internal/sbi/consumer/nrf_service.go` of the NEF) asks for the `nnrf-nfm` token with `targetNfType=NEF`. The NRF refuses (`invalid_scope`), and the NEF does not deregister on shutdown. It fails with the original NRF too.
- **Specification.** TS 33.501 cl. 13.4.1.1.2 step 1: the token request *"shall include the NF type of the expected NF Service Producer instance"*. The producer of `nnrf-nfm` is the NRF.
- **How.** `GetTokenCtx(ServiceName_NNRF_NFM, NrfNfManagementNfType_NRF)`, as in the other free5GC NFs.
- **Here.** Fixed by `nef/0004`. Not an AKMA issue, but before it the old profile of the NEF stayed at the NRF after each stop.

## F15 — `complexQuery` without `routing-indicator` for `AANF`

- **free5GC today.** Discovery with `complexQuery` (the `[Query-27]` part of `nf_discovery.go`) does not handle `routing-indicator` for `AANF`, as it already does not for the types other than AUSF and UDM.
- **Specification.** TS 29.510 cl. 6.2.3.2.3.1: the NRF *"may support"* the `complexQuery` expression (TS 29.501), which combines the query parameters of table 6.2.3.2.3.1-1, `routing-indicator` among them. An NRF that does not support it *"shall reject"* the request with `INVALID_QUERY_PARAM`.
- **How.** The filter of F2 also applies inside `complexQuery`; or, if the NRF does not handle the parameter there, it rejects the request with `INVALID_QUERY_PARAM`.
- **Here.** Open. No consumer here uses `complexQuery`.

## F16 — `openapi` without the models of the primary authentication triggered by the home network

- **free5GC today.** `openapi` v1.2.4 and v1.2.5 have neither `AuthTriggerInfo` nor `ReauthNotificationInfo`. `Amf3GppAccessRegistration` and `AmfNon3GppAccessRegistration` lack the `reauthNotifyCallbackUri` attribute. The `Nudm_UEContextManagement` client has no `trigger-auth` operation.
- **Specification.** TS 29.503:
  - cl. 6.2.6.2.36: `AuthTriggerInfo`, with the SUPI;
  - cl. 6.2.6.2.35: `ReauthNotificationInfo`, with the SUPI and the optional `oldGuami` and `ausfRediscoveryInd`;
  - cl. 6.2.6.2.2 and 6.2.6.2.3: `reauthNotifyCallbackUri`, optional in both AMF registrations;
  - cl. 6.2.3.13: the custom operation `trigger-auth` on `{apiRoot}/nudm-uecm/v1/{ueId}/registrations/trigger-auth`;
  - Annex A: `TS29503_Nudm_UECM.yaml`.
- **How.** The models and the client operation, generated from the YAML with the tool free5GC uses for the other APIs. The YAML declares `get:` with a request body, while table 6.2.3.13.4.1-1, the procedure of cl. 5.3.2.16.2 and the custom operations of TS 29.501 cl. 4.6.1.2 use POST. The operation should use POST.
- **Here.** `free5gc/patches/openapi/0003-home-network-triggered-authentication.patch`, written by hand in the style of the generated code, applies to both `openapi` versions that free5GC v4.2.3 pins. `oldGuami` and `ausfRediscoveryInd` are read and ignored.

## F17 — UDM without `Nudm_UECM_AuthTrigger` and without the re-authentication notification

- **free5GC today.** The UDM routes (`internal/sbi/api_uecontextmanagement.go`) have no `trigger-auth`. The UDM keeps the AMF registration in memory (`UdmUeContext.Amf3GppAccessRegistration`) and already notifies the AMF through `deregCallbackUri` (`SendOnDeregistrationNotification`, `internal/sbi/processor/notifier.go`), but has no re-authentication notification.
- **Specification.**
  - TS 33.535 cl. 6.4.4: *"the AAnF may decide to refresh the KAKMA based on the operator's local authentication policy by sending the Nudm_UECM_AuthTrigger Request message to the UDM. The UDM may further decide whether to trigger the primary authentication as defined in clause 6.1.5 of TS 33.501"*.
  - TS 33.501 cl. 6.1.5.2: step 1, *"The NF may send a Nudm_UECM_AuthTrigger Request message to the UDM with the SUPI of the target UE"*; NOTE A, *"the UDM can decide not to proceed with triggering the primary authentication based on the UDM's local authentication policy"*; step 2, *"The UDM sends a Nudm_UECM_Re-AuthenticationNotification message to the AMF/SEAF with the UE's SUPI"*. The procedure is optional (cl. 6.1.5.1); the operations are in cl. 14.2.6 and 14.2.7.
  - TS 29.503 cl. 5.3.2.16 and 6.2.3.13 (`trigger-auth`: `204`, and `404` when the user does not exist); cl. 5.3.2.15 and 6.2.5.6 (*"The UDM sends a POST request to the reauthNotifyCallbackUri"*).
- **How.** The UDM serves `trigger-auth` and applies its local policy. When it goes ahead, it finds the AMF registered for the UE and POSTs `ReauthNotificationInfo` to the `reauthNotifyCallbackUri`. It answers the consumer with `204`, `403 REAUTHENTICATION_NOT_ALLOWED` or `404` (`USER_NOT_FOUND`, `CONTEXT_NOT_FOUND`).
- **Here.** `free5gc/patches/udm/0002-auth-trigger.patch`: POST, and `405` for GET. Local policy: another request for the same SUPI within 60 s is refused. The UDM answers after the AMF; the specification does not say whether it waits. The notification goes without an access token (F20).

## F18 — AMF without the re-authentication notification callback

- **free5GC today.** The AMF registers at the UDM with `deregCallbackUri` only (`internal/sbi/consumer/udm_service.go`). Its callback routes (`internal/sbi/api_httpcallback.go`) have none for the re-authentication notification.
- **Specification.**
  - TS 33.501 cl. 6.1.5.2 step 0b: *"The AMF shall provide a callback URI within the AMF registration for the UDM to create an implicit subscription to later notify the AMF for potential home network triggered re-authentication using the Nudm_UECM_Re-AuthenticationNotification service operation"*, when the network supports the procedure (cl. 6.1.5.1).
  - TS 29.503 cl. 5.3.2.15.2: `204` when accepted; `202` when accepted and the UE is not reachable (*"the reauthentication pending flag has been set"*); the errors of table 6.2.5.6-3: `403 REAUTHENTICATION_NOT_ALLOWED`, `404 CONTEXT_NOT_FOUND` and `409`.
- **How.** The AMF puts `reauthNotifyCallbackUri` in `Nudm_UECM_Registration` and serves that route. The answer follows F19.
- **Here.** `free5gc/patches/amf/0001-home-network-triggered-authentication.patch`: `<AMF>/namf-callback/v1/reauth/<SUPI>`, in the 3GPP access registration, like `deregCallbackUri`. The route is outside the token check of the other callback routes (F20).

## F19 — AMF does not run the primary authentication the home network asks for

- **free5GC today.**
  - The GMM state machine (`internal/gmm/init.go`) has the transition from `Registered` to `Authentication`, but `internal/gmm/sm.go` only uses it on a Registration Request.
  - `AuthenticationProcedure` (`internal/gmm/handler.go`) skips the authentication when the security context is valid, and sends `Registration Reject` on failure.
  - After the NAS SMC, `HandleSecurityModeComplete` and the `ContextSetup` state expect the Registration Request in the NAS message container.
- **Specification.** TS 33.501:
  - cl. 6.1.5.2 step 3: the AMF *"shall decide whether to run the primary authentication procedure based on its own local authentication policy, and the UE state"*; when it accepts and cannot reach the UE, it *"shall set the authentication pending flag"* and re-authenticates *"When UE re-attaches to the same AMF or becomes reachable"*;
  - cl. 6.1.5.2 step 4: *"The AMF/SEAF starts the primary authentication procedure as defined in clause 6.1.2"*;
  - cl. 6.9.4.2: *"After a primary authentication has taken place, new NAS keys from a new KAMF shall be derived"*; the NAS SMC takes them into use;
  - cl. 6.9.4.4: AS key re-keying after the authentication *"may be used"*.
- **How.** With the UE in `Registered`, the AMF runs the primary authentication outside a registration, then the NAS SMC with the new KAMF, and goes back to `Registered` without waiting for a Registration Request. With the UE unreachable, it keeps the pending flag and runs the authentication at the next Service Request or registration. A failure outside a registration cannot depend on a `Registration Reject`.
- **Here.** `free5gc/patches/amf/0001-home-network-triggered-authentication.patch`. The answers follow table 6.2.5.6-3:
  - UE connected: `204`, and the authentication starts at once with a new ngKSI; after the NAS SMC the UE is back in `Registered`;
  - UE registered and not connected: `202` and the pending flag, served after the next Service Request or registration;
  - registration in progress: `409 TEMPORARY_REJECT_REGISTRATION_ONGOING`; handover in progress: `409 TEMPORARY_REJECT_HANDOVER_ONGOING`;
  - authentication or deregistration in progress: `403 REAUTHENTICATION_NOT_ALLOWED`;
  - UE unknown or deregistered: `404 CONTEXT_NOT_FOUND`.

  When the AUSF does not answer, the AMF sends no `Registration Reject`: it answers `500` to the UDM and the UE stays registered. The NAS SMC of this authentication asks neither for the initial NAS message (RINMR) nor for a horizontal derivation of KAMF (HDP). No AS re-keying here: UERANSIM has no AS security. The AUSF patch (F8) already registers the K_AKMA of the new authentication at the AAnF.

## F20 — AMF requires an access token on notifications

- **free5GC today.** With OAuth2 on, the AMF requires a token with the `namf-callback` scope on every route of `/namf-callback/v1` (`internal/sbi/server.go`), notifications included. The SMF and the PCF request that token before notifying the AMF. The UDM sends the deregistration notification (`SendOnDeregistrationNotification`, `internal/sbi/processor/notifier.go`) with a `nudm-uecm` token requested for the UDM type; reading the code, the AMF rejects it with 401 because the scope does not match.
- **Specification.**
  - TS 29.500 cl. 6.7.3: *"For the notify operation of subscribe/notify semantics service operations, in this release of this specification OAuth 2.0 access token is not used."*
  - TS 29.500 cl. 6.10.7, NOTE: *"access token is not used in notification / callback, see clause 6.7.3"*.
  - TS 33.501 cl. 13.4.1.0: *"The OAuth 2.0 framework does not apply to the notification operation."*
- **How.** The routes that receive notifications do not require a token, and the NFs that notify do not request one.
- **Here.** Open for the notifications that already existed. The new re-authentication route of F18 is outside the token check, and the UDM sends it without a token.

---

## F21 — The SBI client neither checks the server nor presents a certificate

- **free5GC today.** The HTTP/2 client of `openapi` v1.2.4 (`client.go`, `innerHTTP2Client`) sets `InsecureSkipVerify: true` and presents no client certificate; `udr/ImsDataRepository/client.go` does the same. Every NF uses this client. With `oauth: true` and `https`, the NRF requires and checks a client certificate against `cert/root.pem` (`internal/sbi/server.go`, `configureOAuthMutualTLS`): in that setting no NF can talk to it.
- **Specification.**
  - TS 33.501 cl. 13.1.0: *"All network functions shall support mutually authenticated TLS and HTTPS"*; *"Network functions shall support both server-side and client-side certificates."*; *"TLS clients shall include the SNI extension as specified in RFC 9113"*.
  - TS 33.501 cl. 13.3.2.1: *"If the PLMN uses token-based authorization, the network shall use protection at the transport layer as described in clause 13.1."*
  - TS 33.310 cl. 6.3.1: *"Validity of certificates received from the TLS entity shall be verified by CRLs or OCSP responses"*.
- **How.** The client checks the server certificate: the CA of the operator, the name of the URI (the DNS-ID) or the address, and revocation. It presents the certificate of the NF and sends the SNI when the URI has a name. The TLS profile is the one of TS 33.210 cl. 6.2, with the restrictions of RFC 9113 cl. 9.2.
- **Here.** Fixed by `openapi/0005`: the package `sbitls` and the client ([sbi-tls.md](sbi-tls.md)).

## F22 — The NFs write the secrets of the TLS sessions to a file

- **free5GC today.** `httpwrapper.NewHttp2Server` (`util` v1.3.2): with the log path (`-l`), it creates `log/<date>/key/<nf>sslkey.log` and sets `KeyLogWriter` on the server. The metrics servers use the same function. With `https`, the file gets the secrets of every session, and whoever reads it decrypts the traffic.
- **Specification.** TS 33.501 cl. 13.1.0: *"TLS shall be used for transport protection within a PLMN unless network security is provided by other means."* TS 33.535 cl. 4.4.0: the interfaces of the AAnF *"shall be confidentiality, integrity and replay protected"*. The specifications say nothing about a key log; it voids the confidentiality those clauses ask for.
- **How.** No TLS session secret in a file. If there is one, only through an explicit debug option, off by default.
- **Here.** Fixed by `util/0001`. The AAnF, which had copied the pattern, no longer writes one either.

## F23 — Access tokens of the NRF in `RS512`

- **free5GC today.** The NRF signs the tokens with `RS512`, with the RSA key of its own certificate (`processor/access_token.go`, `AccessTokenProcedure`; `context.GetTokenCtx`), without `kid`. `oauth.VerifyOAuth` (`openapi`) only accepts `RS512`.
- **Specification.**
  - TS 33.501 cl. 13.4.1.0: *"The Access token shall follow the JWS profile specified in the clause 6.3.3 of TS 33.210"*.
  - TS 33.210 cl. 6.3.3.1: *"The "alg" header parameter value ES256 (ECDSA using P-256 and SHA-256) shall be supported."*; *"The "kid" header parameter shall be supported."* In V20.0.0: *"Usage of "alg" header parameter values RS256, RS384 and RS512 ... is not recommended."* Cl. 6.3.3.4: *"The "x5t#S256" header parameter should be supported."*
  - TS 33.310 table 6.1.3c.3-2: the certificate of the key that signs the tokens, with `id-kp-oauthAccessTokenSigning` (RFC 9509).
- **How.** The NRF signs with `ES256`, with `kid` and `x5t#S256`, with an ECDSA P-256 key whose certificate follows table 6.1.3c.3-2. The producers check `ES256`.
- **Here.** Fixed by `nrf/0005` and `openapi/0006`.

## F24 — Profiles without `fqdn` and URIs built from addresses

- **free5GC today.**
  - The profiles of the NFs only have IP addresses, without `fqdn`. The `apiPrefix` of each service carries the whole URI, `<scheme>://<IP>:<port>`.
  - The own URI of each NF, of the profile, of the callbacks and of `Location`, comes from the address (`GetIPv4Uri()`, `context.Url` and the like).
  - Consumers build the URI of another NF in four ways: `SearchNFServiceUri` (AMF, SMF, UDM, PCF) returns the `fqdn` without scheme or port; the one of the NEF adds the scheme, without the port; `openapi.GetNFServiceUri` (AUSF) prefers `apiPrefix`; the SMF and the PCF use `service.ApiPrefix` directly.
  - With an `fqdn` in the profile and nothing else, the AMF, SMF, UDM and PCF build invalid URIs.
- **Specification.**
  - TS 29.510 table 6.1.6.2.2-1, NOTE 1: *"If the NF supports the NF services with "https" URI scheme (i.e use of TLS is mandatory), then the FQDN shall be provided in the NF Profile or the NF Service profile (see clause 6.1.6.2.3) and it shall be used to construct the target URI"*. Table 6.1.6.2.3-1, NOTE 8, says the same.
  - TS 29.510 table 6.1.6.2.5-1, NOTE 4: with `https`, the consumer *"shall use such port number along with the FQDN parameter present in the NFService or NFProfile data types to construct the target URI"*.
  - TS 29.510 table 6.2.6.2.4-1 and TS 29.501 cl. 4.4.1: `apiPrefix` is an *"optional deployment-specific string that starts with a "/" character"*.
  - TS 33.501 cl. 13.1.0: the client sends the SNI, which takes no address (RFC 6066 cl. 3).
- **How.** With `https`, each NF registers its FQDN, and its own URIs use the name. The consumer builds `https://<FQDN>:<port>`, plus the `apiPrefix`, which is only the path, and sends the SNI with the name.
- **Here.** Fixed by one `*-sbi-tls` patch per NF and the helper of `openapi/0005`. With `https`, no NF starts without `sbi.fqdn` (the `*-fqdn-required` patches). `apiPrefix` still carries the whole URI, now with the name, for the SMF and the PCF that use it directly: that part stays open.

## F25 — Certificates of the NFs outside the profile of TS 33.310

- **free5GC today.**
  - With OAuth2, the NRF makes a certificate for each NF that registers (`oauth.GenerateCertificate`, `context.SignNFCert`): RSA 2048, 10 years, `C=TW, ST=Taiwan, L=Hsinchu, O=free5gc, OU=free5gc`, the CN and the DNS with the NF type; no `keyUsage`, `extendedKeyUsage`, CRL distribution point or `nfTypes`.
  - The NRF makes its own certificate again at each start, with `CN=NRF`, `DNS:NRF` and no URI of its NF instance ID.
  - On a token request, the NRF checks the file it made itself, not the certificate of the TLS session, and only warns when the chain does not verify (*"unknown authority"*).
  - The TLS certificates that come with free5GC (`cert/<nf>.pem`) are outside the profile too.
- **Specification.**
  - TS 33.501 cl. 13.1.0: *"TLS client and server certificates shall be compliant with the SBA certificate profile specified in clause 6.1.3c of TS 33.310"*.
  - TS 33.310 cl. 6.1.3c.3, table 6.1.3c.3-1: the Subject with `C`, and `O` equal to the home network domain; *"3 years or less"*; critical `keyUsage` with `digitalSignature`; `extendedKeyUsage`; `authorityKeyIdentifier`; `cRLDistributionPoint`; a critical `subjectAltName` that *"shall ... contain a URI-ID with the URI for the NF Instance ID"* and the DNS-ID with the FQDN; `nfTypes` (RFC 9310). Cl. 6.1.3c.2: *"ECDSA is recommended"*.
  - TS 33.501 cl. 13.4.1.1.2 step 2: the NRF checks the token request with *"the public key certificate of the NF Service Consumer or those in the NF profile"*.
- **How.** Certificates issued by the CA of the operator in the profile of cl. 6.1.3c.3. The NRF checks the certificate of the TLS session and refuses one without a valid chain.
- **Here.** Fixed: the certificates of `make-sba-certs.sh`, and `nrf/0005`, which checks the certificate of the session and no longer makes certificates.

## F26 — Tokens of the NRF with an empty `iss`, certificate of the NRF without its NF instance ID

- **free5GC today.** The field `NRFContext.Nrf_NfInstanceID` (`internal/context/context.go`) is never set. `AccessTokenProcedure` puts it in `iss`, so every token the NFs ask for has an empty `iss`. `InitNrfContext` passes it to `oauth.GenerateCertificate`, and the certificate of the NRF has no URI.
- **Specification.**
  - TS 29.510 table 6.3.5.2.4-1: `iss`, mandatory: *"This IE shall contain NF instance id of the NRF."*
  - TS 33.501 cl. 13.4.1.1.2 step 2: *"The claims in the token shall include the NF Instance Id of NRF (issuer)"*; the producer *"shall check that the identity in the issuer claim in the access token matches the identity of the OAuth 2.0 authorization server(s) (NRF or NRF Set) that is allowed to issue access tokens to this NF Service Producer."*
  - TS 33.310 cl. 6.1.3c.3: the `subjectAltName` of the TLS certificates and of those that validate the signature of the tokens *"shall ... contain a URI-ID with the URI for the NF Instance ID as an URN"*.
- **How.** The NRF puts its own NF instance ID in `iss`, the same as the URI of the certificate that validates the signature. The producer checks `iss` against that URI.
- **Here.** Fixed by `nrf/0005`; the signing certificate comes from `make-sba-certs.sh`.

## F27 — The scope of a token is checked on one profile of the target type only

- **free5GC today.** `AccessTokenScopeCheck` (`internal/sbi/processor/access_token.go` of the NRF): for a `targetNfType`, `RestfulAPIGetOne` returns one profile, the first of that type in MongoDB, and the scope is checked on it. An old profile without the service, left by an NF that stopped without deregistering, blocks the token for every NF of the type.
- **Specification.** TS 33.501 cl. 13.4.1.1.2 step 2: *"The NRF checks whether the NF Service Consumer is authorized to access the requested service(s)."* NOTE 1 of the same step: without a list of slices, the token *"can be used to access expected NF services of all expected NF Service Producers of the NF type based on local configuration and operator policy."*
- **How.** The clause does not say which profile to look at. The request is by NF type, and the answer should not depend on the order of the profiles in the database: the NRF checks the profiles of the requested type.
- **Here.** Fixed by `nrf/0006`: with `targetNfInstanceId`, the profile of that instance; without it, a `REGISTERED` profile of the type that grants the scopes is enough.

## F28 — The NRF has no `Nnrf_AccessToken_RetrieveKey`

- **free5GC today.** The NRF only serves `/oauth2/token` (`internal/sbi/api_accesstoken.go`); there is no `/oauth2/retrieve-key`. Each producer gets the key that validates the tokens by configuration.
- **Specification.**
  - TS 29.510 V20.1.0 cl. 6.3.4.1: *"The "Retrieve Key Request" custom operation shall be supported."*
  - TS 29.510 cl. 5.4.2.3.1: the consumer sends a POST to `{nrfApiRoot}/oauth2/retrieve-key`, with the NF instance ID of the issuer and the header parameters that identify the key; *"On success, "200 OK" shall be returned, the content of the POST response shall contain the raw public key, the X.509 certificate or a certificate chain required to validate the signature of the access token."*
  - TS 33.501 cl. 14.3.3 defines `Nnrf_AccessToken_RetrieveKey`; cl. 13.4.1.0 NOTE 1b also allows the key to be provisioned by that operation or *"in any other implementation specific way"*.
- **How.** The NRF serves `retrieve-key` and returns the signing certificate of the tokens for the `kid` or `x5t#S256` asked. A producer can ask for the key when it does not have it.
- **Here.** Fixed by `nrf/0006` and `openapi/0008`: the certificate in DER, in a multipart answer, by `kid` or `x5t#S256` ([sbi-tls.md](sbi-tls.md) section 5). The NFs and the AAnF still read the certificate from `nrfCertPem`, which cl. 13.4.1.0 allows.

## F29 — No heart-beat of the NFs at the NRF

- **free5GC today.** No NF of free5GC sends the heart-beat, the periodic `PATCH` of its own profile. The NRF keeps the `heartBeatTimer` and suspends no NF.
- **Specification.** TS 29.510 V20.1.0 cl. 5.2.2.3.2:
  - *"Each NF that has previously registered in NRF shall contact the NRF periodically (heart-beat), by invoking the NFUpdate service operation, in order to show that the NF is still operative."*
  - *"The time interval at which the NRF shall be contacted is deployment-specific, and it is returned by the NRF to the NF Service Consumer as a result of a successful registration."*
  - the request is a `PATCH` that replaces `nfStatus`, without `If-Match`; the NRF marks `SUSPENDED` an NF that does not renew, and no longer returns it in discovery.
- **How.** Each NF repeats the `PATCH` at the interval returned at registration; the NRF suspends those that do not renew.
- **Here.** Done in the AAnF ([aanf.md](aanf.md) section 10): it proposes `heartBeatTimer`, follows the one of the answer and repeats the `PATCH`. Open in the free5GC NFs and in the NRF. The suspension would also take out of discovery the old profiles behind F27.

## F30 — The UDM has no `ROAMING_STATUS` event by SUPI

- **free5GC today.** `CreateEeSubscriptionProcedure` (`internal/sbi/processor/event_exposure.go`) only accepts `msisdn-`, `extid-`, `extgroupid-` and `anyUE` in `ueIdentity`, and answers 400 `MANDATORY_IE_INCORRECT` to `imsi-`. The subscription is stored, but no code makes the event report.
- **Specification.** TS 29.503 V20.1.0:
  - table 6.4.3.2.2-1: `ueIdentity` *"shall contain the Generic Public Subscription Identifier (see TS 23.501 [2] clause 5.9.8) or Subscription Permanent Identifier (see TS 33.535 [55] clause 6.2.1 for the usage of SUPI in this procedure)"*;
  - cl. 5.5.2.2.2: with the `immediateFlag`, for an event the UDM detects, such as `ROAMING_STATUS`, *"the UDM may include the current status of the event if available"*;
  - table 6.4.6.2.8-1: `RoamingStatusReport`, with `roaming`, `newServingPlmn`, `accessType` and `purged`;
  - cl. 5.5.2.4.2: the notification to the `callbackReference` of the subscription.

  TS 33.535 cl. 6.2.1 steps 5 and 6 are the use by the AAnF.
- **How.** The UDM accepts the subscription by SUPI, answers with the current status, taken from the registration of the AMF (the PLMN of the GUAMI against the HPLMN of the SUPI), and notifies when the registration changes PLMN.
- **Here.** Open: the AAnF does not subscribe to the roaming status, and the test bed has no visited PLMN.

## F31 — No headers of TS 29.500

- **free5GC today.** In v4.2.3 and v4.3.0:
  - no NF calls `SetUserAgent`, and the requests carry the default `User-Agent` of the generated clients of `openapi`, `OpenAPI-Generator/1.0.0/go`, without the NF type;
  - no NF sets `Server` on error answers;
  - no NF sends or reads the `3gpp-Sbi-*` headers; only the generated clients read `3gpp-Sbi-Target-Nf-Id` on 307 and 308.
- **Specification.** TS 29.500 V20.0.0:
  - table 5.2.2.2-1, `User-Agent`: *"This header shall be mainly used to identify the NF type of the HTTP/2 client. This header should be included in every HTTP/2 request sent over any SBI"*; *"The pattern of the content should start with the value of NF type ... and followed by a "-" and any other specific information if needed afterwards."*;
  - table 5.2.2.2-1, `Server`: *"This header should be inserted by the originator of an HTTP error response (see clause 6.10.8)."*, in the form `<NFType>-<NF Instance ID>` for an NF;
  - cl. 5.2.3.2.1: *"The 3GPP NF Services shall support the HTTP custom headers specified in Table 5.2.3.2.1-1 below."* There, `3gpp-Sbi-Callback` *"should also be included in the HTTP POST message of any event notification request for direct communications"*, and of `3gpp-Sbi-NF-Peer-Info`: *"The HTTP client and server should include this header in every HTTP request and response messages."*;
  - TS 29.535 cl. 5.1.2.3 repeats the *shall* for the AAnF.
- **How.** Each NF sends the `User-Agent` with its type and sets `Server` on error answers, in the form of the table. In direct communication, it handles the headers of table 5.2.3.2.1-1 as the table says: `3gpp-Sbi-Callback` on event notifications, `3gpp-Sbi-NF-Peer-Info` on requests and answers, and `3gpp-Sbi-Message-Priority` when there is a priority to pass on.
- **Here.** Partly: `User-Agent` and `3gpp-Sbi-NF-Peer-Info` on the requests of the AUSF and of the NEF to the AAnF (`ausf/0004`, `nef/0006`) and on those of the AAnF; `Server` and `3gpp-Sbi-NF-Peer-Info` on the answers of the AAnF; `User-Agent` on the token request of every NF (`openapi/0008`). The CCF is not an NF type, and the CAPIF APIs follow TS 29.122 cl. 5.2.8. The rest applies to every NF of free5GC and stays open.

---

## Integration changes without a specification clause

Changes AKMA needs in free5GC that no specification calls for:

| Where | What | Patch |
|---|---|---|
| `run.sh`, `force_kill.sh` | start and stop the AAnF, the CCF and the CRL service with the other NFs (`./run.sh -crl -aanf -ccf`) | `free5gc/patches/run/` |
| `config/` | `akma` in `ausfcfg.yaml`; `3gpp-akma`, the host address, `akma.authorizedAfs` and `capif` in `nefcfg.yaml`; every NF over `https` by name, with its certificate, a fixed `nfInstanceId` and the signing certificate of the NRF | `free5gc/patches/config/` |
| `test/` | AKMA tests in the Go test bench (`TestAkma5GAKA`, `TestAkmaEAPAKAPrime`, `TestAkmaWithoutSubscription`), and the configuration of the patched NFs | `free5gc/patches/test/` |
