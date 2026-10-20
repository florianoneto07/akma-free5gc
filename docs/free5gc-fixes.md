# What free5GC has to change for AKMA

Base: free5GC v4.2.3 (NRF, UDM and AUSF v1.4.5, NEF v1.2.5, `openapi` v1.2.4).

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
| F4 | NRF | no scopes per operation and per consumer type | open |
| F5 | `openapi` | `VerifyOAuth` checks neither `exp` nor `aud` | handled in the AAnF; open in the free5GC NFs |
| F6 | `openapi` | no Naanf_AKMA models or client | fixed, `openapi/0001` and `0002` |
| F7 | UDM | sends neither `akmaInd` nor `routingId` | fixed, `udm/0001` |
| F8 | AUSF | neither derives K_AKMA nor registers at the AAnF | fixed, `ausf/0001` |
| F9 | web console | no `akmaAllowed` and `routingId`; editing drops them | worked around with a script |
| F10 | UDM | `id-translation-result` only maps GPSI to SUPI | open |
| F11 | NEF | no `3gpp-akma` API | fixed, `nef/0001` |
| F12 | NEF | 401 of the OAuth2 middleware without `ProblemDetails` or `WWW-Authenticate` | open |
| F13 | NEF | AF-facing APIs without CAPIF and without mutual TLS | open |
| F14 | NEF | asks for the `nnrf-nfm` token with the wrong target type and does not deregister | open |
| F15 | NRF | `complexQuery` without `routing-indicator` for `AANF` | open |

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
- **Here.** Open. The AAnF only checks `naanf-akma`.

## F5 — `oauth.VerifyOAuth` checks neither `exp` nor `aud`

- **free5GC today.** `oauth.VerifyOAuth` (`openapi` v1.2.4, `oauth/oauth.go`) checks the signature and the scope of the token, but not its expiry (`exp`) or its audience (`aud`). Every free5GC NF that requires a token uses this function, the NEF middleware included.
- **Specification.** TS 33.501 cl. 13.4.1.1.2 step 2: the producer *"checks that the audience claim in the access token matches its own identity or the NF type of NF Service Producer"* and *"checks that the access token has not expired by verifying the expiration time"*. TS 29.522 cl. 7.2, for the NEF with CAPIF: the NEF checks *"whether the NEF identifier in the "token" matches its own published identifier"*.
- **How.** `VerifyOAuth` refuses an expired token and a token whose `aud` is neither the producer instance nor the producer type. The 401 follows TS 29.500 cl. 6.7.3 (F12).
- **Here.** The AAnF does both checks itself ([aanf.md](aanf.md), section 4). Open in the free5GC NFs.

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
- **Here.** Open, left as free5GC has it: the fix changes every API of the NEF. What the NEF answers today to a request without a token: `401` with `{"error":"verify OAuth Authorization header invalid"}` in `application/json`, without `WWW-Authenticate`.

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
- **Here.** Open. The `3gpp-akma` API follows the pattern of the other AF-facing APIs of the free5GC NEF:
  - plain HTTP;
  - a token issued by the NRF, which fits the *"based on local configuration"* of TS 29.522 cl. 6;
  - a local policy that binds each AF_ID to source addresses.

  CAPIF support is planned.

## F14 — The NEF asks for the `nnrf-nfm` token with the wrong target type

- **free5GC today.** `DeregisterNFInstance` (`internal/sbi/consumer/nrf_service.go` of the NEF) asks for the `nnrf-nfm` token with `targetNfType=NEF`. The NRF refuses (`invalid_scope`), and the NEF does not deregister on shutdown. It fails with the original NRF too.
- **Specification.** TS 33.501 cl. 13.4.1.1.2 step 1: the token request *"shall include the NF type of the expected NF Service Producer instance"*. The producer of `nnrf-nfm` is the NRF.
- **How.** `GetTokenCtx(ServiceName_NNRF_NFM, NrfNfManagementNfType_NRF)`, as in the other free5GC NFs.
- **Here.** Open. Not an AKMA issue, but after each stop of the NEF its old profile stays at the NRF.

## F15 — `complexQuery` without `routing-indicator` for `AANF`

- **free5GC today.** Discovery with `complexQuery` (the `[Query-27]` part of `nf_discovery.go`) does not handle `routing-indicator` for `AANF`, as it already does not for the types other than AUSF and UDM.
- **Specification.** TS 29.510 cl. 6.2.3.2.3.1: the NRF *"may support"* the `complexQuery` expression (TS 29.501), which combines the query parameters of table 6.2.3.2.3.1-1, `routing-indicator` among them. An NRF that does not support it *"shall reject"* the request with `INVALID_QUERY_PARAM`.
- **How.** The filter of F2 also applies inside `complexQuery`; or, if the NRF does not handle the parameter there, it rejects the request with `INVALID_QUERY_PARAM`.
- **Here.** Open. No consumer here uses `complexQuery`.

---

## Integration changes without a specification clause

Changes AKMA needs in free5GC that no specification calls for:

| Where | What | Patch |
|---|---|---|
| `run.sh`, `force_kill.sh` | start and stop the AAnF with the other NFs (`./run.sh -aanf`) | `free5gc/patches/run/` |
| `config/` | `akma` in `ausfcfg.yaml`; `3gpp-akma`, the host address and `akma.authorizedAfs` in `nefcfg.yaml` | `free5gc/patches/config/` |
| `test/` | AKMA tests in the Go test bench (`TestAkma5GAKA`, `TestAkmaEAPAKAPrime`, `TestAkmaWithoutSubscription`) | `free5gc/patches/test/` |
