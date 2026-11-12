# CAPIF: the CCF, the NEF and the AF

TS 29.522 cl. 7.2 and TS 33.122 cl. 6.5.2.3: with CAPIF, the AF outside the operator network gets the access token of the NEF API from the CAPIF Core Function (CCF). free5GC has no CCF and its `openapi` has no CAPIF model. This repository adds:

- the CCF, a new NF in `free5gc/ccf/`, with the layout of the free5GC NFs;
- the CAPIF models and clients, in `openapi/0004` and `0007`;
- the NEF as API publishing function (APF) and API exposing function (AEF) of `3gpp-akma`, in `nef/0002` and `0005`;
- the AF as API invoker.

Only the path of AKMA is there. Installation: [install.md](install.md), part 12.

## 1. Interfaces

```
              AF host                                        free5GC host
  AF ──(CAPIF-1e) HTTPS ─────────────────────────────▶ CCF 192.168.16.130:8020
  AF ──(CAPIF-2e) HTTPS, mutual TLS ─────────────────▶ NEF nef.5gc…:8000
                                                      NEF ──(CAPIF-3/4) HTTPS, mutual TLS ──▶ CCF ccf.5gc…:8020 (127.0.0.1)
```

| Path | Address | Security |
|---|---|---|
| AF → CCF (CAPIF-1e) | `https://192.168.16.130:8020` | TLS 1.3 and 1.2; server only at onboarding (TS 33.122 cl. 6.1 step 2), mutual afterwards, with the certificate the CCF issued |
| NEF → CCF (CAPIF-3/4) | `https://ccf.5gc.mnc093.mcc208.3gppnetwork.org:8020`, on 127.0.0.1 | mutual TLS with the CA of the operator; the CCF knows the NEF by the NF instance ID of its certificate |
| AF → NEF (CAPIF-2e) | `https://nef.5gc.mnc093.mcc208.3gppnetwork.org:8000`, discovered at the CCF | mutual TLS: the AF presents the certificate of the CCF and checks the one of the NEF against the CA of the operator; the token and the certificate have to be of the same invoker |

The two servers of the CCF on port 8020 listen on different addresses. The external one only serves the APIs of the invoker; the internal one only those of the provider. An API asked on the wrong server gets 404.

## 2. Keys and certificates

`free5gc/scripts/make-capif-certs.sh <directory> <address>` makes them in the `cert/` folder of free5GC, with OpenSSL. Test only: the private keys are not encrypted.

| Files | What | Used by |
|---|---|---|
| `ccf-ca.pem`, `ccf-ca.key` | CA of the CCF, ECDSA P-384, SHA-384; the CA profile of TS 33.310 cl. 6.1.4a | the CCF signs its server certificate and the certificates of the invokers with it (TS 33.122 cl. 6.1 step 4); the AF gets it in the onboarding information |
| `ccf.pem`, `ccf.key` | server certificate of CAPIF-1e, ECDSA P-256, with the address in `subjectAltName` and the CRL distribution point; profile of TS 33.310 cl. 6.1.3a | CAPIF-1e |
| `ccf-token.key`, `ccf-token.pub.pem` | ECDSA P-256 for the `ES256` of the tokens | the CCF signs; the NEF checks with the public key |
| `ccf-credential.key` | ECDSA P-256 for the `ES256` of the onboarding credentials | the CCF only |

The internal server uses `cert/sba/ccf-internal.pem`, from the CA of the operator ([sbi-tls.md](sbi-tls.md)).

The AF makes its own key pair (ECDSA P-256) and sends only the public key. The CCF accepts ECDSA P-256 or P-384, or RSA of 2048 to 4096 bits with a public exponent of at least 65537 (TS 33.310 cl. 6.1.1). The certificate it issues has `O=<O of the CA>, CN=<API invoker ID>`, `keyUsage` `digitalSignature`, `extendedKeyUsage` `clientAuth`, the CRL distribution point that TS 33.310 cl. 6.1.3a requires, and a configurable validity, one year by default. TS 29.222 gives no format to `apiInvokerPublicKey` and `apiInvokerCertificate`: they go in PEM.

## 3. Configuration of the CCF

`free5gc/config/ccfcfg.yaml`, installed in the `config/` folder of free5GC:

| Field | Content |
|---|---|
| `ccfName` | issuer of the onboarding credentials |
| `capif1e` | `bindingIPv4`, `port`, `certificate`, `key`: the server of the invokers. The address also builds the `Location` headers, so it cannot be `0.0.0.0` |
| `internal` | `bindingIPv4`, `port`, `fqdn`, `certificate`, `key`, `ca`: the server of the provider. With TLS, `fqdn` is required |
| `ca` | `certificate`, `key`, `invokerCertLifetime`; `crlUri`, which goes in the certificates of the invokers; `crlFile`, which the CCF signs and the CRL service serves |
| `token` | `key`, `lifetime` (10 minutes in the example) |
| `credentialKey` | the key of the onboarding credentials |
| `providers` | the API provider domain functions, fixed by configuration: `name`, `nfInstanceId` (the one of the client certificate of the NEF), `apfId`, `aefIds` |
| `invokerProfiles` | the AFs that may onboard: `name`, `apis`, and `afIds`, the AF_IDs the NEF accepts from invokers of the profile |

The CCF does not register at the NRF.

## 4. Operations of the CCF

| Operation | Method and path | Server |
|---|---|---|
| `Onboard_API_Invoker` | `POST /api-invoker-management/v1/onboardedInvokers`, with `Authorization: Bearer <onboarding credential>` | CAPIF-1e, server-only TLS |
| `Offboard_API_Invoker` | `DELETE /api-invoker-management/v1/onboardedInvokers/{onboardingId}` | CAPIF-1e, mutual TLS |
| `Discover_Service_API` | `GET /service-apis/v1/allServiceAPIs?api-invoker-id=<id>` | CAPIF-1e, mutual TLS |
| `Obtain_Security_Method` | `PUT /capif-security/v1/trustedInvokers/{apiInvokerId}` | CAPIF-1e, mutual TLS |
| `Obtain_Authorization` | `POST /capif-security/v1/securities/{securityId}/token`, `application/x-www-form-urlencoded` | CAPIF-1e, mutual TLS |
| `Publish_Service_API`, `Get_Service_API`, `Unpublish_Service_API` | `POST`, `GET`, `DELETE /published-apis/v1/{apfId}/service-apis[/{serviceApiId}]` | internal, mutual TLS |
| `Obtain_API_Invoker_Info` | `GET /capif-security/v1/trustedInvokers/{apiInvokerId}?authenticationInfo=true&authorizationInfo=true` | internal, mutual TLS |

**Onboarding** (TS 29.222 cl. 5.5.2.2.2; TS 33.122 cl. 6.1). The credential is a JWT in `ES256`, with `kid`, issued by `ccf credential --profile <name> --validity <duration>`. The CCF checks the signature, `iss`, `aud` (`api-invoker-management`), `exp` and that `sub` is a profile of its configuration. Each onboarding creates a new invoker, with an API invoker ID (UUID v4), a client certificate and an `onboardingSecret` of 32 random octets. The answer is `201` with `Location`, the certificate, the secret and the published APIs of the profile.

**Offboarding** (TS 33.122 cl. 6.8). The CCF deletes the invoker, revokes its certificate in the CRL of its CA, answers `204` and ends the TLS session. Tokens already issued are valid until `exp`.

**Discovery.** The published APIs of the profile of the invoker that pass the filters; filters of features the CCF does not support give `400`.

**Security method.** The CCF picks, for each AEF, the first method of the preference of the invoker that the AEF published and that the policy accepts: `OAUTH` only.

**Token** (TS 29.222 cl. 5.6.2.3.2; TS 33.122 Annex C). `grant_type=client_credentials`, `client_id` and `client_secret` (the `onboardingSecret`), or `Authorization: Basic`, and `scope` in the form `3gpp#<aefId>:<apiName>`. The answer has `Cache-Control: no-store` and `AccessTokenRsp`. The token is a JWS in `ES256` with `kid` (TS 33.210 cl. 6.3.3), with the claims `iss` and `client_id`, both with the API invoker ID, `scope` and `exp`, an instant. Errors go in `AccessTokenErr`: `invalid_client`, `unsupported_grant_type`, `invalid_request`, `unauthorized_client`, `invalid_scope`.

**Invoker information.** For the AEF that asks, the security context of the invoker, with `authenticationInfo`, the CA of the CCF in PEM, and `authorizationInfo`, the JSON text `{"akmaAfIds":[...]}` with the AF_IDs of the profile.

All other errors carry `ProblemDetails` in `application/problem+json`. CAPIF-1e negotiates HTTP/1.1 or HTTP/2 with ALPN. The CCF supports no optional feature: `supportedFeatures` is `"0"`.

**State.** The invokers, the security contexts and the published APIs live in memory. After a restart, the NEF publishes again and the AF onboards again. The CRL is a file, and the revocations survive a restart.

## 5. The NEF

The `capif` section of `nefcfg.yaml` ([nef-akma-api.md](nef-akma-api.md), section 7) turns CAPIF on:

- **publication.** At start, the NEF publishes `3gpp-akma` (`v1`, custom operation `retrieve`, `POST`, `OAUTH`) with its `fqdn` and port. Without the CCF it tries again every 5 s. On shutdown, it unpublishes;
- **`check-authentication`** (AEF_Security_API, TS 29.222 cl. 10): `POST /aef-security/v1/check-authentication`. The CN of the client certificate has to be the `apiInvokerId` of the body, and the certificate has to come from the CA of `authenticationInfo` (TS 33.122 cl. 6.5.2.3 step 5);
- **the token of the CCF** on `retrieve`: [nef-akma-api.md](nef-akma-api.md), section 4.

## 6. The AF as API invoker

With the `capif` section of `af/config/afcfg-capif.yaml`, the AF:

1. without its state file, makes a key pair and onboards; the state goes to the file of `state`, with mode `0600`;
2. discovers `3gpp-akma` `v1` and builds the `apiRoot` of the first profile with `OAUTH`, with the scheme of `apiScheme` (TS 29.222 has no scheme in `InterfaceDescription`);
3. obtains the security method `OAUTH` for that AEF;
4. calls `check-authentication` at the NEF;
5. at the first K_AF request, gets the token, keeps it in memory only and renews it 30 s before it expires (TS 33.122 C.4.1 and C.5).

When the CCF no longer knows the invoker, the AF deletes its state and onboards again, once. With `offboardOnExit: true`, it offboards on shutdown.

## 7. Logs

No log shows a token, a credential, a secret or a private key.

| Where | Messages |
|---|---|
| CCF | `API invoker <id> onboarded, profile <profile>`; `API invoker <id> offboarded`; `<apiName> published by <apfId> as <apiId>, AEF <aefId>`; `security method OAUTH for API invoker <id> at AEF <aefId>`; `access token for API invoker <id>, scope <scope>, expires in <n> s`; `CRL <file> signed: <n> revoked`; a warning for each refusal, with the reason |
| NEF | `3gpp-akma published at the CCF as <apiId>`; `check-authentication of API invoker <id>: <n> AF_IDs from the CCF`; `Access token of API invoker <id> accepted for AF_ID <afId>` |
| AF | `Onboarded at the CCF as API invoker <id>`; `3gpp-akma discovered at <apiRoot>, AEF <aefId>`; `Security method OAUTH at AEF <aefId>`; `The NEF has the authentication data of API invoker <id>`; `Access token obtained, expires in <n> s` |

## 8. Limitations

- Partial CAPIF: no events, logging, auditing, access control policy, routing, API provider registration through the API, open discovery, interconnection or charging; CAPIF-2e security methods 1 (TLS-PSK) and 2 (PKI) are not implemented.
- One CCF, one API provider (the NEF), one AEF.
- State in memory (section 4).
- The AF_IDs of an external AF are in three configurations: the profile of the CCF, the policy of the NEF and the list of the AAnF.
- Revocation by CRL only, without OCSP. The NEF fetches the CRL of the CA of the CCF again after `invokerCrlMaxAge`.

Where the specifications contradict each other or leave a choice open, the choice of this repository is in [3gpp-recommendations.md](3gpp-recommendations.md), items AA to AJ.
