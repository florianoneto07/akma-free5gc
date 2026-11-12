# Mutual TLS on the SBI

TS 33.501 cl. 13.1.0: *"All network functions shall support mutually authenticated TLS and HTTPS"*, with the certificates of TS 33.310. free5GC v4.2.3 can serve the SBI over `https`, but its client checks no server certificate and presents none (F21), its NFs write the secrets of the TLS sessions to a file (F22), its profiles have no FQDN (F24) and its certificates are outside the profile of TS 33.310 (F25). This repository puts every NF, the AAnF, the CCF and the AF on mutual TLS, by name, with a test PKI of the operator and CRLs. Installation: [install.md](install.md), part 13.

## 1. Names and addresses

Home network domain (TS 23.003 cl. 28.2): `5gc.mnc093.mcc208.3gppnetwork.org`, with the MNC in three digits.

| Entity | FQDN | Address and port |
|---|---|---|
| NRF | `nrf.5gc.mnc093.mcc208.3gppnetwork.org` | 127.0.0.10:8000 |
| AMF | `amf1.amf.5gc.mnc093.mcc208.3gppnetwork.org`, also the AMF Name | 127.0.0.18:8000 |
| NSSF | `nssf.5gc.mnc093.mcc208.3gppnetwork.org` | 127.0.0.31:8000 |
| SMF, UDR, PCF, UDM, AUSF, CHF | `<type>.5gc.mnc093.mcc208.3gppnetwork.org` | 127.0.0.2, .4, .7, .3, .9, .113, port 8000 |
| BSF | `bsf.5gc.mnc093.mcc208.3gppnetwork.org` | 127.0.0.15:8000, only with `run.sh -bsf` |
| NEF | `nef.5gc.mnc093.mcc208.3gppnetwork.org` | 192.168.16.130:8000 |
| AAnF | `aanf.5gc.mnc093.mcc208.3gppnetwork.org` | 192.168.16.130:8010 |
| CCF, CAPIF-3/4 | `ccf.5gc.mnc093.mcc208.3gppnetwork.org` | 127.0.0.1:8020 |
| CCF, CAPIF-1e | by address | 192.168.16.130:8020 |
| AF | `af1.akma.example` | client only |
| CRL service | by address | `http://192.168.16.130:8030` |

`free5gc/config/sba-entities.conf` lists them, with the NF type and the NF instance ID of each one, and `/etc/hosts` resolves them. The free5GC host has all thirteen names; the AF host only those of the AAnF and of the NEF.

**FQDN required with `https`.** TS 29.510 table 6.1.6.2.2-1 NOTE 1: *"If the NF supports the NF services with "https" URI scheme (i.e use of TLS is mandatory), then the FQDN shall be provided in the NF Profile or the NF Service profile ... and it shall be used to construct the target URI"*. With `sbi.scheme: https`, every NF, the AAnF and the internal server of the CCF (`internal.fqdn`) refuse to start without the FQDN, with the message `sbi.fqdn is required with https (TS 29.510 table 6.1.6.2.2-1 NOTE 1)`. With `http`, nothing changes: the free5GC test bench stays on `http`, by address.

**URIs.** The profile carries the `fqdn`, and each service its `ipEndPoints` and `apiPrefix`. The own URIs of each NF (profile, callbacks, `Location`) go by name. Consumers build `https://<FQDN>:<port>` with one helper, `openapi.GetNFServiceUri` (TS 29.510 table 6.1.6.2.3-1 NOTE 1 and table 6.1.6.2.5-1 NOTES 2 to 4). The `apiPrefix` still carries the whole URI, now with the name, as free5GC does: the SMF and the PCF use it directly (F24).

A client sends the SNI and checks the DNS-ID when the URI has a name; with an address, it checks the IP address of the certificate and sends no SNI (RFC 6066 cl. 3).

## 2. The test PKI

`free5gc/scripts/make-sba-certs.sh <directory> <entities> [all|crl|revoke <name>|check]` makes everything with OpenSSL in `cert/sba/` of free5GC, and the CRL in `cert/crl/`. The key of the CA stays on the free5GC host, without a password: this is a test PKI.

**CA of the operator.** `sba-ca.pem`: ECDSA P-384, SHA-384, five years; `C=FR, O=5gc.mnc093.mcc208.3gppnetwork.org, CN=SBA test CA`; the CA profile of TS 33.310 cl. 6.1.4a. It is P-384 because *"The security level of the public key used to sign the certificate shall be at least the same as the public keys in the certificate"* (cl. 6.1.1).

**Certificates of the NFs** (TS 33.310 table 6.1.3c.3-1), ECDSA P-256 (cl. 6.1.3c.2: *"ECDSA is recommended"*):

| Field or extension | Value |
|---|---|
| version, serial | v3; 16 random octets, positive |
| signature | `ecdsa-with-SHA384` |
| Subject | `C=FR, O=5gc.mnc093.mcc208.3gppnetwork.org, CN=<FQDN>`; for the AF, `CN=af1.akma.example` |
| validity | one year (*"3 years or less"*) |
| `keyUsage` | critical; `digitalSignature` |
| `extendedKeyUsage` | `clientAuth` and `serverAuth`; the AF, `clientAuth` only |
| `authorityKeyIdentifier`, `subjectKeyIdentifier` | method (1) of RFC 5280 cl. 4.2.1.2 |
| `cRLDistributionPoints` | `URI:http://192.168.16.130:8030/sba-ca.crl` |
| `subjectAltName` | **critical**; `URI:urn:uuid:<nfInstanceId>`; `DNS:<FQDN>`; `IP:<address>`; on servers also `URI:https://<FQDN>:<port>`, the `apiRoot` |
| `nfTypes` | the NF type, as an `IA5String` (RFC 9310) |

The NF instance ID of each certificate is the fixed `nfInstanceId` of its configuration.

**Token signing certificate of the NRF** (table 6.1.3c.3-2). `nrf-token.pem`: ECDSA P-256 for `ES256`; `extendedKeyUsage` `id-kp-oauthAccessTokenSigning` (RFC 9509); `subjectAltName` with only `URI:urn:uuid:<nfInstanceId of the NRF>`, the `iss` of the tokens; the other extensions as in table 6.1.3c.3-1.

**Internal server of the CCF.** `ccf-internal.pem`: the server profile of TS 33.310 cl. 6.1.3a (TS 33.122 cl. 6.6), with the name and the address of CAPIF-3/4; no `nfTypes`, since the CCF is not an NF type of TS 29.510.

**Test certificates.** `seed-ausf` and `seed-af`, for the `seed` tool in the roles of the AUSF and of an AF; `af2`, an AF outside the policy of `af1`; `revoked`, revoked in the CRL; `no-crldp`, without a distribution point; `other-ca`, from another CA.

**Check.** `make-sba-certs.sh … check` reads each certificate and refuses, with the reason, anything outside its profile: version, serial, Subject, validity, signature, `keyUsage`, `extendedKeyUsage`, key identifiers, distribution point, `subjectAltName`, `nfTypes`, or another critical extension. The answer is `every certificate fits its profile`.

## 3. Revocation

- `sba-ca.crl`, the CRL of the CA of the operator: v2, signed with SHA-384, `nextUpdate` one week after `thisUpdate` (TS 33.310 cl. 6.1a). `make-sba-certs.sh … crl` signs it again; `e2e.sh` does it at each run.
- `ccf-ca.crl`, the CRL of the CA of the CCF, signed by the CCF at start, at each offboarding and before `nextUpdate`.

**CRL service** (`free5gc/crl/`, `run.sh -crl`). It serves `GET` and `HEAD` of `/<name>.crl` from `cert/crl/`, with `Content-Type: application/pkix-crl`, on `192.168.16.130:8030`, over HTTP/1.1 without TLS: TS 33.310 cl. 7.1 says the repository *"shall be accessible without relying on a secure connection"*. It lists no directory and answers 404 to any other path.

**At each end** of every connection, client and server, after the chain and the validity (package `sbitls` of `openapi/0005`):

1. the certificate has to have an `http` distribution point; otherwise it is refused;
2. the CRL comes from memory, by URI; when it is not there, or after `nextUpdate`, it is downloaded again (2 s at most, 1 MiB at most, no redirection);
3. the CRL has to be v2, signed by the CA that issued the certificate, with the same issuer and `thisUpdate ≤ now < nextUpdate`;
4. without a valid CRL after the download, the connection is refused: the check fails closed;
5. a serial number in the list is refused.

Go's `crypto/tls` checks no CRL: this code is part of the repository, with its own tests.

## 4. TLS profile

TS 33.210 cl. 6.2: TLS 1.3 and 1.2, and in TLS 1.2 only ECDHE with AEAD, with the suites that RFC 9113 cl. 9.2.2 requires. HTTP/2 is negotiated with ALPN. No OCSP stapling. `util/0001` removes the key log of free5GC: no NF, AAnF or CCF writes the secrets of the TLS sessions to a file (F22).

## 5. Access tokens of the NRF

**The request and the certificate.** The NRF reads the certificate of the TLS session (`nrf/0005`):

| Operation | Check | Refusal |
|---|---|---|
| `POST /oauth2/token` | `nfInstanceId` equal to the URI of the certificate; `nfType` in its `nfTypes`; `requesterPlmn`, when present, equal to the PLMN of the `O` of the certificate | `400 invalid_client`, with `Cache-Control: no-store` (TS 29.510 cl. 5.4.2.2.1) |
| `PUT`, `PATCH`, `DELETE /nnrf-nfm/v1/nf-instances/{nfInstanceID}` | `{nfInstanceID}` equal to the URI; on `PUT`, the `nfType` of the profile in `nfTypes` | `403` with `ProblemDetails` |
| `GET /nnrf-disc/v1/nf-instances` | `requester-nf-type` in `nfTypes`; `requester-nf-instance-id`, when present, equal to the URI | `403` with `ProblemDetails` |

The NRF no longer makes certificates for the NFs (F25).

**The JWS profile** (TS 33.210 cl. 6.3.3). Header `{"alg":"ES256","kid":"<RFC 7638 thumbprint>","typ":"JWT","x5t#S256":"<SHA-256 of nrf-token.pem>"}`. `iss` is the NF instance ID of the NRF, the one of the URI of its signing certificate (F26).

**Scopes per NF type** (TS 29.510 table 6.1.6.2.3-1 NOTE 11; F4). The AAnF registers in its `naanf-akma` service:

```json
"allowedOperationsPerNfType": {
  "AUSF": ["naanf-akma", "naanf-akma:anchorkey"],
  "NEF":  ["naanf-akma", "naanf-akma:applicationkeyget", "naanf-akma:applicationkeyget:supi-access"],
  "AF":   ["naanf-akma", "naanf-akma:applicationkeyget", "naanf-akma:applicationkeyget:supi-access"]
}
```

The NRF only grants a scope in the list of the type of the consumer; a type outside the list gets none, and a scope asked outside the list gets `400 invalid_scope`. It checks the scope on the profile of `targetNfInstanceId` when given, and otherwise on the registered profiles of the target type: an old profile no longer blocks a token (`nrf/0006`, F27).

**Retrieve Key** (TS 29.510 cl. 5.4.2.3 and 6.3.4.3; F28). `POST /oauth2/retrieve-key` with `RetrieveKeyReq` (`issuer`, `headerParameters` with `kid` or `x5t#S256`) answers `200` with `multipart/related; type="application/json"`: a JSON part `RetrieveKeyRsp` and the signing certificate in DER, `application/pkix-cert`. An unknown key gives `400 KEY_IDENTIFICATION_FAIL`; another issuer, `404 UNKNOWN_ISSUER`. The NFs still read the certificate from `nrfCertPem`, which TS 33.501 cl. 13.4.1.0 also allows.

**The checks of every producer** (`openapi/0006`; TS 33.501 cl. 13.4.1.1.2 step 2; F5, F12), in order:

1. `Authorization: Bearer <jwt>`; without it, `401` with `WWW-Authenticate: Bearer realm="<URI of the API>"`;
2. `ES256` only (`RS512` and `none` are refused), `kid` and `x5t#S256` of the signing certificate, which has to come from the CA of the operator, with `id-kp-oauthAccessTokenSigning`, and not be revoked; otherwise `401`, `error="invalid_token"`;
3. `iss`, `sub`, `aud`, `scope` and `exp` present; otherwise `401` with `ACCESS_TOKEN_CLAIM_MISSING`;
4. `exp` in the future, without tolerance: the hosts use NTP;
5. `iss` equal to the URI of the signing certificate, `aud` equal to the NF instance ID or the type of the producer, `sub` equal to the URI of the client certificate of the session; otherwise `403` with `ACCESS_TOKEN_CLAIM_MISMATCH`;
6. the service name in `scope`; otherwise `403`, `error="insufficient_scope"`.

The answers follow TS 29.500 cl. 6.7.3, with `ProblemDetails` in `application/problem+json`, in every NF.

## 6. Policies by certificate

The AAnF knows its consumers by the certificate, without source addresses:

```yaml
    authorizedAfs: # TS 33.535 cl. 6.2.1 step 2
      - afId: af1.akma.example.0100011301
        nfInstanceIds:
          - 2170454b-4cfa-406a-a77c-2137042b54b4
    authorizedNefs: # TS 33.535 cl. 6.3
      - nfInstanceIds:
          - 8e73ad07-906c-4952-93ac-cd32bbb076ed
        afIds:
          - af1.akma.example.0100011301
```

On `retrieve-applicationkey`: the identity is the URI of the client certificate, and the type its `nfTypes`. With a token, the checks of section 5 apply, `sub` included; a NEF of `authorizedNefs` may ask for the `afIds` of its entry. Without a token, the identity has to be in the `nfInstanceIds` of the `afId` and the type has to be `AF`. Otherwise `403` without `cause`. Without `naanf-akma:applicationkeyget:supi-access`, the answer has no `supi`. Details in [aanf.md](aanf.md).

On CAPIF-2e the NEF binds the token of the CCF to the client certificate of the AF ([nef-akma-api.md](nef-akma-api.md), section 4), and on CAPIF-3/4 the CCF knows the NEF by the NF instance ID of its certificate ([capif.md](capif.md)).

## 7. Logs

- From the CRL service, `Start CRL service (http, listen on 192.168.16.130:8030)`.
- From the NFs, the URIs with names, such as `AAnF for Routing Indicator 0000: https://aanf.5gc.mnc093.mcc208.3gppnetwork.org:8010 (discovered at the NRF)`.
- A client with a revoked certificate is refused in the handshake, and the server logs the reason.
- No log shows a private key, a token or a TLS secret.

## 8. Limitations

- The web console of free5GC does not talk to the NRF over mutual TLS.
- The free5GC test bench stays on `http`.
- `apiPrefix` carries the whole URI, against TS 29.501 cl. 4.4.1 (F24).
- CRL over HTTP only, without LDAP; no OCSP or OCSP stapling.
- No automatic enrolment of certificates (TS 33.310 cl. 10.2 and 10.3): they come from the script, and the key of the CA stays on the free5GC host.
- The CHF has other TLS servers that are not SBI (CGF and ABMF), with the certificates of free5GC: they stay as they are.
- The metrics servers of the NFs stay on `http`.
- No NDS/IP, SEPP, N32, SCP or indirect communication.
