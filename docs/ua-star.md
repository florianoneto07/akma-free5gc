# The simplified Ua\* protocol

This is the protocol between the UE and the test AF, message by message. The AF (`af/af/`, `af/uastar/`) and the Ua\* client of the UE (`af/ue/uaclient/`) implement it.

## 1. Where it stands against the specifications

TS 33.535 cl. 4.4.1: Ua\* is application specific. The generic requirements are three:

- carry the A-KID;
- protect the reference point with K_AF;
- handle the expiry of K_AF.

The normative profiles are in TS 33.535 Annex B.1 and TS 24.109 Annex K:

- **K.2:** HTTP Digest inside a TLS tunnel, with the AF authenticated by certificate;
- **K.3:** TLS with a pre-shared key.

The protocol here is the Digest of K.2 **without the TLS tunnel**. It follows K.2 b), c) and d), TS 24.109 cl. 5.2 and TS 33.535 B.1.2.2 in everything that does not depend on TLS. Without TLS it is not the K.2 profile, so it uses an identifier from the private range, `FF 00 00 00 01`. TS 33.220 H.2 NOTE 2 allows identifiers with `0xFF` as first octet for local or experimental protocols without registration. It is a protocol for test beds; its limitations are in section 10.

## 2. Identifiers and secret

| Item | Value | Specification |
|---|---|---|
| FQDN of the AF | `af1.akma.example` (configurable) | — |
| AF_ID | FQDN ‖ `FF 00 00 00 01`; transport form `af1.akma.example.FF00000001` | TS 33.535 A.4; TS 29.522 table 5.14.5.4.2-1 |
| product token of the UE | `3gpp-akma` in `User-Agent`, in **every** request | TS 24.109 K.2 b) 1) and cl. 5.2.1; TS 33.535 B.1.2.2 step 2 |
| `realm` | `3GPP-bootstrapping-akma@af1.akma.example` | TS 33.535 B.1.2.2 step 3; TS 24.109 K.2 b) 2) and cl. 5.2.2.1 3) |
| `username` | the A-KID, exactly as the UE derived it | TS 24.109 K.2 c) 1); TS 33.535 B.1.2.2 step 5 |
| password | base64(K_AF), RFC 4648 cl. 4, 44 characters | TS 24.109 K.2 c) 2) |
| algorithm | `SHA-256` | RFC 7616; TS 33.222 cl. 5.3.0 NOTE 1b discourages MD5 |

**Which Digest.** TS 24.109 K.2 c) cites RFC 3310, Digest AKA, where the password comes from the RES. With base64(K_AF) as the password only RFC 7616 fits, which is also the Digest of TS 33.222 cl. 5.3.0, the GBA procedure that TS 33.535 B.1.2.2 adapts.

**The realm.** TS 33.535 B.1.2.2 and TS 24.109 K.2 b) 2) give the constant `3GPP-bootstrapping-akma`, and the GBA model of TS 24.109 cl. 5.2.2.1 joins the constant and the FQDN with `@`. TS 24.109 K.2 c) 3) uses `3gpp-akma` instead. The AF follows the first reading, and the first part of the realm is configurable (`realmPrefix`).

## 3. Transport and FQDN

HTTP/1.1 over TCP, without TLS. The test AF listens on `192.168.16.129:8080` (configurable).

TS 33.220 cl. 4.5.2: K_AF only matches if the UE and the network use the same FQDN in the derivation, and each protocol over Ua has to say how it ensures that. This one uses option (3) of that clause: the protocol carries the name used by the UE to the AF, in the `Host` header of HTTP/1.1, as in TS 33.222 cl. 5.3.0 step 2.

- The client sends `Host: af1.akma.example:8080`. Without DNS, it connects to the configured IP address, but `Host` carries the FQDN.
- The AF compares the name in `Host`, without the port and without case, with its single configured FQDN. If it differs, the AF answers `421 Misdirected Request` (RFC 9110 cl. 15.5.20), without a challenge. The same FQDN goes into the `realm` and into the AF_ID sent to the AAnF.

## 4. Protected resource

One resource: `GET /ua/v1/session`.

- The request is the *"Application Session Establishment Request"* of TS 33.535 cl. 6.2.1 step 1.
- The 200 answer is the *"Application Session Establishment Response"* of step 9, with a JSON body:

  ```json
  {"aKid": "<A-KID>", "kafExpiry": "<RFC 3339>"}
  ```

  `kafExpiry` tells the UE how long the session holds (cl. 4.4.1). The SUPI the AF gets from the AAnF never goes to the UE.
- Another path gives `404`; another method, `405`.

## 5. Message exchange

### 5.1 First request and challenge

UE to AF, without `Authorization`:

```
GET /ua/v1/session HTTP/1.1
Host: af1.akma.example:8080
User-Agent: akma-uaclient/0.1 3gpp-akma
```

AF to UE:

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Digest realm="3GPP-bootstrapping-akma@af1.akma.example", qop="auth", algorithm=SHA-256, nonce="<base64 of 32 random octets>", opaque="<base64 of 16 random octets>", charset=UTF-8
```

- `realm`, `qop`, `nonce` and `opaque` are quoted; `algorithm` and `charset` are not (RFC 7616 cl. 3.3, last paragraph).
- The AF offers `qop="auth"`. TS 24.109 cl. 5.2.6 allows `auth-int` (*"may"*); the AF offers it only when configured, and the computation of section 5.3 covers both.
- No `userhash`, although RFC 7616 cl. 3.4.4 says the server *SHOULD* turn it on. The AF needs the A-KID in clear to ask the AAnF for K_AF, and could not recover it from H(A-KID:realm). TS 24.109 K.2 c) 1) puts the A-KID in `username`.
- The AF keeps the challenge: nonce, opaque, time of issue and highest `nc` accepted. A nonce lasts 300 s (configurable).

### 5.2 Checks in the UE

Before answering, the client checks the challenge:

1. scheme `Digest` and `algorithm=SHA-256`;
2. a `realm` with two parts split at the last `@`. The first is `3GPP-bootstrapping-akma`: the AF selected AKMA (B.1.2.2 step 3). The second equals the FQDN the client used (B.1.2.2 step 4; K.2 d));
3. `qop` contains `auth`.

If any check fails, the client stops and does not send the A-KID.

### 5.3 Authenticated request

UE to AF:

```
GET /ua/v1/session HTTP/1.1
Host: af1.akma.example:8080
User-Agent: akma-uaclient/0.1 3gpp-akma
Authorization: Digest username="<A-KID>", realm="3GPP-bootstrapping-akma@af1.akma.example", uri="/ua/v1/session", algorithm=SHA-256, nonce="<nonce>", nc=00000001, cnonce="<base64 of 16 random octets>", qop=auth, response="<64 hex digits>", opaque="<opaque>"
```

Computation (RFC 7616 cl. 3.4.1 to 3.4.3), with H = SHA-256 in lowercase hex and KD(s, d) = H(s ":" d):

```
A1       = A-KID ":" realm ":" base64(K_AF)
A2       = "GET" ":" uri                         (qop=auth)
A2       = "GET" ":" uri ":" H(body)             (qop=auth-int)
response = KD(H(A1), nonce ":" nc ":" cnonce ":" qop ":" H(A2))
```

`nc` has exactly eight hex digits and starts at `00000001` for each nonce (RFC 7616 cl. 3.4 and 3.5).

### 5.4 Checks in the AF

The AF checks in this order and stops at the first failure:

| # | Check | Failure | Reference |
|---|---|---|---|
| 1 | `Host` carries the FQDN of the AF | `421` | section 3 |
| 2 | `Authorization` present, scheme `Digest` | `401` with a new challenge (AKMA initiation) | TS 33.535 cl. 6.5; RFC 7616 cl. 3.3 |
| 3 | mandatory parameters present and well formed; `algorithm=SHA-256`; `qop` among those offered; no `username*` and no `userhash=true` | `400` | RFC 7616 cl. 3.4 (*"the proper response is a 4xx error code"*) |
| 4 | `uri` equals the request target | `400` | RFC 7616 cl. 3.4.6 |
| 5 | `realm` equals that of the AF | `401` with a new challenge | TS 24.109 K.2 d) |
| 6 | `nonce` issued by the AF and still valid; `opaque` equal to the one issued with it | `401` with a new challenge, and `stale=true` if the nonce expired | RFC 7616 cl. 3.3 (`stale`) |
| 7 | `nc` above the last one accepted for the nonce | `401` with a new challenge (replay) | RFC 7616 cl. 3.4 (`nc`) and 5.5 |
| 8 | `username` is a syntactically valid A-KID | `400` | TS 29.522 table 5.14.5.4.2-1 |
| 9 | K_AF available (section 6) | `403` or `503` (section 8) | TS 33.535 B.1.2.2 step 6; cl. 6.2.1 steps 2 and 9 |
| 10 | `response` equals the computed one, compared in constant time | `401` with a new challenge; the attempt is logged at `warn`, without the password | RFC 7616 cl. 3.4 and 3.6 |

### 5.5 Answer and mutual confirmation

AF to UE, when everything matches:

```
HTTP/1.1 200 OK
Authentication-Info: rspauth="<64 hex digits>", qop=auth, nc=00000001, cnonce="<cnonce>"
Content-Type: application/json

{"aKid": "<A-KID>", "kafExpiry": "2026-10-18T17:35:31Z"}
```

`rspauth` is computed as `response`, but with `A2 = ":" uri` for `qop=auth` and `A2 = ":" uri ":" H(body)` for `qop=auth-int`. `rspauth`, `cnonce` and `nc` are mandatory when `qop` is present (RFC 7616 cl. 3.5).

The client **refuses** any 200 answer without a valid `Authentication-Info`: no `rspauth`, a wrong value, or `cnonce` and `nc` different from those sent. This is the key confirmation from the AF to the UE. Without it, a fake AF could accept any client.

### 5.6 Following requests

RFC 7616 cl. 3.6 and TS 33.222 cl. 5.3.0 NOTE 2: every following request carries `Authorization`.

- The client reuses the nonce, with `nc` incremented and a new `cnonce`.
- If the nonce expires, the AF answers `401` with `stale=true`. The client computes again with the new nonce, the same A-KID and the same K_AF.
- Each request goes through all the checks of section 5.4 again.

## 6. K_AF in the AF

TS 33.535 cl. 6.2.1 step 2: if it has no active context for the A-KID, the AF asks the AAnF for K_AF with `Naanf_AKMA_ApplicationKey_Get` (TS 29.535 cl. 4.2.2.3), on `POST {apiRoot}/naanf-akma/v1/retrieve-applicationkey`. The body is `AkmaAfKeyRequest`:

- `afId` in transport form;
- `aKId` exactly the `username` received.

An AF outside the operator network asks the NEF instead ([nef-akma-api.md](nef-akma-api.md)); the rest is the same.

| Answer of the AAnF or NEF | The AF |
|---|---|
| `200` with `AkmaAfKeyData` (`kaf` in hex, `expiry`, and `supi` when it comes from the AAnF) | stores `{A-KID, K_AF, expiry, SUPI}` and goes on with the checks |
| `403` with `K_AKMA_NOT_PRESENT` | `403`, cause `AKMA_KEY_NOT_AVAILABLE` |
| `403` without cause (AF outside the policy), another HTTP error, network failure | `503`, cause `AANF_UNAVAILABLE` |

- **Selection of the AAnF.** The address of the AAnF is configured in the AF (TS 33.535 cl. 6.7, *"locally configured"*). There is no OAuth2 token: the AAnF authorizes the AF by its source address.
- **Active context.** The stored K_AF holds until `expiry`, and the AF never uses it after that (cl. 4.4.0: maximum lifetime). K_AF stays in memory and never shows in a log.

## 7. Expiry of K_AF

TS 33.535 cl. 6.4.2: when K_AF expires, the AF may refuse the UE or renew K_AF, *"based on its policy"*. If it refuses, it may tell the UE that K_AF expired, by means of the Ua\* protocol. Cl. 6.4.3: there is no explicit renewal of K_AF; without a new primary authentication, K_AF stays the same.

Configurable policy `kafExpiry`:

| Value | Behavior |
|---|---|
| `refetch` (default) | the AF drops the expired K_AF and asks the AAnF again with the same A-KID. As long as K_AKMA does not change, the AAnF returns the same K_AF with a new `expiry`. If a re-authentication replaced the A-KID, the AAnF answers 403 and the AF returns `403 AKMA_KEY_NOT_AVAILABLE` |
| `reject` | the AF answers `403` with cause `KAF_EXPIRED`, the expiry notice of cl. 6.4.2. The UE can try again with the A-KID of a new K_AUSF |

The renewal of session keys derived from K_AF (cl. 6.4.3; TS 24.109 K.2 NOTE 2) is not implemented.

## 8. Error answers

Ua\* is application specific (cl. 4.4.1), so the error format is this protocol's own. An error without a challenge carries the JSON body `{"cause": "<CAUSE>"}`:

| Code | Cause | When |
|---|---|---|
| `400` | `INVALID_REQUEST` | a Digest parameter missing, malformed or not supported; `uri` different from the target; invalid A-KID |
| `401` | — (challenge) | no `Authorization`; `realm`, nonce, `nc` or `response` do not match |
| `403` | `AKMA_KEY_NOT_AVAILABLE` | the AAnF has no K_AKMA for the A-KID. TS 33.535 B.1.2.2 step 6: an error **without** the `realm` of the challenge. The UE may try with its latest A-KID (cl. 6.2.1 step 9) |
| `403` | `KAF_EXPIRED` | K_AF expired, with the `reject` policy |
| `404`, `405` | `NOT_FOUND`, `METHOD_NOT_ALLOWED` | another path or method |
| `421` | `MISDIRECTED_REQUEST` | `Host` with another name |
| `503` | `AANF_UNAVAILABLE` | the AF could not get K_AF, because of the AAnF or its own configuration |

## 9. AKMA initiation

TS 33.535 cl. 6.5: if the AF requires AKMA and the request has no AKMA parameters, the AF answers with an AKMA initiation message, whose form depends on the Ua\* protocol.

The initiation message is the `401` of section 5.1. Every request without `Authorization` gets the challenge, with or without the `3gpp-akma` product token. The AF only offers AKMA; the product token is logged and does not change the answer.

## 10. Limitations of a protocol without TLS

| Limitation | Effect | Mitigation |
|---|---|---|
| no confidentiality | the A-KID and the content travel in clear; an eavesdropper links the A-KID to the session | none; the A-KID is a pseudonym and changes at each primary authentication |
| AF not authenticated by the transport | a fake AF can get the request | the UE only accepts an answer with a valid `rspauth`, and only a holder of K_AF can compute it |
| integrity of the authentication only | with `qop=auth`, the body of the messages can be changed | `qop=auth-int` by configuration |
| `Host` can be changed on the way | — | K_AF depends on the FQDN: with another name, `response` does not match |
| offline dictionary attack | — | the password is the base64 of 256 random bits |

A normative profile (K.2 with TLS, or the TLS 1.3 PSK of K.3.3) would replace this one, with the Ua\* identifier of TS 33.220 H.3 for that profile.

## 11. Configuration of the AF

`af/config/afcfg.yaml`:

| Field | Example | Note |
|---|---|---|
| `fqdn` | `af1.akma.example` | the only name accepted in `Host` |
| `uaStarId` | `FF00000001` | private range, TS 33.220 H.2 NOTE 2 |
| `listen` | `192.168.16.129:8080` | |
| `path` | `/ua/v1/session` | |
| `realmPrefix` | `3GPP-bootstrapping-akma` | first part of the realm |
| `qop` | `[auth]` | `auth-int` optional |
| `nonceLifetime` | `300s` | |
| `kafExpiry` | `refetch` | or `reject` |
| `aanfUri` | `http://192.168.16.130:8010` | TS 33.535 cl. 6.7, local configuration |
| `nefUri`, `nrfUri`, `nfInstanceId` | | AF outside the operator network, in place of `aanfUri` ([nef-akma-api.md](nef-akma-api.md)) |
| `anonymous` | `false` | `true`: anonymous user access (TS 33.535 cl. 6.2.2) |
| `clockOffset` | | test only: shifts the clock of the AF |

## 12. Test vectors

`af/uastar/testdata/digest_vectors.json`, generated by `gen_digest_vectors.py`, a Python implementation of the RFC 7616 computations independent from the Go code:

- **RFC 7616 cl. 3.9.1:** `username="Mufasa"`, password `Circle of Life`, `realm="http-auth@example.org"`, `GET /dir/index.html`, SHA-256, the `nonce` and `cnonce` of the example and `nc=00000001` give `response=753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1`.
- **AKMA:** the A-KID and base64(K_AF) of the `testbed-ue` vector of `shared/akma` (`af1.akma.example.FF00000001`), with fixed `nonce`, `cnonce` and `nc`, for `qop=auth` and `auth-int`, with `response` and `rspauth`.
