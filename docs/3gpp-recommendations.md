# Recommendations to 3GPP

Inconsistencies and gaps found while implementing AKMA (TS 33.535, Release 19) on free5GC and UERANSIM. Each item was checked on 28 October 2026 against the latest version of the specification published at <https://www.3gpp.org/ftp/Specs/archive/>; the version is given in the item.

Items A to P are contradictions or errors in the text. Items Q to Z are gaps: the text does not say enough for two implementations to interoperate, and this repository had to choose. Each item has the fields of a Change Request, so that a 3GPP member can take it to the working group in charge. Nothing here has been submitted to 3GPP yet. The letters identify the items and stay the same in later versions of this list.

| Item | Group | Specification | Subject | Kind |
|---|---|---|---|---|
| A | CT3 | TS 29.522 | `atid` versus `akid` in the A-KID format | correction |
| B | CT4 | TS 29.503 | method of `trigger-auth`: POST in the text, `get` in the YAML | correction |
| C | CT1 | TS 24.109 | two `realm` values in the AKMA HTTP Digest profile | correction |
| D | CT3, CT4 | TS 29.535, TS 29.522 | no `pattern` for the key material `kAkma` and `kaf` | correction |
| E | SA3 | TS 33.535 | separator missing in the TLS 1.3 `psk_identity` | correction |
| F | CT1 | TS 24.109 | RFC 3310 cited for the AKMA Digest | correction |
| G | CT3 | TS 29.535 | `204 No Content` with no reachable condition | correction |
| H | CT3 | TS 29.522 | editorial | editorial |
| I | CT3 | TS 29.535 | `CtxRemove` without `required`; editorial | correction, editorial |
| J | SA3 | TS 33.535 | wrong references in the OSCORE profile | editorial |
| K | SA3 | TS 33.535, TS 33.220 | OSCORE request field without encoding | correction |
| L | SA3 | TS 33.535, TS 33.220 | type and negotiation of OSC-INP | correction |
| M | SA3 | TS 33.535, TS 33.220 | HKDF parameters of the OSCORE Master Secret | correction |
| N | SA3 | TS 33.535 | form of the HPLMN-ID in the CBOR A-KID | clarification |
| O | CT4 | TS 29.503 | `trigger-auth`: who answers 204; "manadatory" | editorial |
| P | CT4 | TS 29.503 | `202` missing in the re-authentication notification of non-3GPP access | correction |
| Q | SA3, CT3 | TS 33.535, TS 29.522 | encoding of the A-TID in the A-KID | clarification |
| R | CT1, SA3 | TS 24.109, TS 33.535 | derivation of the TLS PSK and premaster from K_AF | clarification |
| S | CT1 | TS 24.109 | separator of the TLS 1.2 PSK identity | correction |
| T | SA3 | TS 33.535, TS 33.220 | DTLS 1.2 for AKMA | clarification |
| U | SA3 | TS 33.535 | application protocol inside DTLS | clarification |
| V | SA3 | TS 33.535 | errors of the OSCORE profile | clarification |
| W | SA3 | TS 33.535 | CoAP mandatory cipher suite against TS 33.210 | clarification |
| X | CT4 | TS 29.503 | when the UDM answers `trigger-auth` | clarification |
| Y | CT3 | TS 29.522 | authorization server of the NEF without CAPIF | clarification |
| Z | CT1 | TS 24.501 | scope of the NAS message container in Security Mode Complete | clarification |

The last section lists three observations on TS 23.502 (SA2), editorial.

---

## SA3

### E — Separator missing in the TLS 1.3 `psk_identity`

- **Specification:** TS 33.535 V19.0.0 (latest), Annex B.1.3.
- **Current text:** B.1.3 builds the `psk_identity` from the prefix `"3GPP-AKMA"` and the A-KID, with no separator. TS 24.109 V19.0.0, K.3.3 1) d): *"a prefix indicating the PSK identity name space, i.e. "3GPP-AKMA", a separator character ";" and the A-KID"*.
- **Reason for change:** an implementation that follows TS 33.535 alone builds an identity that the Stage 3 format does not accept. TS 33.222 cl. 5.4.0.2 leaves the precise format to TS 24.109.
- **Proposed change:** in B.1.3, `"3GPP-AKMA" ";" A-KID`, or a reference to TS 24.109 K.3.3. B.1.2 could also say that the Digest password is K_AF in base64 (RFC 4648), as TS 24.109 K.2 c) 2) does.
- **Consequences if not changed:** UE and AF built from different specifications do not agree on the identity, and the handshake fails.
- **This repository:** `3GPP-AKMA;<A-KID>`, as TS 24.109.

### J — Wrong references in the OSCORE profile

- **Specification:** TS 33.535 V19.0.0 (latest), D.3.2 and D.3.3.
- **Current text:** D.3.2 refers to *"TS 33.220 [4], clause Y.2.3. Step 1"* and to *"clause P.2.3. Step 3"*; D.3.3 to *"TS 33.220 [4], clause Y.3.3"*. TS 33.220 V19.1.0 has no Annex Y, and P.2.3 is *"Requirements on the NAF"*, without steps.
- **Reason for change:** the content is in P.3.2 (steps 1 and 3) and P.3.3. D.3.3 gives only part of the security context and relies on the referenced clause for the rest (version, HKDF, AEAD, ID Context).
- **Proposed change:** Y.2.3 → P.3.2; P.2.3 → P.3.2; Y.3.3 → P.3.3.
- **Consequences if not changed:** readers have to find the content by subject.
- **This repository:** reads the references as P.3.2 and P.3.3.

### K — OSCORE request field without encoding

- **Specifications:** TS 33.535 V19.0.0, D.3.2 iii) and D.3.5; TS 33.220 V19.1.0, P.3.2 and P.3.5 (latest).
- **Current text:** D.3.2 iii) lists in the request *"CoAP Security protocol identifier, A-KID, N1, AF-SID, ?OSC-INP"*; the CBOR array of D.3.5 is `[A-KID, N1, AF-SID, ? OSC-INP]`, without the identifier. Annex P of TS 33.220 has the same difference: P.3.2 gives the field the value `"01"`, P.3.5 does not encode it.
- **Reason for change:** an implementation that follows D.3.2 sends an array that another one, following D.3.5, cannot parse.
- **Proposed change:** remove the identifier from D.3.2 iii), or add it to the CBOR of D.3.5 (and the same in TS 33.220 Annex P).
- **Consequences if not changed:** OSCORE establishment fails between implementations that follow different clauses.
- **This repository:** the array of D.3.5, without the field.

### L — Type and negotiation of OSC-INP

- **Specifications:** TS 33.535 V19.0.0, D.3.5; TS 33.220 V19.1.0, P.3.3 and P.3.5 (latest).
- **Current text:** in the array, `? OSC-INP: bstr`; in the definition, `OSC-INP = {…}`, a CBOR map. The labels (1 version, 3 HKDF, 4 AEAD, 5 salt, 6 ID Context) are those of `OSCORE_Input_Material` in RFC 9203 cl. 3.2.1, which allows text or integer for HKDF and AEAD; Annex D only allows integers. Label 5 competes with the Master Salt of D.3.3. The response, `[N2, UE-SID]`, cannot tell the UE which values the AF adopted.
- **Reason for change:** an OSC-INP sent as a map and one sent as a `bstr` wrapping the map do not interoperate, and an AF that does not accept the requested algorithm has no way to say so.
- **Proposed change:** fix the type (map or `bstr`), remove or define the salt label, and either add the adopted values to the response or say that the AF refuses values it does not support, with an error.
- **Consequences if not changed:** the optional parameters cannot be used safely.
- **This repository:** `bstr` with the map inside; the UE sends no OSC-INP; the AF accepts only the default values and refuses others with `4.00`.

### M — HKDF parameters of the OSCORE Master Secret

- **Specifications:** TS 33.535 V19.0.0, D.3.3; TS 33.220 V19.1.0, P.3.3 (latest).
- **Current text:** *"OMS = OSCORE Master Secret = HKDF(KAF, "AKMA-OSCORE")"*, with HKDF *"specified in IETF RFC 5869"*. RFC 5869 defines HKDF(salt, IKM, info, L) in two steps. The text gives neither the salt, nor the encoding of the label, nor the length L. Annex P has the same form, with `"GBA-OSCORE"`.
- **Reason for change:** different salt, encoding or length give different Master Secrets.
- **Proposed change:** state the hash (SHA-256), salt (empty), IKM (K_AF), info (the ASCII label) and L (32 octets), or the values intended.
- **Consequences if not changed:** the first protected request does not decrypt between implementations that choose differently.
- **This repository:** full HKDF-SHA-256 (extract and expand), empty salt, IKM = K_AF, info = `AKMA-OSCORE` in ASCII, L = 32.

### N — Form of the HPLMN-ID in the CBOR A-KID

- **Specification:** TS 33.535 V19.0.0 (latest), D.3.5.
- **Current text:** `A-KID = [RID : tstr, A-TID : bstr, HPLMN-ID : tstr]`, without the form of the HPLMN-ID: MCC and MNC (the Home Network Identifier of TS 23.003 cl. 2.2B), the domain of the realm, or another.
- **Reason for change:** with the A-TID in octets, the AF has to rebuild the text of the A-KID to query the AAnF, and the textual encoding of the A-TID is not fixed either (item Q).
- **Proposed change:** define HPLMN-ID (for instance MCC followed by MNC, three digits each) and how the AF rebuilds the A-KID from the array.
- **Consequences if not changed:** a UE and an AF with different forms do not reach the same A-KID.
- **This repository:** HPLMN-ID = MCC followed by MNC; the AF rebuilds the realm with a three-digit MNC and the A-TID in base64.

### Q — Encoding of the A-TID in the A-KID (also CT3)

- **Specifications:** TS 33.535 V19.0.0, cl. 6.1 and Annex A.3; TS 29.522 V20.1.0, table 5.14.5.4.2-1 (`AKId`).
- **Current text:** TS 33.535 cl. 6.1: *"A-KID shall be in NAI format as specified in clause 2.2 of IETF RFC 7542 [6], i.e. username@realm. The username part shall include the RID and the A-TID"*. The A-TID is the 256-bit output of the KDF of A.3. TS 29.522 gives `"rid<value>.atid<value>"`.
- **Reason for change:** no specification says how the 256 bits become characters of the username: hexadecimal, base64 or base64url.
- **Proposed change:** fix the encoding, for instance 64 lower-case hexadecimal characters, as for the other 256-bit values of the APIs (item D), or base64 with the alphabet RFC 7542 allows in the username.
- **Consequences if not changed:** UE, AUSF, AAnF and AF with different encodings produce different A-KIDs for the same A-TID, and the AF gets no K_AF.
- **This repository:** base64, configurable in the AAnF.

### R — Derivation of the TLS PSK and premaster from K_AF (also CT1)

- **Specifications:** TS 24.109 V19.0.0, K.3.2 f) and K.3.3; TS 33.535 V19.0.0, B.1.3 (latest).
- **Current text:** K.3.2 f): *"the UE and AF shall derive the TLS premaster secret from KAF (AKMA Application Key)"*. K.3.3: *"The UE shall derive the TLS external PSK from the AF specific key KAF"* and *"The AF shall derive the TLS external PSK from the AF specific key KAF"*.
- **Reason for change:** neither TS 24.109, TS 33.535 B.1.3 nor TS 33.210 gives the derivation: K_AF can be the PSK itself, or the input of a KDF.
- **Proposed change:** say that K_AF is used directly: in TLS 1.2 as the PSK of RFC 4279 and RFC 5489 in the premaster secret; in TLS 1.3 as the external PSK, with SHA-256. Key separation per protocol is already in the AF_ID (TS 33.220 H.2). Or define the KDF in TS 33.535 Annex A.
- **Consequences if not changed:** UE and AF with different derivations do not complete the handshake.
- **This repository:** K_AF directly, in both versions.

### T — DTLS 1.2 for AKMA

- **Specifications:** TS 33.535 V19.0.0, C.1.1 and C.2; TS 33.220 V19.1.0, Annex H.3 (latest); TS 33.210 V20.0.0, cl. 6.2.1.
- **Current text:** TS 33.210 cl. 6.2.1: *"If DTLS is supported then DTLS 1.2 as specified in RFC 6347 [49] shall be supported and DTLS 1.3 as specified in RFC 9147 [75] should be supported"*. TS 33.535 C.1.1: *"The PSK identity specified in B.1 for TLS is also applicable for DTLS"*. C.2 only has the procedures of DTLS 1.3. TS 33.220 H.3: `(0x01,0x00,0x00,0x00,0x09)` is the *"Ua security protocol for DTLS according to Annex O"*, which only describes DTLS 1.3, and `(0x01,0x00,0x01,yy,zz)` is *"for TLS 1.2"*.
- **Reason for change:** an implementation that follows TS 33.210 and offers DTLS 1.2 has neither a procedure nor a Ua\* security protocol identifier for it.
- **Proposed change:** add the DTLS 1.2 procedure to C.2 and say which identifier it uses, or say that AKMA uses DTLS 1.3 only.
- **Consequences if not changed:** DTLS 1.2 implementations choose their own AF_ID and do not interoperate.
- **This repository:** DTLS 1.2 with the TLS 1.2 procedure and `01 00 01 yy zz` of the cipher suite; `…09` stays for DTLS 1.3 only, so that one K_AF is not shared between the two versions (RFC 8446 Appendix E.7).

### U — Application protocol inside DTLS

- **Specifications:** TS 33.535 V19.0.0, Annex C; TS 33.220 V19.1.0, O.2.2 (latest).
- **Current text:** Annex C of TS 33.535 does not say what DTLS carries. Annex O of TS 33.220, which it adapts: *"It does not have any dependency on the application layer protocol."*
- **Reason for change:** UE and AF need the same application protocol to exchange anything. With CoAP, the usual protocol over DTLS, the mandatory cipher suite of RFC 7252 comes along (item W).
- **Proposed change:** name the protocol, or say that the application chooses it and how the UE and the AF agree on it.
- **Consequences if not changed:** each implementation picks a protocol, and a UE and an AF from different vendors cannot talk after the handshake.
- **This repository:** CoAP (RFC 7252), scheme `coaps`.

### V — Errors of the OSCORE profile

- **Specifications:** TS 33.535 V19.0.0, Annex D; TS 33.220 V19.1.0, Annex P (latest).
- **Current text:** Annex D defines the `POST /akma` request and the successful response (D.3.2, D.3.5), and no error response: unknown A-KID, K_AF not available, AF not authorized, OSC-INP not supported. Annex P has none either. The HTTP profile of Annex B has its errors.
- **Reason for change:** each AF answers its own way, and the UE cannot tell whether to run a new primary authentication, retry, or give up.
- **Proposed change:** define the error responses of the `/akma` resource, with CoAP codes and the causes of Annex B.
- **Consequences if not changed:** UEs cannot react to errors in a uniform way.
- **This repository:** CoAP codes with the cause in the diagnostic payload; OSCORE errors as RFC 8613 cl. 8.2.

### W — CoAP mandatory cipher suite against TS 33.210

- **Specifications:** TS 33.535 V19.0.0, C.2.1; TS 33.210 V20.0.0, cl. 6.2; RFC 7252 cl. 9.1.3.1.
- **Current text:** TS 33.535 C.2.1: *"The TLS profile specified in TS 33.210 [13] clause 6.2 apply to DTLS 1.3"*. TS 33.210 cl. 6.2.3: *"Only cipher suites with AEAD (e.g. GCM) and PFS (i.e., ECDHE) shall be supported."* RFC 7252 cl. 9.1.3.1, for CoAP in PSK mode: *"Implementations in these modes MUST support the mandatory-to-implement cipher suite TLS_PSK_WITH_AES_128_CCM_8"*, a DTLS 1.2 suite without ECDHE.
- **Reason for change:** a UE or AF that uses CoAP over DTLS cannot follow both rules.
- **Proposed change:** with item U, say that on Ua\* the cipher suites of TS 33.210 apply and the mandatory suite of RFC 7252 does not.
- **Consequences if not changed:** implementations following RFC 7252 offer a suite without forward secrecy, which TS 33.210 forbids.
- **This repository:** only the suites of TS 33.210.

---

## CT1

### C — Two `realm` values in the AKMA HTTP Digest profile

- **Specification:** TS 24.109 V19.0.0 (latest), Annex K, K.2.
- **Current text:** item b) 2): the `realm` of the `WWW-Authenticate` header contains the constant `"3GPP-bootstrapping-akma"`; item c) 3): the `realm` has two parts separated by `@`, the constant `"3gpp-akma"` and the FQDN of the AF.
- **Reason for change:** in HTTP Digest the client echoes the `realm` of the challenge in the `Authorization` header, and the value enters HA1: both must be the same. TS 33.535 V19.0.0 B.1.2.2 step 3: *"the AF shall include the "3GPP-bootstrapping-akma" within the WWW-Authenticate header field"*; step 4 checks *"the FQDN in the realm attribute"*. The GBA model of TS 24.109 cl. 5.2.2.1 item 3 uses `<constant>@<FQDN>` with the constant that signals the mode (`3GPP-bootstrapping@naf1.operator.com`).
- **Proposed change:** in c) 3), `"3GPP-bootstrapping-akma"` instead of `"3gpp-akma"`, giving `3GPP-bootstrapping-akma@<FQDN of the AF>`.
- **Consequences if not changed:** a client following c) 3) and an AF following b) 2) compute different digests.
- **This repository:** `realm="3GPP-bootstrapping-akma@<FQDN>"`.

### F — RFC 3310 cited for the AKMA Digest

- **Specification:** TS 24.109 V19.0.0 (latest), K.2 c).
- **Current text:** *"HTTP Digest authentication (see RFC 3310 [6]) shall be used"*. RFC 3310 is HTTP Digest AKA, where the password comes from the RES of AKA. K.2 b) refers to cl. 5.2, whose cl. 5.2.2.1 uses RFC 7616 with the application key in base64 as the password; TS 33.535 B.1.2.2 follows TS 33.222 cl. 5.3.0, which cites RFC 7235 and RFC 7616 and discourages MD5.
- **Reason for change:** with the password = base64(K_AF), only RFC 7616 applies.
- **Proposed change:** RFC 7616 instead of RFC 3310 in K.2 c).
- **Consequences if not changed:** implementers may pick the AKA Digest of RFC 3310, which cannot work with K_AF.
- **This repository:** RFC 7616 with `algorithm=SHA-256`.

### S — Separator of the TLS 1.2 PSK identity

- **Specification:** TS 24.109 V19.0.0 (latest), K.3.2 e).
- **Current text:** the `psk_identity` *"shall contain a prefix "3GPP-AKMA" and the A-KID"*, with no separator. For TLS 1.3, K.3.3 1) d) adds *"a separator character ";""*, and GBA uses `;` (TS 24.109 cl. 5.3.3.1.2).
- **Reason for change:** `3GPP-AKMA<A-KID>` and `3GPP-AKMA;<A-KID>` are different identities.
- **Proposed change:** add the separator `";"` to K.3.2 e), as in K.3.3.
- **Consequences if not changed:** TLS 1.2 UEs and AFs that read the two clauses differently do not find the key.
- **This repository:** `3GPP-AKMA;<A-KID>` in both TLS versions.

### Z — Scope of the NAS message container in Security Mode Complete

- **Specification:** TS 24.501 V20.1.0, cl. 5.4.2.3 and 4.4.6.
- **Current text:** cl. 5.4.2.3: *"If, prior to receiving the SECURITY MODE COMMAND message, the UE without a valid 5G NAS security context had sent a REGISTRATION REQUEST message the UE shall include the entire REGISTRATION REQUEST message in the NAS message container IE of the SECURITY MODE COMPLETE message as described in clause 4.4.6."* The sentence is not limited to the registration in progress. Cl. 4.4.6 a), on the protection of the initial NAS message, refers to the security mode control procedure that follows that REGISTRATION REQUEST. On the network side, cl. 5.4.2.3 says the AMF *"shall complete the ongoing registration procedure by considering the REGISTRATION REQUEST message contained in the NAS message container IE as the message that triggered the procedure"*, and does not say what to do when no registration is in progress.
- **Reason for change:** in a primary authentication triggered by the home network (TS 33.501 cl. 6.1.5), after the registration, a UE that reads the sentence literally puts the old REGISTRATION REQUEST in the SECURITY MODE COMPLETE. UERANSIM does that, and the AMF of free5GC handled it as a new registration.
- **Proposed change:** limit the rule to the security mode control procedure started during the registration in which the REGISTRATION REQUEST was sent, and say that the AMF ignores the container outside a procedure in progress.
- **Consequences if not changed:** home network triggered re-authentication can break the UE context at the AMF.
- **This repository:** the patched AMF ignores the container during that re-authentication; the UE is not changed.

---

## CT3

### A — `atid` versus `akid` in the A-KID format

- **Specification:** TS 29.522 V20.1.0, table 5.14.5.4.2-1, type `AKId`.
- **Current text:** *"<username> shall include Routing Indicatorand the A-TID in the format "rid<value>.atid<value>", where "rid" and "atid" are labels indicating Routing Indicator and A-TID"*; the example that follows uses `akid`: *"rid012.akid019345346@5gc.mnc012.mcc345.3gppnetwork.org"*.
- **Reason for change:** the two forms are incompatible. The AAnF that parses the A-KID from the AF has to recognize one label. The type has had three corrections (CR 0269, CR 0559, CR 1784); the example was not updated with the text.
- **Proposed change:** `atid` in the example (and "Routing Indicator and", item H).
- **Consequences if not changed:** implementations copying the example produce A-KIDs that others reject.
- **This repository:** reads both `atid` and `akid`, writes `atid`.

### D — No `pattern` for the key material `kAkma` and `kaf` (also CT4)

- **Specifications:** `TS29535_Naanf_AKMA.yaml` v1.3.0-alpha.1 (TS 29.535 V20.1.0), `kAkma`; `TS29522_AKMA.yaml` (TS 29.522 V20.1.0), `kaf`.
- **Current text:** both are `type: string`, with no `pattern`, `format` or note on the encoding, although both carry 256-bit keys.
- **Reason for change:** TS 29.509 declares fixed-length key material with an explicit hexadecimal pattern (`Kseaf` as `[A-Fa-f0-9]{64}`), and `TS29503_Nudm_UEAU.yaml` declares `Kausf`, the key K_AKMA comes from, as `^[A-Fa-f0-9]{64}$`.
- **Proposed change:** `pattern: '^[A-Fa-f0-9]{64}$'` on `kAkma` and `kaf`.
- **Consequences if not changed:** one implementation may send hexadecimal and another base64.
- **This repository:** 64 hexadecimal characters, lower case when writing, the anchored pattern when reading.

### G — `204 No Content` with no reachable condition

- **Specification:** TS 29.535 V20.1.0, cl. 4.2.2.3.2 and table 5.1.4.3.2-2; `TS29535_Naanf_AKMA.yaml`.
- **Current text:** *"If KAKMA is not present in the AAnF, the AAnF shall reply with an HTTP "403 Forbidden" status code … "K_AKMA_NOT_PRESENT""* and, in the same clause, *"If the requested AKMA Application Key information for the UE does not exist, the AAnF shall respond with "204 No Content"."* With K_AKMA present, the AAnF derives K_AF (TS 33.535 cl. 6.2.1 step 7), so no condition is left for 204. The NEF API has the same construction (TS 29.522 table 5.14.3.2.2-2).
- **Reason for change:** consumers may expect different answers for the same case.
- **Proposed change:** remove the 204, or state the condition it covers.
- **Consequences if not changed:** AFs and NEFs must handle an answer whose meaning is not defined.
- **This repository:** the AAnF never answers 204; the AF and the NEF handle it anyway.

### H — Editorial

- **Specification:** TS 29.522 V20.1.0. The references corrected since V19.7.0 (table 5.14.5.1-1 to 5.14.5.3.4, "table 5.14.5.2-1") are left out.
- **Current text:** "Routing Indicatorand" in table 5.14.5.4.2-1; "retrievel" in the description of `notifUri`.
- **Proposed change:** "Routing Indicator and"; "retrieval".

### I — `CtxRemove` without `required`; editorial

- **Specification:** TS 29.535 V20.1.0; `TS29535_Naanf_AKMA.yaml` v1.3.0-alpha.1. The wording of the 307/308 responses, corrected since V19.5.0, is left out.
- **Current text:** the schema `CtxRemove` has no `required: [supi]`, although its description says *"the "supi" attribute shall be included"*; `info.title` of the YAML is `3gpp-akma`, the title of the NEF API; *"manadatory"* in a table note.
- **Reason for change:** schema validation accepts an empty `CtxRemove`.
- **Proposed change:** `required: [supi]`; `info.title: Naanf_AKMA`; "mandatory".
- **This repository:** the AAnF refuses a `CtxRemove` without `supi` with 400.

### Y — Authorization server of the NEF without CAPIF

- **Specifications:** TS 29.522 V20.1.0, cl. 6; TS 33.501 V20.3.0, cl. 12.4.
- **Current text:** *"When CAPIF is not supported and/or not used, the access to the NEF Northbound APIs shall be authorized by means of OAuth2 protocol (see IETF RFC 6749 [13]), based on local configuration, using the "Client Credentials" authorization grant as defined in clause 12.4 of 3GPP TS 33.501 [6]. When OAuth2 is used, a client shall obtain a "token" from the authorization server prior to consuming services offered by any NEF Northbound API."* Neither this clause nor TS 33.501 cl. 12.4 says which is the authorization server. With CAPIF it is the CAPIF Core Function (TS 29.522 cl. 7.2).
- **Reason for change:** without CAPIF the AF does not know where to ask for the token.
- **Proposed change:** name the authorization server when CAPIF is not used, or say that the AF gets it by configuration.
- **Consequences if not changed:** each deployment picks one (the NRF, an operator server), and AFs need per-operator integration.
- **This repository:** the NRF, by local configuration.

---

## CT4

### B — Method of `trigger-auth`: POST in the text, `get` in the YAML

- **Specification:** TS 29.503 V20.1.0; `TS29503_Nudm_UECM.yaml` v1.5.0-alpha.2.
- **Current text:** table 6.2.3.13.4.1-1 maps the custom operation `trigger-auth` to POST; cl. 5.3.2.16.2 step 1: *"The NF Service Consumer sends a POST request (custom method: trigger-auth) to the UDM"*; table 6.2.3.13.4.2.2-1 is titled *"Data structures supported by the POST Request Body"*. The YAML declares `get:` with a required `requestBody`. Annex A.1 gives the YAML precedence *"with respect to the encoding of information elements and methods"*.
- **Reason for change:** a GET with a required body goes against the semantics of GET (RFC 9110 cl. 9.3.1) and the custom operations of TS 29.501 cl. 4.6.1.2, which use POST. Applying the precedence rule makes the operation impractical.
- **Proposed change:** `post:` in the YAML. `AuthTriggerInfo` could also declare `required: [supi]`: TS 33.501 cl. 14.2.6 has *"Input, Required: SUPI"*.
- **Consequences if not changed:** consumers that follow the YAML send GET and producers that follow the text answer 405, or the other way round.
- **This repository:** POST; the UDM answers GET with 405.

### O — `trigger-auth`: who answers 204; "manadatory"

- **Specification:** TS 29.503 V20.1.0, cl. 5.3.2.16.2 and table notes.
- **Current text:** step 2a: *"On success, the NF Service Consumer responds with "204 No Content""*; the UDM answers, not the consumer that sent the request in step 1. *"The manadatory HTTP error status code …"* in several table notes, for instance in table 6.2.3.13.4.2.2-2.
- **Proposed change:** *"the UDM responds with "204 No Content""*; "mandatory".

### P — `202` missing in the re-authentication notification of non-3GPP access

- **Specification:** `TS29503_Nudm_UECM.yaml` v1.5.0-alpha.2 (TS 29.503 V20.1.0) against cl. 5.3.2.15.2 and table 6.2.5.6-3.
- **Current text:** the YAML declares the `reauthNotification` callback in the AMF registration for 3GPP access, with `202` (*"Re-Authentication Notification is accepted and reauthentication pending flag has been set."*), and in the one for non-3GPP access, without `202`. The text has a single notification: cl. 5.3.2.15.2 step 2b and table 6.2.5.6-3 define the 202 for an unreachable UE, whatever the access.
- **Reason for change:** with the precedence of the YAML, an AMF registered for non-3GPP access cannot tell the UDM that it set the pending flag.
- **Proposed change:** add the `202` response to the `reauthNotification` callback of the non-3GPP access registration.
- **Consequences if not changed:** a UDM generated from the YAML treats that 202 as undeclared.
- **This repository:** the AMF registers the callback for 3GPP access only; the UDM accepts 202 from any access.

### X — When the UDM answers `trigger-auth`

- **Specifications:** TS 29.503 V20.1.0, cl. 5.3.2.16.2; TS 33.501 V20.3.0, cl. 6.1.5.2.
- **Current text:** TS 33.501 cl. 6.1.5.2 step 1: *"The UDM may acknowledge the request with an Nudm_UECM_AuthTrigger Response to the NF"*. TS 29.503 cl. 5.3.2.16.2 has the 204 of success and the 404 of an unknown user.
- **Reason for change:** neither says whether the 204 comes before or after the Nudm_UECM_Re-AuthenticationNotification to the AMF, nor what the UDM answers when the AMF refuses (403, 409) or sets the pending flag (202). The consumer, the AAnF, cannot tell whether a 204 means that the authentication will take place.
- **Proposed change:** say whether the UDM answers after the AMF and, if so, how the answers of table 6.2.5.6-3 map to those of `trigger-auth`, which has no 409.
- **Consequences if not changed:** the policy of the AAnF for asking again depends on a behaviour that differs between UDMs.
- **This repository:** the UDM answers after the AMF: 204 for 204 and 202; `403 REAUTHENTICATION_NOT_ALLOWED` for 403 and 409; `404 CONTEXT_NOT_FOUND` for 404.

---

## SA2 observations on TS 23.502

Checked in TS 23.502 V20.3.0. Lists of context in a Stage 2 specification, editorial:

- cl. 5.2.3.2: the operations of the `Nudm_UECM` service do not include `AuthTrigger`, which TS 29.503 introduced (CR 1133, 18.3.0) and TS 33.501 cl. 14.2.6 describes;
- cl. 5.2.3.5.2: the consumers of `Nudm_EventExposure_Subscribe` are only *"NEF, SMS-GMSC"*, while TS 29.503 cl. 5.2.2.1 lists the AAnF among the consumers of the UDM (CR 1180, 18.4.0);
- TS 33.535 V19.0.0 cl. 4.3.0 NOTE 1 and cl. 7.4 point to `Nudm_EventExposure_Subscribe` (TS 23.502 cl. 5.2.3.5.2) as a UDM service used by AKMA, and the clause pointed to does not list the AAnF as a consumer.
