# Recommendations to UERANSIM

What we found in UERANSIM against the 3GPP specifications while adding AKMA to it. Each item gives what UERANSIM does, the clause that says what to do, how, and what this repository does.

The patches of this repository apply to UERANSIM commit `85a0fbfd` (v3.2.6-66, 17 April 2024). On 28 October 2026 every item was checked in release v3.3.0 (7 June 2026) and in `master` (`4f45e18f`, 14 October 2026) of `github.com/aligungr/UERANSIM`: all four are still there. Release v3.3.0 changed `src/ue/nas/keys.cpp` and `src/ue/nas/mm/auth.cpp`, so the patches do not apply to it as they are.

| # | Subject | Specification | Here |
|---|---|---|---|
| UE-1 | AKMA in the ME: the K_AKMA of UERANSIM is wrong and the rest is missing | TS 33.535 cl. 4.4.3, 6.1, 6.2.1, Annex A | patches `0001` to `0005` |
| UE-2 | Routing Indicator `"0000"` when none is configured | TS 23.003 cl. 2.2B; TS 24.501 cl. 9.11.3.4 | the configurations set it |
| UE-3 | Security Mode Complete carrying the last Registration Request outside a registration | TS 24.501 cl. 4.4.6, 5.4.2.3 | the patched AMF ignores it |
| UE-4 | No AS security | TS 33.501 cl. 5.2.2, 5.2.3, 6.9.4.4 | limitation |

---

## UE-1 — AKMA in the ME

- **UERANSIM today.** Since April 2025 (commits `89f02d7c` and `27b496ce`, "Fixes #766"), `src/ue/nas/keys.cpp` has `CalculateAkmaKey`, with `KAKMA_derivation_function_code = 0x6A` and a single parameter, the SUPI. `src/ue/nas/mm/auth.cpp` calls it for 5G AKA only, not for EAP-AKA'. There is no A-TID, no A-KID, no K_AF and no interface for applications. `0x6A` is the FC of K_AUSF (TS 33.501 Annex A.2).
- **Specification.** TS 33.535 V19.0.0:
  - A.2: *"FC = 0x80; P0 = "AKMA"; L0 = length of "AKMA"; (i.e. 0x00 0x04); P1 = SUPI; L1 = length of SUPI"*, with K_AUSF as the key and the SUPI as P0 of TS 33.501 Annex A.7.0;
  - A.3: the A-TID, FC = 0x81, P0 = `"A-TID"`; A.4: K_AF, FC = 0x82, P0 = AF_ID; cl. 6.1: the A-KID, in NAI format, with the RID and the A-TID in the username and the home network identifier in the realm;
  - cl. 6.2.1 step 1: *"The UE shall generate the AKMA Anchor Key (KAKMA) and the A-KID from the KAUSF before initiating communication with an AKMA Application Function"*;
  - cl. 4.4.3: *"Applications on the UE shall not be able to get access to KAKMA"* and *"An application on the UE shall only get the KAF keys related to specific AF Identifiers (AF_IDs) that the application is authorized to get"*.
- **How.** K_AKMA with FC = 0x80, P0 = `"AKMA"` and P1 = SUPI, after both authentication methods; the A-TID and the A-KID; K_AF per AF_ID; K_AF handed only to the applications authorized for that AF_ID.
- **Here.** Patches `af/ue/ueransim/patches/0001` to `0005` (GPL-3.0), for `85a0fbfd`: K_AKMA, A-TID and A-KID when the Security Mode Command takes the new context into use, for both methods; K_AF on demand; a key service that gives each application only the K_AF of its own AF_IDs; `nr-akma-selftest` against the test vectors of this repository. Checked end to end with free5GC ([testing.md](testing.md)).

## UE-2 — Routing Indicator when none is configured

- **UERANSIM today.** Without `routingIndicator` in the UE configuration, `src/ue/nas/mm/identity.cpp` (line 105 in v3.3.0 and `master`) uses `"0000"`, four digits.
- **Specification.**
  - TS 23.003 V20.1.0 cl. 2.2B (same text in V19.7.0): *"Each decimal digit present in the Routing Indicator shall be regarded as meaningful (e.g. value "012" is not the same as value "12"). If no Routing Indicator is configured on the USIM or the ME, this data field shall be set to the value 0 (i.e. only consist of one decimal digit of "0")."*
  - TS 24.501 V20.1.0 cl. 9.11.3.4: *"If no Routing Indicator is configured in the USIM or the ME, the UE shall code bits 1 to 4 of octet 8 of the Routing Indicator as "0000" and the remaining digits as "1111"."*
- **How.** The value `"0"`, one digit, coded as `0`, `F`, `F`, `F`.
- **Why it matters for AKMA.** The Routing Indicator is part of the A-KID (`rid0000…` against `rid0…`) and selects the AAnF (TS 33.535 cl. 6.7). A UE with no Routing Indicator configured and a network that follows the specification end up with different A-KIDs.
- **Here.** Not changed: the UE configurations set `routingIndicator: '0000'` explicitly.

## UE-3 — Security Mode Complete carrying the last Registration Request

- **UERANSIM today.** In `src/ue/nas/mm/security.cpp` (line 264 in v3.3.0 and `master`), when the last registration was sent without a NAS security context, the flag `m_lastRegWithoutNsc` stays set after the registration, and every Security Mode Complete carries that REGISTRATION REQUEST in the NAS message container. That includes the Security Mode Command of a primary authentication triggered by the home network, long after the registration.
- **Specification.** TS 24.501 V20.1.0 cl. 5.4.2.3: *"If, prior to receiving the SECURITY MODE COMMAND message, the UE without a valid 5G NAS security context had sent a REGISTRATION REQUEST message the UE shall include the entire REGISTRATION REQUEST message in the NAS message container IE of the SECURITY MODE COMPLETE message as described in clause 4.4.6."* Cl. 4.4.6 a) is about the protection of the initial NAS message: the security mode control procedure that follows that registration.
- **How.** The container goes only in the Security Mode Complete of the registration in which the REGISTRATION REQUEST was sent: clear `m_lastRegWithoutNsc` when the registration completes. This is our reading: the sentence of cl. 5.4.2.3 has no such limit, which is item Z of [3gpp-recommendations.md](3gpp-recommendations.md).
- **Here.** The patched AMF ignores the container during the re-authentication triggered by the home network ([free5gc-fixes.md](free5gc-fixes.md), F19). The UE is not changed.

## UE-4 — No AS security

- **UERANSIM today.** Neither the UE nor the gNB has the RRC security mode procedure or K_gNB (`src/ue/rrc`, `src/gnb/rrc`). RRC and the user plane between the UE and the gNB are neither ciphered nor integrity protected.
- **Specification.** TS 33.501 V20.3.0:
  - cl. 5.2.2: *"The UE shall support ciphering of user data between the UE and the gNB."* and *"The UE shall support ciphering of RRC and NAS-signalling."*;
  - cl. 5.2.3: *"The UE shall support integrity protection and replay protection of user data between the UE and the gNB."*, and the same for RRC and NAS signalling;
  - cl. 6.9.4.4: AS key re-keying after an authentication.
- **How.** The RRC security mode procedure and PDCP security, with the keys derived from K_gNB (TS 33.501 Annex A.9).
- **Why it matters for AKMA.** After a new primary authentication, AS key re-keying cannot be tested.
- **Here.** A limitation, not changed.
