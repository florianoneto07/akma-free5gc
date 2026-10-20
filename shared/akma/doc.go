// Package akma groups the building blocks shared by the AUSF patch, the
// AAnF, the AF and the UE side of the AKMA implementation on free5GC.
//
// Subpackages:
//
//   - kdf: generic key derivation function (3GPP TS 33.220 Annex B.2)
//   - supi: SUPI as KDF input parameter (TS 33.501 Annex A.7.0)
//   - afid: AF identifier, KDF and transport forms (TS 33.535 A.4, TS 29.522)
//   - akid: Routing Indicator, Home Network Domain and A-KID (TS 23.003, TS 29.522)
//   - derive: K_AKMA, A-TID and K_AF derivations (TS 33.535 Annex A)
//   - codec: key encodings per layer (SBI hexadecimal, Digest base64)
//
// The test vectors in testdata/vectors.json are produced by an independent
// Python oracle (reference/kdf/gen_vectors.py); they are not 3GPP test
// vectors.
package akma
