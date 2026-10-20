# Reference implementation of the AKMA KDF

A small Python oracle used to cross-check the Go library in `shared/akma`.

It is written directly from **TS 33.220 V19.1.0, Annex B.2**, without looking at any other implementation. The point is to have two independent implementations, so that agreement between them is evidence that both are right.

## Usage

```
python3 akma_kdf.py
```

Prints the `S` string and the result of K_AKMA, A-TID and K_AF for a worked example (the `worked-example` vector).

## Vector generator

```
python3 reference/kdf/gen_vectors.py > shared/akma/testdata/vectors.json
```

`gen_vectors.py` uses the functions of `akma_kdf.py` and adds, also written from the specifications and not from the Go code:

- the SUPI as KDF parameter (TS 33.501 A.7.0);
- the Home Network Domain (TS 23.003 cl. 28.2);
- the A-KID (TS 29.522 table 5.14.5.4.2-1) in three encodings of the A-TID: base64, base64url and hex;
- the two forms of the AF_ID: KDF parameter and transport string.

It produces 8 vectors, the expected equalities between them and two counterexamples.

## What it implements

| Derivation | FC | Specification |
|---|---|---|
| K_AKMA | `0x80` | TS 33.535 Annex A.2 |
| A-TID | `0x81` | TS 33.535 Annex A.3 |
| K_AF | `0x82` | TS 33.535 Annex A.4 |

The generic KDF is `HMAC-SHA-256(Key, S)` with `S = FC ‖ P0 ‖ L0 ‖ … ‖ Pn ‖ Ln`. Each `Li` is two octets, big-endian. Character strings are UTF-8 with NFKC normalization (TS 33.220 B.2.1.2).

## About the values

**TS 33.535 V19.0.0 has no test vectors.** The inputs here are made up to exercise the construction of `S`. They are not 3GPP test vectors and should not be quoted as such.

## Pitfalls the code makes explicit

- **SUPI.** The SUPI goes into the KDF without the `imsi-` prefix: P0 is the IMSI of TS 23.003 cl. 2.2, digits only (TS 33.501 A.7.0). The counterexample `supi-with-imsi-prefix` shows the wrong K_AKMA you get otherwise.
- **AF_ID.** The `AF_ID` parameter is `UTF-8(FQDN) ‖ 5 raw octets` (TS 33.535 A.4). It is not the transport string `<FQDN>.<10 hex digits>` of TS 29.522. The counterexample `af-id-transport-as-p0` shows the wrong K_AF.
- **Ua\* identifier.** The Ua\* identifier `FF00000001` is in the private range (TS 33.220 H.2 NOTE 2).
