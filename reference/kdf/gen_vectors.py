"""Produce AKMA test vectors for cross-checking the Go library.

Written from the specifications, independently of the Go code:
  - KDF and string encoding: TS 33.220 B.2.0, B.2.1.2 (via akma_kdf.py)
  - K_AKMA, A-TID, K_AF: TS 33.535 A.2, A.3, A.4
  - SUPI as KDF parameter: TS 33.501 A.7.0 (IMSI digits, no "imsi-" prefix)
  - Home Network Domain: TS 23.003 cl. 28.2
  - A-KID: TS 29.522 table 5.14.5.4.2-1, "rid<RID>.atid<A-TID>@<realm>"
  - AfId transport form: TS 29.522 table 5.14.5.4.2-1, "<FQDN>.<Ua* id>"
  - K_AF as Digest password: base64 per RFC 4648 (TS 24.109 K.2 c)2))

Encodings that no specification fixes are listed in "implementation_choices":
  - A-TID text encoding: base64 per RFC 4648 by default, by analogy with the
    GBA B-TID (TS 33.220 cl. 4.5.2)
  - kAkma / kaf over SBI: lowercase hex, as Kausf in TS 29.503
  - Ua* id in AfId written as 10 uppercase hex characters

These are NOT 3GPP test vectors: TS 33.535 V19.0.0 publishes none.

Usage: python3 reference/kdf/gen_vectors.py > shared/akma/testdata/vectors.json
"""
import base64, hashlib, json, os, re, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from akma_kdf import enc_str, kdf  # noqa: E402

FC_KAKMA, FC_ATID, FC_KAF = 0x80, 0x81, 0x82


def supi_kdf_param(supi: str) -> str:
    m = re.fullmatch(r"imsi-([0-9]{5,15})", supi)
    if not m:
        raise ValueError(f"only IMSI-type SUPI supported: {supi!r}")
    return m.group(1)


def home_network_domain(mcc: str, mnc: str) -> str:
    assert re.fullmatch(r"[0-9]{3}", mcc) and re.fullmatch(r"[0-9]{2,3}", mnc)
    return f"5gc.mnc{mnc.zfill(3)}.mcc{mcc}.3gppnetwork.org"


def atid_text(atid: bytes, encoding: str) -> str:
    if encoding == "base64":
        return base64.b64encode(atid).decode()
    if encoding == "base64url":
        return base64.urlsafe_b64encode(atid).decode()
    if encoding == "hex":
        return atid.hex()
    raise ValueError(encoding)


def vector(name, note, k_ausf, supi, mcc, mnc, rid, fqdn, ua_star_id):
    p_supi = supi_kdf_param(supi)
    k_akma, s1 = kdf(k_ausf, FC_KAKMA, [enc_str("AKMA"), enc_str(p_supi)])
    a_tid, s2 = kdf(k_ausf, FC_ATID, [enc_str("A-TID"), enc_str(p_supi)])
    realm = home_network_domain(mcc, mnc)
    ua = bytes.fromhex(ua_star_id)
    assert len(ua) == 5
    af_id_p0 = enc_str(fqdn) + ua
    k_af, s3 = kdf(k_akma, FC_KAF, [af_id_p0])
    return {
        "name": name,
        "note": note,
        "k_ausf": k_ausf.hex(),
        "supi": supi,
        "supi_kdf_param": p_supi,
        "mcc": mcc,
        "mnc": mnc,
        "rid": rid,
        "fqdn": fqdn,
        "ua_star_id": ua.hex().upper(),
        "s_k_akma": s1.hex(),
        "k_akma": k_akma.hex(),
        "s_a_tid": s2.hex(),
        "a_tid": a_tid.hex(),
        "realm": realm,
        "a_kid": {enc: f"rid{rid}.atid{atid_text(a_tid, enc)}@{realm}"
                  for enc in ("base64", "base64url", "hex")},
        "af_id_transport": f"{fqdn}.{ua.hex().upper()}",
        "af_id_kdf_param": af_id_p0.hex(),
        "s_k_af": s3.hex(),
        "k_af": k_af.hex(),
        "k_af_base64": base64.b64encode(k_af).decode(),
    }


def seed(label: str) -> bytes:
    """Deterministic 256-bit K_AUSF for a named vector."""
    return hashlib.sha256(("akma-free5gc test vector: " + label).encode()).digest()


def main():
    worked_kausf = bytes.fromhex("5c7c9be7bf6a1a1a2c0b0f6d4c9c2f81"
                                 "9c1a3b4d5e6f708192a3b4c5d6e7f809")
    testbed = dict(k_ausf=seed("testbed-ue"), supi="imsi-208930000000001",
                   mcc="208", mnc="93", rid="0000")
    vectors = [
        vector("worked-example", "Worked example of akma_kdf.py: illustrative K_AUSF, SUPI and AF",
               worked_kausf, "imsi-208930000000003", "208", "93", "0",
               "af.akma.free5gc.org", "FF00000001"),
        vector("testbed-ue", "Testbed UE subscriber with RID 0000 (UERANSIM configuration)",
               fqdn="af1.akma.example", ua_star_id="FF00000001", **testbed),
        vector("rid-012", "RID with a significant leading zero; MCC 345, MNC 12 (TS 23.003 cl. 28.2 example)",
               seed("rid-012"), "imsi-345120000000001", "345", "12", "012",
               "af2.akma.example", "FF00000001"),
        vector("mnc-3-digits", "Three-digit MNC and single-digit RID",
               seed("mnc-3-digits"), "imsi-310410000000001", "310", "410", "7",
               "af1.akma.example", "FF00000001"),
        vector("ua-tls13", "Same UE as testbed-ue; Ua* id of TLS 1.3 PSK (TS 33.220 H.3)",
               fqdn="af1.akma.example", ua_star_id="0100000007", **testbed),
        vector("nfkc-composed", "FQDN with precomposed U+00E9",
               fqdn="café.akma.example", ua_star_id="FF00000001", **testbed),
        vector("nfkc-decomposed", "FQDN with e + U+0301; NFKC makes it equal to nfkc-composed",
               fqdn="café.akma.example", ua_star_id="FF00000001", **testbed),
        vector("nfkc-fullwidth", "Fullwidth FQDN characters; NFKC makes it equal to testbed-ue",
               fqdn="ａｆ１.akma.example", ua_star_id="FF00000001", **testbed),
    ]
    by = {v["name"]: v for v in vectors}

    # Counterexamples: what silently goes wrong if the SBI forms are fed to the KDF.
    tb = by["testbed-ue"]
    wrong_k_akma, _ = kdf(testbed["k_ausf"], FC_KAKMA, [enc_str("AKMA"), enc_str(tb["supi"])])
    wrong_k_af, _ = kdf(bytes.fromhex(tb["k_akma"]), FC_KAF, [enc_str(tb["af_id_transport"])])
    counterexamples = [
        {"name": "supi-with-imsi-prefix", "vector": "testbed-ue",
         "wrong_input": tb["supi"], "k_akma": wrong_k_akma.hex(),
         "note": "SBI SUPI used as P1; differs from the correct k_akma"},
        {"name": "af-id-transport-as-p0", "vector": "testbed-ue",
         "wrong_input": tb["af_id_transport"], "k_af": wrong_k_af.hex(),
         "note": "AfId transport string used as P0; differs from the correct k_af"},
    ]
    assert counterexamples[0]["k_akma"] != tb["k_akma"]
    assert counterexamples[1]["k_af"] != tb["k_af"]

    equalities = [
        {"field": "k_af", "a": "nfkc-composed", "b": "nfkc-decomposed", "equal": True},
        {"field": "k_af", "a": "testbed-ue", "b": "nfkc-fullwidth", "equal": True},
        {"field": "k_akma", "a": "testbed-ue", "b": "ua-tls13", "equal": True},
        {"field": "k_af", "a": "testbed-ue", "b": "ua-tls13", "equal": False},
    ]
    for e in equalities:
        assert (by[e["a"]][e["field"]] == by[e["b"]][e["field"]]) == e["equal"], e

    doc = {
        "description": "AKMA test vectors produced by an independent Python oracle "
                       "(reference/kdf/gen_vectors.py). NOT 3GPP test vectors: "
                       "TS 33.535 V19.0.0 publishes none.",
        "implementation_choices": {
            "a_kid_default_encoding": "base64 (RFC 4648 section 4), by analogy with the GBA B-TID (TS 33.220 cl. 4.5.2)",
            "a_kid_label": "atid, as the text of TS 29.522 table 5.14.5.4.2-1; its example uses akid",
            "key_encoding_sbi": "lowercase hex, 64 characters, as Kausf in TS 29.503",
            "af_id_ua_star_case": "uppercase hex on write",
        },
        "vectors": vectors,
        "equalities": equalities,
        "counterexamples": counterexamples,
    }
    json.dump(doc, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
