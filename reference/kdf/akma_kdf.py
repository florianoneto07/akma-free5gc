import hmac, hashlib, unicodedata

def enc_str(s: str) -> bytes:
    # TS 33.220 B.2.1.2: UTF-8 + NFKC
    return unicodedata.normalize("NFKC", s).encode("utf-8")

def L(p: bytes) -> bytes:
    return len(p).to_bytes(2, "big")   # TS 33.220 B.2.0 item 1

def kdf(key: bytes, fc: int, params: list) -> tuple[bytes, bytes]:
    """Return (derived key, S)."""
    S = bytes([fc])
    for p in params:
        S += p + L(p)
    return hmac.new(key, S, hashlib.sha256).digest(), S

if __name__ == "__main__":
    # Illustrative inputs (vector "worked-example"); NOT 3GPP test vectors
    K_AUSF = bytes.fromhex("5c7c9be7bf6a1a1a2c0b0f6d4c9c2f81"
                           "9c1a3b4d5e6f708192a3b4c5d6e7f809")
    SUPI_IMSI = "208930000000003"          # TS 33.501 A.7.0 -> IMSI per TS 23.003 cl. 2.2 (no "imsi-" prefix)

    k_akma, s1 = kdf(K_AUSF, 0x80, [enc_str("AKMA"),  enc_str(SUPI_IMSI)])
    a_tid,  s2 = kdf(K_AUSF, 0x81, [enc_str("A-TID"), enc_str(SUPI_IMSI)])

    # AF_ID = FQDN || Ua* security protocol id (5 octets); private-range id 0xFF (TS 33.220 H.2)
    FQDN = "af.akma.free5gc.org"
    UA_STAR_ID = bytes.fromhex("FF00000001")
    AF_ID = enc_str(FQDN) + UA_STAR_ID
    k_af, s3 = kdf(k_akma, 0x82, [AF_ID])

    for name, S, out in (("K_AKMA", s1, k_akma), ("A-TID", s2, a_tid), ("K_AF", s3, k_af)):
        print(f"{name:7s} S = {S.hex()}")
        print(f"{'':7s} L(S) = {len(S)} octets")
        print(f"{'':7s} out = {out.hex()}  ({len(out)*8} bits)\n")
