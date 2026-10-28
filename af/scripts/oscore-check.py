#!/usr/bin/env python3
"""Independent check of the OSCORE profile of the AF (TS 33.535 Annex D).

The OSCORE client is coap-client of libcoap (-E); this script builds the
CBOR of the request (D.3.5), reads the response, and derives the security
context (D.3.3: Master Secret, Master Salt, Sender IDs) with its own code,
which shares nothing with the AF.

Usage:
  oscore-check.py --coap-client PATH --af IP:PORT --fqdn FQDN --akid A-KID
                  --kaf HEX --dir DIR [--osc-inp-alg N]

It prints the payload of the protected GET of /ua/v1/session. With
--osc-inp-alg, the request carries an OSC-INP with that AEAD algorithm, and
the script prints the answer to the POST instead. Exit code 0 when the
exchanges took place; the caller checks the output.
"""

import argparse
import base64
import hashlib
import hmac
import os
import re
import subprocess
import sys


# CBOR (RFC 8949): the items of the profile, shortest arguments.
def head(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    for ai, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * size):
            return bytes([major << 5 | ai]) + n.to_bytes(size, "big")
    raise ValueError(n)


def cbor(v):
    if isinstance(v, bool) or v is None:
        raise ValueError(v)
    if isinstance(v, int):
        return head(0, v) if v >= 0 else head(1, -1 - v)
    if isinstance(v, bytes):
        return head(2, len(v)) + v
    if isinstance(v, str):
        b = v.encode()
        return head(3, len(b)) + b
    if isinstance(v, list):
        return head(4, len(v)) + b"".join(cbor(x) for x in v)
    if isinstance(v, dict):
        items = sorted((cbor(k), cbor(x)) for k, x in v.items())
        return head(5, len(items)) + b"".join(k + x for k, x in items)
    raise ValueError(v)


def uncbor(b, i=0):
    """Decodes the item at b[i:], definite lengths only; returns (value, end)."""
    major, ai = b[i] >> 5, b[i] & 0x1F
    i += 1
    if ai < 24:
        n = ai
    elif ai <= 27:
        size = 1 << (ai - 24)
        n, i = int.from_bytes(b[i:i + size], "big"), i + size
    else:
        raise ValueError("unsupported CBOR")
    if major == 0:
        return n, i
    if major == 1:
        return -1 - n, i
    if major in (2, 3):
        s = b[i:i + n]
        return (s if major == 2 else s.decode()), i + n
    if major == 4:
        out = []
        for _ in range(n):
            x, i = uncbor(b, i)
            out.append(x)
        return out, i
    raise ValueError("unsupported CBOR")


def hkdf_sha256(ikm, salt, info, length):
    """RFC 5869 with SHA-256; an empty salt is HashLen zeros."""
    prk = hmac.new(salt or bytes(32), ikm, hashlib.sha256).digest()
    okm, t, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm, i = okm + t, i + 1
    return okm[:length]


def akid_cbor(akid):
    """A-KID = [RID, A-TID, HPLMN-ID] (D.3.5), from rid<RID>.atid<base64>@
    5gc.mnc<MNC>.mcc<MCC>.3gppnetwork.org; HPLMN-ID is MCC and MNC."""
    m = re.fullmatch(r"rid([0-9]{1,4})\.(?:atid|akid)([A-Za-z0-9+/=]+)@5gc\.mnc([0-9]{3})\.mcc([0-9]{3})"
                     r"\.3gppnetwork\.org", akid)
    if not m:
        sys.exit("oscore-check: A-KID not in the expected form")
    atid = base64.b64decode(m.group(2), validate=True)
    if len(atid) != 32:
        sys.exit("oscore-check: A-TID is not 32 octets")
    return [m.group(1), atid, m.group(4) + m.group(3)]


def coap_client(args, extra, out):
    """Runs coap-client; returns its output and the payload written to out."""
    if os.path.exists(out):
        os.remove(out)
    p = subprocess.run([args.coap_client, "-B", "10", "-O", "3," + args.fqdn, "-o", out] + extra,
                       capture_output=True, timeout=30)
    payload = open(out, "rb").read() if os.path.exists(out) else b""
    return (p.stdout + p.stderr).decode(errors="replace"), payload


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--coap-client", required=True)
    ap.add_argument("--af", required=True, help="IP:PORT of the oscore profile")
    ap.add_argument("--fqdn", required=True)
    ap.add_argument("--akid", required=True)
    ap.add_argument("--kaf", required=True, help="K_AF of <FQDN>.0100000008, 64 hexadecimal characters")
    ap.add_argument("--dir", required=True, help="directory for the files of coap-client")
    ap.add_argument("--osc-inp-alg", type=int)
    args = ap.parse_args()
    kaf = bytes.fromhex(args.kaf)
    os.makedirs(args.dir, exist_ok=True)

    n1, af_sid = os.urandom(16), os.urandom(4)
    req = [akid_cbor(args.akid), n1, af_sid]
    if args.osc_inp_alg is not None:
        req.append(cbor({4: args.osc_inp_alg}))
    req_payload = cbor(req)
    req_file = os.path.join(args.dir, "akma-request.cbor")
    with open(req_file, "wb") as f:
        f.write(req_payload)
    out, rsp_payload = coap_client(args, ["-m", "post", "-t", "60", "-f", req_file,
                                          "coap://%s/akma" % args.af], os.path.join(args.dir, "akma-response.cbor"))
    if args.osc_inp_alg is not None:
        print(out.strip(), rsp_payload.decode(errors="replace"))
        return
    try:
        (n2, ue_sid), _ = uncbor(rsp_payload)
    except (ValueError, IndexError, TypeError):
        sys.exit("oscore-check: POST /akma answered %r %r" % (out.strip(), rsp_payload))

    # D.3.3: the context of the UE.
    conf = os.path.join(args.dir, "oscore.conf")
    with open(conf, "w") as f:
        os.chmod(conf, 0o600)
        f.write('master_secret,hex,"%s"\n' % hkdf_sha256(kaf, b"", b"AKMA-OSCORE", 32).hex())
        f.write('master_salt,hex,"%s"\n' % (req_payload + rsp_payload).hex())
        f.write('sender_id,hex,"%s"\n' % ue_sid.hex())
        f.write('recipient_id,hex,"%s"\n' % af_sid.hex())
        f.write("aead_alg,integer,10\n")
        f.write("hkdf_alg,integer,-10\n")
    out, payload = coap_client(args, ["-E", conf, "-m", "get", "coap://%s/ua/v1/session" % args.af],
                               os.path.join(args.dir, "session.json"))
    os.remove(conf)
    print(out.strip(), payload.decode(errors="replace"))


if __name__ == "__main__":
    main()
