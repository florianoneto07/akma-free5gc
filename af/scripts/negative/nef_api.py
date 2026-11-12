#!/usr/bin/env python3
"""Tests of the AKMA API of the NEF in operation.

Raw HTTP/1.1 requests over mutual TLS from the AF machine, independent of
the Go code of this repository. The script onboards as an API invoker of the
CAPIF core function, as the AF outside the operator network does, with the
functions of capif_api.py, obtains an access token and offboards at the end.
The expected answers come from TS 29.522 cl. 4.4.23.2 and 5.14, TS 29.122
cl. 5.2.6 and TS 33.535 cl. 6.2.2 and 6.3.

Usage: nef_api.py <CCF host:port> <CA of the CCF> <onboarding credential file>
                  <NEF host:port> <AAnF host:port> <registered A-KID>
                  <directory of the certificates of the SBI>
                  <file with an access token of the NRF for 3gpp-akma>
                  [<registered A-KID with the default Routing Indicator, "0">]
Prints one PASS or FAIL line per test; exits 1 when any fails. No key,
secret, credential or token is printed.
"""
import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import capif_api
from capif_api import Invoker, aanf_tls, as_json, report, tls_request

AF_ID = "af1.akma.example.FF00000001"
# Accepted by the NEF and the CCF, and not by the AAnF (test entries of
# nefcfg.yaml and ccfcfg.yaml).
AF_ID_NEF_ONLY = "af5.akma.example.FF00000001"
API = "/3gpp-akma/v1/retrieve"


def retrieve(ctx, nef, token, body, content_type="application/json"):
    headers = {"Content-Type": content_type}
    if token:
        headers["Authorization"] = "Bearer " + token
    s, h, d = tls_request(ctx, nef, "POST", API, json.dumps(body).encode(), headers)
    return s, h.get("content-type", ""), d


def problem(status, ctype, data):
    pd = as_json(data)
    return f"{status} {pd.get('cause', '')} {ctype.split(';')[0]}".strip()


def main():
    if len(sys.argv) not in (9, 10):
        sys.exit(__doc__)
    ccf, ca, cred_file, nef, aanf, akid, sba, nrf_file = sys.argv[1:9]
    akid0 = sys.argv[9] if len(sys.argv) == 10 else ""
    with open(cred_file) as f:
        credential = f.read().strip()
    with open(nrf_file) as f:
        nrf_token = f.read().strip()
    workdir = tempfile.mkdtemp(prefix="nef-api-")
    inv = Invoker(ccf, ca, workdir)
    try:
        run(inv, credential, nef, aanf, akid, sba, nrf_token, akid0)
    finally:
        if inv.id and inv.secret:
            inv.offboard()
        shutil.rmtree(workdir, ignore_errors=True)
    sys.exit(1 if capif_api.failures else 0)


def run(inv, credential, nef, aanf, akid, sba, nrf_token, akid0):
    s, _ = inv.enrol(credential)
    if s != 201:
        report("E00.onboarding", "onboarding of the API invoker of the test", False, f"{s}")
        return
    s, _, _ = inv.security_method()
    ctx = inv.nef_tls(sba)
    s2, _, _ = inv.check_authentication(ctx, nef)
    s3, _, d = inv.token(inv.token_form())
    token = as_json(d).get("access_token", "")
    if not token:
        report("E00.token", "access token of the CCF", False, f"security method {s}, check {s2}, token {s3}")
        return

    # E01: K_AF through the NEF, without SUPI and GPSI (TS 33.535 cl. 6.3 step 5).
    s, ct, d = retrieve(ctx, nef, token, {"afId": AF_ID, "aKId": akid})
    rsp = as_json(d)
    ok = s == 200 and len(rsp.get("kaf", "")) == 64 and "expiry" in rsp and "supi" not in rsp and "gpsi" not in rsp
    report("E01", "K_AF through the NEF, with expiry, without supi and gpsi (TS 33.535 cl. 6.3 step 5)", ok,
           f"{s} attributes {sorted(rsp)}")

    # E02: the same K_AF as the AAnF provides directly to the AF inside the operator network.
    s2, _, d2 = tls_request(aanf_tls(sba), aanf, "POST", "/naanf-akma/v1/retrieve-applicationkey",
                            json.dumps({"afId": AF_ID, "aKId": akid}).encode(), {"Content-Type": "application/json"})
    same = s == 200 and s2 == 200 and rsp.get("kaf") == as_json(d2).get("kaf")
    report("E02", "same K_AF through the NEF and from the AAnF for the same A-KID and AF_ID", same,
           "equal" if same else f"NEF {s}, AAnF {s2}, not equal")

    # E03: anonymous user access through the NEF (TS 33.535 cl. 6.2.2; TS 29.522 table 5.14.5.3.3-1 NOTE 3).
    s, _, d = retrieve(ctx, nef, token, {"afId": AF_ID, "aKId": akid, "anonInd": True})
    rsp = as_json(d)
    report("E03", "anonymous access through the NEF: K_AF without supi and gpsi",
           s == 200 and "kaf" in rsp and "supi" not in rsp and "gpsi" not in rsp, f"{s}")

    # E04: no access token: 401, as TS 29.500 cl. 6.7.3 says.
    s, ct, d = retrieve(ctx, nef, "", {"afId": AF_ID, "aKId": akid})
    report("E04", "no access token: 401 with ProblemDetails",
           s == 401 and ct.startswith("application/problem+json"), f"{s} {ct.split(';')[0]}")

    # E05, S16.nrf: token of the NRF for this API: with CAPIF, only the tokens of the CCF count
    # (TS 29.522 cl. 7.2; RFC 6750 cl. 3.1).
    desc = "access token of the NRF for 3gpp-akma: 401 invalid_token"
    if not nrf_token:
        report("E05", desc, False, "no 3gpp-akma token of the NRF")
    else:
        s, h, _ = capif_api.retrieve(ctx, nef, nrf_token, {"afId": AF_ID, "aKId": akid})
        challenge = h.get("www-authenticate", "")
        ok = s == 401 and 'error="invalid_token"' in challenge
        report("E05", desc, ok, f"{s} {challenge}")
        report("S16.nrf", desc, ok, f"{s} {challenge}")

    # E06: AF_ID not authorized by the NEF (TS 33.535 cl. 6.3 step 2): 403 without cause.
    s, ct, d = retrieve(ctx, nef, token, {"afId": "af2.akma.example.FF00000001", "aKId": akid})
    report("E06", "AF_ID not authorized by the NEF: 403 without cause",
           s == 403 and not as_json(d).get("cause") and ct.startswith("application/problem+json"),
           problem(s, ct, d))

    # E07: AF_ID authorized by the NEF and not accepted from the NEF by the local policy of the
    # AAnF (TS 33.535 cl. 6.3 step 3, cl. 6.2.1 step 2): 403 relayed.
    s, ct, d = retrieve(ctx, nef, token, {"afId": AF_ID_NEF_ONLY, "aKId": akid})
    report("E07", "AF_ID not accepted from the NEF by the AAnF: 403 without cause",
           s == 403 and not as_json(d).get("cause"), problem(s, ct, d))

    # E08: unknown A-KID: 403 K_AKMA_NOT_PRESENT relayed (TS 29.522 cl. 4.4.23.2).
    unknown = akid.split(".atid", 1)[0] + ".atid" + "A" * 43 + "=@" + akid.split("@", 1)[1]
    s, ct, d = retrieve(ctx, nef, token, {"afId": AF_ID, "aKId": unknown})
    report("E08", "unknown A-KID: 403 K_AKMA_NOT_PRESENT relayed, never 204",
           s == 403 and as_json(d).get("cause") == "K_AKMA_NOT_PRESENT", problem(s, ct, d))

    # E09: malformed afId: 400 with invalidParams (TS 29.122 table 5.2.6-1).
    s, ct, d = retrieve(ctx, nef, token, {"afId": "af1.akma.example", "aKId": akid})
    params = [p.get("param") for p in as_json(d).get("invalidParams", [])]
    report("E09", "afId without Ua* id: 400 with invalidParams /afId", s == 400 and params == ["/afId"],
           f"{s} {params}")

    # E10: aKId missing: 400 with invalidParams.
    s, ct, d = retrieve(ctx, nef, token, {"afId": AF_ID})
    params = [p.get("param") for p in as_json(d).get("invalidParams", [])]
    report("E10", "aKId missing: 400 with invalidParams /aKId", s == 400 and params == ["/aKId"],
           f"{s} {params}")

    # E11: Content-Type text/plain: 415 (TS 29.122 table 5.2.6-1).
    s, ct, d = retrieve(ctx, nef, token, {"afId": AF_ID, "aKId": akid}, content_type="text/plain")
    report("E11", "Content-Type text/plain: 415", s == 415, problem(s, ct, d))

    # With the default Routing Indicator, "0" (TS 23.003 cl. 2.2B), the NEF selects any
    # AAnF of the home network (TS 33.535 cl. 6.7).
    if akid0:
        s, ct, d = retrieve(ctx, nef, token, {"afId": AF_ID, "aKId": akid0})
        report("G10", "A-KID with the default Routing Indicator \"0\": K_AF through the NEF (TS 33.535 cl. 6.7)",
               s == 200 and len(as_json(d).get("kaf", "")) == 64, problem(s, ct, d) if s != 200 else "200")


if __name__ == "__main__":
    main()
