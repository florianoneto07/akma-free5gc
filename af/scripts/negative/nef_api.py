#!/usr/bin/env python3
"""Tests of the AKMA API of the NEF in operation.

Raw HTTP/1.1 requests from the AF machine, independent of the Go code of
this repository. The script registers a temporary AF at the NRF to obtain
access tokens, as the AF outside the operator network does (free5GC has no
CAPIF, so the NEF accepts tokens issued by the NRF), and deregisters it at
the end. The expected answers come from TS 29.522 cl. 4.4.23.2 and 5.14,
TS 29.122 cl. 5.2.6 and TS 33.535 cl. 6.2.2 and 6.3.

Usage: nef_api.py <NRF host:port> <NEF host:port> <AAnF host:port> <AF address> <registered A-KID>
Prints one PASS or FAIL line per test; exits 1 when any fails. No key is
printed.
"""
import http.client
import json
import sys
import urllib.parse
import uuid

AF_ID = "af1.akma.example.FF00000001"
# Accepted by the NEF and not by the AAnF (test entry of nefcfg.yaml).
AF_ID_NEF_ONLY = "af3.akma.example.FF00000001"
API = "/3gpp-akma/v1/retrieve"

failures = 0


def request(hostport, method, path, body=b"", headers=None):
    host, port = hostport.rsplit(":", 1)
    conn = http.client.HTTPConnection(host, int(port), timeout=30)
    conn.request(method, path, body=body, headers=headers or {})
    rsp = conn.getresponse()
    data = rsp.read()
    conn.close()
    return rsp.status, rsp.getheader("Content-Type") or "", data


def as_json(data):
    try:
        return json.loads(data)
    except ValueError:
        return {}


def report(tid, desc, ok, got):
    global failures
    if ok:
        print(f"PASS {tid} {desc}: {got}")
    else:
        failures += 1
        print(f"FAIL {tid} {desc}: got {got}")


class Nrf:
    """A temporary AF registered at the NRF (TS 29.510 cl. 5.2.2.2, 5.4.2.2)."""

    def __init__(self, hostport, af_ip):
        self.hostport = hostport
        self.nf_id = str(uuid.uuid4())
        profile = {"nfInstanceId": self.nf_id, "nfType": "AF", "nfStatus": "REGISTERED",
                   "ipv4Addresses": [af_ip]}
        status, _, data = request(hostport, "PUT", f"/nnrf-nfm/v1/nf-instances/{self.nf_id}",
                                  json.dumps(profile).encode(), {"Content-Type": "application/json"})
        if status not in (200, 201):
            sys.exit(f"registration at the NRF: {status} {data[:200]!r}")
        self.oauth2 = bool(as_json(data).get("customInfo", {}).get("oauth2"))

    def token(self, target, scope):
        """An access token (TS 29.510 cl. 5.4.2.2), "" without OAuth2, None if refused."""
        if not self.oauth2:
            return ""
        form = urllib.parse.urlencode({"grant_type": "client_credentials", "nfInstanceId": self.nf_id,
                                       "nfType": "AF", "targetNfType": target, "scope": scope}).encode()
        status, _, data = request(self.hostport, "POST", "/oauth2/token", form,
                                  {"Content-Type": "application/x-www-form-urlencoded"})
        if status != 200:
            return None
        return "Bearer " + as_json(data)["access_token"]

    def deregister(self):
        headers = {}
        tok = self.token("NRF", "nnrf-nfm") or ""
        if tok:
            headers["Authorization"] = tok
        request(self.hostport, "DELETE", f"/nnrf-nfm/v1/nf-instances/{self.nf_id}", headers=headers)


def retrieve(nef, token, body, content_type="application/json"):
    headers = {"Content-Type": content_type}
    if token:
        headers["Authorization"] = token
    return request(nef, "POST", API, json.dumps(body).encode(), headers)


def problem(status, ctype, data):
    pd = as_json(data)
    return f"{status} {pd.get('cause', '')} {ctype.split(';')[0]}".strip()


def main():
    if len(sys.argv) != 6:
        sys.exit(__doc__)
    nrf_hp, nef, aanf, af_ip, akid = sys.argv[1:]
    nrf = Nrf(nrf_hp, af_ip)
    try:
        run(nrf, nef, aanf, akid)
    finally:
        nrf.deregister()
    sys.exit(1 if failures else 0)


def run(nrf, nef, aanf, akid):
    token = nrf.token("NEF", "3gpp-akma")
    if token is None:
        sys.exit("the NRF refused the 3gpp-akma access token")

    # E01: K_AF through the NEF, without SUPI and GPSI (TS 33.535 cl. 6.3 step 5).
    s, ct, d = retrieve(nef, token, {"afId": AF_ID, "aKId": akid})
    rsp = as_json(d)
    ok = s == 200 and len(rsp.get("kaf", "")) == 64 and "expiry" in rsp and "supi" not in rsp and "gpsi" not in rsp
    report("E01", "K_AF through the NEF, with expiry, without supi and gpsi (TS 33.535 cl. 6.3 step 5)", ok,
           f"{s} attributes {sorted(rsp)}")

    # E02: the same K_AF as the AAnF provides directly to the AF inside the operator network.
    s2, _, d2 = request(aanf, "POST", "/naanf-akma/v1/retrieve-applicationkey",
                        json.dumps({"afId": AF_ID, "aKId": akid}).encode(), {"Content-Type": "application/json"})
    same = s == 200 and s2 == 200 and rsp.get("kaf") == as_json(d2).get("kaf")
    report("E02", "same K_AF through the NEF and from the AAnF for the same A-KID and AF_ID", same,
           "equal" if same else f"NEF {s}, AAnF {s2}, not equal")

    # E03: anonymous user access through the NEF (TS 33.535 cl. 6.2.2; TS 29.522 table 5.14.5.3.3-1 NOTE 3).
    s, _, d = retrieve(nef, token, {"afId": AF_ID, "aKId": akid, "anonInd": True})
    rsp = as_json(d)
    report("E03", "anonymous access through the NEF: K_AF without supi and gpsi",
           s == 200 and "kaf" in rsp and "supi" not in rsp and "gpsi" not in rsp, f"{s}")

    # E04: no access token: 401 from the OAuth2 middleware of the NEF (F12: no ProblemDetails).
    s, ct, d = retrieve(nef, "", {"afId": AF_ID, "aKId": akid})
    report("E04", "no access token: 401", s == 401, f"{s} {ct.split(';')[0]}")

    # E05: token of another service (naanf-akma for the AAnF): 401.
    other = nrf.token("AANF", "naanf-akma")
    if other is None:
        report("E05", "access token of another service: 401", False, "the NRF refused the naanf-akma token")
    else:
        s, ct, d = retrieve(nef, other, {"afId": AF_ID, "aKId": akid})
        report("E05", "access token of another service: 401", s == 401, f"{s}")

    # E06: AF_ID not authorized by the NEF (TS 33.535 cl. 6.3 step 2): 403 without cause.
    s, ct, d = retrieve(nef, token, {"afId": "af2.akma.example.FF00000001", "aKId": akid})
    report("E06", "AF_ID not authorized by the NEF: 403 without cause",
           s == 403 and not as_json(d).get("cause") and ct.startswith("application/problem+json"),
           problem(s, ct, d))

    # E07: AF_ID authorized by the NEF and not accepted from the NEF by the local policy of the
    # AAnF (TS 33.535 cl. 6.3 step 3, cl. 6.2.1 step 2): 403 relayed.
    s, ct, d = retrieve(nef, token, {"afId": AF_ID_NEF_ONLY, "aKId": akid})
    report("E07", "AF_ID not accepted from the NEF by the AAnF: 403 without cause",
           s == 403 and not as_json(d).get("cause"), problem(s, ct, d))

    # E08: unknown A-KID: 403 K_AKMA_NOT_PRESENT relayed (TS 29.522 cl. 4.4.23.2).
    unknown = akid.split(".atid", 1)[0] + ".atid" + "A" * 43 + "=@" + akid.split("@", 1)[1]
    s, ct, d = retrieve(nef, token, {"afId": AF_ID, "aKId": unknown})
    report("E08", "unknown A-KID: 403 K_AKMA_NOT_PRESENT relayed, never 204",
           s == 403 and as_json(d).get("cause") == "K_AKMA_NOT_PRESENT", problem(s, ct, d))

    # E09: malformed afId: 400 with invalidParams (TS 29.122 table 5.2.6-1).
    s, ct, d = retrieve(nef, token, {"afId": "af1.akma.example", "aKId": akid})
    params = [p.get("param") for p in as_json(d).get("invalidParams", [])]
    report("E09", "afId without Ua* id: 400 with invalidParams /afId", s == 400 and params == ["/afId"],
           f"{s} {params}")

    # E10: aKId missing: 400 with invalidParams.
    s, ct, d = retrieve(nef, token, {"afId": AF_ID})
    params = [p.get("param") for p in as_json(d).get("invalidParams", [])]
    report("E10", "aKId missing: 400 with invalidParams /aKId", s == 400 and params == ["/aKId"],
           f"{s} {params}")

    # E11: Content-Type text/plain: 415 (TS 29.122 table 5.2.6-1).
    s, ct, d = retrieve(nef, token, {"afId": AF_ID, "aKId": akid}, content_type="text/plain")
    report("E11", "Content-Type text/plain: 415", s == 415, problem(s, ct, d))


if __name__ == "__main__":
    main()
