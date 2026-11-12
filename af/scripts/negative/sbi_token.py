#!/usr/bin/env python3
"""Checks of the identity of the certificates in the access tokens and in the
policies, in operation (TS 33.501 cl. 13.4.1.1.2 and 13.3.1.3; TS 29.500
cl. 6.7.3; TS 33.535 cl. 6.2.1 step 2; TS 33.122 cl. 6.6), and of the Retrieve
Key Request of the NRF (TS 29.510 cl. 5.4.2.3).

At the NRF, at the AAnF and at the internal server of the CCF, with the test
certificates of make-sba-certs.sh, on the free5GC host: the NRF and the CCF are
on loopback addresses. Raw HTTP/1.1 requests over
mutual TLS, independent of the Go code of this repository, on the Python of that
machine (3.6). The script registers the NFs of the seed tool at the NRF and
deregisters them at the end.

Usage: sbi_token.py <sba-entities.conf> <directory of the certificates>
Prints one PASS or FAIL line per test; exits 1 when any fails. No key or token
is printed.
"""
import base64
import hashlib
import http.client
import json
import re
import ssl
import sys
import urllib.parse

AF_ID = "af1.akma.example.FF00000001"
AKID = "rid0000.atid" + "A" * 43 + "=@5gc.mnc093.mcc208.3gppnetwork.org"
RETRIEVE = "/naanf-akma/v1/retrieve-applicationkey"
ANCHOR_KEY_SCOPES = "naanf-akma naanf-akma:anchorkey"
UNKNOWN_INVOKER = "0b4a3c2d-1e0f-4a5b-8c7d-6e5f4a3b2c1d"

failures = 0


def report(tid, desc, ok, got):
    global failures
    if ok:
        print(f"PASS {tid} {desc}: {got}")
    else:
        failures += 1
        print(f"FAIL {tid} {desc}: got {got}")


def entities(path):
    found = {}
    with open(path) as f:
        for line in f:
            fields = line.split()
            if len(fields) == 7 and fields[0] in ("nf", "client", "ccf"):
                found[fields[1]] = {"type": fields[2], "fqdn": fields[3], "port": fields[5], "id": fields[6]}
    return found


def as_json(data):
    try:
        return json.loads(data)
    except ValueError:
        return {}


def params(data):
    return [p.get("param") for p in as_json(data).get("invalidParams", [])]


class Client:
    """A TLS client of the SBI, with the certificate of an entity."""

    def __init__(self, all_entities, certs, name):
        self.entity = all_entities[name]
        self.id, self.type = self.entity["id"], self.entity["type"]
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.ctx.load_verify_locations(f"{certs}/sba-ca.pem")
        self.ctx.load_cert_chain(f"{certs}/{name}.pem", f"{certs}/{name}.key")

    def request(self, server, method, path, body=b"", headers=None):
        conn = http.client.HTTPSConnection(server["fqdn"], int(server["port"]), context=self.ctx, timeout=30)
        conn.request(method, path, body=body, headers=headers or {})
        rsp = conn.getresponse()
        data = rsp.read()
        conn.close()
        return rsp.status, {k.lower(): v for k, v in rsp.getheaders()}, data


class Nrf:
    def __init__(self, server):
        self.server = server

    def register(self, client, nf_id=None, nf_type=None):
        nf_id = nf_id or client.id
        profile = {"nfInstanceId": nf_id, "nfType": nf_type or client.type, "nfStatus": "REGISTERED"}
        return client.request(self.server, "PUT", f"/nnrf-nfm/v1/nf-instances/{nf_id}", json.dumps(profile).encode(),
                              {"Content-Type": "application/json"})

    def token(self, client, target, scope, nf_id=None, nf_type=None, **extra):
        form = {"grant_type": "client_credentials", "nfInstanceId": nf_id or client.id,
                "nfType": nf_type or client.type, "targetNfType": target, "scope": scope}
        form.update(extra)
        return client.request(self.server, "POST", "/oauth2/token", urllib.parse.urlencode(form).encode(),
                              {"Content-Type": "application/x-www-form-urlencoded"})

    def access_token(self, client, target, scope):
        s, _, d = self.token(client, target, scope)
        if s != 200:
            raise SystemExit(f"access token of {client.id} for {scope}: {s} {d[:120]!r}")
        return as_json(d)["access_token"]

    def deregister(self, client):
        bearer = "Bearer " + self.access_token(client, "NRF", "nnrf-nfm")
        client.request(self.server, "DELETE", f"/nnrf-nfm/v1/nf-instances/{client.id}",
                       headers={"Authorization": bearer})


def part(jws, index):
    field = jws.split(".")[index]
    return json.loads(base64.urlsafe_b64decode(field + "=" * (-len(field) % 4)))


def multipart_parts(content_type, data):
    """The body parts of a multipart/related answer as (headers, body), and
    its "type" parameter. Parsed by hand: the certificate is binary."""
    params = {}
    for p in content_type.split(";")[1:]:
        k, _, v = p.strip().partition("=")
        params[k.lower()] = v.strip('"')
    if not content_type.startswith("multipart/related") or "boundary" not in params:
        return [], ""
    delim = b"\r\n--" + params["boundary"].encode()
    parts = []
    for seg in (b"\r\n" + data).split(delim)[1:]:
        if seg.startswith(b"--"):
            break
        head, _, body = seg[2:].partition(b"\r\n\r\n")
        headers = {}
        for line in head.split(b"\r\n"):
            k, _, v = line.decode("latin-1").partition(":")
            headers[k.strip().lower()] = v.strip()
        parts.append((headers, body))
    return parts, params.get("type", "")


def key_of(content_type, data):
    """The certificate of a RetrieveKeyRsp in multipart (TS 29.510 cl. 6.3.3.4
    and 6.3.5.5.2): the JSON root part first, with x509Cert, and the binary
    part application/pkix-cert with that Content-ID."""
    parts, root_type = multipart_parts(content_type, data)
    if len(parts) != 2 or root_type != "application/json":
        return None, f"{content_type.split(';')[0]}, {len(parts)} parts, type {root_type!r}"
    (root_h, root), (bin_h, der) = parts
    ref = as_json(root).get("x509Cert", {}).get("contentId", "")
    if root_h.get("content-type") != "application/json" or bin_h.get("content-type") != "application/pkix-cert" \
            or not ref or bin_h.get("content-id") != ref:
        return None, f"parts {root_h.get('content-type')} and {bin_h.get('content-type')}, contentId {ref!r}"
    return der, "multipart/related with application/pkix-cert"


def retrieve_key(client, nrf, issuer, header_parameters):
    body = json.dumps({"issuer": issuer, "headerParameters": header_parameters}).encode()
    return client.request(nrf.server, "POST", "/oauth2/retrieve-key", body, {"Content-Type": "application/json"})


def der_of(path):
    with open(path) as f:
        pem = f.read()
    return ssl.PEM_cert_to_DER_cert(re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----\n?", pem, re.S)[0])


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    all_entities = entities(sys.argv[1])
    certs = sys.argv[2]
    ausf = Client(all_entities, certs, "seed-ausf")
    af = Client(all_entities, certs, "seed-af")
    nrf = Nrf(all_entities["nrf"])
    for client in (ausf, af):
        s, _, d = nrf.register(client)
        if s not in (200, 201):
            sys.exit(f"registration of {client.id} at the NRF: {s} {d[:120]!r}")
    try:
        run(all_entities, certs, nrf, ausf, af)
    finally:
        nrf.deregister(ausf)
        nrf.deregister(af)
    sys.exit(1 if failures else 0)


def run(all_entities, certs, nrf, ausf, af):
    aanf = all_entities["aanf"]
    json_type = {"Content-Type": "application/json"}

    # S10: the request of the NF of another certificate (TS 29.510 cl. 5.4.2.2.1; TS 33.501 cl. 13.4.1.1.2 step 2).
    for tid, desc, kwargs in [
        ("S10.id", "token with the NF Instance ID of another certificate", {"nf_id": ausf.id}),
        ("S10.type", "token with the NF type of another certificate", {"nf_type": ausf.type}),
        ("S10.plmn", "token with the PLMN of another certificate",
         {"requesterPlmn": json.dumps({"mcc": "208", "mnc": "94"})}),
    ]:
        s, h, d = nrf.token(af, "AANF", "naanf-akma", **kwargs)
        got = as_json(d).get("error")
        report(tid, f"{desc}: 400 invalid_client, no-store",
               s == 400 and got == "invalid_client" and h.get("cache-control") == "no-store"
               and h.get("pragma") == "no-cache", f"{s} {got}")
    s, _, d = nrf.register(af, nf_id=ausf.id, nf_type=af.type)
    report("S10.register", "registration with the UUID of another certificate: 403 without cause",
           s == 403 and not as_json(d).get("cause"), f"{s}")
    s, _, d = nrf.register(af, nf_type=ausf.type)
    report("S10.register-type", "registration with the NF type of another certificate: 403 without cause",
           s == 403 and not as_json(d).get("cause"), f"{s}")
    bearer = "Bearer " + nrf.access_token(af, "NRF", "nnrf-disc")
    s, _, d = af.request(nrf.server, "GET", "/nnrf-disc/v1/nf-instances?target-nf-type=AANF&requester-nf-type=AMF",
                         headers={"Authorization": bearer})
    report("S10.discovery", "discovery with the requester type of another certificate: 403 without cause",
           s == 403 and not as_json(d).get("cause"), f"{s}")

    # S11: the token of another NF (TS 33.501 cl. 13.4.1.1.2: sub).
    token = nrf.access_token(ausf, "AANF", ANCHOR_KEY_SCOPES)
    body = json.dumps({"supi": "imsi-208930000000099", "aKId": AKID, "kAkma": "0" * 64}).encode()
    s, h, d = af.request(aanf, "POST", "/naanf-akma/v1/register-anchorkey", body,
                         dict(json_type, Authorization="Bearer " + token))
    got = as_json(d).get("cause")
    report("S11", "token of seed-ausf with the certificate of seed-af at the AAnF: 403 ACCESS_TOKEN_CLAIM_MISMATCH of sub",
           s == 403 and got == "ACCESS_TOKEN_CLAIM_MISMATCH" and params(d) == ["sub"]
           and 'error="invalid_token"' in h.get("www-authenticate", ""), f"{s} {got} {params(d)}")

    # S12: the token of another producer (aud).
    other = nrf.access_token(ausf, "UDM", "nudm-ueau")
    s, _, d = ausf.request(aanf, "POST", "/naanf-akma/v1/register-anchorkey", body,
                           dict(json_type, Authorization="Bearer " + other))
    got = as_json(d).get("cause")
    report("S12", "token for another type of producer at the AAnF: 403 ACCESS_TOKEN_CLAIM_MISMATCH of aud",
           s == 403 and got == "ACCESS_TOKEN_CLAIM_MISMATCH" and params(d) == ["aud"], f"{s} {got} {params(d)}")

    # S13: the JWS profile (TS 33.210 cl. 6.3.3.1 and 6.3.3.4) and iss (TS 29.510 table 6.3.5.2.4-1).
    header, claims = part(token, 0), part(token, 1)
    x5t = base64.urlsafe_b64encode(hashlib.sha256(der_of(f"{certs}/nrf-token.pem")).digest()).rstrip(b"=").decode()
    ok = (header.get("alg") == "ES256" and header.get("kid") and header.get("x5t#S256") == x5t
          and claims.get("iss") == all_entities["nrf"]["id"] and claims.get("sub") == ausf.id
          and claims.get("aud") == "AANF" and claims.get("scope") == ANCHOR_KEY_SCOPES)
    report("S13", "token of the NRF: ES256, kid, x5t#S256 of its certificate; iss, the UUID of the NRF", ok,
           f"alg {header.get('alg')}, header {sorted(header)}, claims {sorted(claims)}")

    # G01 to G04: the Retrieve Key Request (TS 29.510 cl. 5.4.2.3 and 6.3.4.3; TS 33.501 cl. 14.3.3; F28).
    nrf_id = all_entities["nrf"]["id"]
    signing = der_of(f"{certs}/nrf-token.pem")
    s, h, d = retrieve_key(af, nrf, nrf_id, {"x5t#S256": x5t, "alg": "ES256"})
    der, got = key_of(h.get("content-type", ""), d)
    report("G01", "retrieve-key with the x5t#S256 of a token: 200, the signing certificate in DER, in multipart",
           s == 200 and der == signing, f"{s} {got}")
    s, h, d = retrieve_key(af, nrf, nrf_id, {"kid": header.get("kid", "")})
    der, got = key_of(h.get("content-type", ""), d)
    report("G01.kid", "retrieve-key with the kid of a token: 200, the same certificate", s == 200 and der == signing,
           f"{s} {got}")
    s, _, d = retrieve_key(af, nrf, nrf_id, {"kid": "not-the-key-of-the-nrf"})
    got = as_json(d).get("cause")
    report("G02", "a kid that is not the one of the NRF: 400 KEY_IDENTIFICATION_FAIL (table 6.3.4.3.2-2)",
           s == 400 and got == "KEY_IDENTIFICATION_FAIL", f"{s} {got}")
    s, _, d = retrieve_key(af, nrf, UNKNOWN_INVOKER, {"x5t#S256": x5t})
    got = as_json(d).get("cause")
    report("G03", "an issuer that is not the NRF: 404 UNKNOWN_ISSUER (table 6.3.4.3.2-2)",
           s == 404 and got == "UNKNOWN_ISSUER", f"{s} {got}")
    s, _, _ = af.request(nrf.server, "POST", "/oauth2/retrieve-key", b"issuer=" + nrf_id.encode(),
                         {"Content-Type": "application/x-www-form-urlencoded"})
    report("G04", "a body that is not JSON: 415 (cl. 6.3.3.2.2)", s == 415, f"{s}")

    # S14: the scopes per NF type (TS 29.510 table 6.1.6.2.3-1 NOTE 11; TS 29.535 table 5.1.9-1).
    s, _, d = nrf.token(ausf, "AANF", "naanf-akma naanf-akma:applicationkeyget")
    got = as_json(d).get("error")
    report("S14.grant", "the AUSF asks for naanf-akma:applicationkeyget: 400 invalid_scope",
           s == 400 and got == "invalid_scope", f"{s} {got}")
    only_service = nrf.access_token(af, "AANF", "naanf-akma")
    body = json.dumps({"afId": AF_ID, "aKId": AKID}).encode()
    s, h, _ = af.request(aanf, "POST", RETRIEVE, body, dict(json_type, Authorization="Bearer " + only_service))
    challenge = h.get("www-authenticate", "")
    report("S14.use", "retrieve with a token only of naanf-akma: 403 insufficient_scope",
           s == 403 and 'error="insufficient_scope"' in challenge
           and 'scope="naanf-akma:applicationkeyget"' in challenge, f"{s} {challenge}")

    # S15: the AF is the NF instance of its certificate (TS 33.501 cl. 13.1.0; TS 33.535 cl. 6.2.1 step 2).
    other_af = Client(all_entities, certs, "af2")
    af1 = Client(all_entities, certs, "af1")
    s, _, d = other_af.request(aanf, "POST", RETRIEVE, body, json_type)
    got = as_json(d).get("cause")
    report("S15", "retrieve with the certificate af2 and the AF_ID of af1: 403 without cause", s == 403 and not got,
           f"{s} {got}")
    s, _, d = af1.request(aanf, "POST", RETRIEVE, body, json_type)
    got = as_json(d).get("cause")
    report("S15.af1", "the same with the certificate af1: past the policy, 403 K_AKMA_NOT_PRESENT",
           s == 403 and got == "K_AKMA_NOT_PRESENT", f"{s} {got}")

    # S17: the internal server of the CCF, CAPIF-3/4 (TS 33.122 cl. 6.6): only the API provider of the
    # certificate publishes and asks for the data of an API invoker.
    ccf = all_entities["ccf-internal"]
    published = "/published-apis/v1/nef-apf/service-apis"
    invoker = "/capif-security/v1/trustedInvokers/" + UNKNOWN_INVOKER + "?authenticationInfo=true"
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(f"{certs}/sba-ca.pem")
    try:
        conn = http.client.HTTPSConnection(ccf["fqdn"], int(ccf["port"]), context=ctx, timeout=30)
        conn.request("POST", published, body=b"{}", headers=json_type)
        s = conn.getresponse().status
        conn.close()
        ok, got = False, f"HTTP {s}"
    except (ssl.SSLError, OSError, http.client.HTTPException) as e:
        ok, got = True, type(e).__name__
    report("S17.none", "internal server of the CCF without a client certificate: refused in TLS", ok, got)
    s, _, d = af.request(ccf, "POST", published, b"{}", json_type)
    s2, _, _ = af.request(ccf, "GET", invoker)
    report("S17.other", "publication and data of an API invoker with the certificate of another NF: 403",
           s == 403 and s2 == 403, f"{s} {s2} {as_json(d).get('detail', '')}")
    nef = Client(all_entities, certs, "nef")
    s, _, _ = nef.request(ccf, "GET", invoker)
    report("S17.nef", "data of an API invoker with the certificate of the NEF: past the certificate, 404", s == 404, f"{s}")


if __name__ == "__main__":
    main()
