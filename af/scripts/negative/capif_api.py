#!/usr/bin/env python3
"""Tests of CAPIF in operation: the CAPIF core function and the NEF as API
exposing function.

A second API invoker, independent of the Go code of this repository: raw
HTTP/1.1 requests over mutual TLS (module ssl), at the CAPIF core function and
at the NEF with the certificate of the onboarding, and the OpenSSL command line for its
key pair. It onboards with the onboarding credential, discovers the AKMA
API, obtains the security method and an access token, requests K_AF through
the NEF with the token, and offboards at the end. A third API invoker checks
that the access token and the certificate are of the same API invoker. The
expected answers come from TS 29.222 cl. 5.2, 5.5, 5.6 and 6.2.2.2, TS 33.122
cl. 6.1, 6.3, 6.5.2.3, 6.8 and Annex C, TS 33.310 cl. 6.3.1, TS 29.522 cl. 7.2
and TS 33.535 cl. 6.3.

Usage: capif_api.py <CCF host:port> <CA of the CCF> <onboarding credential file>
                    <NEF host:port> <AAnF host:port> <registered A-KID> <API invoker ID of the AF>
                    <directory of the certificates of the SBI>
Prints one PASS or FAIL line per test; exits 1 when any fails. No key,
secret, credential or token is printed.
"""
import base64
import http.client
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.parse
import uuid

AF_ID = "af1.akma.example.FF00000001"
# In the policy of the NEF, outside the profile of the API invoker.
AF_ID_OUTSIDE_PROFILE = "af3.akma.example.FF00000001"
# In the profile of the API invoker, outside the policy of the NEF.
AF_ID_OUTSIDE_POLICY = "af4.akma.example.FF00000001"
AEF_ID = "nef-aef"
SCOPE = "3gpp#nef-aef:3gpp-akma"
NOTIFY = "https://192.168.16.129/capif/notify"
# capif.invokerCrlMaxAge of nefcfg.yaml, plus a margin: how long the NEF may
# still use the CRL it fetched before an API invoker offboarded.
CRL_WAIT = 7

failures = 0


def report(tid, desc, ok, got):
    global failures
    if ok:
        print(f"PASS {tid} {desc}: {got}")
    else:
        failures += 1
        print(f"FAIL {tid} {desc}: got {got}")


def as_json(data):
    try:
        return json.loads(data)
    except ValueError:
        return {}


def split(hostport):
    host, port = hostport.rsplit(":", 1)
    return host, int(port)


def tls_request(ctx, hostport, method, path, body=b"", headers=None):
    conn = http.client.HTTPSConnection(*split(hostport), context=ctx, timeout=30)
    conn.request(method, path, body=body, headers=headers or {})
    rsp = conn.getresponse()
    data = rsp.read()
    conn.close()
    return rsp.status, {k.lower(): v for k, v in rsp.getheaders()}, data


def refused(call):
    """Whether a request is refused in TLS: an alert, and no HTTP answer."""
    try:
        s = call()[0]
    except (ssl.SSLError, OSError, http.client.HTTPException) as e:
        return True, type(e).__name__
    return False, f"HTTP {s}"


def openssl(*args, data=None):
    return subprocess.run(["openssl", *args], input=data, capture_output=True, text=True)


class Invoker:
    """The API invoker: its key pair, certificate and onboarding secret."""

    def __init__(self, ccf, ca, workdir):
        self.ccf, self.ca, self.dir = ccf, ca, workdir
        self.key = os.path.join(workdir, "invoker.key")
        self.cert = os.path.join(workdir, "invoker.pem")
        self.id = ""
        self.secret = ""
        if openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", self.key).returncode:
            sys.exit("openssl genpkey failed")
        os.chmod(self.key, 0o600)
        self.public_key = openssl("pkey", "-in", self.key, "-pubout").stdout

    def request(self, method, path, body=b"", headers=None, cert=True):
        """CAPIF-1e: TLS with the CA of the CCF, and the client certificate when cert."""
        ctx = ssl.create_default_context(cafile=self.ca)
        if cert:
            ctx.load_cert_chain(self.cert, self.key)
        conn = http.client.HTTPSConnection(*split(self.ccf), context=ctx, timeout=30)
        conn.request(method, path, body=body, headers=headers or {})
        rsp = conn.getresponse()
        data = rsp.read()
        conn.close()
        return rsp.status, {k.lower(): v for k, v in rsp.getheaders()}, data

    def nef_tls(self, sba):
        """CAPIF-2e: the CA of the operator, and the certificate of the onboarding
        (TS 33.122 cl. 6.5.2.3 step 5)."""
        ctx = ssl.create_default_context(cafile=f"{sba}/sba-ca.pem")
        ctx.load_cert_chain(self.cert, self.key)
        return ctx

    def onboard(self, credential):
        headers = {"Content-Type": "application/json"}
        if credential:
            headers["Authorization"] = "Bearer " + credential
        body = {"onboardingInformation": {"apiInvokerPublicKey": self.public_key},
                "notificationDestination": NOTIFY, "apiInvokerInformation": "capif_api.py",
                "supportedFeatures": "0"}
        return self.request("POST", "/api-invoker-management/v1/onboardedInvokers", json.dumps(body).encode(),
                            headers, cert=False)

    def enrol(self, credential):
        """Onboarding (TS 33.122 cl. 6.1): keeps the identifier, the secret and the certificate."""
        s, h, d = self.onboard(credential)
        rsp = as_json(d)
        info = rsp.get("onboardingInformation", {})
        self.id, self.secret = rsp.get("apiInvokerId", ""), info.get("onboardingSecret", "")
        with open(self.cert, "w") as f:
            f.write(info.get("apiInvokerCertificate", ""))
        return s, h

    def security_method(self):
        """OAUTH at the NEF (TS 29.222 cl. 5.6.2.2)."""
        body = {"securityInfo": [{"aefId": AEF_ID, "prefSecurityMethods": ["OAUTH"]}],
                "notificationDestination": NOTIFY}
        return self.request("PUT", f"/capif-security/v1/trustedInvokers/{self.id}", json.dumps(body).encode(),
                            {"Content-Type": "application/json"})

    def check_authentication(self, ctx, nef):
        """check-authentication at the NEF (TS 29.222 cl. 6.2.2.2; TS 33.122 cl. 6.5.2.3 step 5)."""
        return tls_request(ctx, nef, "POST", "/aef-security/v1/check-authentication",
                           json.dumps({"apiInvokerId": self.id, "supportedFeatures": "0"}).encode(),
                           {"Content-Type": "application/json"})

    def token(self, form):
        return self.request("POST", f"/capif-security/v1/securities/{self.id}/token",
                            urllib.parse.urlencode(form).encode(),
                            {"Content-Type": "application/x-www-form-urlencoded"})

    def token_form(self, **change):
        form = {"grant_type": "client_credentials", "client_id": self.id, "client_secret": self.secret,
                "scope": SCOPE}
        form.update(change)
        return form

    def offboard(self):
        return self.request("DELETE", f"/api-invoker-management/v1/onboardedInvokers/{self.id}")


def tamper(jws):
    """The JWS with a character of its signature changed: the one before the
    last, because the low bits of the last one are padding, which decoders ignore."""
    i = len(jws) - 2
    return jws[:i] + ("A" if jws[i] != "A" else "B") + jws[i + 1:]


def claims(jws):
    payload = jws.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def aanf_tls(sba):
    """The AF inside the operator network: the certificate of af1 (TS 33.501 cl. 13.1.0)."""
    ctx = ssl.create_default_context(cafile=f"{sba}/sba-ca.pem")
    ctx.load_cert_chain(f"{sba}/af1.pem", f"{sba}/af1.key")
    return ctx


def retrieve(ctx, nef, token, body):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    return tls_request(ctx, nef, "POST", "/3gpp-akma/v1/retrieve", json.dumps(body).encode(), headers)


def main():
    if len(sys.argv) != 9:
        sys.exit(__doc__)
    ccf, ca, cred_file, nef, aanf, akid, af_invoker, sba = sys.argv[1:]
    with open(cred_file) as f:
        credential = f.read().strip()
    workdir = tempfile.mkdtemp(prefix="capif-api-")
    otherdir = tempfile.mkdtemp(prefix="capif-api-")
    inv = Invoker(ccf, ca, workdir)
    other = Invoker(ccf, ca, otherdir)
    try:
        run(inv, other, credential, nef, aanf, akid, af_invoker or str(uuid.uuid4()), sba)
    finally:
        for i in (inv, other):
            if i.id and i.secret:
                i.offboard()
        shutil.rmtree(workdir, ignore_errors=True)
        shutil.rmtree(otherdir, ignore_errors=True)
    sys.exit(1 if failures else 0)


def run(inv, other, credential, nef, aanf, akid, af_invoker, sba):
    # CP08: onboarding without the credential, and with a tampered one
    # (TS 29.222 cl. 5.5.2.2.2 NOTE 4; RFC 6750 cl. 3).
    s1, h1, _ = inv.onboard("")
    s2, h2, _ = inv.onboard(tamper(credential))
    ok = (s1 == 401 and h1.get("www-authenticate", "").startswith("Bearer") and s2 == 401
          and 'error="invalid_token"' in h2.get("www-authenticate", ""))
    report("CP08", "onboarding without credential and with a tampered one: 401 with WWW-Authenticate Bearer", ok,
           f"{s1} {h1.get('www-authenticate', '')!r}, {s2} {h2.get('www-authenticate', '')!r}")

    # CP01: onboarding (TS 33.122 cl. 6.1): the certificate of the API invoker, CN = its identifier
    # (TS 29.222 table 8.4.4.2.5-1), issued by the CA of the CCF.
    s, h = inv.enrol(credential)
    subject = openssl("x509", "-in", inv.cert, "-noout", "-subject", "-nameopt", "multiline").stdout
    verify = openssl("verify", "-CAfile", inv.ca, inv.cert).stdout.strip()
    ok = (s == 201 and h.get("location", "").endswith("/api-invoker-management/v1/onboardedInvokers/" + inv.id)
          and inv.id != "" and f"commonName                = {inv.id}" in subject and verify.endswith(": OK"))
    report("CP01", "onboarding: 201 and Location; certificate with CN = API invoker ID, issued by the CA of the CCF",
           ok, f"{s} invoker {inv.id}, verify {verify.rsplit(':', 1)[-1].strip()}")
    if s != 201:
        return

    query = "/service-apis/v1/allServiceAPIs?" + urllib.parse.urlencode(
        {"api-invoker-id": inv.id, "api-name": "3gpp-akma", "api-version": "v1"})
    # CP09, CP10: discovery without the client certificate, and for another API invoker
    # (TS 33.122 cl. 6.3.1.1).
    s, _, _ = inv.request("GET", query, cert=False)
    report("CP09", "discovery without client certificate: 403", s == 403, f"{s}")
    s, _, _ = inv.request("GET", query.replace(inv.id, af_invoker))
    report("CP10", "discovery with the api-invoker-id of the AF of the repository: 403", s == 403, f"{s}")

    # CP02: discovery of the AKMA API (TS 29.222 cl. 5.2.2.2).
    s, _, d = inv.request("GET", query)
    api_root, methods = "", []
    for api in as_json(d).get("serviceAPIDescriptions", []):
        for p in api.get("aefProfiles", []):
            if p.get("aefId") == AEF_ID and p.get("interfaceDescriptions"):
                i = p["interfaceDescriptions"][0]
                api_root = f"https://{i.get('fqdn')}:{i.get('port')}"
                methods = i.get("securityMethods") or p.get("securityMethods")
    report("CP02", f"discovery: apiRoot https://{nef}, aefId {AEF_ID}, securityMethods [OAUTH]",
           s == 200 and api_root == f"https://{nef}" and methods == ["OAUTH"], f"{s} {api_root} {methods}")

    # CP03: security method (TS 29.222 cl. 5.6.2.2).
    s, _, d = inv.security_method()
    sel = [i.get("selSecurityMethod") for i in as_json(d).get("securityInfo", [])]
    report("CP03", "security method: 201, selSecurityMethod OAUTH", s == 201 and sel == ["OAUTH"], f"{s} {sel}")

    # CP04: check-authentication at the NEF (TS 29.222 cl. 6.2.2.2; TS 33.122 cl. 6.5.2.3 step 5).
    ctx = inv.nef_tls(sba)
    s, _, d = inv.check_authentication(ctx, nef)
    report("CP04", "check-authentication at the NEF: 200", s == 200 and as_json(d).get("supportedFeatures") == "0",
           f"{s}")

    # CP05: access token (TS 29.222 cl. 5.6.2.3; TS 33.122 Annex C.2.2).
    before = int(time.time())
    s, h, d = inv.token(inv.token_form())
    after = int(time.time())
    rsp = as_json(d)
    token = rsp.get("access_token", "")
    c = claims(token) if token.count(".") == 2 else {}
    life = rsp.get("expires_in", 0)
    ok = (s == 200 and rsp.get("token_type") == "Bearer" and h.get("cache-control") == "no-store"
          and rsp.get("scope") == SCOPE and c.get("iss") == inv.id and c.get("client_id") == inv.id
          and c.get("scope") == SCOPE and before + life - 5 <= c.get("exp", 0) <= after + life + 5)
    report("CP05", "access token: Bearer, no-store; iss = client_id = API invoker ID; scope; exp = now + expires_in",
           ok, f"{s} expires_in {life}, claims {sorted(c)}")

    # CP11 to CP13: refused token requests (TS 29.222 table 8.5.5.3-1; RFC 6749 cl. 5.2).
    for tid, desc, form, want in [
        ("CP11", "token with a wrong secret: 400 invalid_client", inv.token_form(client_secret="wrong"),
         "invalid_client"),
        ("CP12", "token with a scope outside the profile: 400 invalid_scope",
         inv.token_form(scope="3gpp#nef-aef:3gpp-traffic-influence"), "invalid_scope"),
        ("CP13", "grant_type=password: 400 unsupported_grant_type", inv.token_form(grant_type="password"),
         "unsupported_grant_type"),
    ]:
        s, _, d = inv.token(form)
        got = as_json(d).get("error")
        report(tid, desc, s == 400 and got == want, f"{s} {got}")

    if not token:
        return
    # CP06: K_AF through the NEF with the token of the CCF (TS 29.522 cl. 7.2), the same as the AAnF
    # gives directly, without SUPI (TS 33.535 cl. 6.3 step 5).
    s, _, d = retrieve(ctx, nef, token, {"afId": AF_ID, "aKId": akid})
    rsp = as_json(d)
    s2, _, d2 = tls_request(aanf_tls(sba), aanf, "POST", "/naanf-akma/v1/retrieve-applicationkey",
                            json.dumps({"afId": AF_ID, "aKId": akid}).encode(), {"Content-Type": "application/json"})
    same = s == 200 and s2 == 200 and len(rsp.get("kaf", "")) == 64 and rsp.get("kaf") == as_json(d2).get("kaf")
    report("CP06", "K_AF through the NEF with the token of the CCF: the K_AF of the AAnF, without supi",
           same and "supi" not in rsp, "equal, no supi" if same and "supi" not in rsp else f"NEF {s}, AAnF {s2}")

    # CP07: the same, anonymous (TS 33.535 cl. 6.2.2).
    s, _, d = retrieve(ctx, nef, token, {"afId": AF_ID, "aKId": akid, "anonInd": True})
    rsp = as_json(d)
    report("CP07", "anonymous access through the NEF with the token of the CCF: without supi and gpsi",
           s == 200 and "kaf" in rsp and "supi" not in rsp and "gpsi" not in rsp, f"{s}")

    # CP14, CP15: no token, and a tampered token (F12: the middleware of the NRF answers).
    s, _, _ = retrieve(ctx, nef, "", {"afId": AF_ID, "aKId": akid})
    report("CP14", "NEF without token: 401", s == 401, f"{s}")
    s, _, _ = retrieve(ctx, nef, tamper(token), {"afId": AF_ID, "aKId": akid})
    report("CP15", "NEF with a tampered token: 401", s == 401, f"{s}")

    # CP16, CP17: AF_ID outside the profile of the API invoker, and outside the policy of the NEF:
    # 403 without cause (TS 29.522 cl. 7.2; TS 33.535 cl. 6.3 step 2).
    for tid, desc, af_id in [
        ("CP16", f"AF_ID {AF_ID_OUTSIDE_PROFILE}, in the policy of the NEF and outside the profile: 403 without cause",
         AF_ID_OUTSIDE_PROFILE),
        ("CP17", f"AF_ID {AF_ID_OUTSIDE_POLICY}, in the profile and outside the policy of the NEF: 403 without cause",
         AF_ID_OUTSIDE_POLICY),
    ]:
        s, _, d = retrieve(ctx, nef, token, {"afId": af_id, "aKId": akid})
        pd = as_json(d)
        report(tid, desc, s == 403 and not pd.get("cause"), f"{s} {pd.get('detail', '')}")

    # S16: the access token and the certificate on CAPIF-2e are of the same API invoker
    # (TS 33.122 cl. 6.5.2.3 step 5; TS 33.501 cl. 13.3.1.3), and the groups of the SBI of the NEF
    # are not for the certificates of the CA of the CCF. The token of the NRF is S16.nrf, in nef_api.py.
    s, _ = other.enrol(credential)
    if s == 201:
        other_ctx = other.nef_tls(sba)
        s, h, _ = retrieve(other_ctx, nef, token, {"afId": AF_ID, "aKId": akid})
        challenge = h.get("www-authenticate", "")
        report("S16.token", "token of an API invoker with the certificate of another: 401 invalid_token",
               s == 401 and 'error="invalid_token"' in challenge, f"{s} {challenge}")
        s, _, _ = inv.check_authentication(other_ctx, nef)
        report("S16.check", "check-authentication of an API invoker with the certificate of another: 403",
               s == 403, f"{s}")
    else:
        report("S16.token", "onboarding of the third API invoker", False, f"{s}")
    s, _, d = tls_request(ctx, nef, "GET", "/nnef-pfdmanagement/v1/applications")
    got = as_json(d).get("cause")
    report("S16.sbi", "certificate of an API invoker on a group of the SBI of the NEF: 403 without cause",
           s == 403 and not got, f"{s} {got}")

    # CP18: offboarding (TS 33.122 cl. 6.8): the CCF revokes the certificate and refuses it on CAPIF-1e.
    s, _, _ = inv.offboard()
    if s == 204:
        inv.secret = ""
    gone, got = refused(lambda: inv.token(inv.token_form()))
    report("CP18", "offboarding: 204; token requested after: the certificate is refused in TLS", s == 204 and gone,
           f"{s}, {got}")

    # S18: the NEF sees it in the CRL of the CA of the CCF (TS 33.310 cl. 6.3.1).
    time.sleep(CRL_WAIT)
    gone, got = refused(lambda: inv.check_authentication(ctx, nef))
    report("S18", "certificate of an API invoker that offboarded, at the NEF: refused in TLS", gone, got)


if __name__ == "__main__":
    main()
