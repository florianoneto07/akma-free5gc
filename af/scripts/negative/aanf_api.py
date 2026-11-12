#!/usr/bin/env python3
"""Negative tests of Naanf_AKMA against the AAnF in operation.

Raw HTTP/1.1 requests over mutual TLS from the AF machine, with the
certificate of the AF, which the local policy of the AAnF authorizes for
af1.akma.example.FF00000001. Independent of the Go code
of this repository: the expected answers come from TS 29.500 cl. 5.2.7 and
TS 29.535 cl. 4.2.2 and 5.1.7.3.

Usage: aanf_api.py <AAnF host:port> <registered A-KID> <directory of the certificates>
Prints one PASS or FAIL line per test; exits 1 when any fails.
"""
import http.client
import json
import os
import re
import socket
import ssl
import sys

API = "/naanf-akma/v1"
AF_ID = "af1.akma.example.FF00000001"

failures = 0
tls = None


def client_tls(certs):
    """TLS with the CA of the operator and the certificate of the AF (TS 33.501 cl. 13.1.0)."""
    ctx = ssl.create_default_context(cafile=f"{certs}/sba-ca.pem")
    ctx.load_cert_chain(f"{certs}/af1.pem", f"{certs}/af1.key")
    return ctx


def request(hostport, method, path, body=b"", content_type="application/json", headers=None):
    host, port = hostport.rsplit(":", 1)
    conn = http.client.HTTPSConnection(host, int(port), context=tls, timeout=30)
    h = {"Content-Type": content_type} if content_type else {}
    h.update(headers or {})
    conn.request(method, path, body=body, headers=h)
    rsp = conn.getresponse()
    data = rsp.read()
    conn.close()
    return rsp.status, data


def cause_of(data):
    try:
        return json.loads(data).get("cause", "")
    except (ValueError, AttributeError):
        return ""


def check(tid, desc, status, data, want_status, want_cause=None):
    global failures
    cause = cause_of(data)
    ok = status == want_status and (want_cause is None or cause == want_cause) and status != 204
    got = f"{status} {cause}".strip()
    want = f"{want_status} {want_cause or ''}".strip()
    if ok:
        print(f"PASS {tid} {desc}: {got}")
    else:
        failures += 1
        print(f"FAIL {tid} {desc}: got {got}, want {want}")


def headers_of(hostport, body, headers):
    """The headers of the answer to a retrieve-applicationkey."""
    host, port = hostport.rsplit(":", 1)
    conn = http.client.HTTPSConnection(host, int(port), context=tls, timeout=30)
    conn.request("POST", API + "/retrieve-applicationkey", body=body,
                 headers=dict({"Content-Type": "application/json"}, **headers))
    rsp = conn.getresponse()
    rsp.read()
    conn.close()
    return rsp.status, {k.lower(): v for k, v in rsp.getheaders()}


def instance_of(pem_path):
    """The NF instance ID in the URI of a certificate (TS 33.310 cl. 6.1.3c.3)."""
    with open(pem_path) as f:
        der = ssl.PEM_cert_to_DER_cert(f.read())
    found = re.search(rb"urn:uuid:([0-9a-fA-F-]{36})", der)
    return found.group(1).decode().lower() if found else ""


def retrieve(hostport, af_id, akid, **kw):
    body = json.dumps({"afId": af_id, "aKId": akid}).encode()
    return request(hostport, "POST", API + "/retrieve-applicationkey", body, **kw)


def raw_post(hostport, body, declared_length):
    """POST with a Content-Length that differs from the body sent."""
    host, port = hostport.rsplit(":", 1)
    head = (f"POST {API}/retrieve-applicationkey HTTP/1.1\r\nHost: {hostport}\r\n"
            f"Content-Type: application/json\r\nContent-Length: {declared_length}\r\n"
            "Connection: close\r\n\r\n").encode()
    with tls.wrap_socket(socket.create_connection((host, int(port)), timeout=30), server_hostname=host) as s:
        s.sendall(head + body)
        # End of the body: the TCP half close of the connection, under the TLS.
        with socket.socket(fileno=os.dup(s.fileno())) as tcp:
            tcp.shutdown(socket.SHUT_WR)
        raw = b""
        while chunk := s.recv(65536):
            raw += chunk
    status_line, _, rest = raw.partition(b"\r\n")
    status = int(status_line.split()[1])
    return status, rest.partition(b"\r\n\r\n")[2]


def main():
    global tls
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    aanf, akid = sys.argv[1], sys.argv[2]
    tls = client_tls(sys.argv[3])

    s, d = retrieve(aanf, AF_ID, akid)
    check("N01", "retrieve with the registered A-KID", s, d, 200)
    if s == 200:
        rsp = json.loads(d)
        ok = len(rsp.get("kaf", "")) == 64 and "expiry" in rsp
        print(("PASS" if ok else "FAIL") + " N01b AkmaAfKeyData carries kaf (64 hexadecimal characters) and expiry")
        globals()["failures"] += 0 if ok else 1

    s, d = request(aanf, "POST", API + "/retrieve-applicationkey",
                   json.dumps({"afId": AF_ID, "aKId": akid, "anonInd": True}).encode())
    rsp = json.loads(d) if s == 200 else {}
    ok = s == 200 and "kaf" in rsp and "supi" not in rsp
    print(("PASS" if ok else "FAIL") + f" N01c anonymous access (anonInd, TS 33.535 cl. 6.2.2): {s}, supi absent: {'supi' not in rsp}")
    globals()["failures"] += 0 if ok else 1

    s, d = retrieve(aanf, AF_ID, akid.replace(".atid", ".akid", 1))
    check("N02", 'A-KID with the label "akid" accepted (example of TS 29.522 table 5.14.5.4.2-1)', s, d, 200)

    s, d = retrieve(aanf, "af2.akma.example.FF00000001", akid)
    check("N03", "AF_ID not authorized by the local policy (TS 33.535 cl. 6.2.1 step 2)", s, d, 403, "")

    s, d = retrieve(aanf, "af1.akma.exampleFF0000000", akid)
    check("N04", "afId with 9 hexadecimal digits and no dot", s, d, 400, "MANDATORY_IE_INCORRECT")

    s, d = retrieve(aanf, AF_ID, "rid0000.atidAAAA@5gc.mnc093.mcc208.3gppnetwork.org")
    check("N05", "aKId that is not an A-KID", s, d, 400, "MANDATORY_IE_INCORRECT")

    unknown = akid.split(".atid", 1)[0] + ".atid" + "A" * 43 + "=@" + akid.split("@", 1)[1]
    s, d = retrieve(aanf, AF_ID, unknown)
    check("N06", "unknown A-KID (TS 29.535 cl. 4.2.2.3.2; never 204)", s, d, 403, "K_AKMA_NOT_PRESENT")

    s, d = request(aanf, "POST", API + "/retrieve-applicationkey", json.dumps({"afId": AF_ID}).encode())
    check("N07", "aKId missing", s, d, 400, "MANDATORY_IE_MISSING")

    s, d = request(aanf, "POST", API + "/retrieve-applicationkey", b'{"afId": ')
    check("N08", "body that is not JSON", s, d, 400, "INVALID_MSG_FORMAT")

    body = json.dumps({"afId": AF_ID, "aKId": akid}).encode()
    s, d = request(aanf, "POST", API + "/retrieve-applicationkey", body, content_type="text/plain")
    check("N09", "Content-Type text/plain (TS 29.500 cl. 5.2.7.2)", s, d, 415)

    s, d = raw_post(aanf, body, 16_000_001)
    check("N10", "declared body above 16 000 000 octets (TS 29.501 cl. 6.2)", s, d, 413, "MAX_JSON_SIZE_EXCEEDED")

    s, d = raw_post(aanf, body, len(body) + 50)
    check("N11", "Content-Length larger than the body", s, d, 411, "INCORRECT_LENGTH")

    s, d = request(aanf, "GET", API + "/retrieve-applicationkey", content_type=None)
    check("N12", "GET on an operation of the API (TS 29.500 cl. 5.2.7.2)", s, d, 501)

    s, d = request(aanf, "POST", API + "/unknown-operation", body)
    check("N13", "unknown operation", s, d, 404, "RESOURCE_URI_STRUCTURE_NOT_FOUND")

    s, d = request(aanf, "POST", "/naanf-akma/v2/retrieve-applicationkey", body)
    check("N14", "unknown API version", s, d, 400, "INVALID_API")

    reg = json.dumps({"supi": "imsi-208930000000001", "aKId": akid, "kAkma": "0" * 64}).encode()
    s, d = request(aanf, "POST", API + "/register-anchorkey", reg)
    check("N15", "register-anchorkey without access token (TS 29.535 cl. 5.1.9)", s, d, 401)

    rem = json.dumps({"supi": "imsi-208930000000001"}).encode()
    s, d = request(aanf, "POST", API + "/remove-context", rem)
    check("N16", "remove-context without access token", s, d, 401)

    # Server and 3gpp-Sbi-NF-Peer-Info in the answers of the AAnF, also in an error
    # (TS 29.500 table 5.2.2.2-1 and cl. 5.2.3.2.21); the consumer is the NF instance of the certificate af1.
    s, h = headers_of(aanf, json.dumps({"afId": AF_ID, "aKId": unknown}).encode(),
                      {"User-Agent": "AF-" + instance_of(f"{sys.argv[3]}/af1.pem")})
    server, peer = h.get("server", ""), h.get("3gpp-sbi-nf-peer-info", "")
    aanf_id = server[len("AANF-"):] if server.startswith("AANF-") else ""
    ok = (s == 403 and re.fullmatch(r"[0-9a-f-]{36}", aanf_id) is not None
          and peer == f"srcinst={aanf_id}; dstinst={instance_of(f'{sys.argv[3]}/af1.pem')}")
    print(("PASS" if ok else "FAIL") + f" G12 Server AANF-<NF instance> and 3gpp-Sbi-NF-Peer-Info with the AF in an error"
          f" answer: {s}, Server {server!r}, 3gpp-Sbi-NF-Peer-Info {peer!r}")
    globals()["failures"] += 0 if ok else 1

    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
