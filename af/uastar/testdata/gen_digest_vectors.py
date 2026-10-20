#!/usr/bin/env python3
"""Digest vectors for the simplified Ua* protocol (package uastar).

An implementation of the RFC 7616 calculations independent from the Go one:
response (cl. 3.4.1) and rspauth (cl. 3.5) with SHA-256. It checks the
SHA-256 example of RFC 7616 cl. 3.9.1 and computes the AKMA vectors from
the "testbed-ue" vector of shared/akma (A-KID as username, base64(K_AF) as
password, TS 24.109 K.2 c)).

Usage: gen_digest_vectors.py <shared vectors.json> <output.json>
"""
import hashlib
import json
import sys


def h(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def kd(secret: str, data: str) -> str:
    return h((secret + ":" + data).encode("utf-8"))


def digest(username, realm, password, a2, nonce, nc, cnonce, qop):
    ha1 = h(f"{username}:{realm}:{password}".encode("utf-8"))
    return kd(ha1, f"{nonce}:{nc}:{cnonce}:{qop}:{h(a2.encode('utf-8'))}")


def a2_request(method, uri, qop, body: bytes):
    if qop == "auth-int":
        return f"{method}:{uri}:{h(body)}"
    return f"{method}:{uri}"


def a2_response(uri, qop, body: bytes):
    if qop == "auth-int":
        return f":{uri}:{h(body)}"
    return f":{uri}"


def rfc7616_example():
    v = {
        "name": "rfc7616-3.9.1-sha256",
        "username": "Mufasa",
        "password": "Circle of Life",
        "realm": "http-auth@example.org",
        "method": "GET",
        "uri": "/dir/index.html",
        "nonce": "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v",
        "nc": "00000001",
        "cnonce": "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ",
        "qop": "auth",
        "request_body": "",
        "response_body": "",
    }
    v["response"] = digest(v["username"], v["realm"], v["password"],
                           a2_request(v["method"], v["uri"], v["qop"], b""),
                           v["nonce"], v["nc"], v["cnonce"], v["qop"])
    expected = "753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1"
    if v["response"] != expected:
        sys.exit(f"RFC 7616 cl. 3.9.1 example not reproduced: {v['response']}")
    v["rspauth"] = digest(v["username"], v["realm"], v["password"],
                          a2_response(v["uri"], v["qop"], b""),
                          v["nonce"], v["nc"], v["cnonce"], v["qop"])
    return v


def akma_vectors(shared):
    ue = next(x for x in shared["vectors"] if x["name"] == "testbed-ue")
    realm = "3GPP-bootstrapping-akma@" + ue["fqdn"]
    out = []
    for qop, request_body, response_body in (
        ("auth", "", ""),
        ("auth-int", "", '{"aKid":"' + ue["a_kid"]["base64"] + '"}'),
    ):
        v = {
            "name": "testbed-ue-" + qop,
            "shared_vector": "testbed-ue",
            "username": ue["a_kid"]["base64"],
            "realm": realm,
            "method": "GET",
            "uri": "/ua/v1/session",
            "nonce": "q2N0YXN0aWMtbm9uY2UtZm9yLXRlc3RzLW9ubHktMDAwMA==",
            "nc": "00000001",
            "cnonce": "c3RhdGljLWNub25jZS0wMQ==",
            "qop": qop,
            "request_body": request_body,
            "response_body": response_body,
        }
        password = ue["k_af_base64"]
        v["response"] = digest(v["username"], realm, password,
                               a2_request(v["method"], v["uri"], qop, request_body.encode()),
                               v["nonce"], v["nc"], v["cnonce"], qop)
        v["rspauth"] = digest(v["username"], realm, password,
                              a2_response(v["uri"], qop, response_body.encode()),
                              v["nonce"], v["nc"], v["cnonce"], qop)
        out.append(v)
    return out


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    with open(sys.argv[1], encoding="utf-8") as f:
        shared = json.load(f)
    doc = {
        "description": "HTTP Digest (RFC 7616, SHA-256) vectors for the simplified Ua* protocol. "
                       "The password of the testbed-ue vectors is k_af_base64 of the shared "
                       "vector named in shared_vector; it is not repeated here.",
        "vectors": [rfc7616_example()] + akma_vectors(shared),
    }
    with open(sys.argv[2], "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")


if __name__ == "__main__":
    main()
