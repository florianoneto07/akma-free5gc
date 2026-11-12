#!/usr/bin/env python3
"""Checks of the mutual TLS of the SBI in operation (TS 33.501 cl. 13.1.0).

From one machine, for each server named: no cleartext, no client without a
certificate of the CA of the operator, the certificate of the server with its
name and NF instance (TS 33.310 cl. 6.1.3c.3), and a revoked certificate and
one without CRL distribution point refused (TS 33.310 cl. 6.3.1). Independent
of the Go code of this repository: module ssl only, on the Python of both
machines (3.6 on the free5GC host).

Usage: sbi_tls.py <sba-entities.conf> <directory of the certificates> <certificate of the client>
                  <tag of this machine> <name>...
Prints one PASS or FAIL line per test, with the identifier <test>.<name>.<tag>;
exits 1 when any fails.
"""
import re
import socket
import ssl
import sys

# Cleartext at a port of the SBI: HTTP/1.1, and HTTP/2 with prior knowledge
# (h2c; RFC 9113 cl. 3.3), the two forms the SBI could answer.
CLEARTEXT = {
    "HTTP/1.1": b"GET /nnrf-nfm/v1/nf-instances HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    "h2c": b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
}

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
            if len(fields) == 7 and fields[0] in ("nf", "ccf"):
                found[fields[1]] = {"fqdn": fields[3], "address": fields[4], "port": int(fields[5]), "id": fields[6]}
    return found


def context(certs, client):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(f"{certs}/sba-ca.pem")
    if client:
        ctx.load_cert_chain(f"{certs}/{client}.pem", f"{certs}/{client}.key")
    return ctx


def cleartext(entity, request):
    """What the server answers to a request without TLS."""
    with socket.create_connection((entity["fqdn"], entity["port"]), timeout=10) as s:
        s.sendall(request)
        try:
            return s.recv(4096)
        except ConnectionError:
            return b""


def https(ctx, entity):
    """A request over TLS: the certificate of the server, in DER, its names and the answer."""
    with socket.create_connection((entity["fqdn"], entity["port"]), timeout=10) as raw:
        with ctx.wrap_socket(raw, server_hostname=entity["fqdn"]) as s:
            s.sendall(b"GET / HTTP/1.1\r\nHost: " + entity["fqdn"].encode() + b"\r\nConnection: close\r\n\r\n")
            answer = s.recv(4096)
            return s.getpeercert(True), s.getpeercert().get("subjectAltName", ()), answer


def refused(certs, client, entity):
    """Whether the server refuses this client: an alert, and no HTTP answer."""
    try:
        _, _, answer = https(context(certs, client), entity)
    except ssl.CertificateError as e:
        return False, f"the client refused the server: {e}"[:80]
    except (ssl.SSLError, ConnectionResetError, BrokenPipeError) as e:
        # Before Python 3.7, the client refuses a chain with a plain SSLError.
        if getattr(e, "reason", "") == "CERTIFICATE_VERIFY_FAILED":
            return False, f"the client refused the server: {e}"[:80]
        return True, f"{type(e).__name__} {e}"[:80]
    except OSError as e:
        return False, str(e)[:80]
    return not answer.startswith(b"HTTP/"), repr(answer[:30])


def installed(certs, name):
    """The certificate of the file of this NF, in DER; None without the file."""
    try:
        with open(f"{certs}/{name}.pem") as f:
            pem = f.read()
    except OSError:
        return None
    return ssl.PEM_cert_to_DER_cert(re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----\n?", pem, re.S)[0])


def main():
    if len(sys.argv) < 6:
        sys.exit(__doc__)
    all_entities = entities(sys.argv[1])
    certs, client, tag = sys.argv[2:5]
    for name in sys.argv[5:]:
        entity = all_entities[name]
        where = f'{entity["fqdn"]}:{entity["port"]}'

        for kind, request in CLEARTEXT.items():
            try:
                answer = cleartext(entity, request)
                # Nothing, a TLS alert, or the answer of Go to HTTP at a TLS port.
                ok = answer == b"" or answer[:1] == b"\x15" or b"HTTP request to an HTTPS server" in answer
                got = repr(answer[:24])
            except OSError as e:
                ok, got = False, str(e)[:80]
            report(f"S01.{name}.{tag}", f"{where} does not serve {kind} in cleartext", ok, got)

        ok, got = refused(certs, None, entity)
        report(f"S02.{name}.{tag}", f"{where} refuses TLS without a client certificate", ok, got)

        ok, got = refused(certs, "other-ca", entity)
        report(f"S03.{name}.{tag}", f"{where} refuses a certificate of another CA", ok, got)

        try:
            der, alt, answer = https(context(certs, client), entity)
            want = installed(certs, name)
            # The internal server of the CCF is no NF: it has no NF instance.
            ok = (("DNS", entity["fqdn"]) in alt and ("IP Address", entity["address"]) in alt
                  and (entity["id"] == "-" or ("URI", "urn:uuid:" + entity["id"]) in alt)
                  and answer.startswith(b"HTTP/")
                  and want in (None, der))
            got = f"{len(alt)} names, {'file not here' if want is None else 'the installed certificate'}, {answer[:12]!r}"
        except (ssl.SSLError, OSError) as e:
            ok, got = False, str(e)[:80]
        report(f"S04.{name}.{tag}", f"{where} presents its name, NF instance and address, with the SNI of the name",
               ok, got)

        ok, got = refused(certs, "revoked", entity)
        report(f"S06.{name}.{tag}", f"{where} refuses a revoked certificate", ok, got)

        ok, got = refused(certs, "no-crldp", entity)
        report(f"S07.{name}.{tag}", f"{where} refuses a certificate without CRL distribution point", ok, got)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
