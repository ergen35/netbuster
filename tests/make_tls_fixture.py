#!/usr/bin/env python3
"""Produit tests/tls_fixture.json : de vraies sessions TLS locales, enregistrées par un relais
TCP, avec leur fichier de clés. Rien ne sort de la machine (tout passe par 127.0.0.1)."""
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
CLIENT_SAYS = "GET /secret HTTP/1.1\r\nHost: exemple.test\r\n\r\n"
SERVER_SAYS = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nBonjour test!"


def make_cert(tmp):
    cert, key = os.path.join(tmp, "c.pem"), os.path.join(tmp, "k.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
         "-nodes", "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=exemple.test"],
        check=True, capture_output=True)
    return cert, key


def session(name, cert, key, version, ciphers, tmp):
    keylog = os.path.join(tmp, name + ".keys")
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(cert, key)
    client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_ctx.check_hostname = False
    client_ctx.verify_mode = ssl.CERT_NONE
    client_ctx.keylog_filename = keylog
    for ctx in (server_ctx, client_ctx):
        ctx.minimum_version = version
        ctx.maximum_version = version
    if ciphers and version != ssl.TLSVersion.TLSv1_3:
        server_ctx.set_ciphers(ciphers)
        client_ctx.set_ciphers(ciphers)

    srv = socket.create_server(("127.0.0.1", 0))
    relay = socket.create_server(("127.0.0.1", 0))
    events, lock = [], threading.Lock()

    def server():
        c, _ = srv.accept()
        with server_ctx.wrap_socket(c, server_side=True) as s:
            got = b""
            while b"\r\n\r\n" not in got:
                got += s.recv(4096)
            s.sendall(SERVER_SAYS.encode())

    def pump(a, b, direction):
        try:
            while True:
                d = a.recv(4096)
                if not d:
                    break
                with lock:
                    events.append([direction, d.hex()])
                b.sendall(d)
        except OSError:
            pass
        try:
            b.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    def relay_main():
        a, _ = relay.accept()
        b = socket.create_connection(srv.getsockname())
        threads = [threading.Thread(target=pump, args=(a, b, 0)), threading.Thread(target=pump, args=(b, a, 1))]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    threads = [threading.Thread(target=server), threading.Thread(target=relay_main)]
    for t in threads:
        t.start()
    with client_ctx.wrap_socket(socket.create_connection(relay.getsockname())) as c:
        negotiated = c.cipher()
        c.sendall(CLIENT_SAYS.encode())
        got = b""
        while len(got) < len(SERVER_SAYS):
            d = c.recv(4096)
            if not d:
                break
            got += d
        assert got.decode() == SERVER_SAYS
    for t in threads:
        t.join(5)
    print(name, negotiated, file=sys.stderr)
    return {
        "name": name,
        "cipher": negotiated[0],
        "keylog": open(keylog).read(),
        "events": events,
        "client_says": CLIENT_SAYS,
        "server_says": SERVER_SAYS,
    }


def main():
    out = []
    with tempfile.TemporaryDirectory() as tmp:
        cert, key = make_cert(tmp)
        v13, v12 = ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_2
        out.append(session("tls13", cert, key, v13, None, tmp))
        out.append(session("tls12-aes128", cert, key, v12, "ECDHE-ECDSA-AES128-GCM-SHA256", tmp))
        out.append(session("tls12-aes256", cert, key, v12, "ECDHE-ECDSA-AES256-GCM-SHA384", tmp))
        out.append(session("tls12-chacha", cert, key, v12, "ECDHE-ECDSA-CHACHA20-POLY1305", tmp))
    with open(os.path.join(HERE, "tls_fixture.json"), "w") as f:
        json.dump(out, f, indent=0)


if __name__ == "__main__":
    main()
