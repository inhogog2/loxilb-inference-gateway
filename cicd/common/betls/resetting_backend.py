#!/usr/bin/env python3
"""An HTTPS backend that turns a client away with a reset.

The fixture tool's server is Go: when it refuses a client certificate it has
read the client's whole last flight, so its close is an orderly one and the
client reads the alert. A server on OpenSSL stops at the message it refuses.
In TLS 1.3 that message is the client's Certificate, and the Finished behind
it stays unread in the socket, so the close that follows the alert is a
reset. A client that writes its request after the reset arrived fails on the
write, not on the read of an answer.

This server is that backend: the Python standard library on OpenSSL, the
handshake done in accept, a client certificate required. A request it serves
is answered the way the fixture tool answers, and its nonce is appended to
the receipt file.
"""
import argparse
import hashlib
import http.server
import ssl
import threading
import urllib.parse

VERSIONS = {"1.2": ssl.TLSVersion.TLSv1_2, "1.3": ssl.TLSVersion.TLSv1_3}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True, help="name the server answers with")
    ap.add_argument("--addr", default="0.0.0.0")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--clientca", required=True, help="CA a client certificate must chain to")
    ap.add_argument("--receipts", required=True, help="file the nonce of every request is appended to")
    ap.add_argument("--tls", choices=sorted(VERSIONS), required=True, help="the one TLS version offered")
    args = ap.parse_args()

    lock = threading.Lock()

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            nonce = query.get("nonce", [""])[0]
            der = self.connection.getpeercert(binary_form=True)
            peer = hashlib.sha256(der).hexdigest() if der else "none"
            if nonce:
                with lock, open(args.receipts, "a") as f:
                    f.write(nonce + "\n")
            sni = getattr(self.connection, "requested_name", None) or "none"
            body = ("name=%s proto=HTTP/1.1 peer=%s sni=%s tls=%s nonce=%s\n"
                    % (args.name, peer, sni, self.connection.version(), nonce)).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True

        def log_message(self, *a):
            pass

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(args.cert, args.key)
    ctx.minimum_version = ctx.maximum_version = VERSIONS[args.tls]
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(args.clientca)

    def requested(sock, name, _ctx):
        sock.requested_name = name

    ctx.sni_callback = requested

    server = http.server.ThreadingHTTPServer((args.addr, args.port), Handler)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
