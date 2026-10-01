#!/usr/bin/env python3
"""hf_stub.py <root> <port> [required-token] — a local stand-in for the model hub's file endpoint.

Serves <root>/<org>/<name>/resolve/<revision>/<file> with Range support. With a required token, a request
without `Authorization: Bearer <token>` answers 401, as a gated repository does. Every request is appended to
<root>/requests.log (method, path, Range, whether a bearer header was present — never the token).
"""
import http.server
import os
import sys

ROOT, PORT = os.path.abspath(sys.argv[1]), int(sys.argv[2])
TOKEN = sys.argv[3] if len(sys.argv) > 3 else None


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        rng, auth = self.headers.get("Range"), self.headers.get("Authorization")
        with open(os.path.join(ROOT, "requests.log"), "a") as f:
            f.write(f"GET {self.path} range={rng} bearer={'yes' if auth else 'no'}\n")
        if TOKEN and auth != "Bearer " + TOKEN:
            self.send_error(401)
            return
        path = os.path.normpath(os.path.join(ROOT, self.path.lstrip("/")))
        if not path.startswith(ROOT + os.sep) or not os.path.isfile(path):
            self.send_error(404)
            return
        size, start = os.path.getsize(path), 0
        if rng and rng.startswith("bytes="):
            start = int(rng[6:].split("-")[0])
        self.send_response(206 if start else 200)
        if start:
            self.send_header("Content-Range", f"bytes {start}-{size - 1}/{size}")
        self.send_header("Content-Length", str(size - start))
        self.end_headers()
        with open(path, "rb") as f:
            f.seek(start)
            self.wfile.write(f.read())


http.server.ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
