#!/usr/bin/env python3
"""hold_backend.py - an HTTP/1.1 backend that reports when the proxy lets go
of a connection, for validation_hold.sh.

A held client is torn down by the proxy, and with it the backend leg it was
paired with. The client cannot report when that happened (it has gone, or it
is the one being cut), so the backend does: it prints one JSON line per
connection once the connection ends:

  {"id": "<id>", "gone": <epoch seconds>, "answered": true|false, "sent": <bytes>}

Request knobs (GET /?id=<id>&...):
  wait=MS    hold the answer back MS ms; a connection that goes away first is
             never answered
  bytes=N    the answer's body is N bytes (default 2, "ok"), written as fast
             as the proxy takes it

The proxy never forwards a client's FIN to the backend (an HTTP/1 request is
not framed by EOF), so an EOF or an error here is the proxy closing the leg.
It closes it with a FIN, which a backend blocked in a send cannot read: the
answer is written without blocking, watching the socket for that EOF all the
while, so "gone" is when the FIN came, not when the kernel later gave up on
a send towards a closed window.

  python3 hold_backend.py <port>
"""
import json
import select
import socket
import sys
import threading
import time
from urllib.parse import parse_qs, urlsplit

GONE_WAIT_S = 60


def report(rec):
    sys.stdout.write(json.dumps(rec) + "\n")
    sys.stdout.flush()


def gone_after(conn):
    """Blocks until the proxy closes the connection; returns the time."""
    end = time.time() + GONE_WAIT_S
    while time.time() < end:
        r, _, _ = select.select([conn], [], [], 1.0)
        if not r:
            continue
        try:
            if not conn.recv(65536):
                return time.time()
        except OSError:
            return time.time()
    return None


def serve(conn):
    rec = {"id": "", "gone": None, "answered": False, "sent": 0}
    try:
        buf = b""
        while b"\r\n\r\n" not in buf:
            d = conn.recv(65536)
            if not d:
                rec["gone"] = time.time()
                return
            buf += d
        target = buf.split(b"\r\n", 1)[0].split(b" ")[1].decode("latin-1")
        q = parse_qs(urlsplit(target).query)
        rec["id"] = q.get("id", [""])[0]
        wait_ms = int(q.get("wait", ["0"])[0])
        nbytes = int(q.get("bytes", ["2"])[0])

        if wait_ms:
            r, _, _ = select.select([conn], [], [], wait_ms / 1000.0)
            if r:
                rec["gone"] = gone_after(conn)
                return
        body = b"ok" if nbytes == 2 else b"x" * nbytes
        head = b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body)
        view = memoryview(head + body)
        conn.setblocking(False)
        while view:
            r, w, _ = select.select([conn], [conn], [], 1.0)
            if r:
                # Nothing more is ever sent to us: readable is the leg closing.
                try:
                    if not conn.recv(65536):
                        rec["gone"] = time.time()
                        return
                except BlockingIOError:
                    pass
                except OSError:
                    rec["gone"] = time.time()
                    return
            if w:
                try:
                    n = conn.send(view[:1 << 20])
                except BlockingIOError:
                    continue
                except OSError:
                    rec["gone"] = time.time()
                    return
                rec["sent"] += n
                view = view[n:]
        rec["answered"] = True
        rec["gone"] = gone_after(conn)
    finally:
        conn.close()
        report(rec)


def main():
    port = int(sys.argv[1])
    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("0.0.0.0", port))
    ls.listen(64)
    while True:
        conn, _ = ls.accept()
        threading.Thread(target=serve, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
