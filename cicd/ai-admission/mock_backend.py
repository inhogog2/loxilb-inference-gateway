#!/usr/bin/env python3
"""
mock_backend.py — an OpenAI-compatible backend the capacity gate can be
measured against.

One process serves every port it is given, so the counters below are shared
across the pool's endpoints: "how many requests were executing at the
backend at the same instant" is a question about the pool, and two
processes cannot answer it.

Endpoints:
  POST /v1/chat/completions   the inference request (JSON, or SSE when the
                              body carries "stream": true)
  GET  /v1/models             a non-inference request on the same service
  GET  /health                readiness
  GET  /__receipts/<nonce>    requests that arrived carrying that X-Test-Nonce
  GET  /__peak/<nonce>        the most requests with that nonce executing at
                              once, across every port, plus the per-port peaks
  GET  /__inflight            requests executing right now
  GET  /__order/<nonce>       the X-Request-Id of every request carrying that
                              nonce, in the order they arrived
  GET  /__release/<nonce>     let every held request with that nonce answer
  GET  /__release_all         let every held request answer
  GET  /metrics               the engine's own metrics, as the gateway's
                              scraper reads them: vllm:num_requests_waiting
  GET  /__waiting/<n>         report <n> requests waiting from now on (every port)
  GET  /__metrics/off|on      stop answering /metrics (503) or answer again,
                              so the gateway's view of the engine goes stale

Request headers that shape the answer:
  X-Test-Nonce: <n>       counted as a receipt and tracked for its peak
  X-Test-Hold: 1          the request is read in full, counted, then held
                          until released (or 90 s), so a caller can look at
                          the gateway while the request is executing
  X-Test-Delay-Ms: <ms>   time to first byte (for a stream: to its first
                          event, the time to first token)
  X-Test-Fail: <status>   answer with that status and an error body
  X-Test-Reset: 1         drop the connection with a TCP RST, no answer
  X-Test-Forever: 1       with "stream": true, keep sending SSE chunks until
                          the connection dies
  X-Test-Spoof-Admission: 1
                          the answer carries X-Loxilb-Admission-Inflight: 999
                          of its own, which the gateway must replace

The receipt count is the honest oracle for a refused request: from the
client side a refusal and a forwarded request whose answer was discarded
look identical, and the count is read from inside the backend's own
namespace, never through the gateway.

Usage: mock_backend.py <port> [<port> ...]
"""

import json
import socket
import struct
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from urllib.parse import urlparse

HOLD_MAX_S = 90.0

LOCK = threading.Lock()
RECEIPTS = {}        # nonce -> arrivals
INFLIGHT = 0         # executing right now, every port
INFLIGHT_PORT = {}   # port -> executing right now
PEAK = {}            # nonce -> most executing at once, every port
PEAK_PORT = {}       # nonce -> {port: most executing at once on that port}
ORDER = {}           # nonce -> request ids in arrival order
RELEASED = set()     # nonces whose holds were released
RELEASE_ALL = 0      # generation: bumped by /__release_all
COND = threading.Condition(LOCK)
WAITING = 0          # vllm:num_requests_waiting reported by /metrics
METRICS_ON = True    # /metrics answers; off: 503, the scrape fails


class Server(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    # ── helpers ────────────────────────────────────────────────────────────
    @property
    def port(self):
        return self.server.server_address[1]

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n > 0 else b""
        try:
            return json.loads(raw or b"{}")
        except (ValueError, UnicodeDecodeError):
            return {}

    def _send_json(self, obj, status=200):
        payload = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self._spoof_header()
        self.end_headers()
        self.wfile.write(payload)

    def _spoof_header(self):
        if getattr(self, "spoof", False):
            self.send_header("X-Loxilb-Admission-Inflight", "999")

    def _enter(self, nonce):
        global INFLIGHT
        with LOCK:
            if nonce:
                RECEIPTS[nonce] = RECEIPTS.get(nonce, 0) + 1
                ORDER.setdefault(nonce, []).append(
                    self.headers.get("X-Request-Id", ""))
            INFLIGHT += 1
            INFLIGHT_PORT[self.port] = INFLIGHT_PORT.get(self.port, 0) + 1
            if nonce:
                if INFLIGHT > PEAK.get(nonce, 0):
                    PEAK[nonce] = INFLIGHT
                pp = PEAK_PORT.setdefault(nonce, {})
                if INFLIGHT_PORT[self.port] > pp.get(self.port, 0):
                    pp[self.port] = INFLIGHT_PORT[self.port]

    def _leave(self):
        global INFLIGHT
        with LOCK:
            INFLIGHT -= 1
            INFLIGHT_PORT[self.port] = INFLIGHT_PORT.get(self.port, 1) - 1

    def _hold(self, nonce):
        deadline = time.monotonic() + HOLD_MAX_S
        with COND:
            gen = RELEASE_ALL
            while nonce not in RELEASED and RELEASE_ALL == gen:
                left = deadline - time.monotonic()
                if left <= 0:
                    return "timeout"
                COND.wait(left)
        return "released"

    def _reset(self):
        try:
            self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                       struct.pack("ii", 1, 0))
        except OSError:
            pass
        self.close_connection = True
        try:
            self.connection.close()
        except OSError:
            pass

    # ── routes ─────────────────────────────────────────────────────────────
    def do_GET(self):
        self.spoof = False
        global WAITING, METRICS_ON
        path = urlparse(self.path).path
        nonce = self.headers.get("X-Test-Nonce", "")
        if path == "/health":
            self._send_json({"status": "ok"})
            return
        if path == "/metrics":
            with LOCK:
                on, waiting = METRICS_ON, WAITING
            if not on:
                self.send_error(503)
                return
            payload = ("# TYPE vllm:num_requests_waiting gauge\n"
                       "vllm:num_requests_waiting{model_name=\"cap-model\"} %d\n"
                       % waiting).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if path.startswith("/__waiting/"):
            with LOCK:
                WAITING = int(path[len("/__waiting/"):] or 0)
            self._send_json({"waiting": WAITING})
            return
        if path in ("/__metrics/off", "/__metrics/on"):
            with LOCK:
                METRICS_ON = path.endswith("/on")
            self._send_json({"metrics": METRICS_ON})
            return
        if path == "/v1/models":
            # A non-inference request: counted like any other arrival so a
            # scenario can prove it reached the backend while the gate was
            # full, then answered as a model listing.
            self._enter(nonce)
            try:
                self._send_json({"object": "list", "data": [
                    {"id": "cap-model", "object": "model", "owned_by": "cicd"}]})
            finally:
                self._leave()
            return
        if path.startswith("/__receipts/"):
            n = path[len("/__receipts/"):]
            with LOCK:
                self._send_json({"nonce": n, "count": RECEIPTS.get(n, 0)})
            return
        if path.startswith("/__peak/"):
            n = path[len("/__peak/"):]
            with LOCK:
                self._send_json({"nonce": n, "peak": PEAK.get(n, 0),
                                 "ports": {str(k): v for k, v in
                                           PEAK_PORT.get(n, {}).items()}})
            return
        if path.startswith("/__order/"):
            n = path[len("/__order/"):]
            with LOCK:
                self._send_json({"nonce": n, "order": list(ORDER.get(n, []))})
            return
        if path == "/__inflight":
            with LOCK:
                self._send_json({"inflight": INFLIGHT,
                                 "ports": {str(k): v for k, v in INFLIGHT_PORT.items()}})
            return
        if path.startswith("/__release/"):
            n = path[len("/__release/"):]
            with COND:
                RELEASED.add(n)
                COND.notify_all()
            self._send_json({"released": n})
            return
        if path == "/__release_all":
            global RELEASE_ALL
            with COND:
                RELEASE_ALL += 1
                COND.notify_all()
            self._send_json({"released": "all"})
            return
        self.send_error(404)

    def do_POST(self):
        if urlparse(self.path).path != "/v1/chat/completions":
            self.send_error(404)
            return
        nonce = self.headers.get("X-Test-Nonce", "")
        hold = self.headers.get("X-Test-Hold", "") == "1"
        delay_ms = int(self.headers.get("X-Test-Delay-Ms") or 0)
        fail = int(self.headers.get("X-Test-Fail") or 0)
        reset = self.headers.get("X-Test-Reset", "") == "1"
        forever = self.headers.get("X-Test-Forever", "") == "1"
        self.spoof = self.headers.get("X-Test-Spoof-Admission", "") == "1"

        body = self._body()          # read before anything else: a held
        self._enter(nonce)           # request has fully arrived
        try:
            if hold:
                self._hold(nonce)
            if delay_ms > 0:
                time.sleep(delay_ms / 1000.0)
            if reset:
                self._reset()
                return
            if fail:
                self._send_json({"error": {"message": "injected", "type": "test"}}, fail)
                return
            model = body.get("model") or "cap-model"
            if body.get("stream"):
                self._stream(model, forever)
            else:
                self._complete(model)
        finally:
            self._leave()

    def _complete(self, model):
        self._send_json({
            "id": "cmpl-cap", "object": "chat.completion",
            "created": int(time.time()), "model": model,
            "backend_port": self.port,
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"},
                         "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        })

    def _stream(self, model, forever):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Transfer-Encoding", "chunked")
        self._spoof_header()
        self.end_headers()

        def chunk(payload):
            self.wfile.write(b"%x\r\n" % len(payload) + payload + b"\r\n")
            self.wfile.flush()

        def sse(obj):
            chunk(b"data: " + json.dumps(obj).encode() + b"\n\n")

        base = {"id": "cmpl-cap", "object": "chat.completion.chunk", "model": model}
        i = 0
        try:
            while True:
                sse(dict(base, choices=[{"index": 0, "delta": {"content": "t%d " % i}}]))
                i += 1
                if not forever and i >= 3:
                    break
                time.sleep(0.2)
        except OSError:
            # The connection died under a forever stream: that is how a
            # forever stream ends, not an error of the fixture.
            self.close_connection = True
            return
        sse(dict(base, choices=[{"index": 0, "delta": {}, "finish_reason": "stop"}]))
        sse(dict(base, choices=[],
                 usage={"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}))
        chunk(b"data: [DONE]\n\n")
        chunk(b"")


def main():
    ports = [int(p) for p in sys.argv[1:]] or [8080]
    servers = [Server(("0.0.0.0", p), Handler) for p in ports]
    for s in servers[1:]:
        threading.Thread(target=s.serve_forever, daemon=True).start()
    print("mock_backend listening on %s" % ",".join(str(p) for p in ports), flush=True)
    servers[0].serve_forever()


if __name__ == "__main__":
    main()
