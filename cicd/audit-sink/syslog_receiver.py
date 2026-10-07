#!/usr/bin/env python3
"""RFC 5425 (syslog over TLS, octet-counted) receiver: the SIEM oracle for
the audit-sink scenario.

A real SIEM answers nothing at the syslog layer, so a client-visible outcome
can never prove delivery. This receiver is strict where a permissive
collector is lenient — every frame must be `MSG-LEN SP SYSLOG-MSG`, every
message a well-formed RFC 5424 header with the audit envelope as MSG — and
it keeps, per record, everything the assertions need: the (instance_id,
boot_id, seq) identity, the sink's (xseq_epoch, xseq) export identity, the
STRUCTURED-DATA element, the SHA-256 of the MSG bytes (replay identity is
byte identity), and the arrival time.

It also carries the fault levers the T5/T6/T23 arms need, on a plain HTTP
control port that only the harness reaches:

  /__probe            "0" while nothing has arrived (readiness, ai-jwtauth style)
  /__stats            counters + per-boot seq holes + xseq reuse, as JSON
  /__records[?since=N] the recorded frames from index N, JSONL
  /__pause            stop reading from every connection (the kernel window
                      fills; the SENDER's TLS write still returns — T5 (c))
  /__resume           read again
  /__kill             abort every open connection with an RST
  /__slow?bps=N       throttle reads to N bytes/s (0 = unthrottled) — T6, T9 export twin
  /__reset            forget everything recorded so far and begin a new
                      session file

The --out file is the evidence of a session: every accepted frame, one JSON
object a line. It is never emptied behind the caller's back. A file that is
already there when the receiver starts, and the one in use when /__reset is
called, is moved aside as FILE.1, FILE.2, ... (the next number that is
free) before a new one is begun, so the frames of a receiver that was
restarted in the middle of a run are still on disk afterwards. --overwrite
is the old behaviour, for a caller that wants the file emptied.

Usage:
  syslog_receiver.py --cert srv.pem --key srv-key.pem [--port 6514]
                     [--control 127.0.0.1:6515] [--out FILE] [--overwrite]
                     [--max-msg BYTES] [--pen N] [--sink NAME]

Standard library only. Runs as root inside a network namespace via
`ip netns exec`, so nothing here may depend on a user-site package.
"""

import argparse
import hashlib
import json
import os
import re
import socket
import ssl
import struct
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

# <PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP SD [SP MSG]
HEADER_RE = re.compile(
    rb"^<(?P<pri>\d{1,3})>(?P<ver>\d{1,2}) "
    rb"(?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) (?P<procid>\S+) (?P<msgid>\S+) "
)
SD_ELEMENT_RE = re.compile(rb'\[([^\s\]=]+)((?:\s+[^\s=\]]+="(?:[^"\\\]]|\\.)*")*)\]')
SD_PARAM_RE = re.compile(rb'([^\s=\]]+)="((?:[^"\\\]]|\\.)*)"')

# The audit-side vocabulary the plan fixes (§3 "Syslog sink"): HOSTNAME is the
# instance_id, APP-NAME is loxilb-igw, MSGID is the stream. Anything else is a
# header mismatch, counted and kept, never dropped — a receiver that discards
# what it does not like would hide the very defect the assertion looks for.
APP_NAME = b"loxilb-igw"
KNOWN_STREAMS = {b"mgmt", b"data", b"audit_system"}


class State:
    def __init__(self, out_path, max_msg, pen, sink, overwrite=False):
        self.lock = threading.Lock()
        self.out_path = out_path
        self.overwrite = overwrite
        self.kept = None           # where the previous session's file went
        self.max_msg = max_msg
        self.pen = pen
        self.sink = sink
        self.paused = False
        self.bps = 0
        self.conns = set()
        self.reset()

    def reset(self):
        self.records = []          # every accepted frame, in arrival order
        self.connections = 0       # TLS sessions accepted
        self.connections_open = 0
        self.frames = 0            # frames that parsed end to end
        self.framing_errors = 0    # bad MSG-LEN / short read / not SP after len
        self.header_errors = 0     # RFC 5424 header unparsable or VERSION != 1
        self.header_mismatch = 0   # parsed, but HOSTNAME/APP-NAME/MSGID disagree with the envelope
        self.json_errors = 0       # MSG is not the JSON envelope
        self.sd_errors = 0         # SD present but not one of the two audit elements, or wrong PEN
        self.oversized = 0         # frame longer than --max-msg: connection closed (strict receiver)
        self.bytes = 0
        self.seq_seen = {}         # (instance_id, boot_id) -> {seq: count}, every accepted frame
        self.seq_seen_orig = {}    # the same, ORIGINAL submissions only (SD "-"): a replay
                                   # repairs a hole here without erasing the evidence that it existed
        self.seq_max = {}          # (instance_id, boot_id) -> max seq
        self.xseq_seen = {}        # xseq_epoch -> {xseq: [hash, ...]}
        self.replays = 0           # frames carrying audit-replay@PEN
        self.exports = 0           # frames carrying audit-export@PEN
        self.tls_peers = []        # cipher/version per session, for the connect assertion
        self.first_arrival = None
        self.last_arrival = None
        self.kept = self.begin_out()

    def begin_out(self):
        """Begin an empty session file. What the file held is moved aside
        first and its new path returned; with --overwrite, or when it held
        nothing, there is nothing to keep and None is returned."""
        kept = None
        try:
            held = os.path.getsize(self.out_path) > 0
        except OSError:
            held = False
        if held and not self.overwrite:
            n = 1
            while os.path.lexists("%s.%d" % (self.out_path, n)):
                n += 1
            kept = "%s.%d" % (self.out_path, n)
            os.rename(self.out_path, kept)
        with open(self.out_path, "w"):
            pass
        return kept

    # --- accounting -------------------------------------------------------

    def record(self, rec):
        with self.lock:
            idx = len(self.records)
            rec["idx"] = idx
            self.records.append(rec)
            self.frames += 1
            now = rec["arrival"]
            self.first_arrival = self.first_arrival or now
            self.last_arrival = now
            key = (rec.get("instance_id"), rec.get("boot_id"))
            seq = rec.get("seq")
            sd = rec.get("sd")
            sd_ok = "sd" not in rec["errors"]
            if seq is not None:
                seen = self.seq_seen.setdefault(key, {})
                seen[seq] = seen.get(seq, 0) + 1
                self.seq_max[key] = max(self.seq_max.get(key, 0), seq)
                if sd is None:
                    orig = self.seq_seen_orig.setdefault(key, {})
                    orig[seq] = orig.get(seq, 0) + 1
            # A malformed or wrong-PEN element is an error, never an export
            # or a replay: it must not feed the xseq books, or an assertion
            # on xseq continuity could be satisfied by a frame the receiver
            # should have rejected.
            if sd_ok and sd and sd.get("id") == "audit-export":
                self.exports += 1
                epoch = sd.get("xseq_epoch")
                xseq = sd.get("xseq")
                if xseq is not None:
                    self.xseq_seen.setdefault(epoch, {}).setdefault(xseq, []).append(rec["msg_sha256"])
            if sd_ok and sd and sd.get("id") == "audit-replay":
                self.replays += 1
            with open(self.out_path, "a") as fh:
                fh.write(json.dumps(rec, sort_keys=True) + "\n")

    def holes(self):
        out = {}
        for key, seen in self.seq_seen.items():
            mx = self.seq_max.get(key, 0)
            missing = [s for s in range(1, mx + 1) if s not in seen]
            dups = sorted(s for s, n in seen.items() if n > 1)
            orig = self.seq_seen_orig.get(key, {})
            orig_missing = [s for s in range(1, mx + 1) if s not in orig]
            out["%s/%s" % key] = {"max_seq": mx, "received": len(seen),
                                   "holes": missing[:200], "hole_count": len(missing),
                                   "dups": dups[:200], "dup_count": len(dups),
                                   "orig_received": len(orig),
                                   "orig_holes": orig_missing[:200], "orig_hole_count": len(orig_missing)}
        return out

    def xseq_report(self):
        out = {}
        for epoch, seen in self.xseq_seen.items():
            mx = max(seen) if seen else 0
            missing = [x for x in range(1, mx + 1) if x not in seen]
            # Any xseq emitted twice within one epoch is a reuse, whether or
            # not the bytes match: the plan's rule is "never reused", and a
            # matching hash would only say the duplicate was faithful.
            reused = sorted(x for x, hs in seen.items() if len(hs) > 1)
            out[str(epoch)] = {"max_xseq": mx, "received": len(seen),
                               "holes": missing[:200], "hole_count": len(missing),
                               "reused": reused[:200], "reuse_count": len(reused)}
        return out

    def stats(self):
        with self.lock:
            span = (self.last_arrival - self.first_arrival) if self.first_arrival and self.last_arrival else 0.0
            return {
                "connections": self.connections,
                "connections_open": self.connections_open,
                "frames": self.frames,
                "records": len(self.records),
                "bytes": self.bytes,
                "framing_errors": self.framing_errors,
                "header_errors": self.header_errors,
                "header_mismatch": self.header_mismatch,
                "json_errors": self.json_errors,
                "sd_errors": self.sd_errors,
                "oversized": self.oversized,
                "replays": self.replays,
                "exports": self.exports,
                "paused": self.paused,
                "bps": self.bps,
                "pen": self.pen,
                "sink": self.sink,
                "tls_peers": self.tls_peers[-5:],
                "arrival_span_s": round(span, 3),
                "records_per_s": round(len(self.records) / span, 1) if span > 0 else None,
                "seq": self.holes(),
                "xseq": self.xseq_report(),
            }


def parse_sd(raw, state):
    """Return (sd_dict_or_None, ok). '-' is the only SD an original submission may carry."""
    if raw == b"-":
        return None, True
    elems = SD_ELEMENT_RE.findall(raw)
    if len(elems) != 1:
        return {"raw": raw.decode("utf-8", "replace")}, False
    sd_id, params = elems[0]
    name, _, pen = sd_id.partition(b"@")
    out = {"id": name.decode(), "pen": pen.decode() if pen else None}
    for k, v in SD_PARAM_RE.findall(params):
        out[k.decode()] = v.decode("utf-8", "replace")
    ok = out["id"] in ("audit-replay", "audit-export")
    if ok and state.pen and out["pen"] != str(state.pen):
        ok = False
    for k in ("xseq", "xseq_epoch", "n"):
        if k in out and out[k].isdigit():
            out[k] = int(out[k])
    return out, ok


def parse_message(msg, state, conn_id, arrival):
    rec = {"arrival": arrival, "conn": conn_id, "len": len(msg),
           "msg_sha256": None, "sd": None, "errors": []}
    m = HEADER_RE.match(msg)
    if not m:
        rec["errors"].append("header")
        return rec
    if m.group("ver") != b"1":
        rec["errors"].append("version")
    rest = msg[m.end():]
    # STRUCTURED-DATA is either "-" or one or more [..] elements, then SP MSG.
    if rest.startswith(b"-"):
        sd_raw, sep, body = rest.partition(b" ")
    else:
        depth, i = 0, 0
        while i < len(rest):
            c = rest[i:i + 1]
            if c == b"[":
                depth += 1
            elif c == b"]":
                depth -= 1
                if depth == 0 and (i + 1 == len(rest) or rest[i + 1:i + 2] == b" "):
                    i += 1
                    break
            elif c == b"\\":
                i += 1
            i += 1
        sd_raw, body = rest[:i], rest[i + 1:]
    if body.startswith(b"\xef\xbb\xbf"):
        body = body[3:]
    sd, sd_ok = parse_sd(sd_raw, state)
    rec["sd"] = sd
    if not sd_ok:
        rec["errors"].append("sd")
    rec["msg_sha256"] = hashlib.sha256(body).hexdigest()
    rec["msg_len"] = len(body)
    rec["hostname"] = m.group("host").decode("utf-8", "replace")
    rec["app"] = m.group("app").decode("utf-8", "replace")
    rec["msgid"] = m.group("msgid").decode("utf-8", "replace")
    try:
        env = json.loads(body)
        for k in ("instance_id", "boot_id", "seq", "stream", "event_type", "event_id", "truncated"):
            if k in env:
                rec[k] = env[k]
        rec["msg"] = env
    except (ValueError, UnicodeDecodeError):
        rec["errors"].append("json")
        rec["msg_raw"] = body[:512].decode("utf-8", "replace")
        return rec
    if rec.get("instance_id") != rec["hostname"] or m.group("app") != APP_NAME \
            or rec.get("stream") != rec["msgid"] or m.group("msgid") not in KNOWN_STREAMS:
        rec["errors"].append("header_mismatch")
    return rec


def throttle(state, nbytes):
    if state.bps > 0:
        time.sleep(nbytes / float(state.bps))


def serve_conn(tls, addr, state, conn_id):
    with state.lock:
        state.connections += 1
        state.connections_open += 1
        state.conns.add(tls)
        state.tls_peers.append({"peer": "%s:%d" % addr, "version": tls.version(),
                                "cipher": (tls.cipher() or [None])[0], "conn": conn_id})
    # The 30 s on the raw socket bounds the handshake. A session, once up,
    # is held for as long as the sender holds it: an idle sender is not a
    # failed one, and a receiver that hung up on it would put disconnects
    # into the sender's trail that no assertion asked for.
    tls.settimeout(None)
    buf = b""
    try:
        while True:
            while state.paused:
                time.sleep(0.05)
            try:
                chunk = tls.recv(16384)
            except (socket.timeout, ssl.SSLError, OSError):
                break
            if not chunk:
                break
            throttle(state, len(chunk))
            with state.lock:
                state.bytes += len(chunk)
            buf += chunk
            while True:
                sp = buf.find(b" ")
                if sp < 0:
                    if len(buf) > 10:
                        # a MSG-LEN longer than 10 digits is not a length
                        with state.lock:
                            state.framing_errors += 1
                        return
                    break
                lenb = buf[:sp]
                if not lenb.isdigit() or (len(lenb) > 1 and lenb[0:1] == b"0"):
                    with state.lock:
                        state.framing_errors += 1
                    return  # strict: close on a bad frame, like a real 5425 receiver
                n = int(lenb)
                if n > state.max_msg:
                    with state.lock:
                        state.oversized += 1
                    return
                if len(buf) < sp + 1 + n:
                    break
                msg = buf[sp + 1: sp + 1 + n]
                buf = buf[sp + 1 + n:]
                rec = parse_message(msg, state, conn_id, time.time())
                with state.lock:
                    if "header" in rec["errors"] or "version" in rec["errors"]:
                        state.header_errors += 1
                    if "json" in rec["errors"]:
                        state.json_errors += 1
                    if "sd" in rec["errors"]:
                        state.sd_errors += 1
                    if "header_mismatch" in rec["errors"]:
                        state.header_mismatch += 1
                state.record(rec)
        if buf:
            # bytes left over after the peer closed: a truncated frame
            with state.lock:
                state.framing_errors += 1
    finally:
        with state.lock:
            state.connections_open -= 1
            state.conns.discard(tls)
        try:
            tls.close()
        except OSError:
            pass


def accept_loop(ctx, port, state):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(64)
    print("syslog_receiver: TLS listening on :%d" % port, flush=True)
    conn_id = 0
    while True:
        raw, addr = srv.accept()
        raw.settimeout(30)
        conn_id += 1
        try:
            tls = ctx.wrap_socket(raw, server_side=True)
        except (ssl.SSLError, OSError) as e:
            # A sender that refuses our certificate (wrong CA on its side)
            # shows up here as a handshake failure. Counted as a connection
            # that never became a session — the control is "connections ==
            # 0 while connect attempts > 0".
            with state.lock:
                state.tls_peers.append({"peer": "%s:%d" % addr, "handshake_error": str(e)[:120], "conn": conn_id})
            raw.close()
            continue
        threading.Thread(target=serve_conn, args=(tls, addr, state, conn_id), daemon=True).start()


class Control(BaseHTTPRequestHandler):
    state = None

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        st = self.state
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/__probe":
            return self._send(200, str(len(st.records)), "text/plain")
        if u.path == "/__stats":
            return self._send(200, json.dumps(st.stats(), sort_keys=True))
        if u.path == "/__records":
            since = int(q.get("since", ["0"])[0])
            with st.lock:
                rows = st.records[since:]
            return self._send(200, "".join(json.dumps(r, sort_keys=True) + "\n" for r in rows), "application/x-ndjson")
        if u.path == "/__pause":
            st.paused = True
            return self._send(200, '{"paused": true}')
        if u.path == "/__resume":
            st.paused = False
            return self._send(200, '{"paused": false}')
        if u.path == "/__slow":
            st.bps = int(q.get("bps", ["0"])[0])
            return self._send(200, json.dumps({"bps": st.bps}))
        if u.path == "/__kill":
            with st.lock:
                conns = list(st.conns)
            n = 0
            for c in conns:
                try:
                    # RST, not FIN: the sender must see an abrupt loss, not a clean close
                    c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                    c.close()
                    n += 1
                except OSError:
                    pass
            return self._send(200, json.dumps({"killed": n}))
        if u.path == "/__reset":
            with st.lock:
                st.reset()
                kept = st.kept
            return self._send(200, json.dumps({"reset": True, "kept": kept}))
        return self._send(404, '{"error": "unknown control path"}')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=6514)
    ap.add_argument("--control", default="127.0.0.1:6515")
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--out", default="/tmp/audit-sink-receiver.jsonl")
    ap.add_argument("--overwrite", action="store_true",
                    help="empty --out at start and on /__reset instead of moving what it holds aside")
    ap.add_argument("--max-msg", type=int, default=65536,
                    help="strict receiver cap; a longer frame closes the connection (poison-record arm)")
    ap.add_argument("--pen", type=int, default=0,
                    help="IANA PEN the audit-* SD elements must carry (0 = accept any)")
    ap.add_argument("--sink", default="compliance", help="label only; appears in /__stats")
    ap.add_argument("--min-tls", default="1.2", choices=["1.2", "1.3"])
    args = ap.parse_args()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3 if args.min_tls == "1.3" else ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(args.cert, args.key)

    state = State(args.out, args.max_msg, args.pen, args.sink, args.overwrite)
    if state.kept:
        print("syslog_receiver: %s held an earlier session, kept as %s" % (args.out, state.kept), flush=True)
    Control.state = state
    host, _, port = args.control.rpartition(":")
    ctl = ThreadingHTTPServer((host or "127.0.0.1", int(port)), Control)
    threading.Thread(target=ctl.serve_forever, daemon=True).start()
    print("syslog_receiver: control on http://%s -> %s" % (args.control, args.out), flush=True)
    try:
        accept_loop(ctx, args.port, state)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    sys.exit(main())
