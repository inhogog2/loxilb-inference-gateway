#!/usr/bin/env python3
"""request_path_client.py - raw HTTP/1.1 client for validation_request_path.sh.

Each mode drives one request shape through the proxy against
request_path_server.js, which answers with the path, length and sha256 of the
body it received. A mode prints one line starting with OK or FAIL and exits 0
on OK.

  split     <host> <port> <conns>   first request headers and body in separate
                                    writes, ending with a 1 byte tail; then a
                                    second request whose header block ends in a
                                    separate 2 byte write
  stream    <host> <port> <mb>      streamed upload (application/octet-stream,
                                    above the 64KB streaming threshold) sent
                                    without pauses, then a second request on the
                                    same connection
  pipeline  <host> <port>           three requests in one write, then two more
                                    right behind them
  halfclose <host> <port>           request, then shutdown(SHUT_WR); expects an answer
  halfslow  <host> <port> [ms]      same, against a backend that holds the response
                                    back ms (default 500); expects an answer
  halfsplit <host> <port> [ms]      same, against a backend that sends the opening
                                    bytes at once and the rest ms later; expects
                                    the WHOLE body, not just the opening bytes
  halfmid   <host> <port> [ms]      the same split response, but the client waits
                                    for the opening bytes BEFORE shutdown(SHUT_WR);
                                    expects the whole body
  halfinflight <host> <port>        half-closes while the rest of a 256KB answer is
                                    still in the pipeline; expects the whole body
  halfprefix <host> <port>          the same, but passes on ANY length as long as
                                    what arrived is a correct prefix of the pattern:
                                    a hole or reordering fails, a clean cut does not
  halfpartial <host> <port>         half a request, then shutdown(SHUT_WR); the
                                    connection goes away and the service keeps
                                    serving a fresh one
  halfcork  <host> <port> [ms]      request and FIN in ONE segment (TCP_CORK), so
                                    the FIN is there before the proxy pairs the
                                    connection; backend holds ms (default 500);
                                    expects an answer
  halfafter <host> <port> [ms] [after]
                                    FIN after ms (default 20) past the request,
                                    once the proxy has paired the connection;
                                    backend holds ms (default 500); expects an
                                    answer
  slowread  <host> <port> <query> <rate> [half] [rcvbuf]
                                    GET /slowread?<query>, read at rate bytes/s
                                    through a rcvbuf-byte receive buffer (default
                                    65536); half=1 half-closes after the request.
                                    Expects every promised byte; reports the time
  stall     <host> <port> <query> <secs> [half] [rcvbuf]
                                    GET /stall?<query>, then read NOTHING for secs
                                    (receive window 0), then read everything;
                                    reports what was still delivered
  halfupload <host> <port> <bytes> <rpause_ms> [half] [lull]
                                    POST a <bytes> body to a backend that leaves it
                                    unread for rpause_ms, then shutdown(SHUT_WR)
                                    (half=0: no FIN, the control). With lull, pause
                                    300ms after the first lull bytes; that reaches
                                    the paused shape only when lull is past the
                                    proxy's cache high-water mark plus what the
                                    kernel buffers take (about 13MB), the rest of
                                    the body fits those buffers (a few MB), and
                                    rpause_ms outlasts the writes. Expects the
                                    backend to have received the whole body and
                                    the answer to arrive; reports when the body
                                    was written and when the connection ended
  queuehalf <host> <port> <hold_ms> <first|keepalive> [fin_ms] [model]
                                    against an AI-gateway rule whose pool holds
                                    ONE request: a holder takes the unit for
                                    hold_ms, then a second request parks behind it
                                    and half-closes fin_ms later. first parks the
                                    connection's first request, keepalive its
                                    second. fin_ms < 0 sends no FIN (the control).
                                    Expects the parked request answered
  keepalive <host> <port> <secs> <interval_ms>
                                    one request per interval on one connection
  echo      <host> <port>           one connection, a fixed request sequence
                                    (bodies of 0/100/65535/65536/70000 bytes);
                                    prints one JSON record per request for the
                                    equivalence diff instead of a verdict
  chunked   <host> <port>           Transfer-Encoding: chunked request body
  sizes     <host> <port>           responses of 1/65535/65536/307200/1048576
                                    bytes, verified against the backend pattern
  special   <host> <port>           204, 304 and HEAD on one connection
  abort     <host> <port> [n]       backend promises 2N bytes, sends N, then FIN;
                                    repeated n times (the race is intermittent)
  idle      <host> <port> <secs>    connect, wait secs sending nothing, then use
                                    the connection (it was never accelerated)
  volume    <host> <port> [hold]    one connection, the echo sequence then the
                                    sizes sequence: a fixed byte volume in both
                                    directions for the counter comparison. With
                                    hold, prints DONE and keeps the connection
                                    open for hold seconds before closing it

The echo mode is the only one that prints records rather than OK/FAIL: the
equivalence suite diffs its output across acceleration modes.
"""
import hashlib
import json
import socket
import sys
import threading
import time

TIMEOUT = 10


def connect(host, port):
    s = socket.create_connection((host, port), timeout=TIMEOUT)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return s


class Reader:
    def __init__(self, sock):
        self.sock = sock
        self.buf = b''
        self.head = None   # the last response head split off; None until then

    def _fill(self):
        chunk = self.sock.recv(65536)
        if not chunk:
            raise EOFError('connection closed')
        self.buf += chunk

    def response_full(self, no_body=False):
        """Returns (status, headers dict, body). no_body is for HEAD, where
        Content-Length describes the body a GET would have carried."""
        self.head = None
        while b'\r\n\r\n' not in self.buf:
            self._fill()
        head, self.buf = self.buf.split(b'\r\n\r\n', 1)
        self.head = head
        lines = head.decode('latin-1').split('\r\n')
        status = int(lines[0].split()[1])
        headers = {}
        length = 0
        for line in lines[1:]:
            k, _, v = line.partition(':')
            k = k.strip().lower()
            if not k:
                continue
            headers[k] = v.strip()
            if k == 'content-length':
                length = int(v.strip())
        if no_body:
            length = 0
        while len(self.buf) < length:
            self._fill()
        body, self.buf = self.buf[:length], self.buf[length:]
        return status, headers, body

    def response(self):
        status, _, body = self.response_full()
        return status, body

    def drain(self):
        """Reads whatever is left until EOF. Returns the bytes received."""
        try:
            while True:
                self._fill()
        except (EOFError, ConnectionResetError):
            pass
        out, self.buf = self.buf, b''
        return out


def request(method, path, host, body=b'', ctype='text/plain'):
    head = '%s %s HTTP/1.1\r\nHost: %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n' % (
        method, path, host, ctype, len(body))
    return head.encode(), body


# The backend fills ?bytes= responses with this 64 byte block repeated, so a body
# of any length is verifiable without shipping an expected copy.
PATTERN = hashlib.sha256(b'sockmap-pattern').hexdigest().encode()


def pattern(n):
    return (PATTERN * (-(-n // len(PATTERN))))[:n]


def first_diff(got, want):
    for i in range(min(len(got), len(want))):
        if got[i] != want[i]:
            return i
    return min(len(got), len(want))


def check(status, body, path, payload=b''):
    if status != 200:
        return 'status %d on %s' % (status, path)
    try:
        got = json.loads(body)
    except ValueError:
        return 'unparseable body on %s: %r' % (path, body[:80])
    if got.get('path') != path:
        return 'wrong response: expected %s, got %s' % (path, got.get('path'))
    if got.get('len') != len(payload) or got.get('sha256') != hashlib.sha256(payload).hexdigest():
        return 'body mismatch on %s: sent %d bytes, backend got %s' % (path, len(payload), got.get('len'))
    return None


def mode_split(host, port, conns):
    for c in range(conns):
        s = connect(host, port)
        r = Reader(s)
        payload = (b'split-%d-' % c) * 2000
        head, body = request('POST', '/split1', host, payload)
        s.sendall(head)
        time.sleep(0.01)
        s.sendall(body[:-1])
        time.sleep(0.02)
        s.sendall(body[-1:])
        err = check(*r.response(), '/split1', payload)
        if err:
            return 'FAIL conn %d: %s' % (c, err)
        head, _ = request('GET', '/split2', host)
        s.sendall(head[:-2])
        time.sleep(0.02)
        s.sendall(head[-2:])
        err = check(*r.response(), '/split2')
        if err:
            return 'FAIL conn %d: %s' % (c, err)
        s.close()
    return 'OK %d connections' % conns


def mode_stream(host, port, mb):
    s = connect(host, port)
    r = Reader(s)
    payload = hashlib.sha256(b'seed').digest() * (mb * 1024 * 1024 // 32)
    head, body = request('POST', '/stream', host, payload, 'application/octet-stream')
    s.sendall(head)
    for off in range(0, len(body), 65536):
        s.sendall(body[off:off + 65536])
    err = check(*r.response(), '/stream', payload)
    if err:
        return 'FAIL ' + err
    for i in range(3):
        head, _ = request('GET', '/after%d' % i, host)
        s.sendall(head)
        err = check(*r.response(), '/after%d' % i)
        if err:
            return 'FAIL ' + err
    s.close()
    return 'OK %d bytes' % len(payload)


def mode_pipeline(host, port):
    s = connect(host, port)
    r = Reader(s)
    paths = ['/p1', '/p2', '/p3', '/p4', '/p5']
    bodies = [b'a' * 1000, b'', b'c' * 3000, b'', b'e' * 10]
    reqs = [b''.join(request('POST', p, host, b)) for p, b in zip(paths, bodies)]
    s.sendall(reqs[0] + reqs[1] + reqs[2])
    time.sleep(0.001)
    s.sendall(reqs[3])
    s.sendall(reqs[4])
    for p, b in zip(paths, bodies):
        err = check(*r.response(), p, b)
        if err:
            return 'FAIL ' + err
    s.close()
    return 'OK 5 pipelined requests in order'


def mode_halfclose(host, port):
    s = connect(host, port)
    r = Reader(s)
    head, _ = request('GET', '/halfclose', host)
    s.sendall(head)
    s.shutdown(socket.SHUT_WR)
    err = check(*r.response(), '/halfclose')
    s.close()
    return 'FAIL ' + err if err else 'OK'


def mode_halfslow(host, port, ms=500):
    """halfclose against a slow backend. An immediate backend cannot tell whether
    the proxy waits for the response: it answers inside the proxy's deferred-close
    bound either way. Holding the response past that bound is what distinguishes
    "the response leg is kept open" from "the pair is torn down on a timer".

    Only meaningful through the proxy. Pointed straight at request_path_server.js
    this fails on the backend rather than the proxy: Node's HTTP server destroys a
    connection whose peer half-closes (httpAllowHalfOpen defaults to false). The
    proxy does not propagate the client's FIN to the backend, so the backend never
    sees the half-close on the path under test."""
    s = connect(host, port)
    r = Reader(s)
    path = '/halfslow?rdelay=%d' % ms
    head, _ = request('GET', path, host)
    s.sendall(head)
    s.shutdown(socket.SHUT_WR)
    err = check(*r.response(), path)
    s.close()
    return 'FAIL ' + err if err else 'OK answered after %dms' % ms


def mode_halfsplit(host, port, ms=500):
    """A half-closed client whose answer has already started.

    halfslow holds the whole response back, so a proxy that gives up mid-wait
    always yields a clean EOF and the case cannot tell "nothing was sent" from
    "what was sent got cut". Here the opening bytes arrive at once under a
    promised Content-Length and the rest follows ms later, so a proxy that
    delivers the opening and drops the remainder is a FAIL rather than a pass.
    That is the shape of real inference traffic, and the reason this case exists
    alongside halfslow rather than replacing it.

    Kept small on purpose: an unpatched kernel duplicates bytes on an accelerated
    response at multi-megabyte sizes, which would make the length check meaningless.

    Only meaningful through the proxy, for the reason in mode_halfslow."""
    return _split_case(host, port, ms, '/halfsplit', wait_for_opening=False)


def mode_halfmid(host, port, ms=500):
    """halfsplit, but the client half-closes with the answer already in flight.

    Every other half-* mode shuts its write side down before a single response
    byte exists, so none of them produces the order where the FIN lands on top of
    a response the proxy has already begun. Two things ride on that order:

      - It is the only case that shows layer 1 truncating a stream rather than
        losing it whole: off and request deliver the opening bytes and then drop
        the remainder, where halfsplit has them deliver nothing at all.
      - It is the worst order for a fix that responds to the FIN by dropping the
        connection's acceleration, because the kernel may already hold response
        bytes taken for redirect and no userspace queue can see them.

    Keep it even if that fix is not the one taken: the first point stands on its
    own. Only meaningful through the proxy, for the reason in mode_halfslow."""
    return _split_case(host, port, ms, '/halfmid', wait_for_opening=True)


def mode_halfinflight(host, port):
    """A half-close that lands while the answer is still moving.

    halfmid waits for the opening bytes and the backend then stays silent, so by
    the time the FIN goes out the kernel has delivered everything it was given
    and nothing is in flight. That is the same queue state as halfsplit; what
    halfmid varies is the connection's state, not the kernel's.

    Here the remainder follows the opening immediately and is far larger than one
    buffer hop, so when the client reads its 4096 bytes and half-closes, the rest
    is provably still in the pipeline. It is the order that matters to any fix
    which responds to the FIN by dropping the connection's acceleration: the
    unpair then happens on top of bytes the kernel has taken for redirect and no
    userspace queue can see.

    256KB is under the largest size measured intact on an unpatched kernel
    (300KB); above that an accelerated response duplicates bytes and the length
    check stops meaning anything.

    Expect this to PASS on the arms where it passes today and keep passing: it is
    a regression guard for that fix, not a defect case of its own."""
    return _split_case(host, port, 0, '/halfinflight', wait_for_opening=True,
                       total=262144)


def mode_halfprefix(host, port):
    """halfinflight's shape with a different question.

    halfinflight asked for the whole body, and its answer turned on whether
    256KB beat the proxy's deferred-close bound - which depends on the load in
    front of it, so it was withdrawn. This asks only that whatever DID arrive is
    the pattern's correct prefix: bytes 0..N-1, contiguous. A response cut short
    by the bound still passes, because it is only late. A response with a hole,
    or with a later chunk delivered before an earlier one, fails at the offset.

    That is exactly the split the withdrawn case could not make, and it is the
    failure a fix that drops the connection's acceleration on the FIN could
    introduce: the kernel may still hold response bytes taken for redirect at
    that moment, and if userspace then relays bytes that arrive after them, the
    two orders race to the client. Passes on all four arms today, on purpose -
    it is a guard, and it is registered as nothing."""
    return _split_case(host, port, 0, '/halfprefix', wait_for_opening=True,
                       total=262144, prefix_only=True)


def _prefix_verdict(body, total):
    """None if body is the pattern's correct prefix, else the failing offset."""
    want = pattern(min(len(body), total))
    if body[:len(want)] == want:
        return None
    return first_diff(body, want)


def _split_case(host, port, ms, path_base, wait_for_opening, total=65536,
                prefix_only=False):
    first = 4096
    s = connect(host, port)
    r = Reader(s)
    path = '%s?bytes=%d&split=%d&rdelay=%d' % (path_base, total, first, ms)
    head, _ = request('GET', path, host)
    s.sendall(head)
    if wait_for_opening:
        try:
            while b'\r\n\r\n' not in r.buf or \
                    len(r.buf.split(b'\r\n\r\n', 1)[1]) < first:
                r._fill()
        except (OSError, EOFError) as e:
            return 'FAIL the opening bytes never arrived (%s)' % e
    s.shutdown(socket.SHUT_WR)
    try:
        status, headers, body = r.response_full()
    except (OSError, EOFError) as e:
        if r.head is None:
            return 'FAIL cut before the headers completed (%s)' % e
        got = r.buf
        bad = _prefix_verdict(got, total)
        if bad is not None:
            return 'FAIL body differs at offset %d of %d received (%s)' % (bad, len(got), e)
        if prefix_only:
            return 'OK %d of %d bytes, a correct prefix (cut: %s)' % (len(got), total, e)
        return 'FAIL cut after %d bytes, a correct prefix (%s)' % (len(got), e)
    if status != 200:
        return 'FAIL status %d' % status
    if headers.get('content-length') != str(total):
        return 'FAIL promised %s bytes, expected %d' % (headers.get('content-length'), total)
    if len(body) != total:
        return 'FAIL truncated: promised %d, got %d' % (total, len(body))
    want = pattern(total)
    if body != want:
        return 'FAIL body differs at offset %d' % first_diff(body, want)
    if prefix_only:
        return 'OK %d bytes, the whole body' % total
    return 'OK %d bytes, opening %d then the rest after %dms' % (total, first, ms)


def mode_keepalive(host, port, secs, interval_ms):
    s = connect(host, port)
    r = Reader(s)
    end = time.time() + secs
    ok = 0
    while time.time() < end:
        path = '/ka%d' % ok
        head, _ = request('GET', path, host)
        try:
            s.sendall(head)
            err = check(*r.response(), path)
        except (OSError, EOFError) as e:
            err = str(e)
        if err:
            return 'FAIL after %d requests: %s' % (ok, err)
        ok += 1
        time.sleep(interval_ms / 1000.0)
    s.close()
    return 'OK %d requests' % ok


# One connection, a fixed sequence that crosses the 64KB streaming threshold.
# Request 1 is served by userspace on every mode; requests 2+ are the ones the
# kernel carries once the request direction is active, which is where a skipped
# header rewrite would show up.
ECHO_SEQ = [('GET', '/e1', 0), ('POST', '/e2', 100), ('POST', '/e3', 65535),
            ('POST', '/e4', 65536), ('POST', '/e5', 70000), ('GET', '/e6', 0)]


def mode_echo(host, port):
    s = connect(host, port)
    r = Reader(s)
    out = []
    for i, (method, path, blen) in enumerate(ECHO_SEQ):
        payload = pattern(blen)
        head, body = request(method, path, host, payload)
        s.sendall(head + body)
        status, hdrs, rbody = r.response_full()
        try:
            backend = json.loads(rbody)
        except ValueError:
            backend = {'unparseable': rbody[:120].decode('latin-1')}
        out.append(json.dumps({'i': i, 'req': '%s %s' % (method, path),
                               'sent': blen, 'status': status,
                               'rhdr': hdrs, 'backend': backend},
                              sort_keys=True))
    s.close()
    return '\n'.join(out)


def mode_chunked(host, port):
    s = connect(host, port)
    r = Reader(s)
    payload = pattern(30000)
    head = ('POST /chunked HTTP/1.1\r\nHost: %s\r\nContent-Type: text/plain\r\n'
            'Transfer-Encoding: chunked\r\n\r\n' % host).encode()
    s.sendall(head)
    for off in range(0, len(payload), 4096):
        chunk = payload[off:off + 4096]
        s.sendall(b'%x\r\n' % len(chunk) + chunk + b'\r\n')
    s.sendall(b'0\r\n\r\n')
    err = check(*r.response(), '/chunked', payload)
    if err:
        return 'FAIL ' + err
    head, _ = request('GET', '/afterchunked', host)
    s.sendall(head)
    err = check(*r.response(), '/afterchunked')
    s.close()
    return 'FAIL ' + err if err else 'OK %d bytes chunked, connection reusable' % len(payload)


SIZES = [1, 65535, 65536, 307200, 1048576]


def mode_sizes(host, port):
    s = connect(host, port)
    r = Reader(s)
    for n in SIZES:
        head, _ = request('GET', '/size?bytes=%d' % n, host)
        s.sendall(head)
        status, _, body = r.response_full()
        if status != 200:
            return 'FAIL status %d at bytes=%d' % (status, n)
        if len(body) != n:
            return 'FAIL bytes=%d: received %d bytes' % (n, len(body))
        want = pattern(n)
        if body != want:
            return 'FAIL bytes=%d: content differs at offset %d' % (n, first_diff(body, want))
    s.close()
    return 'OK sizes %s' % ','.join(str(n) for n in SIZES)


def mode_volume(host, port, hold=0):
    s = connect(host, port)
    r = Reader(s)
    n = 0
    for method, path, blen in ECHO_SEQ:
        payload = pattern(blen)
        head, body = request(method, path, host, payload)
        s.sendall(head + body)
        status, _, _ = r.response_full()
        if status != 200:
            return 'FAIL status %d at %s' % (status, path)
        n += 1
    for size in SIZES:
        head, _ = request('GET', '/size?bytes=%d' % size, host)
        s.sendall(head)
        status, _, body = r.response_full()
        if status != 200 or len(body) != size:
            return 'FAIL bytes=%d: status %d, received %d' % (size, status, len(body))
        n += 1
    if hold:
        print('DONE %d requests' % n, flush=True)
        time.sleep(hold)
    s.close()
    return 'OK %d requests' % n


def mode_special(host, port):
    s = connect(host, port)
    r = Reader(s)
    for code in (204, 304):
        head, _ = request('GET', '/special?status=%d' % code, host)
        s.sendall(head)
        status, _, body = r.response_full()
        if status != code or body:
            return 'FAIL status=%d answered %d with %d body bytes' % (code, status, len(body))
    s.sendall(('HEAD /head?bytes=1000 HTTP/1.1\r\nHost: %s\r\n\r\n' % host).encode())
    status, hdrs, body = r.response_full(no_body=True)
    if status != 200 or body:
        return 'FAIL HEAD answered %d with %d body bytes' % (status, len(body))
    if hdrs.get('content-length') != '1000':
        return 'FAIL HEAD content-length %r' % hdrs.get('content-length')
    head, _ = request('GET', '/afterspecial', host)
    s.sendall(head)
    err = check(*r.response(), '/afterspecial')
    s.close()
    return 'FAIL ' + err if err else 'OK 204/304/HEAD, connection reusable'


ABORT_N = 50000


def mode_abort(host, port, n=1, delay=0):
    """Repeated on purpose. When the response direction is accelerated the
    backend's FIN can beat its own redirected bytes to the client, and that race
    is lost only some of the time — a single attempt reports a defect present as
    a pass most runs, which is worse than not testing it."""
    bad = []
    for i in range(n):
        err = _abort_once(host, port, delay)
        if err:
            bad.append(err)
    # The count is always reported, in a fixed shape the suite parses, so a rate
    # that grows is visible even where the case does not fail on it.
    if bad:
        return 'FAIL %d/%d early: %s' % (len(bad), n, bad[0])
    return 'OK 0/%d early' % n


def _abort_once(host, port, delay=0):
    """Returns None when the truncation looked as it does without acceleration,
    or a description of how it differed."""
    s = connect(host, port)
    r = Reader(s)
    head, _ = request('GET', '/abort?abort=%d&delay=%d' % (ABORT_N, delay), host)
    s.sendall(head)
    try:
        while b'\r\n\r\n' not in r.buf:
            r._fill()
    except (EOFError, ConnectionResetError) as e:
        s.close()
        return 'closed before the response headers arrived (%s)' % type(e).__name__
    hdr, r.buf = r.buf.split(b'\r\n\r\n', 1)
    lines = hdr.decode('latin-1').split('\r\n')
    status = int(lines[0].split()[1])
    promised = 0
    for line in lines[1:]:
        k, _, v = line.partition(':')
        if k.strip().lower() == 'content-length':
            promised = int(v.strip())
    body = r.drain()
    s.close()
    if status != 200 or promised != ABORT_N * 2:
        return 'status=%d content-length=%d' % (status, promised)
    if len(body) != ABORT_N:
        return 'delivered %d of the %d bytes the backend sent' % (len(body), ABORT_N)
    if body != pattern(ABORT_N):
        return 'content differs at offset %d' % first_diff(body, pattern(ABORT_N))
    return None


def mode_halfpartial(host, port):
    """A request that stops half way and then half-closes can never complete, so
    the connection must end — either with no answer at all or with a 4xx. What it
    must NOT do is hang, and it must not disturb the service."""
    s = connect(host, port)
    r = Reader(s)
    head, _ = request('GET', '/halfpartial', host)
    s.sendall(head[:len(head) // 2])
    s.shutdown(socket.SHUT_WR)
    got = r.drain()
    s.close()
    answer = 'none'
    if got:
        first = got.split(b'\r\n', 1)[0].decode('latin-1')
        if not first.startswith('HTTP/1.'):
            return 'FAIL a partial request drew a non-HTTP answer: %r' % got[:80]
        code = first.split()[1] if len(first.split()) > 1 else '?'
        if not code.startswith('4'):
            return 'FAIL a partial request was answered %s' % first
        answer = code
    s2 = connect(host, port)
    r2 = Reader(s2)
    head, _ = request('GET', '/afterpartial', host)
    s2.sendall(head)
    err = check(*r2.response(), '/afterpartial')
    s2.close()
    if err:
        return 'FAIL ' + err
    return 'OK partial request closed (answer: %s), service intact' % answer


def mode_halfcork(host, port, ms=500):
    """The FIN reaches the proxy with the request, before it pairs anything.

    halfclose's FIN leaves a few microseconds after the request, so whether it
    lands before or after the proxy installs the socket pair is a race. Corked,
    the request stays in the send queue and shutdown(SHUT_WR) puts the FIN on
    that same segment: by the time the proxy reads the request, the socket has
    already received the FIN. The request must fit one segment for that, which
    a bodyless GET does on any link.

    Same backend hold as halfslow, for the same reason: an answer that beats
    the proxy's deferred-close bound cannot show whether the proxy waited."""
    s = socket.create_connection((host, port), timeout=TIMEOUT)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_CORK, 1)
    path = '/halfcork?rdelay=%d' % ms
    head, _ = request('GET', path, host)
    t0 = time.time()
    s.sendall(head)
    s.shutdown(socket.SHUT_WR)
    return _half_verdict(s, t0, path, ms)


def _half_verdict(s, t0, path, ms):
    """The answer, or when and how the connection ended without one: a cut
    near 0ms and one near the proxy's deferred-close bound are different
    layers of the same defect."""
    status, got, at = _outcome(Reader(s), t0)
    s.close()
    if status is None:
        return 'FAIL cut at %.0fms (%s), backend holds %dms' % (at, got, ms)
    err = check(status, got, path)
    return 'FAIL ' + err if err else 'OK answered at %.0fms' % at


def mode_halfafter(host, port, ms=500, after=20):
    """The FIN reaches the proxy after it has paired the connection, but early:
    after ms past the request, while the backend is still holding the answer
    for ms.

    The backend connect is sub-millisecond on this testbed, so 20ms is well past
    the pairing and still well inside the 100ms that separates a half-close's
    FIN from a cancel's. That is the population a close-time fix cannot reach
    without undoing the pairing, which is what makes it a separate case from
    halfcork."""
    s = connect(host, port)
    path = '/halfafter?rdelay=%d' % ms
    head, _ = request('GET', path, host)
    t0 = time.time()
    s.sendall(head)
    time.sleep(after / 1000.0)
    s.shutdown(socket.SHUT_WR)
    return _half_verdict(s, t0, path, ms)


def _query_int(query, key):
    for part in query.split('&'):
        k, _, v = part.partition('=')
        if k == key and v.isdigit():
            return int(v)
    return None


def _small_rcvbuf_connect(host, port, rcvbuf, timeout):
    """Connects with the receive buffer fixed BEFORE the handshake: the window
    scale is chosen then, and a buffer set afterwards still lets the window
    open as far as autotuning had taken it."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if rcvbuf:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
    s.settimeout(timeout)
    s.connect((host, port))
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return s


def _read_head(r):
    """Returns (status, promised length or None) and leaves the body bytes
    already received in r.buf."""
    while b'\r\n\r\n' not in r.buf:
        r._fill()
    head, r.buf = r.buf.split(b'\r\n\r\n', 1)
    r.head = head
    lines = head.decode('latin-1').split('\r\n')
    promised = None
    for line in lines[1:]:
        k, _, v = line.partition(':')
        if k.strip().lower() == 'content-length':
            promised = int(v.strip())
    return int(lines[0].split()[1]), promised


def _body_verdict(body, want, t, how):
    """The common report of the slow-reader cases: how much of the promised
    body arrived, whether it is the pattern's correct prefix, and when."""
    bad = _prefix_verdict(body, len(body))
    if bad is not None:
        return 'FAIL body differs at offset %d of %d received at %.1fs' % (bad, len(body), t)
    if want is not None and len(body) == want:
        return 'OK %d bytes at %.1fs' % (want, t)
    return 'FAIL cut after %d of %s bytes at %.1fs (%s)' % (
        len(body), want if want is not None else '?', t, how)


def mode_slowread(host, port, query, rate, half=0, rcvbuf=65536):
    """A client that keeps reading, slower than the backend writes.

    The body is ?bytes= of the pattern under whatever else the query asks the
    backend for (?close=, ?chunk=&gap=, or ?abort= for a backend that leaves
    part way). A close-delimited body has no length, so the expected length is
    the query's bytes=. The receive buffer is fixed small so the backlog sits
    in the proxy rather than in this socket, and the report carries the time
    the answer ended: the cases this serves are told apart by WHEN a cut
    happens, not only whether it does."""
    s = _small_rcvbuf_connect(host, port, rcvbuf, 60)
    r = Reader(s)
    path = '/slowread?%s' % query
    head, _ = request('GET', path, host)
    t0 = time.time()
    s.sendall(head)
    if half:
        s.shutdown(socket.SHUT_WR)
    try:
        status, promised = _read_head(r)
    except (OSError, EOFError) as e:
        return 'FAIL cut before the headers completed at %.1fs (%s)' % (time.time() - t0, e)
    if status != 200:
        return 'FAIL status %d' % status
    want = promised if promised is not None else _query_int(query, 'bytes')
    body, r.buf = r.buf, b''
    how = 'EOF'
    start = time.time()
    try:
        while want is None or len(body) < want:
            allowance = int(rate * (time.time() - start)) - len(body)
            if allowance <= 0:
                time.sleep(0.01)
                continue
            chunk = s.recv(min(65536, allowance))
            if not chunk:
                break
            body += chunk
    except socket.timeout:
        how = 'no byte for 60s'
    except OSError as e:
        how = type(e).__name__
    s.close()
    return _body_verdict(body, want, time.time() - t0, how)


def mode_stall(host, port, query, secs, half=1, rcvbuf=4096):
    """A client that stops reading: its receive window closes and stays shut
    for secs. Then it reads everything as fast as it can and reports what was
    still delivered — a proxy that gave up on it during the stall has closed
    its end, so what arrives is the bytes that were already in the kernel and
    then an EOF (or a reset) short of the promised length."""
    s = _small_rcvbuf_connect(host, port, rcvbuf, 30)
    r = Reader(s)
    path = '/stall?%s' % query
    head, _ = request('GET', path, host)
    t0 = time.time()
    s.sendall(head)
    if half:
        s.shutdown(socket.SHUT_WR)
    time.sleep(secs)
    try:
        status, promised = _read_head(r)
    except (OSError, EOFError) as e:
        return 'FAIL cut before the headers completed, read at %.1fs (%s)' % (time.time() - t0, e)
    if status != 200:
        return 'FAIL status %d' % status
    want = promised if promised is not None else _query_int(query, 'bytes')
    body, r.buf = r.buf, b''
    how = 'EOF'
    try:
        while want is None or len(body) < want:
            chunk = s.recv(65536)
            if not chunk:
                break
            body += chunk
    except socket.timeout:
        how = 'no byte for 30s'
    except OSError as e:
        how = type(e).__name__
    s.close()
    return _body_verdict(body, want, time.time() - t0, how)


def mode_halfupload(host, port, nbytes, rpause, half=1, lull=0):
    """A half-close that lands while the proxy still owes the backend part of
    the request.

    The other half-* modes send a request that fits the socket buffers, so by
    the time the FIN arrives the proxy has handed the backend every byte. Here
    the backend leaves the body unread for rpause ms, the rest of it waits in
    the proxy's cache for the backend, and the FIN reaches the proxy on top of
    that. Which shape the proxy then sees depends on how much of the body is
    cached: below the cache's high-water mark the client is still being read
    and the FIN goes down the EOF path; above it the client is paused and the
    FIN is seen while it waits. The size alone does not decide it (the kernel
    buffers on the way take a share first), so the harness tells the two apart
    from the proxy's log, not from nbytes.

    The proxy checks its cache against the high-water mark once per read
    event, and one event can read a great deal, so a client that writes the
    whole body at once can run the cache well past the mark without ever being
    paused. lull makes the pause reachable: the client stops for 300ms after
    the first lull bytes, the proxy's read event ends, and the next one finds
    the cache over the mark. Three things have to hold for that. The first
    lull bytes must leave more than the mark in the cache once the kernel
    buffers on the way have taken their share (lull of about 13MB against a
    12MB mark). The rest of the body must fit the client's send buffer and the
    proxy's receive buffer, so sendall() returns and the FIN goes out while the
    proxy is paused; a larger rest blocks until the backend reads again, and
    the rest and the FIN then arrive in one read event down the EOF path. And
    rpause must outlast the client's writes.

    The body is application/octet-stream, the proxy's streamed-upload path.
    sendall() can block while the proxy is paused; the report says when it
    returned, which is when the FIN left."""
    s = connect(host, port)
    s.settimeout(rpause / 1000.0 + 30)
    payload = pattern(nbytes)
    path = '/halfupload?rpause=%d' % rpause
    head, body = request('POST', path, host, payload, 'application/octet-stream')
    t0 = time.time()
    try:
        if 0 < lull < len(body):
            s.sendall(head + body[:lull])
            time.sleep(0.3)
            s.sendall(body[lull:])
        else:
            s.sendall(head + body)
        sent = (time.time() - t0) * 1000
        if half:
            s.shutdown(socket.SHUT_WR)
    except OSError as e:
        # The proxy can drop the connection while this is still writing; say
        # when, rather than leave main() to report the bare exception.
        s.close()
        return 'FAIL write %s at %.0fms, backend reads after %dms' % (
            type(e).__name__, (time.time() - t0) * 1000, rpause)
    status, got, at = _outcome(Reader(s), t0)
    s.close()
    if status is None:
        # The FIN left when the writes returned: the cut measured from it is
        # the figure to compare against the proxy's close bounds.
        fin = ', FIN+%.0fms' % (at - sent) if half else ''
        return 'FAIL cut at %.0fms (%s%s), body of %d written by %.0fms, backend reads after %dms' % (
            at, got, fin, nbytes, sent, rpause)
    err = check(status, got, path, payload)
    if err:
        return 'FAIL %s at %.0fms' % (err, at)
    return 'OK answered at %.0fms, body of %d written by %.0fms' % (at, nbytes, sent)


def ai_request(path, host, model, content):
    """An inference request: the capacity gate counts only a POST to a known
    inference path, and an AI-gateway rule routes on the model it names."""
    body = json.dumps({'model': model,
                       'messages': [{'role': 'user', 'content': content}]}).encode()
    head, body = request('POST', path, host, body, 'application/json')
    return head + body, body


def _outcome(r, t0):
    """(status, body, ms since t0) for one response, or (None, what ended it,
    ms since t0) when none arrived."""
    try:
        status, _, body = r.response_full()
        return status, body, (time.time() - t0) * 1000
    except socket.timeout:
        return None, 'timeout', (time.time() - t0) * 1000
    except EOFError:
        return None, 'EOF', (time.time() - t0) * 1000
    except OSError as e:
        return None, type(e).__name__, (time.time() - t0) * 1000


def mode_queuehalf(host, port, hold_ms, entry, fin_ms=0, model='hc-model'):
    """A request that half-closes while it waits in the service queue.

    The rule's pool must admit ONE request at a time and queue the rest. A
    holder takes that unit for hold_ms; the request under test arrives behind
    it, parks, and half-closes fin_ms after it was sent. Two ways into the park,
    because the proxy parks them at different places: the first request of a
    connection parks before the connection has a backend leg, a keep-alive
    request parks after the previous request released its leg.

    The report carries both times. A parked request that is cut near fin_ms was
    dropped while it waited; one cut near hold_ms was dropped when it resumed;
    one answered near hold_ms waited and was served. Every response carries a
    usage object, as an inference backend's does: that is what hands the unit
    back when the response completes. A negative fin_ms sends no
    FIN at all: the control, which shows the park itself serves the request."""
    kept = None
    if entry == 'keepalive':
        kept = connect(host, port)
        kr = Reader(kept)
        kept.sendall(ai_request('/v1/chat/completions?qh=warm&usage=1', host, model, 'warm')[0])
        status, _ = kr.response()
        if status != 200:
            return 'FAIL the warm-up request was answered %d' % status
    elif entry != 'first':
        return 'FAIL entry must be first or keepalive, not %r' % entry
    holder = connect(host, port)
    holder.settimeout(hold_ms / 1000.0 + 15)
    hr = Reader(holder)
    th = time.time()
    holder.sendall(ai_request('/v1/chat/completions?qh=holder&usage=1&rdelay=%d' % hold_ms,
                              host, model, 'holder')[0])
    # Read on its own thread: its answer is due while the parked request is
    # still waiting, and the time it lands is the time the unit came back.
    held = []
    ht = threading.Thread(target=lambda: held.append(_outcome(hr, th)))
    ht.start()
    # The holder's request is admitted within a millisecond on this testbed;
    # this only has to be long enough that the parked request comes second.
    time.sleep(0.3)
    s = kept if kept is not None else connect(host, port)
    s.settimeout(hold_ms / 1000.0 + 15)
    r = kr if kept is not None else Reader(s)
    path = '/v1/chat/completions?qh=%s&usage=1' % entry
    wire, payload = ai_request(path, host, model, entry)
    t0 = time.time()
    s.sendall(wire)
    if fin_ms > 0:
        time.sleep(fin_ms / 1000.0)
    if fin_ms >= 0:
        s.shutdown(socket.SHUT_WR)
    status, got, ms = _outcome(r, t0)
    s.close()
    ht.join()
    holder.close()
    hstatus, hgot, hms = held[0]
    hold = 'holder %s at %.0fms' % (hstatus if hstatus else hgot, hms)
    if status is None:
        return 'FAIL parked %s request lost: %s at %.0fms, FIN at %dms (%s)' % (
            entry, got, ms, fin_ms, hold)
    err = check(status, got, path, payload)
    if err:
        return 'FAIL parked %s request: %s at %.0fms (%s)' % (entry, err, ms, hold)
    return 'OK parked %s request answered at %.0fms, FIN at %dms (%s)' % (
        entry, ms, fin_ms, hold)


def mode_idle(host, port, secs):
    """Connects, sends nothing for secs, then uses the connection. A connection
    that has not sent a request has no socket pair, so it is NOT accelerated: an
    admin teardown of the rule's accelerated connections must leave it alone."""
    s = connect(host, port)
    r = Reader(s)
    time.sleep(secs)
    head, _ = request('GET', '/idle', host)
    s.sendall(head)
    err = check(*r.response(), '/idle')
    s.close()
    return 'FAIL ' + err if err else 'OK idle connection usable after %ss' % secs


# Modes that print records for the equivalence diff instead of a verdict.
RECORD_MODES = {'echo'}

MODES = {'split': mode_split, 'stream': mode_stream, 'pipeline': mode_pipeline,
         'halfclose': mode_halfclose, 'halfslow': mode_halfslow,
         'halfsplit': mode_halfsplit, 'halfmid': mode_halfmid,
         'halfinflight': mode_halfinflight, 'halfprefix': mode_halfprefix,
         'halfpartial': mode_halfpartial, 'halfcork': mode_halfcork,
         'halfafter': mode_halfafter, 'slowread': mode_slowread,
         'stall': mode_stall, 'queuehalf': mode_queuehalf,
         'halfupload': mode_halfupload,
         'keepalive': mode_keepalive, 'echo': mode_echo, 'chunked': mode_chunked,
         'sizes': mode_sizes, 'special': mode_special, 'abort': mode_abort,
         'idle': mode_idle, 'volume': mode_volume}


def main():
    mode, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
    args = [int(a) if a.lstrip('-').isdigit() else a for a in sys.argv[4:]]
    failed = False
    try:
        out = MODES[mode](host, port, *args)
    except (OSError, EOFError, ValueError) as e:
        out = 'FAIL %s: %s' % (type(e).__name__, e)
        failed = True
    print(out)
    if mode in RECORD_MODES:
        sys.exit(1 if failed else 0)
    sys.exit(0 if out.startswith('OK') else 1)


if __name__ == '__main__':
    main()
