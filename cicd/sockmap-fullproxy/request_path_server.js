// request_path_server.js - HTTP/1.1 backend for the sockmap request-path and
// equivalence scenarios.
//
// Answers every request with what it received, so the client can tell whether
// the proxy delivered the request intact, in order and UNMODIFIED:
//   {"name","method","path","len","sha256","headers"}
// headers is every request header the backend saw (Node lowercases the names),
// which is what makes header injection or removal by the proxy visible to the
// client. len/sha256 cover the request body.
//
// Query knobs, for the response shapes the equivalence suite compares:
//   ?bytes=N   respond with N bytes of PATTERN instead of the JSON echo
//   ?status=N  respond with status N (204/304 carry no body)
//   ?abort=N   write N bytes, promise 2N, then FIN mid-response
//   ?rdelay=N  hold the whole response back N ms (a backend slower than the
//              proxy's deferred-close bound)
//   ?split=N   with ?bytes=: send N bytes at once, the rest after ?rdelay= ms,
//              under the promised Content-Length (a response cut mid-stream)
//   ?chunk=N&gap=M
//              with ?bytes= and no ?split=: send the body N bytes at a time,
//              M ms apart, under the promised Content-Length (slow generation)
//   ?close=1   with ?bytes=: Connection: close — the backend closes once the
//              body is out
//   ?close=2   with ?bytes=: close-delimited — no Content-Length, no chunking;
//              the backend's close is what ends the body
//   ?usage=1   add an OpenAI usage object to the JSON echo. A gateway's
//              capacity unit comes back when it reads one; without it the
//              unit stays with the connection until its next request or its
//              close, so a holder that keeps its connection never frees it
//   ?rpause=N  leave the request body unread for N ms. The socket stops being
//              read, its receive window closes, and whatever the proxy still
//              has to send piles up in the proxy's backend-side cache
//   ?interim=100|103
//              send a 100 Continue or a 103 Early Hints as soon as the request
//              is in, before the answer (which ?rdelay= can hold back)
// A backend that closes part way through a response is ?abort=: it promises
// twice what it sends.
// A HEAD request gets the GET headers and no body.
//
// PATTERN is sha256("sockmap-pattern") in hex, repeated — the client derives the
// same 64 bytes, so a body of any length is verifiable without transferring an
// expected copy.
//
//   node request_path_server.js <name> <port>
var http = require('http');
var crypto = require('crypto');

var name = process.argv[2] || 'server';
var port = parseInt(process.argv[3] || '8080', 10);

var PATTERN = crypto.createHash('sha256').update('sockmap-pattern').digest('hex');

function pattern(n) {
  var out = Buffer.alloc(n);
  for (var off = 0; off < n; off += PATTERN.length) {
    out.write(PATTERN, off, Math.min(PATTERN.length, n - off), 'latin1');
  }
  return out;
}

function query(url, key) {
  var m = url.match(new RegExp('[?&]' + key + '=([0-9]+)'));
  return m ? parseInt(m[1], 10) : null;
}

// Writes body n bytes at a time, gap ms apart, ending with the last piece. A
// client that goes away stops the timer instead of writing into a dead socket.
function paced(res, body, n, gap) {
  var off = 0;
  (function next() {
    if (res.destroyed) {
      return;
    }
    var end = Math.min(off + n, body.length);
    if (end === body.length) {
      res.end(body.slice(off));
      return;
    }
    res.write(body.slice(off, end));
    off = end;
    setTimeout(next, gap);
  })();
}

var server = http.createServer(function (req, res) {
  var hash = crypto.createHash('sha256');
  var len = 0;
  req.on('data', function (chunk) {
    hash.update(chunk);
    len += chunk.length;
  });
  // ?rpause=ms is the request-side counterpart of ?rdelay=: a backend slow to
  // take the request rather than slow to answer it. Paused, the request stream
  // stops Node reading the socket once its own small buffer is full, so a large
  // body stays in the proxy's cache for the backend. A client that half-closes
  // then does so while the proxy still owes the backend part of the request.
  var rpause = query(req.url, 'rpause');
  if (rpause) {
    req.pause();
    setTimeout(function () { req.resume(); }, rpause);
  }
  req.on('end', function () {
    // ?rdelay=ms holds the RESPONSE back by ms before anything is written — the
    // whole answer, not just the FIN (?delay=, below, is the ?abort= FIN knob).
    // It is how the half-close cases reach a backend slower than the proxy's
    // deferred-close bound: answered immediately, a client that shut its write
    // side down is served inside that bound whether or not the proxy actually
    // waits for the response, so an immediate backend cannot tell the two apart.
    //
    // ?split=N pairs with ?bytes= and moves that pause INTO the response: the
    // first N bytes go out at once and the rest follows ?rdelay= later, under
    // the Content-Length already promised. That is the shape real inference
    // traffic has (first token fast, stream for seconds), and it is the one an
    // rdelay-only case cannot produce: with the whole answer held back, a proxy
    // that gives up mid-wait always yields a clean EOF, so a fix that delivers
    // only the opening bytes and drops the rest still looks like a pass.
    // ?interim= puts an interim response ahead of the answer. It is not the
    // answer: a proxy that counts it as one believes the request answered
    // while the answer is still on its way.
    var interim = query(req.url, 'interim');
    if (interim === 100) {
      res.writeContinue();
    } else if (interim === 103) {
      res.writeEarlyHints({ link: '</hint.css>; rel=preload' });
    }

    var rdelay = query(req.url, 'rdelay');
    var split = query(req.url, 'split');
    if (rdelay && split === null) {
      setTimeout(answer, rdelay);
    } else {
      answer();
    }

    function answer() {
      var abort = query(req.url, 'abort');
      if (abort !== null) {
        // ?delay=ms holds the FIN back after the short write. It isolates a race:
        // if a truncation only loses bytes when the FIN follows immediately, the
        // bytes were still in flight when the connection was torn down.
        var delay = query(req.url, 'delay');
        // Headers promise more than is sent, then the socket dies: the client must
        // see the same truncation with and without acceleration.
        res.writeHead(200, { 'Content-Type': 'application/octet-stream',
                             'Content-Length': String(abort * 2) });
        res.write(pattern(abort));
        // FIN, not RST: a reset can make the client's stack discard the bytes it
        // already buffered, which would make the truncation length flaky.
        if (delay) {
          setTimeout(function () { res.socket.end(); }, delay);
        } else {
          res.socket.end();
        }
        return;
      }

      var status = query(req.url, 'status');
      if (status !== null) {
        // 204 and 304 are body-less by definition; Node enforces that.
        res.writeHead(status);
        res.end();
        return;
      }

      var bytes = query(req.url, 'bytes');
      if (bytes !== null) {
        var body = pattern(bytes);
        // ?close= is how a response reaches the proxy's backend-EOF path: this
        // server otherwise keeps every connection alive, so the proxy never
        // sees the backend leave while it still owes the client bytes.
        var close = query(req.url, 'close');
        var hdrs = { 'Content-Type': 'application/octet-stream' };
        if (close === 2) {
          // With no length and chunking off, Node sends the body raw and
          // closes after it: the close is the only end marker.
          res.useChunkedEncodingByDefault = false;
          hdrs['Connection'] = 'close';
        } else {
          hdrs['Content-Length'] = String(body.length);
          if (close === 1) {
            hdrs['Connection'] = 'close';
          }
        }
        res.writeHead(200, hdrs);
        if (req.method === 'HEAD') {
          res.end();
          return;
        }
        if (split !== null && split > 0 && split < body.length) {
          res.write(body.slice(0, split));
          setTimeout(function () { res.end(body.slice(split)); }, rdelay || 0);
          return;
        }
        // ?chunk=&gap= paces the WHOLE body, where ?split= makes one pause.
        // It is the slow-generation shape: the proxy's client-side cache fills
        // and empties once per chunk instead of once per response.
        var chunk = query(req.url, 'chunk');
        if (chunk !== null && chunk > 0 && chunk < body.length) {
          paced(res, body, chunk, query(req.url, 'gap') || 0);
          return;
        }
        res.end(body);
        return;
      }

      var headers = {};
      Object.keys(req.headers).sort().forEach(function (k) {
        headers[k] = req.headers[k];
      });
      var echo = { name: name, method: req.method, path: req.url,
                   len: len, sha256: hash.digest('hex'), headers: headers };
      if (query(req.url, 'usage') === 1) {
        // Last, so it sits in the tail the gateway scans for it.
        echo.usage = { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 };
      }
      var json = JSON.stringify(echo);
      res.writeHead(200, { 'Content-Type': 'application/json',
                           'Content-Length': Buffer.byteLength(json) });
      if (req.method === 'HEAD') {
        res.end();
      } else {
        res.end(json);
      }
    }
  });
});
server.keepAliveTimeout = 30000;
server.listen(port);
