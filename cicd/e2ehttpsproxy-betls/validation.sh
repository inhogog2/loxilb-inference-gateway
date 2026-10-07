#!/bin/bash
# Qualification of the backend leg of an end-to-end HTTPS rule.
#
# Every backend is a fixture server that reports, per request, the SHA-256 of
# the client certificate it was shown and the server name it was asked for,
# and that appends the nonce of the request to a receipt file. So:
#
#   served   = an HTTP 200 whose body carries the nonce, AND the nonce is in
#              the receipt file of the backend that was meant to answer;
#   rejected = the client got the gateway's own error for a backend it could
#              not connect to, within the time a handshake takes, the gateway
#              logged a failed handshake with that backend for this request,
#              AND the nonce is in no receipt file. A request that only timed
#              out is not a rejection;
#   turned away = the same answer, for a backend that accepted the gateway's
#              handshake and closed the connection afterwards (it wanted a
#              client certificate it was not shown, or does not accept the
#              one it was shown). The gateway logs that failure under its
#              own line, and the nonce is in no receipt file.
#
# An answer the gateway writes itself must also be whole: curl has to end
# with exit 0. A status line followed by a cut connection is not an answer
# a client can rely on. curl is not the whole test of that: a recent curl
# accepts an HTTP/1.1 response that ends without a TLS close_notify and an
# older one ends with exit 56. So an HTTP/1.1 answer is also read by a client
# that accepts nothing less: its Content-Length is the size of its body, and
# the TLS stream ends with a close_notify.
#
# A backend that must be rejected is first reached through the same rule
# without verification: what turns it away afterwards is the policy, not a
# backend that could not serve.
source ../common.sh
echo SCENARIO-e2ehttps-betls-qualification

ROOT=http://localhost:11111/netlox/v1
API=$ROOT/config
VIP=10.10.10.254
EP1=31.31.31.1
EP2=32.32.32.1
NAME=backend.betls.test
RUN=$(date +%s)$$
code=0
seq=0

fail() { echo "  FAIL: $*"; code=1; }
pass() { echo "  ok: $*"; }

gw_pid() { $dexec llb1 pidof loxilb 2>/dev/null | tr -d '\r'; }
dp_log() { $dexec llb1 cat /var/log/loxilbdp.log 2>/dev/null; }
replaced() { dp_log | grep -c ":$1 rule [0-9]* backend TLS policy replaced"; }
kept() { dp_log | grep -c ":$1 rule [0-9]* backend TLS policy not replaced"; }
# Client connections of a listener closed because their backend connection
# was made under a policy that has since been replaced, by the reason logged.
drained() { dp_log | grep -c ":$1 backend TLS policy replaced: closing client fd=[0-9]*, .*($2)"; }
expect_drained() { # port, reason, count before, seconds to wait, what
  for i in $(seq 1 $4); do [ "$(drained $1 "$2")" -gt "$3" ] && break; sleep 1; done
  [ "$(drained $1 "$2")" -gt "$3" ] && pass "$5" || fail "not seen in the data plane log within $4 s: $5"
}
# Failed TLS handshakes of the gateway with one backend.
hs_failed() { dp_log | grep -cF "ssl-connect $1:$2(failed)"; }
# Backend legs that failed after their handshake, before any response.
late_failed() { dp_log | grep -cF "ssl-read $1:$2(failed after handshake, before any response)"; }
fp() { cat pki/$1.fp; }
receipts() { cat pki/receipts/*.txt 2>/dev/null | grep -cx "$1"; }
receipt_of() { grep -cx "$2" pki/receipts/$1.txt 2>/dev/null; }

cert_json() { # id, usage, cert file, [key file]
  python3 - "$@" <<'PY'
import json, sys
d = {"certId": sys.argv[1], "usage": sys.argv[2], "certPem": open(sys.argv[3]).read()}
d["keyPem"] = open(sys.argv[4]).read() if len(sys.argv) > 4 else ""
print(json.dumps(d))
PY
}
post_cert() { cert_json "$@" | $dexec llb1 curl -s -o /dev/null -w '%{http_code}' -X POST $API/cert -H "Content-Type: application/json" -d @-; }
# These two print the answer's body, then its status on a line of its own.
post_cert_answer() { cert_json "$@" | $dexec llb1 curl -s -w '\n%{http_code}' -X POST $API/cert -H "Content-Type: application/json" -d @-; }
put_cert() { cert_json "$@" | $dexec llb1 curl -s -w '\n%{http_code}' -X PUT $API/cert/$1 -H "Content-Type: application/json" -d @-; }
del_cert() { $dexec llb1 curl -s -o /dev/null -w '%{http_code}' -X DELETE $API/cert/$1; }

# One rule, one endpoint: a request has nowhere else to go.
post_rule() { # port, endpoint address, endpoint port, extra serviceArguments (JSON members, leading comma)
  $dexec llb1 curl -s -o /dev/null -w '%{http_code}' -X POST $API/loadbalancer \
    -H "Content-Type: application/json" -d '{
  "serviceArguments": { "externalIP": "'$VIP'", "port": '$1', "protocol": "tcp",
    "security": 2, "mode": 4, "host": "'$VIP'"'"$4"' },
  "endpoints": [ { "endpointIP": "'$2'", "targetPort": '$3', "weight": 1 } ]}'
}
del_rule() {
  $dexec llb1 curl -s -o /dev/null -w '%{http_code}' -X DELETE \
    "$API/loadbalancer/hosturl/$VIP/externalipaddress/$VIP/port/$1/protocol/tcp"
}
# What the data plane has installed for the backend leg of the rule on a
# port: "status verify ca client_cert client_cert_id server_name generation".
effective() {
  $dexec llb1 curl -s $API/loadbalancer/all | python3 -c "
import sys, json
for r in json.load(sys.stdin).get('lbAttr') or []:
    s = r.get('serviceArguments') or {}
    if s.get('port') == $1 and s.get('host') == '$VIP':
        e = s.get('backend_tls_effective')
        if e is None:
            print('absent')
        else:
            print(e.get('status'), e.get('verify'), e.get('ca'), e.get('client_cert'), e.get('client_cert_id'), e.get('server_name'), e.get('generation'))
" 2>/dev/null
}
generation() { local e; e=$(effective $1); echo "${e##* }"; }
expect_effective() { # port, want (without the generation), what
  local got; got=$(effective $1); got=${got% *}
  [ "$got" == "$2" ] && pass "GET reports what is installed $3: $got" || fail "GET reports '$got' $3, want '$2'"
}
expect_replaced() { # port, count before
  for i in $(seq 1 20); do [ "$(replaced $1)" -gt "$2" ] && break; sleep 1; done
  [ "$(replaced $1)" -gt "$2" ] && pass "the listener on $1 took the new backend policy in place" \
    || fail "the data plane did not replace the backend policy of the listener on $1"
}

# One request on a connection of its own. Sets R_NONCE, R_CODE, R_TIME, R_BODY
# and R_EXIT, curl's own verdict on the exchange.
request() { # port, http1.1 | http2
  local out
  seq=$((seq + 1)); R_NONCE="q$RUN-$seq"
  out=$($hexec l3h1 curl -s --$2 --cacert pki/ca-a.crt --max-time 15 \
    -w '\n%{http_code} %{time_total}' "https://$VIP:$1/?nonce=$R_NONCE" 2>/dev/null)
  R_EXIT=$?
  R_BODY=${out%$'\n'*}
  R_CODE=${out##*$'\n'}; R_TIME=${R_CODE#* }; R_CODE=${R_CODE% *}
}
field() { local f; for f in $R_BODY; do [[ "$f" == $1=* ]] && echo "${f#*=}"; done; }
record() { # case, port, expected fingerprint, result
  echo "  record: case='$1' nonce=$R_NONCE generation=$(generation $2) expected_peer=$3 result=$4 http=$R_CODE curl_exit=$R_EXIT time=${R_TIME}s receipts=$(receipts $R_NONCE) answer='${R_BODY:0:200}'"
}
# The gateway's own answer reached the client whole.
expect_whole() { # case
  [ "$R_EXIT" == "0" ] && pass "$1: the answer is whole (curl exit 0)" \
    || fail "$1: curl ended with exit $R_EXIT, the answer was cut or never came"
  [[ "$R_BODY" == *backend_unreachable* ]] && pass "$1: the body says backend_unreachable" \
    || fail "$1: the body does not say backend_unreachable: '${R_BODY:0:160}'"
}

# The request is answered by the named backend, which saw the named client
# certificate (or none) and was asked for the named server (or none).
expect_served() { # case, port, protocol, backend, client certificate | none, server name | none
  local want_peer=none want_proto=HTTP/1.1 ok=1
  [ "$5" != "none" ] && want_peer=$(fp $5)
  [ "$3" == "http2" ] && want_proto=HTTP/2.0
  request $2 $3
  [ "$R_CODE" == "200" ] || ok=0
  [ "$(field name)" == "$4" ] || ok=0
  [ "$(field nonce)" == "$R_NONCE" ] || ok=0
  [ "$(field proto)" == "$want_proto" ] || ok=0
  [ "$(receipt_of $4 $R_NONCE)" == "1" ] || ok=0
  record "$1" $2 $want_peer served
  if [ $ok == 1 ]; then
    pass "$1: answered by backend '$4' over $want_proto, and its receipt has the request"
  else
    fail "$1: not served by backend '$4' over $want_proto (status $R_CODE, receipt $(receipt_of $4 $R_NONCE))"
    return
  fi
  [ "$(field peer)" == "$want_peer" ] && pass "$1: the backend saw the client certificate '$5'" \
    || fail "$1: the backend saw client certificate $(field peer), want '$5' = $want_peer"
  [ "$(field sni)" == "$6" ] && pass "$1: the backend was asked for server name '$6'" \
    || fail "$1: the backend was asked for server name '$(field sni)', want '$6'"
}
# One HTTP/1.1 request read to the end of the TLS stream by a client that does
# not forgive a missing close_notify. Prints "status content-length body-bytes
# end", where end is "clean" for a close_notify.
STRICT_CLIENT='
import socket, ssl, sys
host, port, ca, nonce = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
ctx = ssl.create_default_context(cafile=ca)
ctx.set_alpn_protocols(["http/1.1"])
tls = ctx.wrap_socket(socket.create_connection((host, port), timeout=10),
                      server_hostname=host, suppress_ragged_eofs=False)
tls.sendall(("GET /?nonce=%s HTTP/1.1\r\nHost: %s:%d\r\nAccept: */*\r\n\r\n" % (nonce, host, port)).encode())
data, end = b"", "clean"
try:
    while True:
        chunk = tls.recv(4096)
        if not chunk:
            break
        data += chunk
except ssl.SSLEOFError:
    end = "no-close-notify"
except Exception as e:
    end = "error-" + type(e).__name__
head, _, body = data.partition(b"\r\n\r\n")
lines = head.split(b"\r\n")
status = lines[0].split()[1].decode() if len(lines[0].split()) > 1 else "000"
length = "none"
for line in lines[1:]:
    if line.lower().startswith(b"content-length:"):
        length = line.split(b":", 1)[1].strip().decode()
print(status, length, len(body), end)'
expect_strict() { # case, port
  local got n
  seq=$((seq + 1)); n="q$RUN-$seq"
  got=$($hexec l3h1 python3 -c "$STRICT_CLIENT" $VIP $2 pki/ca-a.crt $n 2>&1 | tail -1)
  set -- "$1" $got
  echo "  record: case='$1' nonce=$n strict client: status=$2 content-length=$3 body=$4 end=$5 receipts=$(receipts $n)"
  [ "$2" == "502" ] && pass "$1: a strict client got the 502" || fail "$1: a strict client got status '$2'"
  [[ "$3" != "none" && "$3" == "$4" && "$4" -gt 0 ]] && pass "$1: Content-Length is the size of the body ($4 bytes)" \
    || fail "$1: Content-Length '$3' against a body of '$4' bytes"
  [ "$5" == "clean" ] && pass "$1: the TLS stream ended with a close_notify" \
    || fail "$1: the TLS stream ended with '$5', not a close_notify"
  [ "$(receipts $n)" == "0" ] && pass "$1: no backend has that request either" \
    || fail "$1: the strict client's request reached a backend"
}

# The request is turned away by the gateway and reaches no backend.
expect_rejected() { # case, port, protocol, endpoint address, endpoint port
  local want=502 before
  [ "$3" == "http2" ] && want=503
  before=$(hs_failed $4 $5)
  request $2 $3
  record "$1" $2 - rejected
  [ "$R_CODE" == "$want" ] && pass "$1: the client got the gateway's $want" \
    || fail "$1: the client got '$R_CODE', want the gateway's $want"
  expect_whole "$1"
  python3 -c "import sys; sys.exit(0 if float('${R_TIME:-99}') < 5 else 1)" \
    && pass "$1: answered in ${R_TIME}s, not by a timeout" || fail "$1: took ${R_TIME}s, a timeout is not a rejection"
  [ "$(hs_failed $4 $5)" -gt "$before" ] && pass "$1: the gateway dialled $4:$5 anew and the handshake failed" \
    || fail "$1: the gateway logged no failed handshake with $4:$5 for this request"
  [ "$(receipts $R_NONCE)" == "0" ] && pass "$1: no backend has the request" \
    || fail "$1: the request reached a backend ($(receipts $R_NONCE) receipt)"
  [ "$3" == "http1.1" ] && expect_strict "$1" $2
}

# The request is turned away by the gateway because the backend closed the
# connection after the handshake. The client gets the answer of a backend that
# could not be connected to, and the gateway's log names the endpoint.
expect_turned_away() { # case, port, protocol, endpoint address, endpoint port
  local want=502 before
  [ "$3" == "http2" ] && want=503
  before=$(late_failed $4 $5)
  request $2 $3
  record "$1" $2 - turned-away
  [ "$R_CODE" == "$want" ] && pass "$1: the client got the gateway's $want" \
    || fail "$1: the client got '$R_CODE', want the gateway's $want"
  expect_whole "$1"
  python3 -c "import sys; sys.exit(0 if float('${R_TIME:-99}') < 5 else 1)" \
    && pass "$1: answered in ${R_TIME}s, not by a timeout" || fail "$1: took ${R_TIME}s"
  [ "$(late_failed $4 $5)" -gt "$before" ] && pass "$1: the gateway logged that $4:$5 closed after the handshake" \
    || fail "$1: the gateway logged no failure after the handshake with $4:$5"
  [ "$(receipts $R_NONCE)" == "0" ] && pass "$1: no backend has the request" \
    || fail "$1: the request reached a backend ($(receipts $R_NONCE) receipt)"
  [ "$3" == "http1.1" ] && expect_strict "$1" $2
}

serve() { # host, name, port, certificate, extra arguments
  $hexec $1 ./fixture serve -name $2 -port $3 -cert pki/$4.crt -key pki/$4.key \
    -receipts pki/receipts/$2.txt -clientca pki/ca-a.crt $5 > /dev/null 2>&1 &
  track_helper
}
serve l3ep1 good 9443 good-rsa -require
serve l3ep1 optional 9444 good-rsa
serve l3ep1 wrongca 9445 wrongca
serve l3ep1 expired 9446 expired
serve l3ep1 wrongip 9447 wrongip
serve l3ep1 dnsonly 9448 dnsonly
serve l3ep1 wrongdns 9449 wrongdns
serve l3ep2 good-ecdsa 9443 good-ecdsa -require
sleep 5

VERIFY='"mtls_backend": {"verify_server_cert": true}, "backend_ca_cert_id": "qual-ca"'
H2=', "backend_protocol": "http2"'

pid0=$(gw_pid)
[ -n "$pid0" ] || fail "precondition: the gateway is not running"

echo "Build under test"
echo "  record: image=$(sudo docker inspect llb1 --format '{{.Config.Image}} {{.Image}}' 2>/dev/null)"
echo "  record: gateway=$($dexec llb1 /root/loxilb-io/loxilb/loxilb --version 2>&1 | tr '\n' ' ' | cut -c1-200)"
caps=$($dexec llb1 curl -s $ROOT/status/capabilities)
echo "  record: capability=$(echo "$caps" | python3 -c "
import sys, json
print([c for c in json.load(sys.stdin)['capabilities'] if c['name'] == 'backend_tls_verify'])" 2>/dev/null)"
ready=$(echo "$caps" | python3 -c "
import sys, json
c = [x for x in json.load(sys.stdin)['capabilities'] if x['name'] == 'backend_tls_verify']
print('yes' if len(c) == 1 and c[0]['ready'] is True else 'no')" 2>/dev/null)

if [ "$ready" != "yes" ]; then
  # A build that cannot verify a backend. It must say so, refuse a rule that
  # asks for a backend policy, and never report a leg as protected.
  echo "A build without backend verification"
  [[ "$caps" == *'"name":"backend_tls_verify"'* ]] && pass "the capability is listed, and not ready" \
    || fail "backend_tls_verify is not in the capabilities"
  [ "$(post_cert qual-ca ca pki/ca-a.crt)" == "201" ] || fail "precondition: the CA bundle could not be registered"
  [ "$(post_cert qual-client-rsa client pki/client-rsa.crt pki/client-rsa.key)" == "201" ] || fail "precondition: the client certificate could not be registered"
  rc=$(post_rule 2051 $EP1 9444 ", $VERIFY")
  [ "$rc" == "412" ] && pass "a rule that asks for verification is answered 412" || fail "a rule that asks for verification was answered $rc, want 412"
  rc=$(post_rule 2051 $EP1 9444 ', "backend_client_cert_id": "qual-client-rsa"')
  [ "$rc" == "412" ] && pass "a rule that names a client certificate is answered 412" || fail "a rule that names a client certificate was answered $rc, want 412"
  [ "$(effective 2051)" == "" ] && pass "neither rule exists" || fail "a refused rule is in the rule list: $(effective 2051)"
  rc=$(post_rule 2051 $EP1 9444 "")
  [ "$rc" == "200" ] || fail "precondition: a rule without a backend policy was answered $rc"
  expect_effective 2051 "unsupported False none False None None" "on this build"
  expect_served "re-encryption without a policy" 2051 http1.1 optional none none
  del_rule 2051 > /dev/null; del_cert qual-ca > /dev/null; del_cert qual-client-rsa > /dev/null
  [ "$(gw_pid)" == "$pid0" ] && pass "gateway pid unchanged ($pid0)" || fail "gateway pid changed $pid0 -> $(gw_pid)"
  stop_helpers
  [[ $code == 0 ]] && echo "SCENARIO-e2ehttps-betls-qualification (no backend verification in this build) [OK]" \
    || echo "SCENARIO-e2ehttps-betls-qualification (no backend verification in this build) [FAILED]"
  exit $code
fi

echo "Fixtures"
[ "$(post_cert qual-ca ca pki/ca-a.crt)" == "201" ] && pass "the backends' CA is registered" || fail "CA bundle refused"
[ "$(post_cert qual-otherca ca pki/ca-b.crt)" == "201" ] && pass "a CA the backends do not chain to is registered" || fail "second CA refused"
[ "$(post_cert qual-client-rsa client pki/client-rsa.crt pki/client-rsa.key)" == "201" ] && pass "an RSA client certificate is registered" || fail "RSA client certificate refused"
[ "$(post_cert qual-client-ecdsa client pki/client-ecdsa.crt pki/client-ecdsa.key)" == "201" ] && pass "an ECDSA client certificate is registered" || fail "ECDSA client certificate refused"
[ "$(post_cert qual-client-otherca client pki/client-otherca.crt pki/client-otherca.key)" == "201" ] && pass "a client certificate from a CA the backends do not accept is registered" || fail "the other CA's client certificate was refused"
ans=$(post_cert_answer qual-badpair client pki/client-rsa.crt pki/client-ecdsa.key)
[[ "${ans##*$'\n'}" == "400" && "$ans" == *"not a usable pair"* ]] && pass "a certificate with another key is refused, and the answer says why" \
  || fail "a mismatched pair was answered ${ans##*$'\n'} without the reason: ${ans:0:200}"
[ "$(fp default-rsa)" != "$(fp client-rsa)" ] && [ "$(fp default-ecdsa)" != "$(fp client-rsa)" ] \
  || fail "precondition: the gateway's own certificate and the client certificate are the same"
# The arrangement that would hide a gateway presenting its own certificate:
# the backend that requires a client certificate accepts that one too.
n="direct$RUN"
out=$($hexec l3ep1 curl -s --cacert pki/ca-a.crt --cert pki/default-rsa.crt --key pki/default-rsa.key --max-time 10 "https://$EP1:9443/?nonce=$n")
[[ "$out" == *"peer=$(fp default-rsa) "* ]] && pass "the backend accepts the gateway's own certificate when shown it, and reports it" \
  || fail "precondition: the backend does not accept the gateway's own certificate: ${out:0:160}"
out=$($hexec l3ep1 curl -s -o /dev/null -w '%{http_code}' --cacert pki/ca-a.crt --max-time 10 "https://$EP1:9443/?nonce=$n")
[ "$out" == "000" ] && pass "the backend refuses a client without a certificate" \
  || fail "precondition: the backend served a client without a certificate ($out)"

# The certificate a listener shows its clients, as a SHA-256.
listener_fp() {
  $hexec l3h1 python3 -c "
import ssl, hashlib
print(hashlib.sha256(ssl.PEM_cert_to_DER_cert(ssl.get_server_certificate(('$VIP', $1)))).hexdigest())" 2>/dev/null
}

echo "The client certificate a rule names, RSA beside an RSA default"
rc=$(post_rule 2051 $EP1 9443 ", $VERIFY"', "backend_client_cert_id": "qual-client-rsa"'); echo "  POST -> $rc"
[ "$(listener_fp 2051)" == "$(fp default-rsa)" ] && pass "the listener's own certificate is the RSA default" \
  || fail "precondition: the listener on 2051 does not show the RSA default certificate"
expect_effective 2051 "applied True qual-ca True qual-client-rsa None" "for the rule"
expect_served "RSA client, RSA default" 2051 http1.1 good client-rsa none

echo "The same over HTTP/2"
rc=$(post_rule 2052 $EP1 9443 ", $VERIFY"', "backend_client_cert_id": "qual-client-rsa"'"$H2"); echo "  POST -> $rc"
expect_served "RSA client, RSA default, HTTP/2" 2052 http2 good client-rsa none

echo "An ECDSA client certificate beside an RSA default, an ECDSA backend"
rc=$(post_rule 2053 $EP2 9443 ", $VERIFY"', "backend_client_cert_id": "qual-client-ecdsa"'); echo "  POST -> $rc"
expect_effective 2053 "applied True qual-ca True qual-client-ecdsa None" "for the rule"
expect_served "ECDSA client, RSA default" 2053 http1.1 good-ecdsa client-ecdsa none

echo "No client certificate named"
rc=$(post_rule 2055 $EP1 9444 ", $VERIFY"); echo "  POST -> $rc"
expect_effective 2055 "applied True qual-ca False None None" "for the rule"
expect_served "verification only" 2055 http1.1 optional none none
rc=$(post_rule 2056 $EP1 9443 ", $VERIFY"); echo "  POST -> $rc"
expect_turned_away "a backend that requires a client certificate, none named" 2056 http1.1 $EP1 9443
expect_turned_away "the same on a second connection" 2056 http1.1 $EP1 9443
rc=$(post_rule 2057 $EP1 9443 ", $VERIFY$H2"); echo "  POST -> $rc"
expect_turned_away "none named, HTTP/2" 2057 http2 $EP1 9443
expect_turned_away "none named, HTTP/2, a second connection" 2057 http2 $EP1 9443

echo "A client certificate the backend does not accept"
rc=$(post_rule 2058 $EP1 9443 ", $VERIFY"', "backend_client_cert_id": "qual-client-otherca"'); echo "  POST -> $rc"
expect_effective 2058 "applied True qual-ca True qual-client-otherca None" "for the rule"
expect_turned_away "a client certificate from another CA" 2058 http1.1 $EP1 9443

echo "The rule that was turned away, once it names a certificate the backend accepts"
n=$(replaced 2056)
rc=$(post_rule 2056 $EP1 9443 ", $VERIFY"', "backend_client_cert_id": "qual-client-rsa"'); echo "  POST -> $rc"
expect_replaced 2056 $n
expect_served "after the certificate was named" 2056 http1.1 good client-rsa none

# One backend the gateway must not talk to: served while the rule does not
# verify, turned away once it does, over the same listener.
rogue() { # case, port, backend, endpoint port, protocol, policy that must reject, effective state under it
  local extra="" n
  [ "$5" == "http2" ] && extra=$H2
  echo "A backend with $1"
  rc=$(post_rule $2 $EP1 $4 "$extra"); echo "  POST without a policy -> $rc"
  expect_effective $2 "applied False none False None None" "without a policy"
  expect_served "$1, not verified" $2 $5 $3 none none
  n=$(replaced $2)
  rc=$(post_rule $2 $EP1 $4 ", $6$extra"); echo "  POST with the policy -> $rc"
  expect_replaced $2 $n
  expect_effective $2 "$7" "under the policy"
  expect_rejected "$1, verified" $2 $5 $EP1 $4
}
rogue "a certificate from another CA" 2061 wrongca 9445 http1.1 "$VERIFY" "applied True qual-ca False None None"
rogue "a certificate from another CA (HTTP/2)" 2062 wrongca 9445 http2 "$VERIFY" "applied True qual-ca False None None"
rogue "an expired certificate" 2063 expired 9446 http1.1 "$VERIFY" "applied True qual-ca False None None"
rogue "a certificate for another address" 2064 wrongip 9447 http1.1 "$VERIFY" "applied True qual-ca False None None"
rogue "a certificate without its address" 2065 dnsonly 9448 http1.1 "$VERIFY" "applied True qual-ca False None None"
rogue "a certificate for another name" 2066 wrongdns 9449 http1.1 "$VERIFY, \"backend_tls_server_name\": \"$NAME\"" "applied True qual-ca False None $NAME"

echo "A server name"
rc=$(post_rule 2067 $EP1 9448 ", $VERIFY"', "backend_client_cert_id": "qual-client-rsa", "backend_tls_server_name": "'$NAME'"'); echo "  POST -> $rc"
expect_effective 2067 "applied True qual-ca True qual-client-rsa $NAME" "for the rule"
expect_served "the name the certificate carries" 2067 http1.1 dnsonly client-rsa $NAME

echo "A policy changed under a rule that has served"
expect_served "before the change" 2051 http1.1 good client-rsa none
g=$(generation 2051); n=$(replaced 2051)
rc=$(post_rule 2051 $EP1 9443 ', "mtls_backend": {"verify_server_cert": true}, "backend_ca_cert_id": "qual-otherca", "backend_client_cert_id": "qual-client-rsa"'); echo "  POST -> $rc"
expect_replaced 2051 $n
expect_effective 2051 "applied True qual-otherca True qual-client-rsa None" "after the change"
[[ "$g" == [0-9]* && "$(generation 2051)" -gt "$g" ]] && pass "the installed generation moved ($g -> $(generation 2051))" \
  || fail "the generation did not move with the change: $g -> $(generation 2051)"
expect_rejected "a CA the backend does not chain to" 2051 http1.1 $EP1 9443
g=$(generation 2051); n=$(replaced 2051)
rc=$(post_rule 2051 $EP1 9443 ", $VERIFY"', "backend_client_cert_id": "qual-client-ecdsa"'); echo "  POST -> $rc"
expect_replaced 2051 $n
[[ "$g" == [0-9]* && "$(generation 2051)" -gt "$g" ]] && pass "the installed generation moved again ($g -> $(generation 2051))" \
  || fail "the generation did not move with the second change: $g -> $(generation 2051)"
expect_served "the right CA again, another client certificate" 2051 http1.1 good client-ecdsa none

# Two requests on one connection of the client, the backend policy of the
# rule changed between them.
pair() { # port, extra client arguments; sets P_FIRST, P_N1, P_N2 and leaves the client waiting
  P_N1="k$RUN-$1-1"; P_N2="k$RUN-$1-2"; rm -f pki/gate
  $hexec l3h1 ./fixture pair -ca pki/ca-a.crt -gate pki/gate $2 \
    "https://$VIP:$1/?nonce=$P_N1" "https://$VIP:$1/?nonce=$P_N2" > pki/pair.out 2>&1 &
  P_PID=$!
  for i in $(seq 1 100); do grep -q '^first' pki/pair.out 2>/dev/null && break; sleep 0.1; done
  P_FIRST=$(grep '^first' pki/pair.out)
}
pair_second() { touch pki/gate; wait $P_PID; P_SECOND=$(grep '^second' pki/pair.out); }

echo "One HTTP/2 client connection across a policy change"
# The streams of one client connection share backend connections. A stream
# opened after the change must travel on a backend connection made under the
# new policy: the backend reports the client certificate of each.
pair 2052 ""
[[ "$P_FIRST" == "first status=200 "*"proto=HTTP/2.0 peer=$(fp client-rsa) "* && "$(receipt_of good $P_N1)" == "1" ]] \
  && pass "the first stream is served with the client certificate of the policy in service" \
  || fail "the first stream on the connection: ${P_FIRST:0:200}"
n=$(replaced 2052)
rc=$(post_rule 2052 $EP1 9443 ", $VERIFY"', "backend_client_cert_id": "qual-client-ecdsa"'"$H2"); echo "  POST -> $rc"
expect_replaced 2052 $n
# The pass that closes HTTP/1.1 client connections made under a replaced
# policy runs once a second and must leave this connection alone. Three
# seconds is at least two passes; that this wait is long enough to catch a
# pass that does close it is what the scenario's mutation run checks.
sleep 3
[ "$(drained 2052 "no answer owed")" == "0" ] && pass "three seconds after the change the HTTP/2 client connection has not been closed" \
  || fail "the HTTP/2 client connection was closed after the policy change"
pair_second
echo "  record: case='one HTTP/2 client connection' first='${P_FIRST:0:170}' second='${P_SECOND:0:170}' generation=$(generation 2052)"
[[ "$P_SECOND" == "second status=200 reused=true "* ]] && pass "the second stream is served on the same client connection" \
  || fail "the second stream was not served on the same client connection: ${P_SECOND:0:200}"
[[ "$P_SECOND" == *"peer=$(fp client-ecdsa) "* && "$(receipt_of good $P_N2)" == "1" ]] \
  && pass "the second stream reached the backend with the client certificate of the new policy" \
  || fail "the second stream did not travel under the new policy: ${P_SECOND:0:200}"

echo "One HTTP/1.1 client connection across a policy change"
# A relayed HTTP/1.1 client keeps the backend connection it has, so a policy
# change reaches it by ending the client connection once nothing is owed on
# it. The client then connects again, and that connection is made under the
# new policy.
pair 2051 -http1
[[ "$P_FIRST" == "first status=200 "*"peer=$(fp client-ecdsa) "* && "$(receipt_of good $P_N1)" == "1" ]] \
  && pass "the first request is served with the client certificate of the policy in service" \
  || fail "the first request on the connection: ${P_FIRST:0:200}"
n=$(replaced 2051); d=$(drained 2051 "no answer owed")
rc=$(post_rule 2051 $EP1 9443 ", $VERIFY"', "backend_client_cert_id": "qual-client-rsa"'); echo "  POST -> $rc"
expect_replaced 2051 $n
expect_drained 2051 "no answer owed" $d 15 "the idle client connection made under the earlier policy was closed"
pair_second
echo "  record: case='one HTTP/1.1 client connection' first='${P_FIRST:0:170}' second='${P_SECOND:0:170}' generation=$(generation 2051)"
[[ "$P_SECOND" == "second status=200 reused=false "* && "$(receipt_of good $P_N2)" == "1" ]] \
  && pass "the client's next request was served on a new connection" \
  || fail "the client's next request after the change: ${P_SECOND:0:200}"
[[ "$P_SECOND" == *"peer=$(fp client-rsa) "* ]] \
  && pass "and reached the backend with the client certificate of the new policy" \
  || fail "the next request did not travel under the new policy: ${P_SECOND:0:200}"
expect_served "a connection opened after the change" 2051 http1.1 good client-rsa none

echo "A request in flight across a policy change"
# The answer to a request that was forwarded before the change is not cut:
# the connection is closed after it, not during it.
seq=$((seq + 1)); w="q$RUN-$seq"
$hexec l3h1 curl -s --http1.1 --cacert pki/ca-a.crt --max-time 30 -o pki/inflight.out \
  -w '%{http_code} %{exitcode}' "https://$VIP:2051/?nonce=$w&wait=5000" > pki/inflight.code 2>/dev/null &
w_pid=$!
for i in $(seq 1 50); do [ "$(receipts $w)" == "1" ] && break; sleep 0.1; done
[ "$(receipts $w)" == "1" ] && pass "a request is waiting for its answer at the backend" || fail "precondition: the slow request did not reach the backend"
n=$(replaced 2051); d=$(drained 2051 "no answer owed")
rc=$(post_rule 2051 $EP1 9443 ", $VERIFY"', "backend_client_cert_id": "qual-client-ecdsa"'); echo "  POST -> $rc"
expect_replaced 2051 $n
sleep 2
[ "$(drained 2051 "no answer owed")" == "$d" ] && [ "$(drained 2051 "an answer still owed after the bound")" == "0" ] \
  && pass "two passes later the connection with an answer owed is still open" \
  || fail "a connection with an answer owed was closed before the bound"
wait $w_pid
echo "  record: case='a request in flight' nonce=$w answer='$(cat pki/inflight.code) $(head -c 160 pki/inflight.out)'"
[ "$(cat pki/inflight.code)" == "200 0" ] && grep -q "peer=$(fp client-rsa) .*nonce=$w" pki/inflight.out \
  && pass "the request in flight got its whole answer, from the connection it was sent on" \
  || fail "the request in flight was not answered whole: $(cat pki/inflight.code) $(head -c 160 pki/inflight.out)"
expect_served "a connection opened after that change" 2051 http1.1 good client-ecdsa none

echo "An answer that does not end within the bound"
# A connection that never reaches a point where nothing is owed is closed
# when the bound (30 s) is up, and not before.
seq=$((seq + 1)); w="q$RUN-$seq"
$hexec l3h1 curl -s --http1.1 --cacert pki/ca-a.crt --max-time 90 -o /dev/null \
  -w '%{http_code} %{exitcode} %{time_total}' "https://$VIP:2051/?nonce=$w&wait=60000" > pki/bound.code 2>/dev/null &
w_pid=$!
for i in $(seq 1 50); do [ "$(receipts $w)" == "1" ] && break; sleep 0.1; done
[ "$(receipts $w)" == "1" ] && pass "a request that will not be answered for a minute is at the backend" || fail "precondition: the slow request did not reach the backend"
n=$(replaced 2051); d=$(drained 2051 "an answer still owed after the bound"); t0=$(date +%s)
rc=$(post_rule 2051 $EP1 9443 ", $VERIFY"', "backend_client_cert_id": "qual-client-rsa"'); echo "  POST -> $rc"
expect_replaced 2051 $n
sleep 20
[ "$(drained 2051 "an answer still owed after the bound")" == "$d" ] && kill -0 $w_pid 2>/dev/null \
  && pass "20 s after the change the connection is still open" || fail "the connection was closed before the bound"
expect_drained 2051 "an answer still owed after the bound" $d 20 "the connection was closed when the bound was up"
wait $w_pid; t1=$(date +%s)
echo "  record: case='an answer that does not end' nonce=$w curl='$(cat pki/bound.code)' closed_after=$((t1 - t0))s"
[[ "$(cat pki/bound.code)" != "200 0 "* ]] && [ $((t1 - t0)) -ge 28 ] && [ $((t1 - t0)) -le 40 ] \
  && pass "the client's request ended $((t1 - t0)) s after the change, without an answer" \
  || fail "the request ended after $((t1 - t0)) s with '$(cat pki/bound.code)', want no answer at about 30 s"
expect_served "a connection opened after the bound" 2051 http1.1 good client-rsa none

echo "A client certificate rotated under its ID"
expect_served "before the rotation" 2051 http1.1 good client-rsa none
n=$(replaced 2051)
ans=$(put_cert qual-client-rsa client pki/client-ecdsa.crt pki/client-ecdsa.key)
[ "${ans##*$'\n'}" == "200" ] && pass "the entry is rotated to another pair" || fail "the rotation was answered ${ans##*$'\n'}: ${ans:0:200}"
[ "$(replaced 2051)" -gt "$n" ] && pass "the rotation reached the listener before the call returned" \
  || fail "the listener's backend policy was not replaced by the rotation"
expect_served "after the rotation" 2051 http1.1 good client-ecdsa none

echo "A rotation the data plane cannot load"
# The pair is well formed, so the registry stores it; the key is too short
# for the data plane's TLS library, so the listener cannot build a context
# from it and keeps the one in service.
g=$(generation 2051); k=$(kept 2051)
ans=$(put_cert qual-client-rsa client pki/client-weak.crt pki/client-weak.key)
[ "${ans##*$'\n'}" == "400" ] && pass "the rotation is answered 400" || fail "a rotation the data plane cannot load was answered ${ans##*$'\n'}, want 400"
[[ "$ans" == *"could not load"* && "$ans" == *"$VIP"* ]] && pass "the answer names the rule that kept its material" \
  || fail "the answer does not name the rule: ${ans:0:300}"
[ "$(kept 2051)" -gt "$k" ] && pass "the data plane refused the new context and kept the one in service" \
  || fail "the data plane log shows no refused replacement on 2051"
expect_effective 2051 "failed True qual-ca True qual-client-rsa None" "after the refused rotation"
[ "$(generation 2051)" == "$g" ] && pass "the installed generation did not move ($g)" || fail "the generation moved $g -> $(generation 2051) on a refused rotation"
expect_served "the certificate from before the refused rotation" 2051 http1.1 good client-ecdsa none
n=$(replaced 2051)
ans=$(put_cert qual-client-rsa client pki/client-rsa.crt pki/client-rsa.key)
[ "${ans##*$'\n'}" == "200" ] && pass "the entry is written again with a usable pair" || fail "writing the entry again was answered ${ans##*$'\n'}: ${ans:0:200}"
[ "$(replaced 2051)" -gt "$n" ] && pass "the listener took the usable pair" || fail "the listener did not take the usable pair"
expect_effective 2051 "applied True qual-ca True qual-client-rsa None" "after the entry was written again"
expect_served "after the entry was written again" 2051 http1.1 good client-rsa none

echo "An RSA client certificate beside an ECDSA default"
sudo docker cp pki/default-ecdsa.crt llb1:/opt/loxilb/cert/server.crt
sudo docker cp pki/default-ecdsa.key llb1:/opt/loxilb/cert/server.key
rc=$(post_rule 2054 $EP1 9443 ", $VERIFY"', "backend_client_cert_id": "qual-client-rsa"'); echo "  POST -> $rc"
[ "$(listener_fp 2054)" == "$(fp default-ecdsa)" ] && pass "the listener's own certificate is the ECDSA default" \
  || fail "precondition: the listener on 2054 does not show the ECDSA default certificate"
expect_served "RSA client, ECDSA default" 2054 http1.1 good client-rsa none

[ "$(gw_pid)" == "$pid0" ] && pass "gateway pid unchanged ($pid0)" || fail "gateway pid changed $pid0 -> $(gw_pid)"
for p in 2051 2052 2053 2054 2055 2056 2057 2058 2061 2062 2063 2064 2065 2066 2067; do
  [ "$(del_rule $p)" == "200" ] || fail "the rule on $p could not be deleted"
done
for c in qual-ca qual-otherca qual-client-rsa qual-client-ecdsa qual-client-otherca; do
  [ "$(del_cert $c)" == "204" ] || fail "the certificate $c could not be deleted"
done
$dexec llb1 sh -c 'ls -d /etc/loxilb/certs/qual-* 2>/dev/null' | grep -q . && fail "certificate material is left in the managed directory" \
  || pass "no certificate material is left in the managed directory"

stop_helpers

if [[ $code == 0 ]]; then
  echo SCENARIO-e2ehttps-betls-qualification [OK]
else
  echo SCENARIO-e2ehttps-betls-qualification [FAILED]
fi
exit $code
