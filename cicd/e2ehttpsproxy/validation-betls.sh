#!/bin/bash
# The backend leg of an end-to-end HTTPS rule: the gateway verifies the
# endpoint it dialled against the rule's CA, presents the rule's client
# certificate, and takes a changed policy without re-creating the listener.
#
# The endpoints are the scenario's HTTP/2 servers in strict mode: each has a
# certificate for its own address and requires a client certificate signed by
# the scenario CA. So "served" below always means: the endpoint's certificate
# passed AND the endpoint accepted the gateway's client certificate.
source ../common.sh
echo SCENARIO-e2ehttps-betls

API=http://localhost:11111/netlox/v1/config
VIP=10.10.10.254
PORT=2041
code=0

fail() { echo "  FAIL: $*"; code=1; }
pass() { echo "  ok: $*"; }

gw_pid() { $dexec llb1 pidof loxilb 2>/dev/null | tr -d '\r'; }
dp_log() { $dexec llb1 cat /var/log/loxilbdp.log 2>/dev/null; }
replaced() { dp_log | grep -c ":$PORT rule [0-9]* backend TLS policy replaced"; }
refused() { dp_log | grep -c ":$PORT rule [0-9]* backend TLS policy not replaced"; }

cert_json() { # id, usage, cert file, [key file]
  python3 - "$@" <<'PY'
import json, sys
d = {"certId": sys.argv[1], "usage": sys.argv[2], "certPem": open(sys.argv[3]).read()}
d["keyPem"] = open(sys.argv[4]).read() if len(sys.argv) > 4 else ""
print(json.dumps(d))
PY
}
post_cert() { cert_json "$@" | $dexec llb1 curl -s -o /dev/null -w '%{http_code}' -X POST $API/cert -H "Content-Type: application/json" -d @-; }
put_cert() { cert_json "$@" | $dexec llb1 curl -s -o /dev/null -w '%{http_code}' -X PUT $API/cert/$1 -H "Content-Type: application/json" -d @-; }
del_cert() { $dexec llb1 curl -s -o /dev/null -w '%{http_code}' -X DELETE $API/cert/$1; }

post_rule() { # extra serviceArguments (JSON members, leading comma)
  $dexec llb1 curl -s -o /dev/null -w '%{http_code}' -X POST $API/loadbalancer \
    -H "Content-Type: application/json" -d '{
  "serviceArguments": { "externalIP": "'$VIP'", "port": '$PORT', "protocol": "tcp",
    "security": 2, "mode": 4, "host": "'$VIP'", "backend_protocol": "http2"'"$1"' },
  "endpoints": [
    { "endpointIP": "31.31.31.1", "targetPort": 8081, "weight": 1 },
    { "endpointIP": "32.32.32.1", "targetPort": 8081, "weight": 1 },
    { "endpointIP": "33.33.33.1", "targetPort": 8081, "weight": 1 }
  ]}'
}
del_rule() {
  $dexec llb1 curl -s -o /dev/null -w '%{http_code}' -X DELETE \
    "$API/loadbalancer/hosturl/$VIP/externalipaddress/$VIP/port/$PORT/protocol/tcp"
}
get_rules() { $dexec llb1 curl -s $API/loadbalancer/all; }
# The configured rules only: endpoint state and counters are runtime values
# and move between two reads on their own.
rule_list() {
  get_rules | python3 -c "
import sys, json
rules = json.load(sys.stdin).get('lbAttr') or []
for r in rules:
    for ep in r.get('endpoints') or []:
        ep.pop('state', None)
        ep.pop('counter', None)
print(len(rules), json.dumps(sorted(json.dumps(r, sort_keys=True) for r in rules)))
" 2>/dev/null
}

# How many of n requests an endpoint answered.
served() {
  local n=$1 ok=0 res srv
  for i in $(seq 1 $n); do
    res=$($hexec l3h1 timeout 10 ../common/http2/https-client/client -key 10.10.10.1/key.pem --cert 10.10.10.1/cert.pem --cacert minica.pem -host $VIP:$PORT 2>/dev/null | xargs)
    srv=${res#HTTP/2.0:}
    [[ "$srv" == server[123]* ]] && ok=$((ok + 1))
  done
  echo $ok
}
expect_served() { # what
  local got; got=$(served 6)
  [ "$got" == "6" ] && pass "$1: 6 of 6 requests served" || fail "$1: $got of 6 requests served, want 6"
}
expect_refused() { # what
  local got; got=$(served 4)
  [ "$got" == "0" ] && pass "$1: 0 of 4 requests served" || fail "$1: $got of 4 requests served, want 0"
}
# A changed policy must reach the data plane before traffic is judged.
expect_replaced() { # count before
  for i in $(seq 1 20); do [ "$(replaced)" -gt "$1" ] && break; sleep 1; done
  [ "$(replaced)" -gt "$1" ] && pass "the listener's backend context was replaced in place" \
    || fail "the data plane did not replace the backend context"
}

BE='"mtls_backend": {"verify_server_cert": true}, "backend_ca_cert_id": "betls-ca", "backend_client_cert_id": "betls-client"'

for i in 1 2 3; do
  $hexec l3ep$i ../common/http2/https-server/server -host server$i -key 3$i.3$i.3$i.1/key.pem -cert 3$i.3$i.3$i.1/cert.pem -cacert minica.pem -port 8081 -strict > /dev/null 2>&1 &
  track_helper
done
sleep 8

# A second CA the endpoints' certificates do not chain to.
rm -rf otherca && mkdir otherca && ( cd otherca && "${MINICA:-$(command -v minica || echo "$(go env GOPATH)/bin/minica")}" -ip-addresses 10.99.99.1 > /dev/null 2>&1 )
[ -f otherca/minica.pem ] || fail "precondition: could not make a second CA"

pid0=$(gw_pid)
[ -n "$pid0" ] || fail "precondition: the gateway is not running"

echo "Registry"
[ "$(post_cert betls-ca ca minica.pem)" == "201" ] && pass "a CA bundle is registered without a key" || fail "CA bundle refused"
[ "$(post_cert betls-otherca ca otherca/minica.pem)" == "201" ] && pass "a second CA bundle is registered" || fail "second CA refused"
[ "$(post_cert betls-client client 10.10.10.1/cert.pem 10.10.10.1/key.pem)" == "201" ] && pass "a client certificate is registered" || fail "client certificate refused"
[ "$(post_cert betls-cakey ca minica.pem minica-key.pem)" == "400" ] && pass "a CA bundle sent with a private key is refused" || fail "a CA key was accepted"
[ "$(post_cert betls-badpair client 10.10.10.1/cert.pem 31.31.31.1/key.pem)" == "400" ] && pass "a client certificate with another key is refused" || fail "a mismatched client pair was accepted"
body=$($dexec llb1 curl -s $API/cert/betls-client)
[[ "$body" == *'"usage":"client"'* ]] && pass "GET reports the usage" || fail "GET does not report usage client: ${body:0:120}"
[[ "$body" != *"PRIVATE KEY"* ]] && pass "GET returns no key material" || fail "GET returned key material"
$dexec llb1 sh -c 'ls /etc/loxilb/certs/betls-ca/ca.crt /etc/loxilb/certs/betls-client/client.crt /etc/loxilb/certs/betls-client/client.key' > /dev/null 2>&1 \
  && pass "the material is where the data plane reads it" || fail "the managed files are missing"

echo "Requests the gateway must refuse"
before=$(rule_list)
[[ "$before" == [1-9]* ]] || fail "precondition: the rule list is unreadable or empty"
[ "$(post_rule ', "mtls_backend": {"verify_server_cert": true}')" == "400" ] && pass "verification without a CA is refused" || fail "verification without a CA was accepted"
[ "$(post_rule ', "mtls_backend": {"verify_server_cert": true}, "backend_ca_cert_id": "betls-client"')" == "400" ] && pass "a client certificate named as the CA is refused" || fail "a client entry was accepted as a CA"
[ "$(post_rule ', "backend_client_cert_id": "betls-ca"')" == "400" ] && pass "a CA named as the client certificate is refused" || fail "a CA entry was accepted as a client certificate"
[ "$(post_rule ', "backend_client_cert_id": "betls-absent"')" == "400" ] && pass "an ID nothing is registered under is refused" || fail "an unknown ID was accepted"
[ "$(rule_list)" == "$before" ] && pass "the rule list is unchanged by the refused requests" || fail "a refused request changed the rule list"

echo "Verified endpoints and a client certificate"
rc=$(post_rule ", $BE"); echo "  POST -> $rc"
expect_served "CA, endpoint address and client certificate all in order"
body=$(get_rules)
[[ "$body" == *'"backend_ca_cert_id":"betls-ca"'* && "$body" == *'"backend_client_cert_id":"betls-client"'* ]] \
  && pass "GET reports the certificate IDs of the rule" || fail "GET does not report the rule's certificate IDs"
[ "$(del_cert betls-ca)" == "400" ] && pass "a certificate a rule refers to cannot be deleted" || fail "a certificate in use was deleted"

echo "A CA the endpoints do not chain to"
n=$(replaced)
rc=$(post_rule ', "mtls_backend": {"verify_server_cert": true}, "backend_ca_cert_id": "betls-otherca", "backend_client_cert_id": "betls-client"'); echo "  POST -> $rc"
expect_replaced $n
expect_refused "endpoints signed by another CA"

echo "Back to the right CA"
n=$(replaced)
rc=$(post_rule ", $BE"); echo "  POST -> $rc"
expect_replaced $n
expect_served "after the policy was put back"

echo "A server name the endpoints' certificates do not carry"
n=$(replaced)
rc=$(post_rule ", $BE"', "backend_tls_server_name": "backend.invalid.test"'); echo "  POST -> $rc"
expect_replaced $n
expect_refused "right CA, wrong name"

echo "No client certificate"
n=$(replaced)
rc=$(post_rule ', "mtls_backend": {"verify_server_cert": true}, "backend_ca_cert_id": "betls-ca"'); echo "  POST -> $rc"
expect_replaced $n
expect_refused "endpoints that require a client certificate, none named"

echo "The CA is rotated under its ID"
n=$(replaced)
rc=$(post_rule ", $BE"); echo "  POST -> $rc"
expect_replaced $n
expect_served "before the rotation"
[ "$(put_cert betls-ca ca otherca/minica.pem)" == "200" ] && pass "the CA entry is rotated to another CA" || fail "rotation refused"
n=$(replaced)
rc=$(post_rule ", $BE"', "name": "betls-rotated"'); echo "  POST (rule updated) -> $rc"
expect_replaced $n
expect_refused "same IDs, rotated CA"

[ "$(gw_pid)" == "$pid0" ] && pass "gateway pid unchanged ($pid0)" || fail "gateway pid changed $pid0 -> $(gw_pid)"
echo "  DELETE rule -> $(del_rule)"
[ "$(del_cert betls-ca)" == "204" ] && pass "the certificate can be deleted once no rule refers to it" || fail "an unused certificate could not be deleted"
del_cert betls-otherca > /dev/null; del_cert betls-client > /dev/null
rm -rf otherca

stop_helpers

if [[ $code == 0 ]]; then
  echo SCENARIO-e2ehttps-betls [OK]
else
  echo SCENARIO-e2ehttps-betls [FAILED]
fi
exit $code
