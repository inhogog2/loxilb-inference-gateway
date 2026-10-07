#!/bin/bash
# The backend leg of an end-to-end HTTPS rule, configured through loxicmd:
# the certificate registry by usage, the arguments the CLI retired, a rule
# that names its backend certificates by ID, and what `get lb` shows of the
# policy the listener installed. Every write goes through the CLI; the REST
# API is only read, and used to delete the rule between steps.
#
# The endpoints are the scenario's HTTP/2 servers in strict mode, so "served"
# means the gateway presented the client certificate the rule names.
source ../common.sh
echo SCENARIO-e2ehttps-betls-cli

if ! backend_tls_cli_preflight llb1; then
  echo SCENARIO-e2ehttps-betls-cli [SKIPPED]
  exit 0
fi

API=http://localhost:11111/netlox/v1/config
VIP=10.10.10.254
PORT=2041
code=0
L="$dexec llb1 loxicmd"

fail() { echo "  FAIL: $*"; code=1; }
pass() { echo "  ok: $*"; }

served() { # attempts -> how many were answered by an endpoint
  local ok=0 res srv
  for i in $(seq 1 $1); do
    res=$($hexec l3h1 timeout 10 ../common/http2/https-client/client -key 10.10.10.1/key.pem --cert 10.10.10.1/cert.pem --cacert minica.pem -host $VIP:$PORT 2>/dev/null | xargs)
    srv=${res#HTTP/2.0:}
    [[ "$srv" == server[123]* ]] && ok=$((ok + 1))
  done
  echo $ok
}
del_rule() { $dexec llb1 curl -s -o /dev/null -w '%{http_code}' -X DELETE "$API/loadbalancer/hosturl/$VIP/externalipaddress/$VIP/port/$PORT/protocol/tcp"; }
nrules() { $dexec llb1 curl -s $API/loadbalancer/all | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('lbAttr') or []))"; }
RULE="create lb $VIP --tcp=$PORT:8081 --endpoints=31.31.31.1:1,32.32.32.1:1,33.33.33.1:1 --mode=fullproxy --security=e2ehttps --host=$VIP --backend-protocol=http2"

for i in 1 2 3; do
  $hexec l3ep$i ../common/http2/https-server/server -host server$i -key 3$i.3$i.3$i.1/key.pem -cert 3$i.3$i.3$i.1/cert.pem -cacert minica.pem -port 8081 -strict > /dev/null 2>&1 &
  track_helper
done
sleep 8
docker cp minica.pem llb1:/tmp/cli-ca.pem
docker cp 10.10.10.1/cert.pem llb1:/tmp/cli-client.pem
docker cp 10.10.10.1/key.pem llb1:/tmp/cli-client.key
pid0=$($dexec llb1 pidof loxilb | tr -d '\r')

echo "Registry through the CLI"
out=$($L create cert --usage=ca --cert-id=cli-ca --cert-file=/tmp/cli-ca.pem 2>&1); rc=$?
[ $rc == 0 ] && pass "a CA bundle is registered without a key" || fail "create cert --usage=ca: rc=$rc $out"
out=$($L create cert --usage=client --cert-id=cli-client --cert-file=/tmp/cli-client.pem --key-file=/tmp/cli-client.key 2>&1); rc=$?
[ $rc == 0 ] && pass "a client certificate is registered" || fail "create cert --usage=client: rc=$rc $out"
out=$($L create cert --usage=ca --cert-id=cli-cakey --cert-file=/tmp/cli-ca.pem --key-file=/tmp/cli-client.key 2>&1); rc=$?
[ $rc != 0 ] && pass "a CA with a key is refused (rc=$rc)" || fail "a CA with a key was accepted: $out"
out=$($L create cert --usage=client --cert-id=cli-nokey --cert-file=/tmp/cli-client.pem 2>&1); rc=$?
[ $rc != 0 ] && pass "a client certificate without a key is refused (rc=$rc)" || fail "a client certificate without a key was accepted: $out"
for id in cli-cakey cli-nokey; do
  st=$($dexec llb1 curl -s -o /dev/null -w '%{http_code}' $API/cert/$id)
  [ "$st" == "404" ] && pass "the refused entry $id is not in the registry" || fail "GET cert/$id -> $st, want 404"
done
out=$($L get cert cli-ca 2>&1)
[[ "$out" == *"| ca "* ]] && pass "get cert shows usage ca" || fail "get cert does not show usage ca: $out"
out=$($L get cert cli-client 2>&1)
[[ "$out" == *"| client "* ]] && pass "get cert shows usage client" || fail "get cert does not show usage client: $out"

echo "Retired arguments"
n=$(nrules)
for f in "--mtls-backend-ca-path=/tmp/cli-ca.pem" "--mtls-backend-cert-path=/tmp/cli-client.pem" "--mtls-backend-key-path=/tmp/cli-client.key" "--mtls-backend-verify-server"; do
  out=$($L $RULE $f 2>&1); rc=$?
  [[ $rc != 0 && "$out" == *"retired"* && "$out" == *"--backend-"*"-cert-id"* ]] && pass "$f is refused and names its replacement (rc=$rc)" || fail "$f: rc=$rc $out"
done
[ "$(nrules)" == "$n" ] && pass "the refused commands created no rule ($n)" || fail "rule count moved $n -> $(nrules)"
out=$($L create lb $VIP --tcp=$PORT:8081 --endpoints=31.31.31.1:1 --mode=fullproxy --security=https --host=$VIP --backend-ca-cert-id=cli-ca 2>&1); rc=$?
[[ $rc != 0 && "$(nrules)" == "$n" ]] && pass "a backend certificate on a rule with a plain backend leg is refused (rc=$rc)" || fail "accepted on security https: $out"

echo "Verified backend with a client certificate"
out=$($L $RULE --backend-ca-cert-id=cli-ca --backend-client-cert-id=cli-client 2>&1); rc=$?
[ $rc == 0 ] && pass "create lb with both certificate IDs" || fail "create lb: rc=$rc $out"
got=$(served 6); [ "$got" == 6 ] && pass "6 of 6 requests served by the strict endpoints" || fail "$got of 6 served"
body=$($dexec llb1 curl -s $API/loadbalancer/all)
[[ "$body" == *'"verify_server_cert":true'* && "$body" == *'"backend_ca_cert_id":"cli-ca"'* && "$body" == *'"backend_client_cert_id":"cli-client"'* ]] \
  && pass "the stored rule asks for verification and names both IDs" || fail "the stored rule lacks the policy"
wide=$($L get lb -o wide 2>&1)
[[ "$wide" == *"| applied: verify, client "* ]] && pass "get lb -o wide shows the installed policy" \
  || fail "wide view lacks the installed policy: $(echo "$wide" | grep $PORT | cut -c1-300)"

echo "A server name the endpoints do not carry"
[ "$(del_rule)" == 200 ] || fail "precondition: delete"
out=$($L $RULE --backend-ca-cert-id=cli-ca --backend-client-cert-id=cli-client --backend-tls-server-name=backend.invalid.test 2>&1); rc=$?
[ $rc == 0 ] && pass "create lb with a server name" || fail "create lb: rc=$rc $out"
got=$(served 4); [ "$got" == 0 ] && pass "0 of 4 requests served: the endpoints fail the name check" || fail "$got of 4 served, want 0"
js=$($L get lb -o json 2>&1)
[[ "$js" == *'"server_name": "backend.invalid.test"'* && "$js" == *'"ca": "cli-ca"'* && "$js" == *'"client_cert_id": "cli-client"'* ]] \
  && pass "json output carries the installed IDs and the name" \
  || fail "json output lacks the installed policy: $(echo "$js" | grep -A8 backend_tls_effective | tr -d '\n' | cut -c1-300)"
wide=$($L get lb -o wide 2>&1)
[[ "$wide" == *"| applied: verify, client, name "* ]] && pass "wide view shows the name" \
  || fail "wide view lacks the name: $(echo "$wide" | grep $PORT | cut -c1-300)"

echo "Client certificate only"
[ "$(del_rule)" == 200 ] || fail "precondition: delete"
out=$($L $RULE --backend-client-cert-id=cli-client 2>&1); rc=$?
[ $rc == 0 ] && pass "create lb with a client certificate and no CA" || fail "create lb: rc=$rc $out"
got=$(served 6); [ "$got" == 6 ] && pass "6 of 6 served on an unverified leg with a client certificate" || fail "$got of 6 served"
wide=$($L get lb -o wide 2>&1)
[[ "$wide" == *"| applied: no verify, client "* ]] && pass "wide view reads no verify" \
  || fail "wide view: $(echo "$wide" | grep $PORT | cut -c1-300)"

[ "$(del_rule)" == 200 ] && pass "the rule is deleted" || fail "the rule could not be deleted"
pid1=$($dexec llb1 pidof loxilb | tr -d '\r')
[[ -n "$pid0" && "$pid1" == "$pid0" ]] && pass "gateway pid unchanged ($pid0)" || fail "gateway pid changed '$pid0' -> '$pid1'"
for id in cli-ca cli-client; do
  $dexec llb1 curl -s -o /dev/null -X DELETE $API/cert/$id
done
$dexec llb1 rm -f /tmp/cli-ca.pem /tmp/cli-client.pem /tmp/cli-client.key

stop_helpers

if [[ $code == 0 ]]; then
  echo SCENARIO-e2ehttps-betls-cli [OK]
else
  echo SCENARIO-e2ehttps-betls-cli [FAILED]
fi
exit $code
