#!/bin/bash
# validate_takeover.sh — a listener keeps asking clients for what its rule asks.
#
# Deleting the last rule of a listener keeps the listener, and a rule update
# that changes the endpoints of a full proxy rule removes the rule from the
# data plane and installs it again. Either way a rule takes over a listener
# that was kept without one, and the listener must then verify client
# certificates as that rule says: not as the rule before it did, and not at
# all only when the rule does not ask for it.
#
# Called from validation.sh while the backends are still up.
# Sources ../common.sh for $hexec and $dexec.

source ../common.sh

API="http://localhost:11111/netlox/v1/config"
VIP="10.10.10.254"
DPLOG=/var/log/loxilbdp.log
tcode=0

echo ""
echo "========================================="
echo " A rule takes over a kept listener (frontend mTLS)"
echo "========================================="

pass() { echo "  ok: $1"; }
fail() { echo "  FAIL: $1"; tcode=1; }

EP3='{"endpointIP":"31.31.31.1","targetPort":8443,"weight":1},{"endpointIP":"32.32.32.1","targetPort":8443,"weight":1},{"endpointIP":"33.33.33.1","targetPort":8443,"weight":1}'
EP2='{"endpointIP":"31.31.31.1","targetPort":8443,"weight":1},{"endpointIP":"32.32.32.1","targetPort":8443,"weight":1}'
EP1='{"endpointIP":"31.31.31.1","targetPort":8443,"weight":1}'
REQUIRED_CN=', "mtls_frontend": {"client_cert_mode": "required", "client_ca_path": "/opt/loxilb/cert/client_ca.crt", "require_client_cn": true, "client_cn_pattern": "*.internal.corp.com"}'
REQUIRED=', "mtls_frontend": {"client_cert_mode": "required", "client_ca_path": "/opt/loxilb/cert/client_ca.crt"}'
REQUIRED_OTHER_CA=', "mtls_frontend": {"client_cert_mode": "required", "client_ca_path": "/opt/loxilb/cert/client_ca_other.crt"}'

post_rule() { # port, name, endpoints, frontend members (leading comma) or ""
  $hexec llb1 curl -s -o /dev/null -w '%{http_code}' -X POST $API/loadbalancer \
    -H "Content-Type: application/json" -d '{
  "serviceArguments": { "externalIP": "'$VIP'", "port": '$1', "protocol": "tcp",
    "security": 2, "mode": 4, "name": "'$2'", "host": "'$VIP'",
    "mtls_backend": { "verify_server_cert": true },
    "backend_ca_cert_id": "e2e-backend-ca", "backend_client_cert_id": "e2e-backend-client"'"$4"' },
  "endpoints": [ '"$3"' ]}'
}
del_rule() { # port
  $hexec llb1 curl -s -o /dev/null -w '%{http_code}' -X DELETE \
    "$API/loadbalancer/hosturl/$VIP/externalipaddress/$VIP/port/$1/protocol/tcp"
}
logcount() { # fixed string
  local n
  n=$($dexec llb1 grep -c -F -- "$1" $DPLOG 2>/dev/null)
  echo "${n:-0}"
}
# The data plane says when a rule took over the kept listener of a port. The
# probes below wait for that line, not for a time: without it they would be
# asking the listener of the rule before.
taken() { # port
  $dexec llb1 grep -F "takes over the kept listener" $DPLOG 2>/dev/null | grep -c -F ":$1 rule "
}
expect_taken() { # port, count before, what
  local i n=0
  for i in $(seq 1 15); do n=$(taken $1); [ "${n:-0}" -gt "$2" ] && break; sleep 1; done
  [ "${n:-0}" -gt "$2" ] && pass "$3: the rule took over the kept listener on $1" \
    || fail "$3: the data plane did not report a rule taking over the listener on $1"
}

# One request on a connection of its own. Sets P_EXIT (curl), P_CODE, P_BODY.
probe() { # port, client certificate directory or "none"
  local out cert=()
  [ "$2" != "none" ] && cert=(--cert "$2/cert.pem" --key "$2/key.pem")
  out=$($hexec l3h1 curl -s --http1.1 --max-time 10 --cacert minica.pem "${cert[@]}" \
        -w '\n%{http_code}' "https://$VIP:$1" 2>/dev/null)
  P_EXIT=$?
  P_CODE=$(echo "$out" | tail -1)
  P_BODY=$(echo "$out" | head -1)
}
expect_served() { # what, port, client
  probe $2 $3
  if [ "$P_EXIT" == "0" ] && [ "$P_CODE" == "200" ] && [[ "$P_BODY" =~ ^server[123]$ ]]; then
    pass "$1: served ($P_BODY)"
  else
    fail "$1: expected 200 from a backend, got code=$P_CODE curl=$P_EXIT body='$P_BODY'"
  fi
}
# Refused in the TLS handshake: no HTTP status, and curl ends on the handshake
# (35) or, with TLS 1.3, where the gateway refuses after the client's part of
# the handshake, on the alert it reads (56) or on a write to the connection the
# gateway closed (55). A timeout (28) is not a refusal, and neither is any
# exchange that produced a status.
expect_refused() { # what, port, client
  probe $2 $3
  if [ "$P_CODE" == "000" ] && { [ "$P_EXIT" == "35" ] || [ "$P_EXIT" == "55" ] || [ "$P_EXIT" == "56" ]; }; then
    pass "$1: refused in the handshake (curl $P_EXIT)"
  else
    fail "$1: expected a refused handshake, got code=$P_CODE curl=$P_EXIT body='$P_BODY'"
  fi
}

GOOD=client1.internal.corp.com
WRONGCN=client2.external.com
OTHER=rogue-client

for f in $GOOD/cert.pem $WRONGCN/cert.pem $OTHER/cert.pem rogue-ca/ca.pem; do
  [ -f $f ] || { echo "  FAIL: fixture $f is missing"; exit 1; }
done
docker cp rogue-ca/ca.pem llb1:/opt/loxilb/cert/client_ca_other.crt >/dev/null

lost0=$(logcount "No mTLS config for connection")

echo "The rule on 2020 as configured"
expect_served "trusted client, matching name" 2020 $GOOD
expect_refused "no client certificate" 2020 none

echo "An endpoint leaves the rule on 2020"
n=$(taken 2020)
rc=$(post_rule 2020 e2e-mtls-required-service "$EP2" "$REQUIRED_CN"); echo "  POST -> $rc"
[ "$rc" == "200" ] && pass "the update was accepted" || fail "the update was answered $rc"
expect_taken 2020 $n "after the endpoint change"
for i in 1 2 3 4; do expect_served "trusted client, connection $i after the change" 2020 $GOOD; done
expect_refused "no client certificate after the change" 2020 none
expect_refused "a certificate from another CA after the change" 2020 $OTHER
expect_refused "a trusted certificate with another name after the change" 2020 $WRONGCN

echo "The endpoint comes back"
n=$(taken 2020)
rc=$(post_rule 2020 e2e-mtls-required-service "$EP3" "$REQUIRED_CN"); echo "  POST -> $rc"
[ "$rc" == "200" ] && pass "the update was accepted" || fail "the update was answered $rc"
expect_taken 2020 $n "after the second endpoint change"
expect_served "trusted client after the second change" 2020 $GOOD
expect_refused "no client certificate after the second change" 2020 none

echo "The same payload again"
rc=$(post_rule 2020 e2e-mtls-required-service "$EP3" "$REQUIRED_CN"); echo "  POST -> $rc"
[ "$rc" == "409" ] && pass "an unchanged rule is answered 409" || fail "an unchanged rule was answered $rc"
expect_served "trusted client after the unchanged POST" 2020 $GOOD
expect_refused "no client certificate after the unchanged POST" 2020 none

echo "The rule on 2020 deleted and created again"
n=$(taken 2020)
rc=$(del_rule 2020); echo "  DELETE -> $rc"
rc=$(post_rule 2020 e2e-mtls-required-service "$EP3" "$REQUIRED_CN"); echo "  POST -> $rc"
expect_taken 2020 $n "after delete and create"
expect_served "trusted client after delete and create" 2020 $GOOD
expect_refused "no client certificate after delete and create" 2020 none
expect_refused "a trusted certificate with another name after delete and create" 2020 $WRONGCN

# One listener, four rules in turn. Each must be judged by its own arguments.
echo "A listener that asks for no client certificate (2022)"
rc=$(post_rule 2022 e2e-mtls-takeover "$EP1" ""); echo "  POST -> $rc"
sleep 3
expect_served "no client certificate, none asked for" 2022 none

echo "Its rule is replaced by one that requires a client certificate"
n=$(taken 2022)
rc=$(del_rule 2022); echo "  DELETE -> $rc"
rc=$(post_rule 2022 e2e-mtls-takeover "$EP1" "$REQUIRED"); echo "  POST -> $rc"
expect_taken 2022 $n "required after none"
expect_refused "no client certificate, now required" 2022 none
expect_served "trusted client, now required" 2022 $GOOD
expect_refused "a certificate from another CA, now required" 2022 $OTHER

echo "Then by one that trusts another CA"
n=$(taken 2022)
rc=$(del_rule 2022); echo "  DELETE -> $rc"
rc=$(post_rule 2022 e2e-mtls-takeover "$EP1" "$REQUIRED_OTHER_CA"); echo "  POST -> $rc"
expect_taken 2022 $n "another CA"
expect_served "a certificate from the CA the rule names now" 2022 $OTHER
expect_refused "a certificate from the CA the rule before named" 2022 $GOOD
expect_refused "no client certificate, another CA" 2022 none

echo "Then by one that asks for none again"
n=$(taken 2022)
rc=$(del_rule 2022); echo "  DELETE -> $rc"
rc=$(post_rule 2022 e2e-mtls-takeover "$EP1" ""); echo "  POST -> $rc"
expect_taken 2022 $n "none after required"
expect_served "no client certificate, none asked for again" 2022 none
rc=$(del_rule 2022); echo "  DELETE -> $rc"

lost1=$(logcount "No mTLS config for connection")
[ "$lost1" == "$lost0" ] && pass "no handshake found its listener without client verification arguments" \
  || fail "$((lost1 - lost0)) handshakes found their listener without client verification arguments"

alive=$($dexec llb1 pidof loxilb | wc -w)
[ "$alive" == "1" ] && pass "the gateway process is alive" || fail "the gateway process is gone"

if [ $tcode == 0 ]; then
  echo " A rule takes over a kept listener [OK]"
else
  echo " A rule takes over a kept listener [FAILED]"
fi
exit $tcode
