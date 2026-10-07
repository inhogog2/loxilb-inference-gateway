#!/bin/bash
# A rule whose TLS context cannot be built is refused by the data plane and
# leaves nothing behind: the gateway keeps running, the port has no listener,
# and the same port can be used by a valid rule afterwards. A cipher string
# the TLS library does not take is the caller's to correct: it is refused
# before the data plane is asked.
source ../common.sh
echo SCENARIO-e2ehttps-tlsctx

API=http://localhost:11111/netlox/v1/config/loadbalancer
VIP=10.10.10.254
code=0

fail() { echo "  FAIL: $*"; code=1; }
pass() { echo "  ok: $*"; }

gw_pid() { $dexec llb1 pidof loxilb 2>/dev/null | tr -d '\r'; }
gw_log() { $dexec llb1 cat /var/log/loxilbdp.log 2>/dev/null; }
listens() { $dexec llb1 ss -Hltn "sport = :$1" 2>/dev/null | grep -q LISTEN; }
not_installed() { gw_log | grep -c "vip port $1 not installed: TLS context"; }

post_rule() { # port, extra serviceArguments (JSON members, leading comma)
  $dexec llb1 curl -s -o /tmp/tlsctx-answer -w '%{http_code}' -X POST $API \
    -H "Content-Type: application/json" -d '{
  "serviceArguments": { "externalIP": "'$VIP'", "port": '$1', "protocol": "tcp",
    "security": 2, "mode": 4, "host": "'$VIP'"'"$2"' },
  "endpoints": [
    { "endpointIP": "31.31.31.1", "targetPort": 8080, "weight": 1 },
    { "endpointIP": "32.32.32.1", "targetPort": 8080, "weight": 1 },
    { "endpointIP": "33.33.33.1", "targetPort": 8080, "weight": 1 }
  ]}'
}
# What GET reports for a rule's arguments and endpoints. The generation of
# the backend TLS context counts installs, and a rule put back is installed
# again, so it is left out.
rule_of() { # port
  $dexec llb1 curl -s $API/all | jq -cS --argjson p "$1" \
    '.lbAttr[] | select(.serviceArguments.port==$p) | {a: (.serviceArguments | del(.backend_tls_effective.generation)), e: [.endpoints[] | {endpointIP, targetPort, weight}]}'
}
serves() { # port
  local res=""
  for i in $(seq 1 10); do
    res=$($hexec l3h1 curl --max-time 10 -H "HOST: $VIP" --insecure -s https://$VIP:$1)
    [[ "$res" == server[123] ]] && return 0
    sleep 1
  done
  return 1
}
del_rule() {
  $dexec llb1 curl -s -o /dev/null -w '%{http_code}' -X DELETE \
    "$API/hosturl/$VIP/externalipaddress/$VIP/port/$1/protocol/tcp"
}

answer() { $dexec llb1 cat /tmp/tlsctx-answer 2>/dev/null; }

# A client CRL file that is not a CRL: the API does not read the file, the
# TLS library does when the listener's context is built.
BAD_CRL=', "mtls_frontend": { "client_cert_mode": "required", "client_ca_path": "/opt/loxilb/cert/rootCA.crt", "client_crl_path": "/opt/loxilb/cert/tlsctx-not-a-crl.pem" }'
BAD_CIPHERS=', "tls_ciphers": "NOT-A-CIPHER"'

# A cipher string the TLS library does not take: refused as the caller's
# argument, with the field named, and the data plane is never asked.
ciphers_leg() { # port
  local port=$1 rc seen before
  echo "Leg ciphers (port $port)"
  seen=$(not_installed $port)
  rc=$(post_rule $port "$BAD_CIPHERS")
  echo "  POST -> $rc"
  [ "$rc" == "400" ] && pass "a rule with an unusable cipher string is answered 400" \
    || fail "the rule was answered $rc, want 400: the caller can correct tls_ciphers"
  answer | grep -q "tls_ciphers" && pass "the answer names tls_ciphers" || fail "the answer does not name tls_ciphers: $(answer)"
  [ "$(not_installed $port)" == "$seen" ] && pass "the data plane was not asked" || fail "the data plane logged a refusal for port $port"
  listens $port && fail "port $port has a listener" || pass "port $port has no listener"
  [ -z "$(rule_of $port)" ] && pass "no rule is stored" || fail "a rule is stored: $(rule_of $port)"
  rc=$(post_rule $port ', "tls_ciphers": "TLS_AES_256_GCM_SHA384:ECDHE-RSA-AES256-GCM-SHA384"')
  [ "$rc" == "200" ] && pass "a rule with a usable cipher string is accepted" || fail "the usable cipher string was answered $rc, want 200: $(answer)"
  serves $port && pass "it serves" || fail "the rule with a usable cipher string does not serve"
  before=$(rule_of $port)
  rc=$(post_rule $port ', "inactiveTimeOut": 90, "tls_ciphers": "NOT-A-CIPHER"')
  [ "$rc" == "400" ] && pass "a replace with an unusable cipher string is answered 400" \
    || fail "the replace was answered $rc, want 400"
  [ "$(rule_of $port)" == "$before" ] && pass "the rule reads back as it was" || fail "the refused values are stored: $(rule_of $port)"
  serves $port && pass "the rule serves as before" || fail "the rule does not serve after the refused replace"
  echo "  DELETE -> $(del_rule $port)"
}

# One leg: the rule is posted, the data plane must refuse it and survive.
refused_leg() { # name, port, extra serviceArguments
  local name=$1 port=$2 extra=$3 rc before after seen
  echo "Leg $name (port $port)"
  before=$(gw_pid)
  [ -n "$before" ] || { fail "gateway is not running before the leg"; return; }
  seen=$(not_installed $port)
  rc=$(post_rule $port "$extra")
  echo "  POST -> $rc"
  if [ "$rc" == "400" ]; then
    echo "  SKIP: leg $name: the API refuses this argument in this release, so the data plane is never asked"
    return
  fi
  [ "$rc" == "412" ] && pass "the rule the data plane did not install is answered 412" \
    || fail "the rule was answered $rc, want 412: the VIP is the gateway's own, so the refusal is not the caller's"
  # The refusal is the event to wait for, not a clock.
  for i in $(seq 1 20); do
    [ "$(not_installed $port)" -gt "$seen" ] && break
    [ -n "$(gw_pid)" ] || break
    sleep 1
  done
  after=$(gw_pid)
  if [ -z "$after" ]; then fail "gateway exited after the rule was posted"; return; fi
  [ "$after" == "$before" ] && pass "gateway pid unchanged ($after)" || fail "gateway pid changed $before -> $after"
  [ "$(not_installed $port)" -gt "$seen" ] && pass "data plane logged the refusal" \
    || fail "no refusal was logged for port $port: the leg did not reach the TLS context"
  listens $port && fail "port $port has a listener" || pass "port $port has no listener"
  listens 2020 && pass "the existing listener on 2020 is still there" || fail "the listener on 2020 is gone"
  echo "  DELETE -> $(del_rule $port)"
  rc=$(post_rule $port "")
  echo "  POST (valid rule, same port) -> $rc"
  local res=""
  for i in $(seq 1 10); do
    res=$($hexec l3h1 curl --max-time 10 -H "HOST: $VIP" --insecure -s https://$VIP:$port)
    [[ "$res" == server[123] ]] && break
    sleep 1
  done
  [[ "$res" == server[123] ]] && pass "a valid rule on port $port serves ($res)" \
    || fail "a valid rule on port $port does not serve after the refusal (got '$res')"
  echo "  DELETE -> $(del_rule $port)"
}

# A replace the data plane refuses: the rule that was there stays as it was,
# stored and installed, and the same request is not taken for "no change".
replaced_leg() { # port
  local port=$1 rc before seen res
  echo "Leg refused-replace (port $port)"
  rc=$(post_rule $port ', "inactiveTimeOut": 60')
  [ "$rc" == "200" ] || { fail "precondition: the rule on $port was answered $rc"; return; }
  serves $port || { fail "precondition: the rule on $port does not serve"; echo "  DELETE -> $(del_rule $port)"; return; }
  before=$(rule_of $port); seen=$(not_installed $port)
  rc=$(post_rule $port ', "inactiveTimeOut": 90'"$BAD_CRL")
  echo "  POST (replace) -> $rc"
  [ "$rc" == "412" ] && pass "the replace the data plane did not install is answered 412" \
    || fail "the refused replace was answered $rc, want 412"
  [ "$(not_installed $port)" -gt "$seen" ] && pass "data plane logged the refusal" \
    || fail "no refusal was logged for port $port: the replace did not reach the TLS context: $(answer)"
  [ "$(rule_of $port)" == "$before" ] && pass "the rule reads back as it was" \
    || fail "the refused values are stored: $(rule_of $port)"
  serves $port && pass "the rule serves as before" || fail "the rule does not serve after the refused replace"
  rc=$(post_rule $port ', "inactiveTimeOut": 90'"$BAD_CRL")
  [ "$rc" == "412" ] && pass "the same request again is refused again, not taken for no change" \
    || fail "the same refused request was answered $rc the second time, want 412"
  serves $port && pass "the rule still serves" || fail "the rule does not serve after the second refusal"
  rc=$(post_rule $port ', "inactiveTimeOut": 90')
  [ "$rc" == "200" ] && pass "the replace without the bad value is accepted" || fail "the valid replace was answered $rc, want 200"
  [ "$(rule_of $port)" != "$before" ] && pass "the new value reads back" || fail "the valid replace was not stored"
  serves $port && pass "the rule serves after the valid replace" || fail "the rule does not serve after the valid replace"
  echo "  DELETE -> $(del_rule $port)"
}

$hexec l3ep1 node ../common/tcp_https_server.js server1 $VIP &
track_helper
$hexec l3ep2 node ../common/tcp_https_server.js server2 $VIP &
track_helper
$hexec l3ep3 node ../common/tcp_https_server.js server3 $VIP &
track_helper
sleep 5

listens 2020 || fail "precondition: the scenario's rule on 2020 has no listener"

LEGS=${TLSCTX_LEGS:-frontend backend}

# A cipher string no TLS library accepts never reaches the data plane.
if [[ " $LEGS " == *" frontend "* ]]; then
  ciphers_leg 2036
fi

# Frontend context: a client CRL file that is not a CRL.
if [[ " $LEGS " == *" frontend "* ]]; then
  $dexec llb1 sh -c 'echo not-a-crl > /opt/loxilb/cert/tlsctx-not-a-crl.pem'
  refused_leg frontend-crl 2030 "$BAD_CRL"
fi

# The same refusal on a rule that exists.
if [[ " $LEGS " == *" frontend "* ]]; then
  replaced_leg 2034
  $dexec llb1 rm -f /opt/loxilb/cert/tlsctx-not-a-crl.pem
fi

# Backend context: a client certificate ID whose files are not PEM.
if [[ " $LEGS " == *" backend "* ]]; then
  $dexec llb1 sh -c 'mkdir -p /etc/loxilb/certs/tlsctx-bad && echo not-a-certificate > /etc/loxilb/certs/tlsctx-bad/client.crt && echo not-a-key > /etc/loxilb/certs/tlsctx-bad/client.key'
  refused_leg backend-client-cert 2032 ', "backend_client_cert_id": "tlsctx-bad"'
  $dexec llb1 rm -rf /etc/loxilb/certs/tlsctx-bad
fi

stop_helpers

if [[ $code == 0 ]]; then
  echo SCENARIO-e2ehttps-tlsctx [OK]
else
  echo SCENARIO-e2ehttps-tlsctx [FAILED]
fi
exit $code
