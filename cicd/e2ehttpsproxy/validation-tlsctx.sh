#!/bin/bash
# A rule whose TLS context cannot be built is refused by the data plane and
# leaves nothing behind: the gateway keeps running, the port has no listener,
# and the same port can be used by a valid rule afterwards.
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
  $dexec llb1 curl -s -o /dev/null -w '%{http_code}' -X POST $API \
    -H "Content-Type: application/json" -d '{
  "serviceArguments": { "externalIP": "'$VIP'", "port": '$1', "protocol": "tcp",
    "security": 2, "mode": 4, "host": "'$VIP'"'"$2"' },
  "endpoints": [
    { "endpointIP": "31.31.31.1", "targetPort": 8080, "weight": 1 },
    { "endpointIP": "32.32.32.1", "targetPort": 8080, "weight": 1 },
    { "endpointIP": "33.33.33.1", "targetPort": 8080, "weight": 1 }
  ]}'
}
del_rule() {
  $dexec llb1 curl -s -o /dev/null -w '%{http_code}' -X DELETE \
    "$API/hosturl/$VIP/externalipaddress/$VIP/port/$1/protocol/tcp"
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

$hexec l3ep1 node ../common/tcp_https_server.js server1 $VIP &
track_helper
$hexec l3ep2 node ../common/tcp_https_server.js server2 $VIP &
track_helper
$hexec l3ep3 node ../common/tcp_https_server.js server3 $VIP &
track_helper
sleep 5

listens 2020 || fail "precondition: the scenario's rule on 2020 has no listener"

LEGS=${TLSCTX_LEGS:-frontend backend}

# Frontend context: a cipher string no TLS library accepts.
if [[ " $LEGS " == *" frontend "* ]]; then
  refused_leg frontend-ciphers 2030 ', "tls_ciphers": "NOT-A-CIPHER"'
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
