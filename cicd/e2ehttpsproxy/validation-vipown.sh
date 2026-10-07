#!/bin/bash
# A full-proxy rule needs a listener on its VIP. A VIP the gateway does not
# hold is refused with an answer that names the field. On a standby the VIP is
# with the peer: the rule is kept and its listener comes up when the gateway
# becomes the master.
source ../common.sh
echo SCENARIO-e2ehttps-vipown

BASE=http://localhost:11111/netlox/v1/config
INST=llb-inst0
FOREIGN=203.0.113.9   # in no subnet of the gateway
STANDBY=10.10.10.200  # in a subnet of the gateway, on none of its interfaces
PORT=2040
code=0

fail() { echo "  FAIL: $*"; code=1; }
pass() { echo "  ok: $*"; }

listens() { $dexec llb1 ss -Hltn "src = $1 and sport = :$PORT" 2>/dev/null | grep -q LISTEN; }
on_host() { $dexec llb1 ip -4 -o addr show | grep -q " $1/"; }
has_rule() { $dexec llb1 curl -s $BASE/loadbalancer/all | grep -q "\"externalIP\":\"$1\""; }
kept_lines() { $dexec llb1 sh -c 'cat /var/log/loxilb*.log' 2>/dev/null | grep -c "dport-$PORT,.* kept without a listener"; }
post_rule() { # VIP; prints the body and the status on the last line
  $dexec llb1 curl -s -w '\n%{http_code}' -X POST $BASE/loadbalancer \
    -H "Content-Type: application/json" -d '{
  "serviceArguments": { "externalIP": "'$1'", "port": '$PORT', "protocol": "tcp", "mode": 4 },
  "endpoints": [ { "endpointIP": "31.31.31.1", "targetPort": 8080, "weight": 1 } ]}'
}
del_rule() { $dexec llb1 curl -s -o /dev/null -w '%{http_code}' -X DELETE "$BASE/loadbalancer/externalipaddress/$1/port/$PORT/protocol/tcp"; }
set_state() {
  $dexec llb1 curl -s -o /dev/null -w '%{http_code}' -X POST $BASE/cistate \
    -H "Content-Type: application/json" -d '{"instance": "'$INST'", "state": "'$1'", "vip": "0.0.0.0"}'
}

on_host $FOREIGN && fail "precondition: $FOREIGN is on the gateway"
on_host $STANDBY && fail "precondition: $STANDBY is on the gateway"

echo "A VIP the gateway does not hold"
ans=$(post_rule $FOREIGN); rc=${ans##*$'\n'}; echo "  POST -> $rc"
[ "$rc" == "400" ] && pass "the rule is answered 400" || fail "the rule was answered $rc, want 400"
[[ "$ans" == *"externalIP $FOREIGN is not an address of this gateway"* ]] && pass "the answer names externalIP and the address" \
  || fail "the answer does not name the field: ${ans:0:300}"
has_rule $FOREIGN && fail "the refused rule is in the rule list" || pass "the refused rule is not kept"

echo "The same on a standby: the rule is kept"
[ "$(set_state BACKUP)" == "200" ] || fail "precondition: the instance could not be set to BACKUP"
n=$(kept_lines)
ans=$(post_rule $STANDBY); rc=${ans##*$'\n'}; echo "  POST -> $rc"
[ "$rc" == "200" ] && pass "the rule is accepted on the standby" || fail "the standby answered $rc: ${ans:0:300}"
has_rule $STANDBY && pass "the rule is in the rule list" || fail "the standby did not keep the rule"
[ "$(kept_lines)" -gt "$n" ] && pass "the gateway logged that the rule waits for its VIP" \
  || fail "nothing was logged about a kept rule: the listener was bound, or the rule took another path"
listens $STANDBY && fail "a standby has a listener on a VIP it does not hold" || pass "no listener while the VIP is with the peer"

echo "The standby becomes the master"
[ "$(set_state MASTER)" == "200" ] || fail "precondition: the instance could not be set to MASTER"
# The listener is the event to wait for: the periodic sync installs the rule.
for i in $(seq 1 60); do listens $STANDBY && break; sleep 1; done
on_host $STANDBY && pass "the VIP is on the gateway" || fail "the master did not take the VIP"
listens $STANDBY && pass "the kept rule has its listener" || fail "no listener on $STANDBY:$PORT 60s after the gateway became the master"
res=$($hexec l3h1 curl --max-time 10 -s -o /dev/null -w '%{http_code}' http://$STANDBY:$PORT/)
[ "$res" != "000" ] && pass "a client reaches the listener (HTTP $res)" || fail "a client cannot connect to $STANDBY:$PORT"

echo "  DELETE -> $(del_rule $STANDBY)"
[ "$(set_state NOT_DEFINED)" == "200" ] || fail "the instance could not be put back to NOT_DEFINED"
$dexec llb1 ss -Hltn "sport = :2020" | grep -q LISTEN && pass "the scenario's rule on 2020 still has its listener" \
  || fail "the listener on 2020 is gone after the state changes"

if [[ $code == 0 ]]; then
  echo SCENARIO-e2ehttps-vipown [OK]
else
  echo SCENARIO-e2ehttps-vipown [FAILED]
fi
exit $code
