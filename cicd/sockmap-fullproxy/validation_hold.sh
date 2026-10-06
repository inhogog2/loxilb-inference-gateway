#!/bin/bash
#
# sockmap-fullproxy / validation_hold.sh
#
# A client that half-closes after its request, on a service whose
# half_close_mode is hold: kept with its write side open until its answer is
# out, and let go at once when it resets.
#
#   H-1  answered. The answer is held back 300 ms and the client half-closes
#        20 ms after its request. It must get the whole answer: a hold that
#        shut the client's write side as well as its read side would raise
#        POLLHUP at once and lose it.
#   H-2  reset while waiting. The answer is held back 8 s; the client resets
#        200 ms after its FIN. Nothing has been written to it, so no write can
#        fail: the only way out is the reset reported on the fd. It is
#        disarmed while held but stays in the poll set, and POLLERR/POLLHUP
#        come without being asked for; the notifier then drops the fd's
#        registration on them, which tears the connection down. The backend
#        must see its leg closed within a second of the reset - not when its
#        answer is written 8 s in (a write would fail then), not at the 10 s
#        bound.
#   H-3  reset while the answer drains. The backend sends 32 MiB at once to a
#        client with a 64 KiB receive buffer reading 64 KiB a second, which
#        resets after a second. The proxy is still writing to it, and its next
#        write fails. Same bound: the backend's leg closed within a second. The
#        leg closes with a FIN; the backend watches for it while it writes,
#        since a send blocked on the proxy's closed window would not see it
#        until the kernel gave up on that send, a minute or more later.
#
# Every hold ends once, by its first reason: answered for H-1, reset for H-2
# and H-3; none expires, and no held client's EOF is handled twice.
#
# Self-contained: creates its own rule and backend and removes them; the bound
# is set to 10 s for the run and put back to 240 s. The service is not
# accelerated (sockMapMode off), so the kernel requirement of the other suites
# does not apply.
#
#   VIP 10.10.10.254:2110  half_close_mode=hold, sockMapMode=off
#   backend 31.31.31.1:9110, hold_backend.py - it prints when each connection
#   ended, which is what times a teardown the client cannot see

source ../common.sh
source ./sockmap_common.sh

sockmap_init_artifacts

SCENARIO="SCENARIO-sockmap-fullproxy-hold"
VIP=10.10.10.254
PORT=2110
EP_IP=31.31.31.1
EP_PORT=9110
EP_NS=l3ep1
CLIENT_NS=l3h1
LLB=llb1
CAP=10
GONE_WITHIN=1.0     # seconds from the client's reset to the backend's leg closing

echo "$SCENARIO"

API="http://localhost:11111/netlox/v1/config"
BLOG="$SOCKMAP_ARTIFACTS_DIR/hold_backend.jsonl"

api() { _sm_dexec "$LLB" curl -sS -o /dev/null -w '%{http_code}' "$@"; }
hc_set() { api -X POST -H 'Content-Type: application/json' -d "$1" "$API/halfclose"; }

metrics() { _sm_dexec "$LLB" curl -s --max-time 8 "http://localhost:11111/netlox/v1/metrics"; }
# One sample's value from a /metrics dump (0 when absent).
mval() {   # <dump> <exact series, labels included>
  printf '%s\n' "$1" | awk -v s="$2" '$1 == s {v = $2} END {print v + 0}'
}

# The backend's record for one request id, one field of it.
brec() {   # <id> <field>
  python3 - "$BLOG" "$1" "$2" <<'PY'
import json, sys
path, rid, field = sys.argv[1:]
rec = None
for line in open(path):
    try:
        d = json.loads(line)
    except ValueError:
        continue
    if d.get("id") == rid:
        rec = d
print("" if rec is None or rec.get(field) is None else rec.get(field))
PY
}
jfield() { printf '%s\n' "$1" | python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get(sys.argv[1], ""))' "$2" 2>/dev/null; }
# Waits until the backend has a record for the id (its leg closed).
wait_brec() {   # <id> <seconds>
  local i
  for ((i = 0; i < $2 * 10; i++)); do
    [[ -n $(brec "$1" gone) ]] && return 0
    sleep 0.1
  done
  return 1
}
# Within GONE_WITHIN seconds after the reset?
gone_check() {   # <label> <id> <rst epoch>
  local gone d
  gone=$(brec "$2" gone)
  if [[ -z $gone ]]; then
    sockmap_result "$1" "FAILED" "the backend never saw its leg close"
    return
  fi
  d=$(python3 -c 'import sys; print("%.3f" % (float(sys.argv[1]) - float(sys.argv[2])))' "$gone" "$3")
  if python3 -c 'import sys; d = float(sys.argv[1]); sys.exit(0 if -0.05 <= d <= float(sys.argv[2]) else 1)' "$d" "$GONE_WITHIN"; then
    sockmap_result "$1" "OK" "${d}s after the reset"
  else
    sockmap_result "$1" "FAILED" "${d}s after the reset (want <= ${GONE_WITHIN}s)"
  fi
}

cleanup() {
  sockmap_delete_lb_via_api "$LLB" "$VIP" "$PORT" >/dev/null 2>&1
  hc_set '{"allow":true,"capSeconds":240}' >/dev/null
  sudo pkill -f "hold_backend.py $EP_PORT" 2>/dev/null || true
}

echo "  -- Step 1: backend, rule, bound"
: > "$BLOG"
$hexec $EP_NS python3 "$(pwd)/hold_backend.py" "$EP_PORT" >> "$BLOG" 2>&1 &
for i in $(seq 1 20); do
  $hexec $CLIENT_NS python3 -c 'import socket,sys; socket.create_connection((sys.argv[1], int(sys.argv[2])), 1).close()' "$EP_IP" "$EP_PORT" 2>/dev/null && break
  sleep 0.5
done
_sm_dexec "$LLB" curl -s -X POST "$API/metrics" >/dev/null

body=$(cat <<JSON
{"serviceArguments":{"externalIP":"$VIP","port":$PORT,"protocol":"tcp","mode":4,"sel":0,
 "name":"hold-$PORT","sockMapMode":"off","half_close_mode":"hold"},
 "endpoints":[{"endpointIP":"$EP_IP","targetPort":$EP_PORT,"weight":1}]}
JSON
)
code=$(api -X POST -H 'Content-Type: application/json' -d "$body" "$API/loadbalancer")
if [[ $code == 200 ]]; then
  sockmap_result "rule with half_close_mode hold" "OK"
else
  sockmap_result "rule with half_close_mode hold" "FAILED" "HTTP $code"
  cleanup; sockmap_finalize "$SCENARIO"; exit 1
fi
code=$(hc_set "{\"allow\":true,\"capSeconds\":$CAP}")
[[ $code == 200 ]] || { sockmap_result "bound set to ${CAP}s" "FAILED" "HTTP $code"; cleanup; sockmap_finalize "$SCENARIO"; exit 1; }

# The exporter reads the data path every 10 s: settle one cycle, then take the base.
sleep 11
M0=$(metrics)

echo "  -- Step 2: H-1 answered"
out=$($hexec $CLIENT_NS python3 ./hold_client.py answered "$VIP" "$PORT" h1 2>&1)
if [[ $(jfield "$out" status) == 200 && $(jfield "$out" body) == 65536 ]]; then
  sockmap_result "H-1 half-closed client gets its whole answer" "OK"
else
  sockmap_result "H-1 half-closed client gets its whole answer" "FAILED" "$out"
fi

echo "  -- Step 3: H-2 reset while waiting"
out=$($hexec $CLIENT_NS python3 ./hold_client.py rstidle "$VIP" "$PORT" h2 2>&1)
rst=$(jfield "$out" rst)
wait_brec h2 5
gone_check "H-2 reset while waiting: let go at once" h2 "$rst"
if [[ $(brec h2 answered) == False ]]; then
  sockmap_result "H-2 the held-back answer was never written" "OK"
else
  sockmap_result "H-2 the held-back answer was never written" "FAILED" "answered=$(brec h2 answered)"
fi

echo "  -- Step 4: H-3 reset while the answer drains"
out=$($hexec $CLIENT_NS python3 ./hold_client.py rstdrain "$VIP" "$PORT" h3 2>&1)
rst=$(jfield "$out" rst)
got=$(jfield "$out" got)
wait_brec h3 5
if [[ -n $got && $got -gt 0 && $got -lt $((32 << 20)) ]]; then
  sockmap_result "H-3 the answer was under way when the client reset" "OK" "$got bytes read"
else
  sockmap_result "H-3 the answer was under way when the client reset" "FAILED" "got=$got ($out)"
fi
gone_check "H-3 reset while draining: let go at once" h3 "$rst"

echo "  -- Step 5: how the holds ended"
sleep 11
M1=$(metrics)
d() { echo $(( $(mval "$M1" "$1") - $(mval "$M0" "$1") )); }
HT='loxilb_proxy_halfclose_hold_total'
EA='loxilb_proxy_halfclose_hold_ended_total{reason="answered"}'
ER='loxilb_proxy_halfclose_hold_ended_total{reason="reset"}'
EX='loxilb_proxy_halfclose_hold_ended_total{reason="expired"}'
RE='loxilb_proxy_halfclose_hold_spurious_wakeups_total{kind="eof_reentry"}'
got="held $(d "$HT"), answered $(d "$EA"), reset $(d "$ER"), expired $(d "$EX"), eof_reentry $(d "$RE")"
if [[ $(d "$HT") == 3 && $(d "$EA") == 1 && $(d "$ER") == 2 && $(d "$EX") == 0 && $(d "$RE") == 0 ]]; then
  sockmap_result "three holds: one answered, two reset, none expired" "OK" "$got"
else
  sockmap_result "three holds: one answered, two reset, none expired" "FAILED" "$got"
fi
held=$(mval "$M1" 'loxilb_proxy_halfclose_held')
if [[ $held == 0 ]]; then
  sockmap_result "nothing left held" "OK"
else
  sockmap_result "nothing left held" "FAILED" "held=$held"
fi

echo "  -- Step 6: cleanup"
cleanup
sockmap_finalize "$SCENARIO"
