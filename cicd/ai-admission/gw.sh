#!/bin/bash
# gw.sh — the gateway half of the ai-admission scenario, shared by config.sh
# (the first boot, enforce mode) and validation.sh (the observe-mode reboot).
# Sourced after ../common.sh.

VIP=10.10.10.254
MODEL=cap-model
FC_MAX_OUT=8          # LLB_FC_MAX_OUTSTANDING: executing requests per pool
FC_EP_CAP=5           # LLB_FC_EP_MAX_INFLIGHT:  executing requests per endpoint
PORT_H1=2021          # plaintext HTTP/1.1 pool, two backends
PORT_H2=2022          # HTTP/2 (h2c) pool, two h2c backends
PORT_TLS=2023         # TLS listener, the same two HTTP/1.1 backends, SSE cap 3 s
PORT_ONE=2024         # one backend: the endpoint ceiling is the binding one
PORT_Q=2025           # the same two backends with a queue: depth 4, wait 30 s
PORT_W=2026           # one backend, depth 65536: the memory warning fires at apply
# (2027 is the port row R13's refused create names; it never exists.)
PORT_P=2028           # the same two backends, the rule's own ceiling (4) under the env's 8
PORT_U=2029           # the same two backends, rule ceiling 2 and a queue: raised at runtime
FC_P_MAX=4
FC_P_STALE_MS=45000
FC_U_MAX=2
FC_Q_DEPTH=4
# The pool's wait is long enough that a waiter outlives the 10 s metric
# republish the rows poll between parking it and releasing a unit; row T
# shortens it at runtime for the deadline it proves.
FC_Q_WAIT_MS=30000
FC_T_WAIT_MS=4000
SSE_CAP_SEC=3
AUDIT_DIR=/var/log/loxilb/audit
GW_ARGS="--audit-dir $AUDIT_DIR --audit-required"
API="http://$VIP:11111/netlox/v1"

gw_env() { # gw_env <mode> -> the environment the gate reads at pool creation
  echo "LLB_FC_MODE=$1 LLB_FC_MAX_OUTSTANDING=$FC_MAX_OUT LLB_FC_EP_MAX_INFLIGHT=$FC_EP_CAP"
}

gw_wait_api() {
  local i
  for i in $(seq 1 40); do
    if $hexec l3h1 curl -sf --max-time 3 "$API/version" >/dev/null 2>&1; then
      echo "  loxilb REST API ready (${i})"; return 0
    fi
    sleep 2
  done
  echo "FATAL: the REST API never answered"; return 1
}

# The REST listener answers before the boot config replay settles, and until
# it does the freeze middleware 503s every mutation. Probe the freeze with a
# write that can never apply.
gw_wait_boot() {
  local i
  for i in $(seq 1 40); do
    if ! $hexec l3h1 curl -s -m 3 -X POST "$API/config/loadbalancer" \
         -H 'Content-Type: application/json' -d '{}' \
         | grep -qE 'boot config replay settles|frozen while a snapshot restore is in progress'; then
      echo "  boot config settled (${i})"; return 0
    fi
    sleep 2
  done
  echo "FATAL: boot config replay never settled"; return 1
}

gw_wait_audit() {
  local st
  st=$($hexec l3h1 curl -s -m 5 "$API/audit/status")
  echo "  audit: $(printf '%s' "$st" | cut -c1-160)"
  if ! printf '%s' "$st" | jq -e '.available == true and .running == true' >/dev/null 2>&1; then
    echo "FATAL: the audit writer is not running; the deny records cannot be measured"
    return 1
  fi
}

# gw_add_rule <port> <extra-json> <target-port> [<target-port> ...]
# mode 4 (full proxy) turns on the userspace HTTP path; sse_mode makes the
# service an AI-gateway service, which is what the capacity gate keys on. No
# API key: the gate refuses on capacity alone, and the refusal is recorded
# with no actor, which is the shape a keyless VIP produces.
gw_add_rule() {
  local port=$1 extra=$2 resp eps="" tp; shift 2
  for tp in "$@"; do
    eps="$eps${eps:+, }{\"endpointIP\": \"31.31.31.1\", \"targetPort\": $tp, \"weight\": 1}"
  done
  resp=$($hexec l3h1 curl -s -m 10 -X POST "$API/config/loadbalancer" \
    -H 'Content-Type: application/json' \
    -d "{
      \"serviceArguments\": {
        \"externalIP\":      \"$VIP\",
        \"port\":             $port,
        \"protocol\":        \"tcp\",
        \"sel\":              0,
        \"mode\":             4,
        \"host\":            \"$VIP\",
        \"path_prefix\":     \"/\",
        \"path_match_mode\": \"prefix\",
        \"model_name\":      \"$MODEL\",
        \"sse_mode\":         true,
        \"inactiveTimeOut\":  60$extra
      },
      \"endpoints\": [ $eps ]
    }")
  echo "  rule $VIP:$port -> 31.31.31.1:$*: $(printf '%s' "$resp" | cut -c1-120)"
  case "$resp" in
    *Success*|*exist*) ;;
    *) echo "FATAL: rule $port rejected"; return 1 ;;
  esac
}

# gw_queue_json <depth> <wait-ms>: the two queue fields as rule JSON
gw_queue_json() { echo ", \"fc_max_queue_depth\": $1, \"fc_max_queue_wait_ms\": $2"; }
# gw_p_json [<extra>]: the :PORT_P rule's own gate fields, plus <extra>
gw_p_json() { echo ", \"fc_max_outstanding\": $FC_P_MAX, \"fc_telemetry_stale_ms\": $FC_P_STALE_MS${1:-}"; }
# gw_u_json <ceiling>: the :PORT_U rule's ceiling and queue
gw_u_json() { echo ", \"fc_max_outstanding\": $1$(gw_queue_json $FC_Q_DEPTH $FC_Q_WAIT_MS)"; }

gw_add_rules() {
  gw_add_rule $PORT_H1  ""                                                       8080 8081 || return 1
  gw_add_rule $PORT_H2  ", \"backend_protocol\": \"http2\""                       8090 8091 || return 1
  gw_add_rule $PORT_TLS ", \"security\": 1, \"max_stream_duration_sec\": $SSE_CAP_SEC" 8080 8081 || return 1
  gw_add_rule $PORT_ONE ""                                                       8080      || return 1
  gw_add_rule $PORT_Q   "$(gw_queue_json $FC_Q_DEPTH $FC_Q_WAIT_MS)"             8080 8081 || return 1
  gw_add_rule $PORT_W   "$(gw_queue_json 65536 $FC_Q_WAIT_MS)"                   8080      || return 1
  gw_add_rule $PORT_P   "$(gw_p_json)"                                           8080 8081 || return 1
  gw_add_rule $PORT_U   "$(gw_u_json $FC_U_MAX)"                                 8080 8081 || return 1
  sleep 2
}

# gw_restart <mode>: the gate reads its mode from the process environment
# when a pool is created, so a mode change is a new gateway process. The
# container, its links and its certificate mount stay; the datapath process
# is replaced the way cicd/cfg-persist-negative replaces it, and the rules
# are created again.
gw_restart() {
  local mode=$1 i
  echo "  restarting the gateway in $mode mode"
  docker exec llb1 pkill -9 -f '/root/loxilb-io/loxilb/loxilb' >/dev/null 2>&1
  for i in $(seq 1 20); do
    docker exec llb1 pgrep -f '/root/loxilb-io/loxilb/loxilb' >/dev/null 2>&1 || break
    sleep 1
  done
  docker exec -d llb1 bash -c "$(gw_env "$mode") /root/loxilb-io/loxilb/loxilb -p $GW_ARGS --loglevel debug > /tmp/loxilb.out 2> /tmp/loxilb.err"
  sleep 3
  gw_wait_api && gw_wait_boot && gw_wait_audit && gw_add_rules
}
