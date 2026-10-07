#!/bin/bash
# What the EPP integration must do end to end (Phase 1 M9): a request on an
# EPP rule goes to the pod the EPP named (X-Served-By), the request phase
# shows in the metrics, and with the EPP gone FailOpen falls back to the
# rule's own selector while FailClose answers 503 epp_unavailable; when the
# EPP is back, routing follows it again (the restart gap, T5).
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/../common/k8s-inference/k3d_common.sh"
igw_env_load "$HERE" || exit 1
command -v jq >/dev/null 2>&1 || { echo "FATAL: jq is required"; echo "SCENARIO-k3d-incluster-inference-epp [FAILED]"; exit 1; }
fails=0
API="http://$NODE_IP:11111/netlox/v1"
PORT_FC=8080   # FailClose rule
PORT_FO=8081   # FailOpen rule
MODEL="Qwen/Qwen3-0.6B"
BODY() { printf '{"model":"%s","messages":[{"role":"user","content":"%s"}]}' "$1" "$2"; }
epp_pid() { cat "$HERE/.work/epp-fake.pid" 2>/dev/null; }
epp_stop() { local p; p=$(epp_pid); [ -n "$p" ] && kill "$p" 2>/dev/null; sleep 1; }
epp_start() { # <mode>
  nohup "$HERE/.work/epp-fake" -listen "$EPP_IP:$EPP_PORT" -dest "$EPP_DEST" -mode "$1" \
    > "$HERE/.work/epp-fake.log" 2>&1 &
  echo $! > "$HERE/.work/epp-fake.pid"
  sleep 1
}
served_by() { # <port> -> the X-Served-By of one request ("" on failure)
  client_curl -s -i --max-time 8 -X POST "http://$NODE_IP:$1/v1/chat/completions" \
    -H 'Content-Type: application/json' -d "$(BODY "$MODEL" hi)" 2>/dev/null \
    | tr -d '\r' | awk 'tolower($1)=="x-served-by:"{print $2}'
}
status_of() { # <port> -> HTTP status
  client_curl -s -o /dev/null -w '%{http_code}' --max-time 8 -X POST "http://$NODE_IP:$1/v1/chat/completions" \
    -H 'Content-Type: application/json' -d "$(BODY "$MODEL" hi)" 2>/dev/null
}
metric() { # <family> <label=value> -> value (0 when absent)
  curl -s --max-time 5 "$API/metrics" | awk -v fam="$1" -v lab="$2" '$1 ~ "^"fam"\\{" && index($1, lab) {print $2; exit}'
}
rule_json() { # <port> <failure mode>
  local eps
  eps=$(kubectl -n llm get pods -l app=vllm-qwen3 -o json | jq -c '[.items[].status.podIP | {endpointIP: ., targetPort: 8000, weight: 1}]')
  printf '{"serviceArguments":{"externalIP":"%s","port":%d,"protocol":"tcp","mode":4,"sel":0,"name":"epp-%s","eppEndpoint":"%s:%d","eppPlaintext":true,"eppFailureMode":"%s","eppTimeoutMs":2000},"endpoints":%s}' \
    "$NODE_IP" "$1" "$2" "$EPP_IP" "$EPP_PORT" "$2" "$eps"
}

echo "=== 1. EPP rules go in over REST ==="
resp=$(curl -s --max-time 8 -w '\n%{http_code}' -X POST "$API/config/loadbalancer" -H 'Content-Type: application/json' -d "$(rule_json $PORT_FC FailClose)")
code=$(tail -1 <<<"$resp")
if [ "$code" != "200" ]; then
  if grep -qi "eppEndpoint" <<<"$resp"; then
    echo "SKIP: this loxilb image has no Endpoint Picker support (POST refused: $(head -1 <<<"$resp"))"
    echo "SCENARIO-k3d-incluster-inference-epp [SKIPPED]"
    exit 0
  fi
  bad "FailClose rule accepted" "HTTP $code: $(head -1 <<<"$resp")"
else ok "FailClose rule accepted"; fi
code=$(curl -s --max-time 8 -o /dev/null -w '%{http_code}' -X POST "$API/config/loadbalancer" -H 'Content-Type: application/json' -d "$(rule_json $PORT_FO FailOpen)")
check "FailOpen rule accepted" "$code" "200"
RULE=$(curl -s --max-time 5 "$API/config/loadbalancer/all" | jq -c '.lbAttr[]? | select(.serviceArguments.name=="epp-FailClose")')
check "eppEndpoint reads back"   "$(jq -r '.serviceArguments.eppEndpoint' <<<"$RULE")" "$EPP_IP:$EPP_PORT"
check "eppFailureMode reads back" "$(jq -r '.serviceArguments.eppFailureMode' <<<"$RULE")" "FailClose"
check "eppTimeoutMs reads back"  "$(jq -r '.serviceArguments.eppTimeoutMs' <<<"$RULE")" "2000"
poll 30 node_listening "$NODE_IP" "$PORT_FC" && ok "socket bound on $NODE_IP:$PORT_FC" || bad "socket bound on $NODE_IP:$PORT_FC"

echo "=== 2. every request goes to the pod the EPP named ==="
WANT=$(kubectl -n llm get pods -l app=vllm-qwen3 -o json | jq -r --arg ip "${EPP_DEST%:*}" '.items[] | select(.status.podIP==$ip) | .metadata.name')
OTHER=$(kubectl -n llm get pods -l app=vllm-qwen3 -o json | jq -r --arg ip "${EPP_DEST%:*}" '[.items[] | select(.status.podIP!=$ip) | .metadata.name] | join(",")')
ok0=$(metric loxilb_ai_epp_requests_total 'outcome="ok"')
hits=0
for i in $(seq 1 6); do
  s=$(served_by $PORT_FC)
  [ "$s" = "$WANT" ] && hits=$((hits+1)) || echo "  request $i served by '${s:-none}' (want $WANT; other pods: $OTHER)"
done
check "6/6 requests served by the EPP's pod $WANT" "$hits" "6"
ok1=$(metric loxilb_ai_epp_requests_total 'outcome="ok"')
check "loxilb_ai_epp_requests_total{outcome=ok} grew by 6" "$(( ${ok1:-0} - ${ok0:-0} ))" "6"
dur=$(curl -s --max-time 5 "$API/metrics" | awk '$1=="loxilb_ai_epp_duration_seconds_count"{print $2}')
[ "${dur:-0}" -ge 6 ] && ok "loxilb_ai_epp_duration_seconds has samples ($dur)" || bad "loxilb_ai_epp_duration_seconds has samples" "count=${dur:-none}"

echo "=== 3. with the EPP gone: FailOpen falls back, FailClose answers 503 ==="
epp_stop
err0=$(metric loxilb_ai_epp_requests_total 'outcome="error"')
s=$(served_by $PORT_FO)
[ -n "$s" ] && ok "FailOpen still served (by $s, the rule's own selector)" || bad "FailOpen still served" "no X-Served-By"
check "FailClose answers 503" "$(status_of $PORT_FC)" "503"
body=$(client_curl -s --max-time 8 -X POST "http://$NODE_IP:$PORT_FC/v1/chat/completions" -H 'Content-Type: application/json' -d "$(BODY "$MODEL" hi)")
grep -q epp_unavailable <<<"$body" && ok "503 body says epp_unavailable" || bad "503 body says epp_unavailable" "$body"
err1=$(metric loxilb_ai_epp_requests_total 'outcome="error"')
[ "$(( ${err1:-0} - ${err0:-0} ))" -ge 3 ] && ok "error outcomes counted ($(( err1 - err0 )))" || bad "error outcomes counted" "$err0 -> $err1"

echo "=== 4. the EPP is back: routing follows it again (restart gap) ==="
epp_start echo
hits=0
for i in $(seq 1 4); do s=$(served_by $PORT_FC); [ "$s" = "$WANT" ] && hits=$((hits+1)); done
check "4/4 requests back on the EPP's pod after the restart" "$hits" "4"

echo "=== 5. an EPP that sheds: its 429 reaches the client ==="
epp_stop
epp_start immediate
check "immediate response relayed as 429" "$(status_of $PORT_FC)" "429"
imm=$(metric loxilb_ai_epp_requests_total 'outcome="immediate"')
[ "${imm:-0}" -ge 1 ] && ok "immediate outcomes counted ($imm)" || bad "immediate outcomes counted" "none"
epp_stop
epp_start echo

if [ "$fails" -eq 0 ]; then echo "SCENARIO-k3d-incluster-inference-epp [OK]"; else echo "SCENARIO-k3d-incluster-inference-epp [FAILED] ($fails)"; exit 1; fi
