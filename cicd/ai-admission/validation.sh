#!/bin/bash
# Validates the capacity admission gate (see README.md for the row table).
source ../common.sh
source ./gw.sh
echo SCENARIO-ai-admission

require_host_tools jq curl python3 || { echo "SCENARIO-ai-admission [FAILED]"; exit 1; }

code=0; npass=0; nfail=0
chk() { # chk <id> <what> <want> <got>
  if [ "$3" == "$4" ]; then echo "  [PASS] $1 $2 ($4)"; npass=$((npass+1))
  else echo "  [FAIL] $1 $2: want '$3', got '$4'"; nfail=$((nfail+1)); code=1; fi
}
chk_has() { # chk_has <id> <what> <needle> <haystack>
  case "$4" in
    *"$3"*) echo "  [PASS] $1 $2"; npass=$((npass+1)) ;;
    *) echo "  [FAIL] $1 $2: '$3' not found in: $(printf '%s' "$4" | tr '\n' ' ' | cut -c1-200)"; nfail=$((nfail+1)); code=1 ;;
  esac
}
chk_le() { # chk_le <id> <what> <max> <got>
  if [ "$4" != "unreadable" ] && [ "$4" -le "$3" ] 2>/dev/null; then echo "  [PASS] $1 $2 ($4 <= $3)"; npass=$((npass+1))
  else echo "  [FAIL] $1 $2: want <= $3, got '$4'"; nfail=$((nfail+1)); code=1; fi
}
chk_ge() { # chk_ge <id> <what> <min> <got>
  if [ "$4" != "unreadable" ] && [ "$4" -ge "$3" ] 2>/dev/null; then echo "  [PASS] $1 $2 ($4 >= $3)"; npass=$((npass+1))
  else echo "  [FAIL] $1 $2: want >= $3, got '$4'"; nfail=$((nfail+1)); code=1; fi
}

# ── the gateway's metrics (from the client host, through the VIP) ───────────
metrics_raw() { $hexec l3h1 curl -s --max-time 8 "$API/metrics" 2>/dev/null; }
# msum <family> [label-substr ...] -> the sum of the family's samples whose
# line carries every given substring, or "unreadable" when the scrape failed.
msum() {
  local fam="$1"; shift
  local body
  body=$(metrics_raw)
  case "$body" in *loxilb_*) ;; *) echo "unreadable"; return ;; esac
  printf '%s\n' "$body" | awk -v fam="$fam" -v a="${1:-}" -v b="${2:-}" -v c="${3:-}" '
    $0 ~ "^" fam "([{ ]|$)" {
      if (a != "" && index($0, a) == 0) next
      if (b != "" && index($0, b) == 0) next
      if (c != "" && index($0, c) == 0) next
      v = $NF; if (v + 0 == v) { s += v }
    }
    END { printf "%.0f", s + 0 }'
}
# The collector republishes its store every 10 s, so a gauge is read by
# polling for the expected value, and the last value read is what the
# assertion reports on a timeout.
wait_metric() { # wait_metric <family> <want> <secs> [label-substr ...]
  local fam="$1" want="$2" secs="$3" got="" i; shift 3
  for i in $(seq 1 "$secs"); do
    got=$(msum "$fam" "$@")
    [ "$got" == "$want" ] && { echo "$got"; return; }
    sleep 1
  done
  echo "$got"
}
svc() { echo "service=\"$VIP:$1\""; }
inflight() { msum loxilb_ai_admission_inflight "$(svc "$1")" 'role="service"'; }
queued() { msum loxilb_ai_admission_queued "$(svc "$1")"; }
decisions() { msum loxilb_ai_admission_decisions_total "$(svc "$1")" "reason=\"$2\""; }
# The gateway log lives at /var/log/loxilb<hostname>.log inside the container:
# always read it through the glob, and let the caller check it is non-empty.
gw_log() { docker exec llb1 sh -c 'cat /var/log/loxilb*.log 2>/dev/null'; }
lb_get() { $hexec l3h1 curl -s -m 8 "$API/config/loadbalancer/all" | jq -c ".lbAttr[] | select(.serviceArguments.port == $1)"; }
# A rule is deleted by its FULL key: an AI rule carries host, path prefix, match
# mode and model name, and a delete that omits any of them matches nothing
# (404 no-rule error) while the rule and its waiters live on.
lb_delete() { $hexec l3h1 curl -s -m 8 -X DELETE "$API/config/loadbalancer/hosturl/$VIP/externalipaddress/$VIP/port/$1/protocol/tcp?path_prefix=%2F&path_match_mode=prefix&model_name=${MODEL:-cap-model}"; }
# The data plane's live queued count through the rule's read-back: unlike the
# collector's 10 s store this reads the pool now, so a short wait can be seen.
wait_effective_queued() { # wait_effective_queued <port> <want> <secs>
  local got="" i
  for i in $(seq 1 $(( $3 * 2 ))); do
    got=$(lb_get "$1" | jq -r '.serviceArguments.fc_effective.queued // 0' 2>/dev/null)
    [ "$got" == "$2" ] && { echo "$got"; return; }
    sleep 0.5
  done
  echo "$got"
}
# A rule field read back until it holds a value: a replace POST reaches the
# data plane through the broker's queue, so a GET right after it may still
# see the old value.
wait_lb_field() { # wait_lb_field <port> <jq path> <want> <secs>
  local got="" i
  for i in $(seq 1 $(( $4 * 2 ))); do
    got=$(lb_get "$1" | jq -r "$2 // \"unreadable\"" 2>/dev/null)
    [ "$got" == "$3" ] && { echo "$got"; return; }
    sleep 0.5
  done
  echo "$got"
}
maint_put() { $hexec l3h1 curl -s -m 8 -X PUT "$API/maintenance" -H 'Content-Type: application/json' -d "{\"enabled\": $1}"; }
maint_get() { $hexec l3h1 curl -s -m 8 "$API/maintenance"; }

# ── the backends (from inside their namespace, never through the gateway) ───
be() { $hexec l3ep1 curl -s -m 5 "http://127.0.0.1:8080/$1" 2>/dev/null; }
receipts() { be "__receipts/$1" | jq -r '.count // "unreadable"'; }
order() { be "__order/$1" | jq -r '.order | join(" ")'; }
release() { be "__release/$1" >/dev/null; }
peak() { be "__peak/$1" | jq -r '.peak // "unreadable"'; }
peak_port() { be "__peak/$1" | jq -r ".ports[\"$2\"] // 0"; }
release_all() { be __release_all >/dev/null; }
wait_receipts() { # wait_receipts <nonce> <want> <secs>
  local got i
  for i in $(seq 1 "$3"); do got=$(receipts "$1"); [ "$got" == "$2" ] && { echo "$got"; return; }; sleep 1; done
  echo "$got"
}
h2_receipts() { # sum of the h2c backends' receipts for <prefix>-0..<n-1>
  local prefix=$1 n=$2 s=0 i p c
  for i in $(seq 0 $((n-1))); do
    for p in 8090 8091; do
      c=$($hexec l3ep1 curl -s -m 3 --http2-prior-knowledge "http://127.0.0.1:$p/__receipts/$prefix-$i" 2>/dev/null)
      case "$c" in ''|*[!0-9]*) ;; *) s=$((s + c)) ;; esac
    done
  done
  echo "$s"
}

# ── the audit trail ─────────────────────────────────────────────────────────
trail() {
  docker exec llb1 sh -c "cd '$AUDIT_DIR' 2>/dev/null || exit 0; for f in *.jsonl; do [ -f \"\$f\" ] && cat \"\$f\"; done; for f in *.jsonl.gz; do [ -f \"\$f\" ] && zcat \"\$f\"; done" 2>/dev/null \
    | jq -c -R 'fromjson? | select(type=="object" and .event_type != null)'
}
denies_for() { trail | jq -c "select(.event_type==\"sec.ai.deny\" and (.request_id|startswith(\"$1\")))"; }

# ── drivers ─────────────────────────────────────────────────────────────────
BODY='{"model":"cap-model","messages":[{"role":"user","content":"x"}]}'
HDRS=(-H 'Content-Type: application/json')
# hold_burst <dir> <n> <nonce> <url> [curl args...]: n parallel requests the
# backend holds until released; each request's status lands in <dir>/<i>.code
# once it completes, its headers in <dir>/<i>.hdr.
hold_burst() {
  local dir=$1 n=$2 nonce=$3 url=$4 i; shift 4
  for i in $(seq 1 "$n"); do
    $hexec l3h1 curl -s -o "$dir/$i.body" -D "$dir/$i.hdr" -w '%{http_code}' --max-time 120 \
      "${HDRS[@]}" -H 'X-Test-Hold: 1' -H "X-Test-Nonce: $nonce" -H "X-Request-Id: $nonce-$i" \
      "$@" -d "$BODY" "$url" > "$dir/$i.code" 2>/dev/null &
  done
}
# hold_each <dir> <n> <nonce> <url>: like hold_burst, but every request has its
# own nonce (<nonce><i>) so the holds can be released one at a time.
hold_each() {
  local dir=$1 n=$2 nonce=$3 url=$4 i
  for i in $(seq 1 "$n"); do
    $hexec l3h1 curl -s -o "$dir/h$i.body" -D "$dir/h$i.hdr" -w '%{http_code}' --max-time 120 \
      "${HDRS[@]}" -H 'X-Test-Hold: 1' -H "X-Test-Nonce: $nonce$i" -H "X-Request-Id: $nonce$i" \
      -d "$BODY" "$url" > "$dir/h$i.code" 2>/dev/null &
  done
}
sum_receipts() { # sum_receipts <nonce> <n>: receipts of <nonce>1..<nonce><n>
  local s=0 i c
  for i in $(seq 1 "$2"); do c=$(receipts "$1$i"); case "$c" in ''|*[!0-9]*) ;; *) s=$((s + c)) ;; esac; done
  echo "$s"
}
wait_sum_receipts() { # wait_sum_receipts <nonce> <n> <want> <secs>
  local got i
  for i in $(seq 1 "$4"); do got=$(sum_receipts "$1" "$2"); [ "$got" == "$3" ] && { echo "$got"; return; }; sleep 1; done
  echo "$got"
}
# queue_burst <dir> <n> <nonce> <url>: n requests sent one at a time, 300 ms
# apart, so their arrival order at the gateway is their number; nothing holds
# them at the backend, so once admitted each completes at once.
queue_burst() {
  local dir=$1 n=$2 nonce=$3 url=$4 i
  for i in $(seq 1 "$n"); do
    $hexec l3h1 curl -s -o "$dir/q$i.body" -D "$dir/q$i.hdr" -w '%{http_code}' --max-time 60 \
      "${HDRS[@]}" -H "X-Test-Nonce: $nonce" -H "X-Request-Id: $nonce-$i" \
      -d "$BODY" "$url" > "$dir/q$i.code" 2>/dev/null &
    sleep 0.3
  done
}
count_codes() { # count_codes <dir> <code>
  local dir=$1 want=$2 n=0 f
  for f in "$dir"/*.code; do [ -f "$f" ] && [ "$(cat "$f" 2>/dev/null)" == "$want" ] && n=$((n+1)); done
  echo "$n"
}
wait_codes() { # wait_codes <dir> <code> <want> <secs>
  local got i
  for i in $(seq 1 "$4"); do got=$(count_codes "$1" "$2"); [ "$got" == "$3" ] && { echo "$got"; return; }; sleep 1; done
  echo "$got"
}
first_hdr_with() { # first_hdr_with <dir> <code> -> that response's headers
  local f
  for f in "$1"/*.code; do
    [ "$(cat "$f" 2>/dev/null)" == "$2" ] && { cat "${f%.code}.hdr"; return; }
  done
}
hdr_val() { printf '%s' "$1" | grep -i "^$2:" | head -n1 | cut -d: -f2- | tr -d ' \r'; }

H1_URL="http://$VIP:$PORT_H1/v1/chat/completions"
TLS_URL="https://$VIP:$PORT_TLS/v1/chat/completions"
Q_URL="http://$VIP:$PORT_Q/v1/chat/completions"

echo ""
echo "Pre: the gate is on and exported"
chk P1 "the pool reports enforce mode" 2 "$(wait_metric loxilb_ai_admission_mode 2 25 "$(svc $PORT_H1)")"
chk P2 "service ceiling exported"     "$FC_MAX_OUT" "$(msum loxilb_ai_admission_limit "$(svc $PORT_H1)" 'role="service"')"
chk P3 "endpoint ceiling exported"    "$FC_EP_CAP"  "$(msum loxilb_ai_admission_limit "$(svc $PORT_H1)" 'role="normal"')"
chk P4 "nothing in flight"            0 "$(inflight $PORT_H1)"
chk P5 "no anomaly yet"               0 "$(msum loxilb_ai_admission_anomalies_total)"

# ── A: below the ceiling ────────────────────────────────────────────────────
echo ""
echo "A: below the ceiling, requests pass and the gauge returns to zero"
adm0=$(decisions $PORT_H1 admitted)
ok=0
for i in 1 2 3 4; do
  c=$($hexec l3h1 curl -s -o /dev/null -w '%{http_code}' --max-time 20 "${HDRS[@]}" \
        -H 'X-Test-Nonce: capA' -d "$BODY" "$H1_URL")
  [ "$c" == "200" ] && ok=$((ok+1))
done
chk A1 "four sequential requests answered 200" 4 "$ok"
chk A2 "four reached the backend"              4 "$(receipts capA)"
chk A3 "admitted decisions moved by four"      4 "$(( $(wait_metric loxilb_ai_admission_decisions_total $((adm0+4)) 25 "$(svc $PORT_H1)" 'reason="admitted"') - adm0 ))"
chk A4 "gauge back to zero"                    0 "$(wait_metric loxilb_ai_admission_inflight 0 25 "$(svc $PORT_H1)" 'role="service"')"

# ── B: at the ceiling ───────────────────────────────────────────────────────
echo ""
echo "B: 12 held requests against a ceiling of $FC_MAX_OUT"
shed0=$(decisions $PORT_H1 capacity_shed); adm0=$(decisions $PORT_H1 admitted)
DB=$(mktemp -d)
hold_burst "$DB" 12 capB "$H1_URL"
chk B1 "exactly $FC_MAX_OUT reached the backend"      "$FC_MAX_OUT" "$(wait_receipts capB $FC_MAX_OUT 15)"
chk B2 "the other four were refused with 429"        4 "$(wait_codes "$DB" 429 4 15)"
sleep 2
chk B3 "and none of them arrived later"              "$FC_MAX_OUT" "$(receipts capB)"
chk B4 "gauge shows $FC_MAX_OUT executing"           "$FC_MAX_OUT" "$(wait_metric loxilb_ai_admission_inflight $FC_MAX_OUT 25 "$(svc $PORT_H1)" 'role="service"')"
H=$(first_hdr_with "$DB" 429)
chk B5 "refusal carries the ceiling"                 "$FC_MAX_OUT" "$(hdr_val "$H" X-Loxilb-Admission-Limit)"
chk B6 "and the in-flight count"                     "$FC_MAX_OUT" "$(hdr_val "$H" X-Loxilb-Admission-Inflight)"
chk B7 "and an empty queue"                          0 "$(hdr_val "$H" X-Loxilb-Admission-Queued)"
chk B8 "and Retry-After"                             1 "$(hdr_val "$H" Retry-After)"
f=$(grep -l '^429$' "$DB"/*.code | head -n1); chk_has B9 "refusal body names the reason" admission_capacity "$(cat "${f%.code}.body" 2>/dev/null)"
chk_has B10 "with a jitter hint" jitter_hint_ms "$(cat "${f%.code}.body" 2>/dev/null)"
release_all; wait
chk B11 "the eight held requests completed 200"      "$FC_MAX_OUT" "$(count_codes "$DB" 200)"
chk B12 "gauge back to zero"                         0 "$(wait_metric loxilb_ai_admission_inflight 0 25 "$(svc $PORT_H1)" 'role="service"')"
chk B13 "capacity_shed decisions moved by four"      4 "$(( $(wait_metric loxilb_ai_admission_decisions_total $((shed0+4)) 25 "$(svc $PORT_H1)" 'reason="capacity_shed"') - shed0 ))"
chk B14 "admitted decisions moved by eight"          "$FC_MAX_OUT" "$(( $(decisions $PORT_H1 admitted) - adm0 ))"

# ── N: the endpoint ceiling ─────────────────────────────────────────────────
echo ""
echo "N: 12 held requests on a one-endpoint pool, endpoint ceiling $FC_EP_CAP"
DN=$(mktemp -d)
hold_burst "$DN" 12 capN "http://$VIP:$PORT_ONE/v1/chat/completions"
chk N1 "exactly $FC_EP_CAP reached the endpoint"      "$FC_EP_CAP" "$(wait_receipts capN $FC_EP_CAP 15)"
chk N2 "the other seven were refused with 429"       7 "$(wait_codes "$DN" 429 7 15)"
sleep 2
chk N3 "and none of them arrived later"              "$FC_EP_CAP" "$(receipts capN)"
H=$(first_hdr_with "$DN" 429)
chk N4 "refusal names the endpoint ceiling"          "$FC_EP_CAP" "$(hdr_val "$H" X-Loxilb-Admission-Limit)"
chk N5 "endpoint gauge shows $FC_EP_CAP executing"   "$FC_EP_CAP" "$(wait_metric loxilb_ai_admission_inflight $FC_EP_CAP 25 "$(svc $PORT_ONE)" 'role="normal"')"
release_all; wait
chk N6 "the five held requests completed 200"        "$FC_EP_CAP" "$(count_codes "$DN" 200)"
chk N7 "gauges back to zero"                         0 "$(wait_metric loxilb_ai_admission_inflight 0 25 "$(svc $PORT_ONE)")"

# ── C: concurrent acquisition ───────────────────────────────────────────────
echo ""
echo "C: 64 simultaneous requests, ceiling $FC_MAX_OUT: the backend never sees more than $FC_MAX_OUT at once"
DC=$(mktemp -d)
for i in $(seq 1 64); do
  $hexec l3h1 curl -s -o /dev/null -w '%{http_code}' --max-time 60 "${HDRS[@]}" \
    -H 'X-Test-Delay-Ms: 2000' -H 'X-Test-Nonce: capC' -H "X-Request-Id: capC-$i" \
    -d "$BODY" "$H1_URL" > "$DC/$i.code" 2>/dev/null &
done
wait
n200=$(count_codes "$DC" 200); n429=$(count_codes "$DC" 429)
chk C1 "every request was answered 200 or 429"       64 "$((n200 + n429))"
chk C2 "peak concurrency at the backend == ceiling"  "$FC_MAX_OUT" "$(peak capC)"
chk_le C3 "endpoint :8080 never over its ceiling"    "$FC_EP_CAP" "$(peak_port capC 8080)"
chk_le C4 "endpoint :8081 never over its ceiling"    "$FC_EP_CAP" "$(peak_port capC 8081)"
chk C5 "receipts == admitted answers"                "$n200" "$(receipts capC)"
chk C6 "gauge back to zero"                          0 "$(wait_metric loxilb_ai_admission_inflight 0 25 "$(svc $PORT_H1)" 'role="service"')"

# ── D: keep-alive, one unit per request ─────────────────────────────────────
echo ""
echo "D: five requests on one keep-alive connection"
out=$($hexec l3h1 curl -s -o /dev/null -w '%{http_code}:%{num_connects}\n' --max-time 30 "${HDRS[@]}" \
        -H 'X-Test-Nonce: capD' -d "$BODY" "$H1_URL" -o /dev/null "$H1_URL" -o /dev/null "$H1_URL" \
        -o /dev/null "$H1_URL" -o /dev/null "$H1_URL")
chk D1 "five answers, one connection"  "200:1 200:0 200:0 200:0 200:0" "$(printf '%s' "$out" | tr '\n' ' ' | sed 's/ $//')"
chk D2 "five receipts"                 5 "$(receipts capD)"
chk D3 "gauge back to zero"            0 "$(wait_metric loxilb_ai_admission_inflight 0 25 "$(svc $PORT_H1)" 'role="service"')"

# ── E: HTTP/2, one unit per stream, released by RST_STREAM ──────────────────
echo ""
echo "E: 12 HTTP/2 streams on one connection, 3 cancelled mid-flight"
E=$(mktemp -d)
$hexec l3h1 python3 "$(pwd)/h2_admit.py" $VIP $PORT_H2 --streams 12 --delay-ms 40000 \
  --rst 3 --rst-after-s 15 --nonce-prefix capE > "$E/out" 2> "$E/err" &
sleep 2
chk E1 "gauge counts streams, not the connection" "$FC_MAX_OUT" "$(wait_metric loxilb_ai_admission_inflight $FC_MAX_OUT 25 "$(svc $PORT_H2)" 'role="service"')"
chk E2 "three cancelled streams handed their units back" $((FC_MAX_OUT-3)) "$(wait_metric loxilb_ai_admission_inflight $((FC_MAX_OUT-3)) 30 "$(svc $PORT_H2)" 'role="service"')"
wait
S=$(grep '"summary"' "$E/out" | head -n1)
chk E3 "four streams refused on their own stream" 4 "$(printf '%s' "$S" | jq -r '.refused')"
chk E4 "five streams answered 200"                5 "$(printf '%s' "$S" | jq -r '.admitted')"
chk E5 "three streams cancelled while live"       3 "$(printf '%s' "$S" | jq -r '.rst')"
chk E6 "no stream left unanswered"                0 "$(printf '%s' "$S" | jq -r '.other')"
chk E7 "a refused stream carries the ceiling"     "$FC_MAX_OUT" "$(grep '"429"' "$E/out" | head -n1 | jq -r '.headers["x-loxilb-admission-limit"] // empty')"
chk E8 "eight streams reached the h2c backends"   "$FC_MAX_OUT" "$(h2_receipts capE 12)"
chk E9 "gauge back to zero"                       0 "$(wait_metric loxilb_ai_admission_inflight 0 25 "$(svc $PORT_H2)" 'role="service"')"

# ── F: the client vanishes while executing ──────────────────────────────────
echo ""
echo "F: four executing clients reset their connections"
$hexec l3h1 python3 "$(pwd)/h1_client.py" disconnect $VIP $PORT_H1 --n 4 --after-s 3 --nonce-prefix capF > /tmp/ai-admission-F.out 2>&1
chk F1 "all four had reached the backend" 4 "$(( $(receipts capF-0) + $(receipts capF-1) + $(receipts capF-2) + $(receipts capF-3) ))"
chk F2 "gauge back to zero with the backend still holding" 0 "$(wait_metric loxilb_ai_admission_inflight 0 25 "$(svc $PORT_H1)" 'role="service"')"
release_all

# ── G + I: a kept backend leg is re-gated; a model listing bypasses capacity ─
echo ""
echo "G: the second request on a kept connection is gated like the first"
SIG=$(pwd)/.h1_signal; rm -f "$SIG"
$hexec l3h1 python3 "$(pwd)/h1_client.py" kept $VIP $PORT_H1 --signal "$SIG" --nonce-prefix capG --timeout 90 > /tmp/ai-admission-G.out 2>&1 &
for i in $(seq 1 20); do grep -q '"status": "200"' /tmp/ai-admission-G.out 2>/dev/null && break; sleep 1; done
chk G1 "first request on the connection answered 200" 1 "$(grep -c '"status": "200"' /tmp/ai-admission-G.out)"
DG=$(mktemp -d)
hold_burst "$DG" $FC_MAX_OUT capGfill "$H1_URL"
chk G2 "pool filled to the ceiling" "$FC_MAX_OUT" "$(wait_receipts capGfill $FC_MAX_OUT 15)"
echo "I: a model listing while the pool is full"
byp0=$(decisions $PORT_H1 bypass_non_inference)
# The pool is keyed by model, so a listing names it the way a client without a
# body can (X-Model); the gate then sees a non-inference request on that pool.
c=$($hexec l3h1 curl -s -o /dev/null -w '%{http_code}' --max-time 20 -H 'X-Test-Nonce: capI' -H "X-Model: $MODEL" "http://$VIP:$PORT_H1/v1/models")
chk I1 "GET /v1/models answered 200 with the pool full" 200 "$c"
chk I2 "and reached the backend"                        1 "$(receipts capI)"
chk I3 "counted as a bypass, not an admission"          1 "$(( $(wait_metric loxilb_ai_admission_decisions_total $((byp0+1)) 25 "$(svc $PORT_H1)" 'reason="bypass_non_inference"') - byp0 ))"
touch "$SIG"
for i in $(seq 1 30); do grep -q '"summary": "kept"' /tmp/ai-admission-G.out 2>/dev/null && break; sleep 1; done
chk G3 "second request on the SAME connection refused" 429 "$(grep '"summary": "kept"' /tmp/ai-admission-G.out | jq -r '.second')"
chk G4 "on the kept connection"                        true "$(grep '"summary": "kept"' /tmp/ai-admission-G.out | jq -r '.reused')"
chk G5 "and it never reached the backend"              0 "$(receipts capG-second)"
release_all; wait; rm -f "$SIG"
chk G6 "gauge back to zero" 0 "$(wait_metric loxilb_ai_admission_inflight 0 25 "$(svc $PORT_H1)" 'role="service"')"

# ── K: the refusals are on the audit trail ──────────────────────────────────
echo ""
echo "K: every capacity refusal is a sec.ai.deny record"
for i in $(seq 1 20); do [ "$(denies_for capB- | wc -l | tr -d ' ')" == "4" ] && break; sleep 1; done
D=$(denies_for capB-)
chk K1 "four deny records for the four 429s of B"  4 "$(printf '%s\n' "$D" | grep -c .)"
chk K2 "every one names the capacity stage"        4 "$(printf '%s\n' "$D" | jq -r '.detail.stage' | grep -c '^capacity$')"
chk K3 "with the status the client got"            4 "$(printf '%s\n' "$D" | jq -r '.outcome.status' | grep -c '^429$')"
chk K4 "an admission reason"                       4 "$(printf '%s\n' "$D" | jq -r '.outcome.reason' | grep -c '^admission$')"
chk K5 "the decision the body carried"             4 "$(printf '%s\n' "$D" | jq -r '.detail.decision' | grep -c '^admission_capacity$')"
chk K6 "the service"                               4 "$(printf '%s\n' "$D" | jq -r '.detail.service' | grep -c "^$VIP:$PORT_H1\$")"
chk K7 "and the model"                             4 "$(printf '%s\n' "$D" | jq -r '.detail.model' | grep -c "^$MODEL\$")"
chk K8 "security class, data stream"               4 "$(printf '%s\n' "$D" | jq -r '.class + "/" + .stream' | grep -c '^security/data$')"
chk K9 "admitted requests produced no deny record" 0 "$(denies_for capA | wc -l | tr -d ' ')"

# ── L: the TLS listener ─────────────────────────────────────────────────────
echo ""
echo "L: refusals and the reaper's stream cap are TLS records on a TLS listener"
DL=$(mktemp -d)
hold_burst "$DL" $FC_MAX_OUT capL "$TLS_URL" -k
chk L1 "TLS pool filled to the ceiling" "$FC_MAX_OUT" "$(wait_receipts capL $FC_MAX_OUT 20)"
c=$($hexec l3h1 curl -sk -o "$DL/x.body" -D "$DL/x.hdr" -w '%{http_code}' --max-time 20 "${HDRS[@]}" \
      -H 'X-Test-Nonce: capLx' -H 'X-Request-Id: capLx-1' -d "$BODY" "$TLS_URL"); rc=$?
chk L2 "the ninth request read a 429 through TLS"   429 "$c"
chk L3 "curl completed the TLS exchange (exit 0)"    0 "$rc"
chk L4 "the refusal carries the ceiling"            "$FC_MAX_OUT" "$(hdr_val "$(cat "$DL/x.hdr")" X-Loxilb-Admission-Limit)"
chk L5 "and never reached the backend"              0 "$(receipts capLx)"
release_all; wait
chk L6 "eight held TLS requests completed 200"      "$FC_MAX_OUT" "$(count_codes "$DL" 200)"
chk L7 "gauge back to zero"                         0 "$(wait_metric loxilb_ai_admission_inflight 0 25 "$(svc $PORT_TLS)" 'role="service"')"
echo "   an SSE stream that outlives the rule's ${SSE_CAP_SEC}s cap is ended by the reaper thread"
sse_log0=$(docker exec llb1 sh -c 'cat /var/log/loxilb*.log 2>/dev/null' | grep -c 'SSE_CAP')
$hexec l3h1 curl -sk -N --max-time 25 "${HDRS[@]}" -H 'X-Test-Forever: 1' -H 'X-Test-Nonce: capLsse' \
  -d '{"model":"cap-model","stream":true,"messages":[{"role":"user","content":"x"}]}' "$TLS_URL" \
  > "$DL/sse.out" 2> "$DL/sse.err"; rc=$?
chk_has L8 "the client read the cap event through TLS" max_stream_duration_exceeded "$(cat "$DL/sse.out")"
chk L9 "the stream ended before the client's own deadline (curl exit 28 = it did not)" 0 "$([ "$rc" == "28" ] && echo 1 || echo 0)"
chk_has L10 "the reaper cut the stream" "1" "$([ "$(docker exec llb1 sh -c 'cat /var/log/loxilb*.log 2>/dev/null' | grep -c 'SSE_CAP')" -gt "$sse_log0" ] && echo 1 || echo 0)"
chk_has L11 "and the socket's owner worker wrote the event" "written by the owner worker" \
  "$(docker exec llb1 sh -c 'cat /var/log/loxilb*.log 2>/dev/null' | grep '\[REAPER\]' | tail -n1)"
echo "   (curl exit $rc; stderr: $(head -c 160 "$DL/sse.err" | tr '\n' ' '))"

# ── J: the export before the reboot ─────────────────────────────────────────
echo ""
echo "J: the gate's accounting stayed consistent"
chk J1 "no accounting anomaly (underflow)"      0 "$(msum loxilb_ai_admission_anomalies_total 'kind="underflow"')"
chk J2 "no accounting anomaly (unknown permit)" 0 "$(msum loxilb_ai_admission_anomalies_total 'kind="unknown_permit"')"
chk J3 "no request was refused for no capacity" 0 "$(msum loxilb_ai_admission_decisions_total 'reason="no_healthy_capacity"')"
chk J4 "every pool is exported"                 6 "$(metrics_raw | grep -c '^loxilb_ai_admission_mode{')"

# ── Q: the bounded queue, FIFO ──────────────────────────────────────────────
echo ""
echo "Q: 8 held on the queue pool, 4 wait in order, 2 more are refused"
q0=$(decisions $PORT_Q queued); qf0=$(decisions $PORT_Q queue_full); adm0=$(decisions $PORT_Q admitted)
wc0=$(msum loxilb_ai_admission_queue_wait_seconds_count "$(svc $PORT_Q)")
DQ=$(mktemp -d)
hold_each "$DQ" $FC_MAX_OUT capQh "$Q_URL"
chk Q1 "the pool filled to the ceiling"                "$FC_MAX_OUT" "$(wait_sum_receipts capQh $FC_MAX_OUT $FC_MAX_OUT 15)"
queue_burst "$DQ" $FC_Q_DEPTH capQq "$Q_URL"
chk Q2 "queued gauge shows $FC_Q_DEPTH waiting"        "$FC_Q_DEPTH" "$(wait_metric loxilb_ai_admission_queued $FC_Q_DEPTH 25 "$(svc $PORT_Q)")"
chk Q3 "none of them reached the backend"              0 "$(receipts capQq)"
chk Q4 "the depth is exported as the queue limit"      "$FC_Q_DEPTH" "$(msum loxilb_ai_admission_limit "$(svc $PORT_Q)" 'role="queue"')"
chk Q5 "queued decisions moved by $FC_Q_DEPTH"         "$FC_Q_DEPTH" "$(( $(wait_metric loxilb_ai_admission_decisions_total $((q0+FC_Q_DEPTH)) 25 "$(svc $PORT_Q)" 'reason="queued"') - q0 ))"
for i in 1 2; do
  $hexec l3h1 curl -s -o "$DQ/f$i.body" -D "$DQ/f$i.hdr" -w '%{http_code}' --max-time 20 "${HDRS[@]}" \
    -H 'X-Test-Nonce: capQf' -H "X-Request-Id: capQf-$i" -d "$BODY" "$Q_URL" > "$DQ/f$i.code" 2>/dev/null
done
chk Q6 "two more were refused with 429"                2 "$(count_codes "$DQ" 429)"
H=$(first_hdr_with "$DQ" 429)
chk Q7 "the refusal reports the full queue"            "$FC_Q_DEPTH" "$(hdr_val "$H" X-Loxilb-Admission-Queued)"
chk Q8 "and the ceiling"                               "$FC_MAX_OUT" "$(hdr_val "$H" X-Loxilb-Admission-Limit)"
chk_has Q9 "refusal body names the reason"             admission_capacity "$(cat "$DQ/f1.body" 2>/dev/null)"
chk Q10 "and they never reached the backend"           0 "$(receipts capQf)"
chk Q11 "queue_full decisions moved by two"            2 "$(( $(wait_metric loxilb_ai_admission_decisions_total $((qf0+2)) 25 "$(svc $PORT_Q)" 'reason="queue_full"') - qf0 ))"
# One held request completes: its unit wakes the head of the queue; that
# request completes at once and wakes the next, so the four drain in order.
release capQh1
chk Q12 "all four waiting requests reached the backend"  "$FC_Q_DEPTH" "$(wait_receipts capQq $FC_Q_DEPTH 20)"
chk Q13 "in the order they arrived"                    "capQq-1 capQq-2 capQq-3 capQq-4" "$(order capQq)"
chk Q14 "queued gauge back to zero"                    0 "$(wait_metric loxilb_ai_admission_queued 0 25 "$(svc $PORT_Q)")"
chk Q15 "the wait histogram counted four resumes"      4 "$(( $(wait_metric loxilb_ai_admission_queue_wait_seconds_count $((wc0+4)) 25 "$(svc $PORT_Q)") - wc0 ))"
release_all; wait
chk Q16 "the four waiting requests answered 200"       "$FC_Q_DEPTH" "$(count_codes "$DQ" 200 | awk -v h=$FC_MAX_OUT '{print $1 - h}')"
chk Q17 "admitted decisions moved by $((FC_MAX_OUT+FC_Q_DEPTH))" $((FC_MAX_OUT+FC_Q_DEPTH)) "$(( $(wait_metric loxilb_ai_admission_decisions_total $((adm0+FC_MAX_OUT+FC_Q_DEPTH)) 25 "$(svc $PORT_Q)" 'reason="admitted"') - adm0 ))"
chk Q18 "gauge back to zero"                           0 "$(wait_metric loxilb_ai_admission_inflight 0 25 "$(svc $PORT_Q)" 'role="service"')"

# ── T: the wait window ──────────────────────────────────────────────────────
echo ""
echo "T: two requests wait past ${FC_T_WAIT_MS} ms and are ended with 504"
to0=$(decisions $PORT_Q queue_timeout)
DT=$(mktemp -d)
# The wait window is shortened at runtime for this row: a replace POST of the
# same rule with the new wait, read back from the data plane before the burst.
gw_add_rule $PORT_Q "$(gw_queue_json $FC_Q_DEPTH $FC_T_WAIT_MS)" 8080 8081 >/dev/null
chk T0 "the wait window is changed at runtime"           "$FC_T_WAIT_MS" "$(wait_lb_field $PORT_Q .serviceArguments.fc_effective.queue_wait_ms "$FC_T_WAIT_MS" 10)"
hold_burst "$DT" $FC_MAX_OUT capTh "$Q_URL"
chk T1 "the pool filled to the ceiling"                "$FC_MAX_OUT" "$(wait_receipts capTh $FC_MAX_OUT 15)"
queue_burst "$DT" 2 capTq "$Q_URL"
chk T2 "two are waiting (data-plane read-back)"        2 "$(wait_effective_queued $PORT_Q 2 10)"
chk T3 "both were ended with 504"                      2 "$(wait_codes "$DT" 504 2 20)"
chk_has T4 "the body names the timeout"                admission_queue_timeout "$(cat "$DT/q1.body" 2>/dev/null)"
chk_ge T5 "and carries the wait it spent (queued_ms)"  "$FC_T_WAIT_MS" "$(jq -r '.queued_ms // "unreadable"' "$DT/q1.body" 2>/dev/null)"
chk_ge T6 "with Retry-After"                           1 "$(hdr_val "$(cat "$DT/q1.hdr")" Retry-After)"
chk T7 "queue_timeout decisions moved by two"          2 "$(( $(wait_metric loxilb_ai_admission_decisions_total $((to0+2)) 25 "$(svc $PORT_Q)" 'reason="queue_timeout"') - to0 ))"
chk T8 "queued gauge back to zero"                     0 "$(wait_metric loxilb_ai_admission_queued 0 25 "$(svc $PORT_Q)")"
release_all; wait
sleep 2
chk T9 "neither reached the backend, then or later"    0 "$(receipts capTq)"
chk T10 "gauge back to zero"                           0 "$(wait_metric loxilb_ai_admission_inflight 0 25 "$(svc $PORT_Q)" 'role="service"')"
gw_add_rule $PORT_Q "$(gw_queue_json $FC_Q_DEPTH $FC_Q_WAIT_MS)" 8080 8081 >/dev/null
chk T11 "the wait window is restored"                  "$FC_Q_WAIT_MS" "$(wait_lb_field $PORT_Q .serviceArguments.fc_effective.queue_wait_ms "$FC_Q_WAIT_MS" 10)"

# ── X: the client leaves while it waits ─────────────────────────────────────
echo ""
echo "X: two waiting clients reset their connections"
cx0=$(decisions $PORT_Q cancelled)
DX=$(mktemp -d)
hold_burst "$DX" $FC_MAX_OUT capXh "$Q_URL"
chk X1 "the pool filled to the ceiling"                "$FC_MAX_OUT" "$(wait_receipts capXh $FC_MAX_OUT 15)"
$hexec l3h1 python3 "$(pwd)/h1_client.py" disconnect $VIP $PORT_Q --n 2 --after-s 3 --nonce-prefix capXq > /tmp/ai-admission-X.out 2>&1 &
chk X2 "two are waiting (data-plane read-back)"        2 "$(wait_effective_queued $PORT_Q 2 10)"
wait %% 2>/dev/null
chk X3 "cancelled decisions moved by two"              2 "$(( $(wait_metric loxilb_ai_admission_decisions_total $((cx0+2)) 25 "$(svc $PORT_Q)" 'reason="cancelled"') - cx0 ))"
chk X4 "queued gauge back to zero"                     0 "$(wait_metric loxilb_ai_admission_queued 0 25 "$(svc $PORT_Q)")"
release_all; wait
sleep 2
chk X5 "neither ever reached the backend"              "0 0" "$(receipts capXq-0) $(receipts capXq-1)"
chk X6 "gauge back to zero"                            0 "$(wait_metric loxilb_ai_admission_inflight 0 25 "$(svc $PORT_Q)" 'role="service"')"

# ── W: the memory warning at apply ──────────────────────────────────────────
echo ""
echo "W: a depth of 65536 is applied with a warning; a depth of $FC_Q_DEPTH without"
chk_ge W1 "the gateway log is readable and non-empty"  1 "$(gw_log | wc -c | tr -d ' ')"
chk_ge W2 "the warning names the :$PORT_W rule and the two guards" 1 "$(gw_log | grep -c "$VIP:$PORT_W .*fc_max_queue_depth=65536 may park up to .*connectionLimit or LLB_PD_MAX_TOTAL_INFLIGHT")"
chk W3 "no warning for the :$PORT_Q rule"              0 "$(gw_log | grep "may park up to" | grep -c "$VIP:$PORT_Q ")"
chk W4 "the :$PORT_W pool is gated all the same"        65536 "$(msum loxilb_ai_admission_limit "$(svc $PORT_W)" 'role="queue"')"

# ── R: the fields are read back and changeable at runtime ───────────────────
echo ""
echo "R: GET reads the posted fields and the effective state; a replace POST changes them"
L=$(lb_get $PORT_Q)
chk R1 "fc_max_queue_depth read back"                  "$FC_Q_DEPTH"   "$(printf '%s' "$L" | jq -r '.serviceArguments.fc_max_queue_depth')"
chk R2 "fc_max_queue_wait_ms read back"                "$FC_Q_WAIT_MS" "$(printf '%s' "$L" | jq -r '.serviceArguments.fc_max_queue_wait_ms')"
chk R3 "fc_effective.mode"                             enforce         "$(printf '%s' "$L" | jq -r '.serviceArguments.fc_effective.mode')"
chk R4 "fc_effective.max_outstanding"                  "$FC_MAX_OUT"   "$(printf '%s' "$L" | jq -r '.serviceArguments.fc_effective.max_outstanding')"
chk R5 "fc_effective.queue_depth"                      "$FC_Q_DEPTH"   "$(printf '%s' "$L" | jq -r '.serviceArguments.fc_effective.queue_depth')"
chk R6 "fc_effective.queue_wait_ms"                    "$FC_Q_WAIT_MS" "$(printf '%s' "$L" | jq -r '.serviceArguments.fc_effective.queue_wait_ms')"
chk R7 "fc_effective.queue_memory_bound_mib = depth x 1 MiB" "$FC_Q_DEPTH" "$(printf '%s' "$L" | jq -r '.serviceArguments.fc_effective.queue_memory_bound_mib')"
chk R8 "fc_effective.queued is live"                   0 "$(printf '%s' "$L" | jq -r '.serviceArguments.fc_effective.queued // 0')"
gw_add_rule $PORT_Q "$(gw_queue_json 2 $FC_Q_WAIT_MS)" 8080 8081 >/dev/null
chk R9 "a replace POST with depth 2 is read back"      2 "$(wait_lb_field $PORT_Q .serviceArguments.fc_max_queue_depth 2 10)"
chk R10 "and the data plane holds it"                  2 "$(wait_lb_field $PORT_Q .serviceArguments.fc_effective.queue_depth 2 10)"
chk R11 "and exports it"                               2 "$(wait_metric loxilb_ai_admission_limit 2 25 "$(svc $PORT_Q)" 'role="queue"')"
gw_add_rule $PORT_Q "$(gw_queue_json $FC_Q_DEPTH $FC_Q_WAIT_MS)" 8080 8081 >/dev/null
chk R12 "restored to $FC_Q_DEPTH"                      "$FC_Q_DEPTH" "$(wait_metric loxilb_ai_admission_limit $FC_Q_DEPTH 25 "$(svc $PORT_Q)" 'role="queue"')"
c=$($hexec l3h1 curl -s -o /dev/null -w '%{http_code}' -m 8 -X POST "$API/config/loadbalancer" -H 'Content-Type: application/json' \
      -d "{\"serviceArguments\": {\"externalIP\": \"$VIP\", \"port\": 2027, \"protocol\": \"tcp\", \"sel\": 0, \"mode\": 4, \"sse_mode\": true, \"fc_max_queue_depth\": 4}, \"endpoints\": [{\"endpointIP\": \"31.31.31.1\", \"targetPort\": 8080, \"weight\": 1}]}")
chk R13 "a depth without a wait window is refused"     400 "$c"
# A replace is judged on the rule it leaves: one carrying only a depth keeps
# the stored wait; one carrying only a zero wait would leave the stored depth
# without a window, and is refused with the stored rule untouched.
chk_has R14 "a replace carrying only a depth is accepted" Success "$(gw_add_rule $PORT_Q ', "fc_max_queue_depth": 2' 8080 8081)"
chk R15 "the depth is replaced"                        2 "$(wait_lb_field $PORT_Q .serviceArguments.fc_effective.queue_depth 2 10)"
chk R16 "and the stored wait is kept"                  "$FC_Q_WAIT_MS" "$(lb_get $PORT_Q | jq -r '.serviceArguments.fc_max_queue_wait_ms')"
chk_has R17 "a replace leaving the depth without a wait is refused" '"code":400' "$(gw_add_rule $PORT_Q ', "fc_max_queue_wait_ms": 0' 8080 8081)"
chk R18 "and the stored rule is untouched"             "2 $FC_Q_WAIT_MS" "$(lb_get $PORT_Q | jq -r '.serviceArguments | "\(.fc_max_queue_depth) \(.fc_max_queue_wait_ms)"')"
gw_add_rule $PORT_Q "$(gw_queue_json $FC_Q_DEPTH $FC_Q_WAIT_MS)" 8080 8081 >/dev/null
chk R19 "restored to $FC_Q_DEPTH"                      "$FC_Q_DEPTH" "$(wait_lb_field $PORT_Q .serviceArguments.fc_effective.queue_depth "$FC_Q_DEPTH" 10)"

# ── KA: a refusal keeps the connection ──────────────────────────────────────
echo ""
echo "KA: a 429 on a buffered request keeps the connection; the next request on it is admitted"
DK=$(mktemp -d)
hold_burst "$DK" $FC_MAX_OUT capKAh "$H1_URL"
chk KA1 "the pool filled to the ceiling"               "$FC_MAX_OUT" "$(wait_receipts capKAh $FC_MAX_OUT 15)"
SIG=$(pwd)/.h1_signal; rm -f "$SIG"
$hexec l3h1 python3 "$(pwd)/h1_client.py" shed_keepalive $VIP $PORT_H1 --signal "$SIG" --nonce-prefix capKA --timeout 90 > /tmp/ai-admission-KA.out 2>&1 &
for i in $(seq 1 20); do grep -q '"status": "429"' /tmp/ai-admission-KA.out 2>/dev/null && break; sleep 1; done
chk KA2 "the first request was refused with 429"       429 "$(grep '"nonce": "capKA-first"' /tmp/ai-admission-KA.out | jq -r '.status')"
chk KA3 "with Connection: keep-alive"                  keep-alive "$(grep '"nonce": "capKA-first"' /tmp/ai-admission-KA.out | jq -r '.connection')"
chk KA4 "and the socket stayed open"                   false "$(grep '"nonce": "capKA-first"' /tmp/ai-admission-KA.out | jq -r '.closed')"
release_all; wait_metric loxilb_ai_admission_inflight 0 25 "$(svc $PORT_H1)" 'role="service"' >/dev/null
touch "$SIG"
for i in $(seq 1 30); do grep -q '"summary": "shed_keepalive"' /tmp/ai-admission-KA.out 2>/dev/null && break; sleep 1; done
chk KA5 "the second request on the SAME socket was admitted" 200 "$(grep '"summary": "shed_keepalive"' /tmp/ai-admission-KA.out | jq -r '.second')"
chk KA6 "on the kept connection"                       true "$(grep '"summary": "shed_keepalive"' /tmp/ai-admission-KA.out | jq -r '.reused')"
chk KA7 "the refused request never reached the backend" 0 "$(receipts capKA-first)"
chk KA8 "the admitted one did"                          1 "$(receipts capKA-second)"
wait; rm -f "$SIG"

# ── DL: the rule is deleted while requests wait ─────────────────────────────
echo ""
echo "DL: deleting the queue pool ends its two waiting requests with 503"
DD=$(mktemp -d)
hold_burst "$DD" $FC_MAX_OUT capDh "$Q_URL"
chk DL1 "the pool filled to the ceiling"                "$FC_MAX_OUT" "$(wait_receipts capDh $FC_MAX_OUT 15)"
queue_burst "$DD" 2 capDq "$Q_URL"
chk DL2 "two are waiting"                               2 "$(wait_metric loxilb_ai_admission_queued 2 25 "$(svc $PORT_Q)")"
chk_has DL2b "the rule is deleted by its full key"     Success "$(lb_delete $PORT_Q)"
chk DL2c "and the GET no longer lists it"             gone "$([ -z "$(lb_get $PORT_Q)" ] && echo gone || echo listed)"
chk DL3 "both waiting requests were ended with 503"     2 "$(wait_codes "$DD" 503 2 15)"
chk_has DL4 "the body names the drain"                  admission_drained "$(cat "$DD/q1.body" 2>/dev/null)"
release_all; wait
sleep 2
chk DL5 "neither reached the backend, then or later"    0 "$(receipts capDq)"
for i in $(seq 1 20); do [ "$(denies_for capDq- | wc -l | tr -d ' ')" == "2" ] && break; sleep 1; done
chk DL6 "both drains are on the audit trail"            2 "$(denies_for capDq- | jq -r '.detail.decision' | grep -c '^admission_drained$')"
gw_add_rule $PORT_Q "$(gw_queue_json $FC_Q_DEPTH $FC_Q_WAIT_MS)" 8080 8081 >/dev/null
chk DL7 "the pool is back, gated, with an empty queue"  2 "$(wait_metric loxilb_ai_admission_mode 2 25 "$(svc $PORT_Q)")"
chk DL8 "nothing in flight on it"                       0 "$(wait_metric loxilb_ai_admission_inflight 0 25 "$(svc $PORT_Q)" 'role="service"')"

# ── M: maintenance drains the data path ─────────────────────────────────────
echo ""
echo "M: entering maintenance refuses new requests, ends the waiting ones, lets executing ones finish"
dr0=$(decisions $PORT_Q drained); dg0=$(decisions $PORT_Q draining)
DM=$(mktemp -d)
hold_burst "$DM" $FC_MAX_OUT capMh "$Q_URL"
chk M1 "the pool filled to the ceiling"                "$FC_MAX_OUT" "$(wait_receipts capMh $FC_MAX_OUT 15)"
queue_burst "$DM" 2 capMq "$Q_URL"
chk M2 "two are waiting"                               2 "$(wait_metric loxilb_ai_admission_queued 2 25 "$(svc $PORT_Q)")"
chk M3 "maintenance entered"                           maintenance "$(maint_put true | jq -r '.state')"
S=$(maint_get)
chk M4 "the read-back says inference is refused"       true "$(printf '%s' "$S" | jq -r '.refusing_new_inference')"
chk M5 "and counts the $FC_MAX_OUT executing requests"  "$FC_MAX_OUT" "$(printf '%s' "$S" | jq -r '.in_flight_requests')"
chk M6 "both waiting requests were ended with 503"     2 "$(wait_codes "$DM" 503 2 15)"
chk_has M7 "the body names the drain"                  admission_drained "$(cat "$DM/q1.body" 2>/dev/null)"
c=$($hexec l3h1 curl -s -o "$DM/n.body" -D "$DM/n.hdr" -w '%{http_code}' --max-time 20 "${HDRS[@]}" -H 'X-Test-Nonce: capMn' -d "$BODY" "$Q_URL")
chk M8 "a new request is refused with 503"             503 "$c"
chk_has M9 "naming the maintenance drain"              gateway_draining "$(cat "$DM/n.body" 2>/dev/null)"
chk M9b "and closing the connection (traffic moves off the node)" close "$(hdr_val "$(cat "$DM/n.hdr" 2>/dev/null)" Connection)"
chk M9c "with Retry-After 5"                           5 "$(hdr_val "$(cat "$DM/n.hdr" 2>/dev/null)" Retry-After)"
chk M10 "and never reached the backend"                0 "$(receipts capMn)"
chk M11 "drained decisions moved by two"               2 "$(( $(wait_metric loxilb_ai_admission_decisions_total $((dr0+2)) 25 "$(svc $PORT_Q)" 'reason="drained"') - dr0 ))"
chk M12 "draining decisions moved by one"              1 "$(( $(wait_metric loxilb_ai_admission_decisions_total $((dg0+1)) 25 "$(svc $PORT_Q)" 'reason="draining"') - dg0 ))"
release_all; wait
chk M13 "the executing requests finished 200"          "$FC_MAX_OUT" "$(count_codes "$DM" 200)"
chk M14 "maintenance left"                             active "$(maint_put false | jq -r '.state')"
chk M15 "the read-back no longer claims a drain"       false "$(maint_get | jq -r '.refusing_new_inference')"
c=$($hexec l3h1 curl -s -o /dev/null -w '%{http_code}' --max-time 20 "${HDRS[@]}" -H 'X-Test-Nonce: capMr' -d "$BODY" "$Q_URL")
chk M16 "admission is restored"                        200 "$c"
chk M17 "gauge back to zero"                           0 "$(wait_metric loxilb_ai_admission_inflight 0 25 "$(svc $PORT_Q)" 'role="service"')"

# ── H: observe mode ─────────────────────────────────────────────────────────
echo ""
echo "H: the same load in observe mode is admitted and only counted"
if gw_restart observe; then
  chk H1 "the pool reports observe mode" 1 "$(wait_metric loxilb_ai_admission_mode 1 25 "$(svc $PORT_H1)")"
  DH=$(mktemp -d)
  hold_burst "$DH" 12 capH "$H1_URL"
  chk H2 "all twelve reached the backend"     12 "$(wait_receipts capH 12 20)"
  chk H3 "gauge shows twelve executing"       12 "$(wait_metric loxilb_ai_admission_inflight 12 25 "$(svc $PORT_H1)" 'role="service"')"
  chk H4 "nothing was refused"                0  "$(count_codes "$DH" 429)"
  release_all; wait
  chk H5 "twelve answered 200"                12 "$(count_codes "$DH" 200)"
  # Nothing is refused, so every unit lands: 12 on a service ceiling of 8 is 4
  # over, and 6 per endpoint on a ceiling of 5 is 1 over on each of the two.
  # The decision is counted at each ceiling that would have refused it.
  chk H6 "six would have been shed (4 at the service ceiling, 1 per endpoint)" 6 "$(wait_metric loxilb_ai_admission_decisions_total 6 25 "$(svc $PORT_H1)" 'reason="observe_would_shed"')"
  chk H7 "twelve counted admitted"            12 "$(decisions $PORT_H1 admitted)"
  chk H8 "no capacity_shed decision"          0  "$(decisions $PORT_H1 capacity_shed)"
  chk H9 "gauge back to zero"                 0  "$(wait_metric loxilb_ai_admission_inflight 0 25 "$(svc $PORT_H1)" 'role="service"')"
  chk H10 "no anomaly"                        0  "$(msum loxilb_ai_admission_anomalies_total)"
else
  echo "  [FAIL] H0 the gateway did not come back in observe mode"; nfail=$((nfail+1)); code=1
fi

rm -rf "$DB" "$DN" "$DC" "$E" "$DG" "$DL" "$DQ" "$DT" "$DX" "$DK" "$DD" "$DM" "${DH:-/nonexistent}" 2>/dev/null

echo ""
if [ "$code" -eq 0 ]; then
  echo "SCENARIO-ai-admission [OK] ($npass pass)"
else
  echo "SCENARIO-ai-admission [FAILED] ($nfail fail, $npass pass)"
fi
exit $code
