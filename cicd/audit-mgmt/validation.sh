#!/bin/bash
# Validates the management-plane audit trail (stage 1a):
#
#   T-GW-1  /audit/status reports the writer, never the trail's content
#   T-GW-3  the log-archive API refuses an audit segment by name
#   T25     the delegated originator: recorded on every record of the
#           request, trusted only for an account marked delegation_allowed,
#           never promoted to actor.user, malformed values dropped and counted
#           and the value loxicmd --originator sends is recorded as sent
#   TM      the named management routes each leave an intent+result pair
#   T22     the side-effecting OAuth GETs: healthy start (redirect + pair),
#           unknown-state callback, refresh with tokens in the query string;
#           all three refused with 503 while the writer is wedged
#   T15     canary secrets appear in no segment (active, sealed, compressed)
#           and in no error body, after first proving they were sent
#   T11     actor conformance: with --userservice every successful result
#           names a principal; without it every record says auth=none
#   T20     a crash between a durable intent and its result is reported at
#           the next boot as exactly one sys.intent.orphaned, never guessed
#   T3      once a probe has observed the wedge (a full filesystem still takes
#           appends into the active segment's last page, so the probe is the
#           shortest line of all and its refusal covers the rest), the gate
#           fails closed: 503 audit_unavailable through a generated route, a
#           raw route and a named route, with the authoritative state
#           unchanged; the un-wedged repeat leaves a pair sharing one
#           event_id
#   T19     a full audit filesystem is visible on /metrics and in the
#           operational log while the writer writes nothing, and the
#           retroactive sys.writer.write_failed record follows recovery
#
# The scenario restarts the gateway process (tiers.sh pattern) to change
# flag sets and to crash it; every boot's records stay readable because the
# segments of a previous boot are sealed and compressed, not removed.
#
# Rules: every refusal asserts the reason, not just the status; state
# oracles are independent reads of the authoritative store, never the HTTP
# answer; observed values are printed with the verdicts; a count that could
# be satisfied by an empty trail is paired with a floor.

cd "$(dirname "$0")"
source ../common.sh
source .state
echo SCENARIO-audit-mgmt
code=0

require_host_tools jq openssl || { echo "SCENARIO-audit-mgmt [FAILED]"; exit 1; }

API=http://127.0.0.1:11111/netlox/v1
GW_BIN=/root/loxilb-io/loxilb/loxilb
WEDGE_DIR=/var/log/loxilb/audit-wedge
# A regular file, so that an audit directory created beneath it fails with
# ENOTDIR: the writer-less gateway T-GW-5 needs, made without touching the
# healthy directory that --audit-dir defaults to.
NOAUDIT_BLOCK=/var/log/loxilb/audit-not-a-dir
SINK_CA=/tmp/audit-sink-ca.pem
WORK=$(mktemp -d)
REQLOG=$WORK/requests.log      # the harness's own record of what it sent
ERRBODIES=$WORK/error-bodies.log
# Settle probes (gw_start) that got no HTTP answer at all, over every boot.
# A dropped connection is not the freeze answer, so the probe moves on, but
# a management call that is never answered is a finding, and T-GW-6 scores it.
SETTLE_NOANSWER=0
trap 'rm -rf "$WORK"' EXIT

# ── verdict helpers ─────────────────────────────────────────────────────────
ok()  { echo "  [$1] $2 [OK]"; }
bad() { echo "  [$1] $2 [FAILED] — $3"; code=1; }
chk()     { if [[ "$4" == "$3" ]]; then ok "$1" "$2 = '$4'"; else bad "$1" "$2" "expected '$3' got '$4'"; fi; }
chk_ne()  { if [[ "$4" != "$3" ]]; then ok "$1" "$2 = '$4'"; else bad "$1" "$2" "must not be '$3'"; fi; }
chk_has() { if [[ "$4" == *"$3"* ]]; then ok "$1" "$2"; else bad "$1" "$2" "no '$3' in: ${4:0:240}"; fi; }
chk_ge()  { if [[ "$4" =~ ^[0-9]+$ && "$4" -ge "$3" ]]; then ok "$1" "$2 = $4 (>= $3)"; else bad "$1" "$2" "expected >= $3 got '$4'"; fi; }
chk_gt()  { if [[ "$4" =~ ^[0-9]+$ && "$3" =~ ^[0-9]+$ && "$4" -gt "$3" ]]; then ok "$1" "$2 = $4 (> $3)"; else bad "$1" "$2" "expected > $3 got '$4'"; fi; }
chk_nonempty() { if [[ -n "$3" ]]; then ok "$1" "$2 = '${3:0:80}'"; else bad "$1" "$2" "empty"; fi; }

# ── requests ────────────────────────────────────────────────────────────────
# api <method> <path> [curl args...]  → RESP_CODE, RESP_BODY
# Every call is logged with its arguments: that log is the proof T15 needs
# that a canary was actually sent. Error bodies are kept for the same sweep.
api() {
  local method=$1 path=$2 out; shift 2
  printf '%s %s %s\n' "$method" "$path" "$*" >> "$REQLOG"
  out=$(docker exec llb1 curl -s -m 25 -w '\n%{http_code}' -X "$method" "$API$path" "$@")
  RESP_CODE=${out##*$'\n'}
  RESP_BODY=${out%$'\n'*}
  [[ "$RESP_BODY" == "$out" ]] && RESP_BODY=""
  if [[ "$RESP_CODE" =~ ^[45] ]]; then
    # The body only: the request line would carry the very canaries the
    # sweep looks for (a refresh route takes its tokens in the query).
    printf '%s %s %s %s\n' "$method" "${path%%\?*}" "$RESP_CODE" "$RESP_BODY" >> "$ERRBODIES"
  fi
}
# api_headers <path> [curl args...] → response headers (for the redirect arm)
api_headers() {
  local path=$1; shift
  printf 'GET %s %s\n' "$path" "$*" >> "$REQLOG"
  docker exec llb1 curl -s -m 25 -o /dev/null -D - "$API$path" "$@"
}
json() { printf '%s' "$RESP_BODY" | jq -r "$1" 2>/dev/null; }

login() { # login <user> <password> → token on stdout; retries while the store warms
  local i tok
  for i in $(seq 1 10); do
    api POST /auth/login -H 'Content-Type: application/json' -d "{\"username\":\"$1\",\"password\":\"$2\"}"
    tok=$(json '.token // empty')
    [[ -n "$tok" ]] && { printf '%s' "$tok"; return 0; }
    sleep 2
  done
  return 1
}

lb_body() { # lb_body <port> → a plain TCP rule on the VIP
  printf '{"serviceArguments":{"externalIP":"10.10.10.254","port":%s,"protocol":"tcp","sel":0,"mode":0,"inactiveTimeOut":60},"endpoints":[{"endpointIP":"31.31.31.1","targetPort":8080,"weight":1}]}' "$1"
}
rule_count() { # rule_count <port> → how many rules the gateway holds on that port (the state oracle)
  api GET /config/loadbalancer/all "${AUTH[@]}"
  json "[.lbAttr[]? | select(.serviceArguments.port == $1)] | length"
}
user_id() { # user_id <username> → the account id from the listing (the store)
  api GET /auth/users "${AUTH[@]}"
  json "if type==\"array\" then (.[] | select(.username==\"$1\") | .id) else empty end"
}

# ── the trail ───────────────────────────────────────────────────────────────
# trail [dir...] → every record of every segment (active, sealed, gzipped)
# as one JSON object per line. Segment headers and footers (lines carrying
# "kind") and any line that is not JSON are dropped here; T19-6 counts the
# latter separately, because a torn line inside a segment is a finding.
trail_raw() {
  local d dirs=("$@")
  [[ ${#dirs[@]} -eq 0 ]] && dirs=("$AUDIT_DIR" "$WEDGE_DIR")
  for d in "${dirs[@]}"; do
    docker exec llb1 sh -c "cd '$d' 2>/dev/null || exit 0; for f in *.jsonl; do [ -f \"\$f\" ] && cat \"\$f\"; done; for f in *.jsonl.gz; do [ -f \"\$f\" ] && zcat \"\$f\"; done" 2>/dev/null
  done
}
trail() { trail_raw "$@" | jq -c -R 'fromjson? | select(type=="object" and .event_type != null)'; }
# records <jq filter> [dir...] → the matching records, oldest first
records() { local f=$1; shift; trail "$@" | jq -c "select($f)"; }
# count <jq filter> [dir...]
count() { records "$@" | wc -l | tr -d ' '; }
# wait_result <event_id> → waits (bounded) for the result phase of a pair;
# the result is appended asynchronously after the handler answers.
wait_result() {
  local i
  for i in $(seq 1 30); do
    [[ "$(count ".event_id==\"$1\" and .phase==\"result\"")" -ge 1 ]] && return 0
    sleep 0.5
  done
  return 1
}
# pair_of <jq filter for the intent> → the event_id of the newest such intent
newest_intent() { local f=$1; shift; records ".phase==\"intent\" and ($f)" "$@" | tail -n1 | jq -r '.event_id'; }

astatus() { docker exec llb1 curl -s -m 5 "${AUTH[@]}" "$API/audit/status"; }
asink()   { docker exec llb1 curl -s -m 5 "${AUTH[@]}" "$API/audit/sink"; }
# cli <label> <loxicmd args...> → CLI_RC, and the streams in CLI_OUT/CLI_ERR.
# The status is the point of half the CLI cases, so the command is run with no
# wrapper that could swallow one, and it is asserted before the output is read.
CLI_RC=0; CLI_OUT=""; CLI_ERR=""
cli() {
  local label=$1; shift
  CLI_OUT=$WORK/cli-$label.out
  CLI_ERR=$WORK/cli-$label.err
  $dexec llb1 loxicmd "$@" > "$CLI_OUT" 2> "$CLI_ERR"
  CLI_RC=$?
  return 0
}
# make_sink_ca <path in llb1> → 0 when a trust anchor the sink can read is in
# place. Only a certificate is needed — it is what the receiver is verified
# against, never a credential of ours — and it is made per run so nothing is
# committed. It is generated on the HOST and copied in: the image's openssl is
# built against a config prefix that does not exist in it, so it cannot write
# one itself.
make_sink_ca() {
  local host_ca
  host_ca=$WORK/$(basename "$1")
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "${host_ca%.pem}.key" -out "$host_ca" \
      -days 1 -subj '/CN=audit-sink-receiver-ca' >/dev/null 2>&1
  docker cp "$host_ca" "llb1:$1" >/dev/null 2>&1
  docker exec llb1 grep -q 'BEGIN CERTIFICATE' "$1" 2>/dev/null
}
metric_val() { # metric_val <family> [<label substring>] → the sample value
  local fam=$1 lab=${2:-}
  docker exec llb1 curl -s -m 5 "${AUTH[@]}" "$API/metrics" 2>/dev/null |
    awk -v f="$fam" -v l="$lab" '($1 ~ ("^" f "(\\{|$)")) && (l == "" || index($1, l)) { print $2; exit }'
}
gw_log_grep() { # gw_log_grep <pattern> → matching operational log lines
  docker exec llb1 sh -c 'cat /var/log/loxilb.log /tmp/loxilb.out /tmp/loxilb.err 2>/dev/null' | grep -a -- "$1"
}

# ── the gateway process (tiers.sh pattern) ──────────────────────────────────
gw_wait_dead() {
  local i
  for i in $(seq 1 "$1"); do
    docker exec llb1 pgrep -f "$GW_BIN" >/dev/null 2>&1 || return 0
    sleep 1
  done
  return 1
}
gw_stop() { # orderly: SIGTERM, then escalate; the writer closes its segment
  docker exec llb1 pkill -f "$GW_BIN" >/dev/null 2>&1
  gw_wait_dead 15 && return 0
  echo "  (old gateway survived SIGTERM for 15s; escalating to SIGKILL)"
  docker exec llb1 pkill -9 -f "$GW_BIN" >/dev/null 2>&1
  gw_wait_dead 10 && return 0
  echo "  FATAL: the old gateway process would not die"; return 1
}
gw_crash() { # SIGKILL only: no shutdown hook runs, which is the crash T20 needs
  docker exec llb1 pkill -9 -f "$GW_BIN" >/dev/null 2>&1
  gw_wait_dead 10
}
gw_start() { # gw_start <flags...>: datapath cleanup, start, wait for the API and the boot freeze
  local i ifc
  docker exec llb1 ip link del llb0 >/dev/null 2>&1
  for ifc in $(docker exec llb1 ip -o link show | awk -F': ' '{print $2}' | cut -d'@' -f1); do
    [ "$ifc" = "lo" ] && continue
    docker exec llb1 ip link set dev "$ifc" xdpgeneric off >/dev/null 2>&1
    docker exec llb1 tc qdisc del dev "$ifc" clsact >/dev/null 2>&1
  done
  docker exec llb1 umount /opt/loxilb/dp >/dev/null 2>&1
  # Appending, not truncating: T19 reads the failure line out of this log
  # and the boots before it are part of the evidence.
  docker exec -d llb1 bash -c "ulimit -l unlimited; $GW_BIN -p --loglevel debug $* >> /tmp/loxilb.out 2>> /tmp/loxilb.err"
  for i in $(seq 1 40); do
    docker exec llb1 curl -sf -m 3 "$API/version" >/dev/null 2>&1 && break
    sleep 2
  done
  if ! docker exec llb1 curl -sf -m 3 "$API/version" >/dev/null 2>&1; then
    echo "  gateway did not come back; stderr tail:"
    docker exec llb1 tail -20 /tmp/loxilb.err
    return 1
  fi
  # The boot config replay freezes mutations for a while after the listener
  # answers; a write that cannot apply (empty body) probes the freeze. The
  # status is kept apart from the body: a connection dropped without an
  # answer (000) is not the freeze, but neither is it an answer.
  local out status
  for i in $(seq 1 40); do
    out=$(docker exec llb1 curl -s -m 3 -w '\n%{http_code}' -X POST "$API/config/loadbalancer" -H 'Content-Type: application/json' -d '{}')
    status=${out##*$'\n'}
    if ! printf '%s' "${out%$'\n'*}" | grep -qE 'boot config replay settles|frozen while a snapshot restore is in progress'; then
      if [[ "$status" == 000 ]]; then
        SETTLE_NOANSWER=$((SETTLE_NOANSWER + 1))
        echo "  settle probe: POST /config/loadbalancer {} got no HTTP answer"
      fi
      return 0
    fi
    sleep 2
  done
  echo "  boot config replay never settled"
  return 1
}

# ── canaries ────────────────────────────────────────────────────────────────
CANARY_PW='cnry-pw-Zq7!Aa1x'
CANARY_BEARER='cnry-bearer-4f1e77'
CANARY_LIC='cnry-lic-77aa0-9f'
CANARY_OAT='cnry-oat-1a2b3c'
CANARY_ORT='cnry-ort-9z8y7x'
AGENT_PW='Ag3nt-cnry-pw!1a'
AGENT_PW2='Ag3nt-cnry-pw!2b'
WATCHER_PW='W4tch-cnry-pw!3c'
SENT_CANARIES=("$ADMIN_PW" "$CANARY_PW" "$CANARY_BEARER" "$CANARY_LIC" "$CANARY_OAT" "$CANARY_ORT" "$AGENT_PW" "$AGENT_PW2" "$WATCHER_PW")
RECEIVED_CANARIES=()   # secrets the gateway minted for us: raw API key, OAuth state

# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "Boot 1: --userservice, OAuth routes, audit at $AUDIT_DIR"
echo "════════════════════════════════════════════════════════════════════════"
TOKEN=$(login "$ADMIN_USER" "$ADMIN_PW") || { echo "  FATAL: administrator login failed"; echo "SCENARIO-audit-mgmt [FAILED]"; exit 1; }
AUTH=(-H "Authorization: Bearer $TOKEN")
CT=(-H 'Content-Type: application/json')
B1=$(astatus | jq -r '.boot_id')
echo "  boot_id $B1"

# ── T-GW-1: the status endpoint ──────────────────────────────────────────────
echo ""
echo "T-GW-1: GET /audit/status reports the writer"
ST=$(astatus)
chk     T-GW-1-1 "available"           true "$(printf '%s' "$ST" | jq -r '.available')"
chk     T-GW-1-2 "running"             true "$(printf '%s' "$ST" | jq -r '.running')"
chk_nonempty T-GW-1-3 "boot_id"        "$(printf '%s' "$ST" | jq -r '.boot_id // empty')"
chk_ge  T-GW-1-4 "seq_high"            1    "$(printf '%s' "$ST" | jq -r '.seq_high // 0')"
chk_ge  T-GW-1-5 "accepted.mgmt"       1    "$(printf '%s' "$ST" | jq -r '.accepted.mgmt // 0')"
chk_nonempty T-GW-1-6 "segment.uuid"   "$(printf '%s' "$ST" | jq -r '.segment.uuid // empty')"
chk     T-GW-1-7 "status carries no record content (no event_type key)" 0 "$(printf '%s' "$ST" | jq '[.. | objects | has("event_type")] | map(select(.)) | length')"
FIRST=$(records ".boot_id==\"$B1\"" | head -n1 | jq -r '.event_type')
chk     T-GW-1-8 "first record of the boot is sys.writer.start" sys.writer.start "$FIRST"

# ── T-GW-3: the log-archive API never serves an audit segment ───────────────
echo ""
echo "T-GW-3: GET /log-archives/audit.jsonl is refused"
api GET /log-archives/audit.jsonl "${AUTH[@]}"
chk_ne  T-GW-3-1 "status is not 200" 200 "$RESP_CODE"
chk     T-GW-3-2 "no record leaked in the body" 0 "$(printf '%s' "$RESP_BODY" | grep -c '"event_type"')"

# ── T25: the delegated originator ───────────────────────────────────────────
echo ""
echo "T25: X-Loxilb-Originator is recorded, trusted only for delegation_allowed accounts"
ORIG_DROP0=$(metric_val loxilb_audit_originator_dropped_total)
DELEG0=$(metric_val loxilb_audit_delegation_lookups_total)

api POST /auth/users "${AUTH[@]}" "${CT[@]}" -d "{\"username\":\"agent\",\"password\":\"$AGENT_PW\",\"role\":\"admin\"}"
chk     T25-0a "create account agent (admin role)" 200 "$RESP_CODE"
api POST /auth/users "${AUTH[@]}" "${CT[@]}" -d "{\"username\":\"watcher\",\"password\":\"$WATCHER_PW\",\"role\":\"viewer\"}"
chk     T25-0b "create account watcher (viewer role)" 200 "$RESP_CODE"
AGENT_ID=$(user_id agent); WATCHER_ID=$(user_id watcher)
chk_nonempty T25-0c "agent id from the listing" "$AGENT_ID"
api PUT "/auth/users/$AGENT_ID" "${AUTH[@]}" "${CT[@]}" -d "{\"username\":\"agent\",\"password\":\"$AGENT_PW2\",\"delegation_allowed\":true}"
chk     T25-0d "mark agent delegation_allowed" 200 "$RESP_CODE"
api GET /auth/users "${AUTH[@]}"
chk     T25-0e "the store reports agent delegation_allowed" true "$(json '.[] | select(.username=="agent") | .delegation_allowed')"
UPD_ID=$(newest_intent '.event_type=="mgmt.user.update"')
wait_result "$UPD_ID"
chk_has T25-0f "the update record names delegation_allowed among changed_fields" delegation_allowed \
  "$(records ".event_id==\"$UPD_ID\" and .phase==\"result\"" | jq -c '.detail.changed_fields')"

ATOKEN=$(login agent "$AGENT_PW2") || echo "  (agent login failed)"
WTOKEN=$(login watcher "$WATCHER_PW") || echo "  (watcher login failed)"

# arm 1: a delegating account
api POST /config/loadbalancer -H "Authorization: Bearer $ATOKEN" -H 'X-Loxilb-Originator: mcp:ops-agent' "${CT[@]}" -d "$(lb_body 2041)"
chk     T25-1a "agent + originator: mutation accepted" 200 "$RESP_CODE"
EID=$(newest_intent '.event_type=="mgmt.config.mutate" and .detail.path=="/netlox/v1/config/loadbalancer" and .actor.delegated=="mcp:ops-agent"')
wait_result "$EID"
R=$(records ".event_id==\"$EID\" and .phase==\"result\"")
I=$(records ".event_id==\"$EID\" and .phase==\"intent\"")
chk     T25-1b "result actor.user is the authenticated account" agent "$(printf '%s' "$R" | jq -r '.actor.user')"
chk     T25-1c "result actor.delegated"          mcp:ops-agent "$(printf '%s' "$R" | jq -r '.actor.delegated')"
chk     T25-1d "result delegation_trusted"       true       "$(printf '%s' "$R" | jq -r '.actor.delegation_trusted')"
chk     T25-1e "intent carries the claim untrusted (no principal yet)" false "$(printf '%s' "$I" | jq -r '.actor.delegation_trusted')"
chk     T25-1f "intent is the provisional view"  true       "$(printf '%s' "$I" | jq -r '.actor.provisional')"

# arm 2: an account that may not delegate
api POST /config/loadbalancer "${AUTH[@]}" -H 'X-Loxilb-Originator: mcp:ops-agent' "${CT[@]}" -d "$(lb_body 2042)"
chk     T25-2a "admin + originator: mutation accepted" 200 "$RESP_CODE"
EID=$(newest_intent '.event_type=="mgmt.config.mutate" and .detail.path=="/netlox/v1/config/loadbalancer" and .actor.delegated=="mcp:ops-agent"')
wait_result "$EID"
R=$(records ".event_id==\"$EID\" and .phase==\"result\"")
chk     T25-2b "result actor.user"               "$ADMIN_USER" "$(printf '%s' "$R" | jq -r '.actor.user')"
chk     T25-2c "claim recorded as evidence"      mcp:ops-agent    "$(printf '%s' "$R" | jq -r '.actor.delegated')"
chk     T25-2d "claim not trusted"               false         "$(printf '%s' "$R" | jq -r '.actor.delegation_trusted')"

# arm 3: a refusal carries the claim too
api POST /config/loadbalancer -H "Authorization: Bearer $WTOKEN" -H 'X-Loxilb-Originator: mcp:ops-agent' "${CT[@]}" -d "$(lb_body 2043)"
chk     T25-3a "viewer + originator: refused" 403 "$RESP_CODE"
EID=$(newest_intent '.event_type=="mgmt.config.mutate" and .detail.path=="/netlox/v1/config/loadbalancer" and .actor.delegated=="mcp:ops-agent"')
wait_result "$EID"
R=$(records ".event_id==\"$EID\" and .phase==\"result\"")
chk     T25-3b "refusal re-typed as a security decision" sec.mgmt.authz_denied "$(printf '%s' "$R" | jq -r '.event_type')"
chk     T25-3c "result_of names the intent type"  mgmt.config.mutate "$(printf '%s' "$R" | jq -r '.result_of')"
chk     T25-3d "outcome.reason"                  authz      "$(printf '%s' "$R" | jq -r '.outcome.reason')"
chk     T25-3e "refusal names the principal"     watcher    "$(printf '%s' "$R" | jq -r '.actor.user')"
chk     T25-3f "refusal carries the claim"       mcp:ops-agent "$(printf '%s' "$R" | jq -r '.actor.delegated')"
chk     T25-3g "the rule was not created (state oracle)" 0 "$(rule_count 2043)"

# arm 4: a malformed claim is dropped and counted, never stored
api POST /config/loadbalancer "${AUTH[@]}" -H 'X-Loxilb-Originator: not-a-scheme' "${CT[@]}" -d "$(lb_body 2044)"
chk     T25-4a "malformed originator: mutation still accepted" 200 "$RESP_CODE"
EID=$(newest_intent '.event_type=="mgmt.config.mutate" and .detail.path=="/netlox/v1/config/loadbalancer"')
wait_result "$EID"
chk     T25-4b "no delegated field on the pair" 0 "$(count ".event_id==\"$EID\" and (.actor.delegated != null)")"
chk_gt  T25-4c "loxilb_audit_originator_dropped_total rose" "${ORIG_DROP0:-0}" "$(metric_val loxilb_audit_originator_dropped_total)"
chk_ge  T25-4d "/audit/status originator_dropped" 1 "$(astatus | jq -r '.originator_dropped // 0')"
chk     T25-5  "the claim is never promoted to actor.user" 0 "$(count '.actor.user=="mcp:ops-agent"')"
chk_gt  T25-6  "loxilb_audit_delegation_lookups_total rose" "${DELEG0:-0}" "$(metric_val loxilb_audit_delegation_lookups_total)"

# arm 5: the CLI names itself. `loxicmd --originator` sends the OS account and
# host it runs as, so the value expected here is read from the container the
# CLI runs in, never written down. The flag belongs to the loxicmd release
# the image pins; an image whose pin predates it fails one row and skips the
# rest, which would otherwise all go red for that one cause.
if $dexec llb1 loxicmd --help 2>&1 | grep -q -- '--originator'; then
  ok T25-7-0 "the image's loxicmd carries --originator"
  CLI_ORIG="cli:$(docker exec llb1 id -un)@$(docker exec llb1 hostname)"
  ORIG_DROP1=$(metric_val loxilb_audit_originator_dropped_total)
  # The tokens reach the CLI through owner-only files: on the command line
  # they would sit in the container's process list.
  docker exec llb1 sh -c 'umask 077; printf %s "$1" > /tmp/t25-agent.token; printf %s "$2" > /tmp/t25-watcher.token' _ "$ATOKEN" "$WTOKEN"
  cli_lb() { # cli_lb <label> <port> <token file> [flags...] → creates a rule through the CLI
    local label=$1 port=$2 tok=$3; shift 3
    cli "$label" --token-file "$tok" "$@" create lb 10.10.10.254 --tcp="$port:8080" --endpoints=31.31.31.1:1
  }
  cli_pair() { newest_intent ".event_type==\"mgmt.config.mutate\" and .detail.path==\"/netlox/v1/config/loadbalancer\" and .detail.method==\"POST\""; }

  cli_lb orig-agent 2045 /tmp/t25-agent.token --originator
  chk     T25-7a "agent through the CLI with --originator: exit status" 0 "$CLI_RC"
  chk     T25-7b "the rule was created (state oracle)" 1 "$(rule_count 2045)"
  EID=$(cli_pair); wait_result "$EID"
  R=$(records ".event_id==\"$EID\" and .phase==\"result\"")
  chk     T25-7c "result actor.user is the authenticated account" agent "$(printf '%s' "$R" | jq -r '.actor.user')"
  chk     T25-7d "result actor.delegated is the CLI's own account and host" "$CLI_ORIG" "$(printf '%s' "$R" | jq -r '.actor.delegated')"
  chk     T25-7e "trusted, because agent may delegate" true "$(printf '%s' "$R" | jq -r '.actor.delegation_trusted')"

  cli_lb orig-watcher 2046 /tmp/t25-watcher.token --originator
  chk_ne  T25-7f "viewer through the CLI with --originator: refused, exit status" 0 "$CLI_RC"
  EID=$(cli_pair); wait_result "$EID"
  R=$(records ".event_id==\"$EID\" and .phase==\"result\"")
  chk     T25-7g "the refusal names the principal" watcher "$(printf '%s' "$R" | jq -r '.actor.user')"
  chk     T25-7h "the refusal carries the CLI's claim" "$CLI_ORIG" "$(printf '%s' "$R" | jq -r '.actor.delegated')"
  chk     T25-7i "untrusted, because watcher may not delegate" false "$(printf '%s' "$R" | jq -r '.actor.delegation_trusted')"
  chk     T25-7j "the rule was not created (state oracle)" 0 "$(rule_count 2046)"

  cli_lb plain-agent 2047 /tmp/t25-agent.token
  chk     T25-7k "agent through the CLI without the flag: exit status" 0 "$CLI_RC"
  EID=$(cli_pair); wait_result "$EID"
  chk     T25-7l "that pair is the CLI's (the rule exists)" 1 "$(rule_count 2047)"
  chk     T25-7m "no delegated field on the pair" 0 "$(count ".event_id==\"$EID\" and (.actor.delegated != null)")"
  chk     T25-7n "the CLI's value passed the gateway's validation: nothing more was dropped" "${ORIG_DROP1:-x}" "$(metric_val loxilb_audit_originator_dropped_total)"
  docker exec llb1 rm -f /tmp/t25-agent.token /tmp/t25-watcher.token
else
  bad T25-7-0 "the image's loxicmd carries --originator" "the flag is absent from loxicmd --help; the image's LOXICMD_TAG predates it"
fi

# ── TM: the named management routes ─────────────────────────────────────────
echo ""
echo "TM: named routes leave an intent+result pair with their own event type"
tm_pair() { # tm_pair <id> <label> <event_type> <extra jq on the result>
  local eid
  eid=$(newest_intent ".event_type==\"$3\"")
  if [[ -z "$eid" || "$eid" == null ]]; then bad "$1" "$2" "no intent of type $3"; return; fi
  if ! wait_result "$eid"; then bad "$1" "$2" "intent $eid has no result"; return; fi
  local r; r=$(records ".event_id==\"$eid\" and .phase==\"result\"")
  local got; got=$(printf '%s' "$r" | jq -r "$4")
  if [[ "$got" == "true" ]]; then ok "$1" "$2 (event $eid)"; else bad "$1" "$2" "result did not satisfy [$4]: $(printf '%s' "$r" | cut -c1-300)"; fi
}
api POST /config/persist "${AUTH[@]}" "${CT[@]}" -d '{}'
echo "  POST /config/persist -> $RESP_CODE"
tm_pair TM-1 "mgmt.snapshot.persist names the file it wrote" mgmt.snapshot.persist '.outcome.ok==true and (.detail.filename|length)>0 and .detail.bytes>0 and (.detail.checksum|length)>0'
api GET /config/export "${AUTH[@]}"
echo "  GET /config/export -> $RESP_CODE"
tm_pair TM-2 "read.config.export reports what it served, never the content" read.config.export '.class=="read" and .outcome.ok==true and .detail.bytes>0 and .detail.secrets_included==false'
api PUT /maintenance "${AUTH[@]}" "${CT[@]}" -d '{"enabled":true}'
echo "  PUT /maintenance enabled -> $RESP_CODE"
api PUT /maintenance "${AUTH[@]}" "${CT[@]}" -d '{"enabled":false}'
echo "  PUT /maintenance disabled -> $RESP_CODE"
tm_pair TM-3 "mgmt.maintenance carries active_from/active_to" mgmt.maintenance '.outcome.ok==true and (.detail.active_from|length)>0 and (.detail.active_to|length)>0'
api POST /auth/token/upgrade "${AUTH[@]}" "${CT[@]}" -d "{\"license_key\":\"$CANARY_LIC\"}"
echo "  POST /auth/token/upgrade -> $RESP_CODE"
tm_pair TM-4 "mgmt.auth.token_upgrade fingerprints the token" mgmt.auth.token_upgrade '(.detail.token_fingerprint_sha256|length)==64 or .outcome.ok==false'
api POST /auth/logout -H "Authorization: Bearer $WTOKEN"
echo "  POST /auth/logout (watcher) -> $RESP_CODE"
tm_pair TM-5 "mgmt.auth.logout names the session owner" mgmt.auth.logout '.outcome.ok==true and .actor.user=="watcher"'
api GET /auth/users -H "Authorization: Bearer $WTOKEN"
# Whether an already-issued token dies with the logout is the auth plane's
# contract (ai-authsep), not the trail's; observed, not scored here.
echo "  [TM-5b] NOTE a GET with the logged-out token answers $RESP_CODE"
api GET /auth/users "${AUTH[@]}"
tm_list=$(records '.event_type=="read.credential.list" and (.detail.resource|startswith("user")) and .outcome.ok==true' | tail -n1)
if [[ -n "$tm_list" ]]; then ok TM-6 "read.credential.list (users) is one result-only record with a count: $(printf '%s' "$tm_list" | jq -c '{count:.detail.count,user:.actor.user}')"; else bad TM-6 "read.credential.list (users)" "no record"; fi
api POST /config/ai/apikey "${AUTH[@]}" "${CT[@]}" -d '{"tenant_id":"audit-tenant","name":"audit-key-1","allowed_models":["m1"],"rate_limit_rps":5,"burst_size":10,"tokens_per_min":1000,"enabled":true}'
RAW_KEY=$(json '.raw_key // empty'); KEY_ID=$(json '.key_id // empty')
chk     TM-7a "create an API key" 201 "$RESP_CODE"
[[ -n "$RAW_KEY" ]] && RECEIVED_CANARIES+=("$RAW_KEY")
tm_pair TM-7 "the key create is a mgmt.config.mutate pair with field names only" mgmt.config.mutate '.outcome.ok==true and .detail.path=="/netlox/v1/config/ai/apikey" and (.detail.changed_fields|index("name")!=null)'
api GET "/config/ai/apikey/$KEY_ID" "${AUTH[@]}"
tm_key=$(records '.event_type=="read.credential.list" and (.detail.resource|startswith("apikey"))' | tail -n1)
if [[ -n "$tm_key" ]]; then ok TM-8 "read.credential.list (apikey get) recorded: $(printf '%s' "$tm_key" | jq -c '{count:.detail.count,tenant:.detail.tenant}')"; else bad TM-8 "read.credential.list (apikey)" "no record"; fi
api DELETE "/auth/users/$WATCHER_ID" "${AUTH[@]}"
echo "  DELETE /auth/users/$WATCHER_ID -> $RESP_CODE"
tm_pair TM-9 "mgmt.user.delete" mgmt.user.delete '.outcome.ok==true and .actor.user=="admin"'
tm_pair TM-10 "mgmt.user.create names the account and role" mgmt.user.create '.outcome.ok==true and .detail.username=="watcher" and .detail.role=="viewer"'

# ── T15 (send phase): the canaries that need a request of their own ─────────
echo ""
echo "T15: sending the remaining canaries"
api POST /auth/login "${CT[@]}" -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$CANARY_PW\"}"
chk     T15-s1 "wrong password refused" 401 "$RESP_CODE"
EID=$(newest_intent '.event_type=="mgmt.auth.login"')
wait_result "$EID"
R=$(records ".event_id==\"$EID\" and .phase==\"result\"")
chk     T15-s1b "failed login is sec.mgmt.authn_failed" sec.mgmt.authn_failed "$(printf '%s' "$R" | jq -r '.event_type')"
chk     T15-s1c "result_of mgmt.auth.login" mgmt.auth.login "$(printf '%s' "$R" | jq -r '.result_of')"
chk     T15-s1d "reason login_failed" login_failed "$(printf '%s' "$R" | jq -r '.outcome.reason')"
chk     T15-s1e "the claimed name is kept, the password is not" "$ADMIN_USER" "$(printf '%s' "$R" | jq -r '.actor.username_claimed')"
api POST /config/loadbalancer -H "Authorization: Bearer $CANARY_BEARER" "${CT[@]}" -d "$(lb_body 2045)"
chk     T15-s2 "bearer canary refused" 401 "$RESP_CODE"
EID=$(newest_intent '.event_type=="mgmt.config.mutate" and .detail.path=="/netlox/v1/config/loadbalancer"')
wait_result "$EID"
R=$(records ".event_id==\"$EID\" and .phase==\"result\"")
chk     T15-s2b "refused mutation is sec.mgmt.authn_failed" sec.mgmt.authn_failed "$(printf '%s' "$R" | jq -r '.event_type')"
chk     T15-s2c "reason auth" auth "$(printf '%s' "$R" | jq -r '.outcome.reason')"

# ── T22 (healthy boot): the side-effecting OAuth GETs ───────────────────────
echo ""
echo "T22: OAuth start / callback / refresh on a healthy writer"
HDRS=$(api_headers /oauth/google)
OSTATUS=$(printf '%s' "$HDRS" | head -n1 | awk '{print $2}')
LOCATION=$(printf '%s' "$HDRS" | grep -i '^location:' | tr -d '\r' | cut -d' ' -f2-)
OSTATE=$(printf '%s' "$LOCATION" | sed -n 's/.*[?&]state=\([^&]*\).*/\1/p')
chk     T22-1a "start answers a redirect" 307 "$OSTATUS"
chk_nonempty T22-1b "redirect carries a state token" "$OSTATE"
[[ -n "$OSTATE" ]] && RECEIVED_CANARIES+=("$OSTATE")
EID=$(newest_intent '.event_type=="mgmt.auth.oauth_start"')
wait_result "$EID"
R=$(records ".event_id==\"$EID\" and .phase==\"result\"")
chk     T22-1c "start pair: result ok"      true   "$(printf '%s' "$R" | jq -r '.outcome.ok')"
chk     T22-1d "start pair: action"         start  "$(printf '%s' "$R" | jq -r '.detail.action')"
chk     T22-1e "start pair: provider"       google "$(printf '%s' "$R" | jq -r '.detail.provider')"
chk     T22-1f "state recorded as a fingerprint (64 hex)" 64 "$(printf '%s' "$R" | jq -r '.detail.state_token_fingerprint | length')"
chk     T22-1g "the route is unauthenticated: actor stays provisional" true "$(printf '%s' "$R" | jq -r '.actor.provisional')"
api GET "/oauth/google/callback?state=not-a-minted-state&code=x"
chk     T22-2a "callback with an unknown state refused" 400 "$RESP_CODE"
EID=$(newest_intent '.event_type=="mgmt.auth.oauth_callback"')
wait_result "$EID"
R=$(records ".event_id==\"$EID\" and .phase==\"result\"")
chk     T22-2b "callback pair: status" 400 "$(printf '%s' "$R" | jq -r '.outcome.status')"
chk     T22-2c "callback pair: action" login "$(printf '%s' "$R" | jq -r '.detail.action')"
api GET "/oauth/google/token?token=$CANARY_OAT&refreshtoken=$CANARY_ORT"
echo "  GET /oauth/google/token -> $RESP_CODE"
EID=$(newest_intent '.event_type=="mgmt.auth.oauth_token_refresh"')
wait_result "$EID"
R=$(records ".event_id==\"$EID\" and .phase==\"result\"")
chk     T22-3a "refresh pair: action" refresh "$(printf '%s' "$R" | jq -r '.detail.action')"
chk     T22-3b "refresh pair: the path carries no query string" "/netlox/v1/oauth/{provider}/token" "$(printf '%s' "$R" | jq -r '.detail.path')"

# ── T11 arm 1: attribution with --userservice ───────────────────────────────
echo ""
echo "T11 arm 1: every successful result of boot 1 names a principal"
# The rule, stated once: a result whose outcome is ok must carry a real
# principal. Two shapes are exempt by design and are counted separately so
# the exemption cannot swallow the rule: the loopback bootstrap of the first
# account (actor.bootstrap), and the unauthenticated OAuth start whose
# result inherits the provisional view (actor.provisional).
OK_RESULTS=$(count ".boot_id==\"$B1\" and .stream==\"mgmt\" and .phase==\"result\" and .outcome.ok==true and (.actor.bootstrap!=true) and (.actor.provisional!=true)")
UNATTRIBUTED=$(count ".boot_id==\"$B1\" and .stream==\"mgmt\" and .phase==\"result\" and .outcome.ok==true and (.actor.bootstrap!=true) and (.actor.provisional!=true) and ((.actor.user // \"\")==\"\" or .actor.auth==\"none\")")
chk_ge  T11-1a "successful, attributable results in boot 1" 12 "$OK_RESULTS"
chk     T11-1b "of which without a principal or with auth=none" 0 "$UNATTRIBUTED"
chk     T11-1c "bootstrap results (the first account only)" 1 "$(count ".boot_id==\"$B1\" and .phase==\"result\" and .actor.bootstrap==true")"
chk     T11-1d "every successful session result says auth=session" 0 "$(count ".boot_id==\"$B1\" and .stream==\"mgmt\" and .phase==\"result\" and .outcome.ok==true and (.actor.bootstrap!=true) and (.actor.provisional!=true) and .actor.auth!=\"session\"")"
if [[ "$UNATTRIBUTED" != 0 ]]; then
  echo "  offending records:"; records ".boot_id==\"$B1\" and .stream==\"mgmt\" and .phase==\"result\" and .outcome.ok==true and (.actor.bootstrap!=true) and (.actor.provisional!=true) and ((.actor.user // \"\")==\"\" or .actor.auth==\"none\")" | cut -c1-300 | sed 's/^/    /'
fi

# ── T20: crash between intent and result ────────────────────────────────────
echo ""
echo "T20: a crash after the durable intent leaves exactly one orphan report"
# A fresh login makes sure the store pool holds a live connection; the
# paused store then keeps the handler waiting on that connection instead of
# failing fast on a connect timeout, which would have written a result.
TOKEN=$(login "$ADMIN_USER" "$ADMIN_PW"); AUTH=(-H "Authorization: Bearer $TOKEN")
docker pause "$PG_NAME"
printf 'POST /auth/users (ghost, store paused)\n' >> "$REQLOG"
docker exec llb1 curl -s -m 90 -o /dev/null -w '%{http_code}' -X POST "$API/auth/users" "${AUTH[@]}" "${CT[@]}" \
  -d '{"username":"ghost","password":"Gh0st-pass!7q","role":"viewer"}' > "$WORK/t20.code" 2>/dev/null &
T20PID=$!
sleep 4
OPEN_INTENTS=$(trail | jq -s -r '[.[] | select(.phase=="result") | .event_id] as $done
  | .[] | select(.event_type=="mgmt.user.create" and .phase=="intent" and ((.event_id as $i | $done | index($i)) == null)) | .event_id')
ORPHAN_ID=$(printf '%s\n' "$OPEN_INTENTS" | tail -n1)
chk     T20-0a "exactly one user-create intent is open while the store is paused" 1 "$(printf '%s\n' "$OPEN_INTENTS" | grep -c .)"
chk_nonempty T20-0b "its event_id" "$ORPHAN_ID"
gw_crash || echo "  (gateway did not die within 10s)"
wait $T20PID 2>/dev/null
echo "  the blocked request ended with HTTP '$(cat "$WORK/t20.code" 2>/dev/null)' (connection cut by the crash)"
docker unpause "$PG_NAME"
sleep 2
echo "  restarting (boot 2, same flags)"
gw_start $MGMT_ARGS $AIKEY_ARGS $OAUTH_ARGS --audit-dir "$AUDIT_DIR" --audit-required || { echo "SCENARIO-audit-mgmt [FAILED]"; exit 1; }
TOKEN=$(login "$ADMIN_USER" "$ADMIN_PW"); AUTH=(-H "Authorization: Bearer $TOKEN")
B2=$(astatus | jq -r '.boot_id')
echo "  boot_id $B2"
ORPHANS=$(records ".boot_id==\"$B2\" and .event_type==\"sys.intent.orphaned\"")
chk     T20-1a "one sys.intent.orphaned record at boot 2" 1 "$(printf '%s' "$ORPHANS" | grep -c .)"
chk     T20-1b "it names the orphaned intent" "$ORPHAN_ID" "$(printf '%s' "$ORPHANS" | jq -r '.detail.intent_event_id' | head -n1)"
echo "  config_generation_at_boot: $(printf '%s' "$ORPHANS" | jq -r '.detail.config_generation_at_boot // "0 (omitted)"' | head -n1)"
chk     T20-2a "loxilb_audit_orphaned_intents_total" 1 "$(metric_val loxilb_audit_orphaned_intents_total)"
chk     T20-2b "/audit/status orphaned_intents" 1 "$(astatus | jq -r '.orphaned_intents // 0')"
chk     T20-2c "/audit/status last_orphan_event_id" "$ORPHAN_ID" "$(astatus | jq -r '.last_orphan_event_id')"
chk     T20-3  "no result was synthesised for the orphan" 0 "$(count ".event_id==\"$ORPHAN_ID\" and .phase==\"result\"")"
chk_ge  T20-4  "boot 1's unsealed segment was recovered" 1 "$(count ".boot_id==\"$B2\" and .event_type==\"sys.segment.recovered\"")"
api GET /auth/users "${AUTH[@]}"
echo "  (the store $(json '[.[]|select(.username=="ghost")]|length' | sed 's/^0$/does not hold/;s/^1$/holds/') the ghost account; the trail does not guess either way)"

# ── Boot 3: the wedge ───────────────────────────────────────────────────────
echo ""
echo "Boot 3: audit directory on a 1 MiB tmpfs, then filled — T3, T19, T22 wedged arms"
echo "════════════════════════════════════════════════════════════════════════"
gw_stop || { echo "SCENARIO-audit-mgmt [FAILED]"; exit 1; }
docker exec llb1 sh -c "mkdir -p $WEDGE_DIR && mount -t tmpfs -o size=1m,mode=0700 tmpfs $WEDGE_DIR && chmod 0700 $WEDGE_DIR" || { echo "  FATAL: cannot mount the wedge tmpfs"; echo "SCENARIO-audit-mgmt [FAILED]"; exit 1; }
gw_start $MGMT_ARGS $AIKEY_ARGS $OAUTH_ARGS --audit-dir "$WEDGE_DIR" --audit-required || { echo "SCENARIO-audit-mgmt [FAILED]"; exit 1; }
TOKEN=$(login "$ADMIN_USER" "$ADMIN_PW") || { echo "  FATAL: login on boot 3 failed"; echo "SCENARIO-audit-mgmt [FAILED]"; exit 1; }
AUTH=(-H "Authorization: Bearer $TOKEN")
B3=$(astatus | jq -r '.boot_id')
echo "  boot_id $B3"
api POST /config/ai/apikey "${AUTH[@]}" "${CT[@]}" -d '{"tenant_id":"audit-tenant","name":"audit-key-2","allowed_models":["m1"],"rate_limit_rps":5,"burst_size":10,"tokens_per_min":1000,"enabled":true}'
KEY2=$(json '.key_id // empty'); RAW2=$(json '.raw_key // empty')
[[ -n "$RAW2" ]] && RECEIVED_CANARIES+=("$RAW2")
chk_nonempty T3-0 "a key to PATCH through the raw route" "$KEY2"
# The wedge probe is a PATCH that names no field. The gate writes its intent
# before the handler runs, and the handler then refuses it with 400, so one
# that lands changes nothing. Naming no field also makes that intent the
# shortest line anything below can write, and that is what makes the probe's
# refusal mean "wedged": a refused append is cut back to the last complete
# line, so the room left in the segment's last page is still there, and a
# shorter line would still fit into it.
wedge_probe() { api PATCH "/config/ai/apikey/$KEY2" "${AUTH[@]}" "${CT[@]}" -d '{}'; }
wedge_probe
[[ "$RESP_CODE" == 400 && "$RESP_BODY" == *"no patchable field"* ]] || { echo "  FATAL: the wedge probe on a writable trail answered $RESP_CODE: ${RESP_BODY:0:200}"; echo "SCENARIO-audit-mgmt [FAILED]"; exit 1; }
# line_lengths → "<kind> <bytes>" for every line of the trail that is of a
# kind written, or refused, while wedged: the gated calls' intents, the
# listing reads' results and the heartbeat. "probe" is the probe's own
# intent; the PATCH that names a field is not listed, being the same line
# with the field's name added.
line_lengths() {
  trail_raw "$@" | jq -R -r '. as $l | (fromjson? // empty) | select(type=="object" and .event_type != null)
    | (.detail.path // "") as $p | ((.detail.changed_fields // []) | length) as $nf
    | (if .event_type=="sys.heartbeat" then "heartbeat"
       elif .event_type=="read.credential.list" and (.actor.user // "") != "" then "listing"
       elif .phase != "intent" then null
       elif .event_type=="mgmt.user.create" then "user-create"
       elif .event_type=="mgmt.auth.oauth_start" then "oauth-start"
       elif .event_type=="mgmt.auth.oauth_callback" then "oauth-callback"
       elif .event_type=="mgmt.auth.oauth_token_refresh" then "oauth-refresh"
       elif .event_type=="mgmt.config.mutate" and .detail.method=="POST" and $p=="/netlox/v1/config/loadbalancer" and $nf > 0 then "lb-create"
       elif .event_type=="mgmt.config.mutate" and .detail.method=="PATCH" and $p=="/netlox/v1/config/ai/apikey/{key_id}" and $nf == 0 then "probe"
       else null end) as $k
    | select($k != null) | "\($k) \($l | utf8bytelength)"'
}
# No boot before this one stays up for a heartbeat interval, so the trail
# holds no heartbeat to measure until this boot writes its first.
echo "  waiting for this boot's first heartbeat, so that its length can be measured"
for _ in $(seq 40); do
  [[ "$(count ".boot_id==\"$B3\" and .event_type==\"sys.heartbeat\"")" -ge 1 ]] && break
  sleep 1
done
LENS=$(line_lengths | awk '{ if (!($1 in m) || $2 < m[$1]) m[$1] = $2 } END { for (k in m) print k, m[k] }' | sort)
PROBE_LEN=$(printf '%s\n' "$LENS" | awk '$1=="probe" { print $2 }')
echo "  shortest line of each kind, bytes: $(printf '%s' "$LENS" | tr '\n' ',' | sed 's/,/, /g')"
# A trail without the probe's own intent has nothing to compare against, so
# every kind counts as shorter and the row fails rather than passing empty.
chk     T3-0b "kinds of line measured, and how many of them are shorter than the probe's intent (${PROBE_LEN:-not found} bytes)" "7 kinds, 0 shorter" \
  "$(printf '%s\n' "$LENS" | awk -v p="$PROBE_LEN" '$1!="probe" { n++; if (p == "" || $2 < p) s++ } END { printf "%d kinds, %d shorter", n, s }')"
W0=$(metric_val loxilb_audit_write_failures_total)
echo "  before the fill: write_failures_total=$W0"

# Fill to the last byte: a page-sized dd leaves the tail of the last page,
# a byte-sized one closes it. That exhausts the free pages, but not the
# active segment's last page: tmpfs allocates by page, so appends that fit
# in its unused tail still succeed. The fill alone is therefore not the
# wedge; the probe's first refused append is.
docker exec llb1 sh -c "dd if=/dev/zero of=$WEDGE_DIR/fill bs=4096 >/dev/null 2>&1; dd if=/dev/zero of=$WEDGE_DIR/fill2 bs=1 >/dev/null 2>&1; df -k $WEDGE_DIR | tail -n1"

# Drive the probe into that tail until the gate refuses it. How many landed
# is printed, not scored: it depends on the segment's length when the fill
# ran.
PROBES=0; PROBE_LANDED=0; WEDGED=0
while (( PROBES < 32 )); do
  PROBES=$((PROBES+1))
  wedge_probe
  if [[ "$RESP_CODE" == 503 && "$RESP_BODY" == *audit_unavailable* ]]; then WEDGED=1; break; fi
  [[ "$RESP_CODE" == 400 ]] || { echo "  FATAL: wedge probe $PROBES answered $RESP_CODE: ${RESP_BODY:0:200}"; echo "SCENARIO-audit-mgmt [FAILED]"; exit 1; }
  PROBE_LANDED=$((PROBE_LANDED+1))
done
(( WEDGED )) || { echo "  FATAL: the gate never refused within $PROBES probes; the filesystem is not wedged"; echo "SCENARIO-audit-mgmt [FAILED]"; exit 1; }
echo "  wedged after $PROBES probe(s); $PROBE_LANDED landed in the last page's slack"
# A probe that landed is followed by its result, appended after the answer;
# give the writer a moment to take or refuse it, so that the count below is
# of a trail that has stopped moving.
sleep 1
N0=$(count ".boot_id==\"$B3\"")

echo ""
echo "T3: the gate fails closed while the writer cannot append"
api POST /config/loadbalancer "${AUTH[@]}" "${CT[@]}" -d "$(lb_body 2051)"
chk     T3-1a "generated route: 503" 503 "$RESP_CODE"
chk_has T3-1b "generated route: reason audit_unavailable" audit_unavailable "$RESP_BODY"
chk_has T3-1c "generated route: the class of failure is named" "durable write failed" "$RESP_BODY"
chk     T3-1d "generated route: the rule table is unchanged (state oracle)" 0 "$(rule_count 2051)"
api PATCH "/config/ai/apikey/$KEY2" "${AUTH[@]}" "${CT[@]}" -d '{"enabled":false}'
chk     T3-2a "raw route (PATCH apikey): 503" 503 "$RESP_CODE"
chk_has T3-2b "raw route: reason audit_unavailable" audit_unavailable "$RESP_BODY"
api GET "/config/ai/apikey/$KEY2" "${AUTH[@]}"
chk     T3-2c "raw route: the key is still enabled (state oracle)" true "$(json '.enabled')"
api POST /auth/users "${AUTH[@]}" "${CT[@]}" -d '{"username":"ghost2","password":"Gh0st-pass!8r","role":"viewer"}'
chk     T3-3a "named route (POST /auth/users): 503" 503 "$RESP_CODE"
api GET /auth/users "${AUTH[@]}"
chk     T3-3b "named route: the account was not created (state oracle)" 0 "$(json '[.[]|select(.username=="ghost2")]|length')"
chk     T3-3c "named route: the listing itself is still served (R-list)" 200 "$RESP_CODE"

echo ""
echo "T22: the OAuth GETs are refused before any side effect while wedged"
api GET /oauth/google
chk     T22-4a "start: 503" 503 "$RESP_CODE"
chk_has T22-4b "start: reason audit_unavailable" audit_unavailable "$RESP_BODY"
api GET "/oauth/google/callback?state=not-a-minted-state&code=x"
chk     T22-5  "callback: 503 before any exchange" 503 "$RESP_CODE"
api GET "/oauth/google/token?token=$CANARY_OAT&refreshtoken=$CANARY_ORT"
chk     T22-6  "refresh: 503 before any exchange" 503 "$RESP_CODE"

echo ""
echo "T19: the failure is visible outside the writer while it writes nothing"
W1=$(metric_val loxilb_audit_write_failures_total)
chk_gt  T19-1a "loxilb_audit_write_failures_total rose" "${W0:-0}" "$W1"
chk_ge  T19-1b "/audit/status write_failures" 1 "$(astatus | jq -r '.write_failures // 0')"
chk     T19-1c "the writer goroutine is still up (running)" true "$(astatus | jq -r '.running')"
chk     T19-1d "loxilb_audit_writer_up" 1 "$(metric_val loxilb_audit_writer_up)"
chk_ge  T19-2  "the operational log carries the fallback line" 1 "$(gw_log_grep 'audit: write failed (' | wc -l | tr -d ' ')"
L0=$(metric_val loxilb_audit_last_write_timestamp_seconds)
echo "  waiting 35 s across one heartbeat interval so staleness is measurable (last_write=$L0, records=$N0)"
sleep 35
chk     T19-3a "loxilb_audit_last_write_timestamp_seconds did not advance" "$L0" "$(metric_val loxilb_audit_last_write_timestamp_seconds)"
chk_gt  T19-3b "the failing heartbeat added to write_failures_total" "$W1" "$(metric_val loxilb_audit_write_failures_total)"
chk     T19-3c "no record of this boot landed from the first refusal on" "$N0" "$(count ".boot_id==\"$B3\"")"

echo ""
echo "Un-wedge: free the filesystem, repeat the calls"
docker exec llb1 sh -c "rm -f $WEDGE_DIR/fill $WEDGE_DIR/fill2; df -k $WEDGE_DIR | tail -n1"
api POST /config/loadbalancer "${AUTH[@]}" "${CT[@]}" -d "$(lb_body 2051)"
chk     T3-4a "generated route after un-wedge: accepted" 200 "$RESP_CODE"
chk     T3-4b "the rule now exists" 1 "$(rule_count 2051)"
EID=$(newest_intent '.event_type=="mgmt.config.mutate" and .detail.path=="/netlox/v1/config/loadbalancer"' "$WEDGE_DIR")
wait_result "$EID" || true
chk     T3-4c "intent and result share one event_id" 2 "$(count ".event_id==\"$EID\" and (.phase==\"intent\" or .phase==\"result\")" "$WEDGE_DIR")"
chk     T3-4d "the intent was written before the result (seq order)" true \
  "$(records ".event_id==\"$EID\"" "$WEDGE_DIR" | jq -s -r 'sort_by(.seq) | (.[0].phase=="intent" and .[1].phase=="result")')"
api PATCH "/config/ai/apikey/$KEY2" "${AUTH[@]}" "${CT[@]}" -d '{"enabled":false}'
chk     T3-5a "raw route after un-wedge: accepted" 204 "$RESP_CODE"
api GET "/config/ai/apikey/$KEY2" "${AUTH[@]}"
chk     T3-5b "the key is now disabled" false "$(json '.enabled')"
EID=$(newest_intent '.event_type=="mgmt.config.mutate" and .detail.raw==true' "$WEDGE_DIR")
wait_result "$EID" || true
chk     T3-5c "raw pair: route_class raw" raw "$(records ".event_id==\"$EID\" and .phase==\"result\"" "$WEDGE_DIR" | jq -r '.detail.route_class')"
chk     T3-5d "raw pair: path template" "/netlox/v1/config/ai/apikey/{key_id}" "$(records ".event_id==\"$EID\" and .phase==\"result\"" "$WEDGE_DIR" | jq -r '.detail.path')"

WF=$(records '.event_type=="sys.writer.write_failed"' "$WEDGE_DIR" | tail -n1)
chk_nonempty T19-4a "retroactive sys.writer.write_failed record" "$WF"
chk_nonempty T19-4b "errno_class" "$(printf '%s' "$WF" | jq -r '.detail.errno_class // empty')"
chk_ge  T19-4c "count of failed appends in the interval" 3 "$(printf '%s' "$WF" | jq -r '.detail.count // 0')"
chk     T19-4d "first_ts <= last_ts" true "$(printf '%s' "$WF" | jq -r '(.detail.first_ts <= .detail.last_ts)')"
chk_ge  T19-4e "the operational log notes the resumption" 1 "$(gw_log_grep 'audit: writing resumed after' | wc -l | tr -d ' ')"
chk     T19-5  "/audit/status write_failures agrees with the metric" "$(metric_val loxilb_audit_write_failures_total)" "$(astatus | jq -r '.write_failures')"
TORN=$(trail_raw "$WEDGE_DIR" | jq -R 'fromjson? | 1' | wc -l | tr -d ' ')
RAWN=$(trail_raw "$WEDGE_DIR" | grep -c .)
chk     T19-6  "every line of the wedged segment parses ($RAWN lines; a torn line mid-segment is a finding)" "$RAWN" "$TORN"

# ── Boot 4: T11 arm 2, no user service ──────────────────────────────────────
echo ""
echo "Boot 4: no --userservice — the trail says auth=none rather than inventing an actor"
echo "════════════════════════════════════════════════════════════════════════"
gw_stop || { echo "SCENARIO-audit-mgmt [FAILED]"; exit 1; }
gw_start $AIKEY_ARGS --audit-dir "$AUDIT_DIR" --audit-required || { echo "SCENARIO-audit-mgmt [FAILED]"; exit 1; }
AUTH=()
B4=$(astatus | jq -r '.boot_id')
echo "  boot_id $B4"
api POST /config/loadbalancer "${CT[@]}" -d "$(lb_body 2061)"
echo "  POST /config/loadbalancer -> $RESP_CODE"
api PUT /maintenance "${CT[@]}" -d '{"enabled":true}'
api PUT /maintenance "${CT[@]}" -d '{"enabled":false}'
api POST /config/persist "${CT[@]}" -d '{}'
api GET /config/export
api POST /auth/users "${CT[@]}" -d '{"username":"nobody","password":"N0body-pass!5t","role":"viewer"}'
echo "  POST /auth/users (no user service) -> $RESP_CODE"
# One heartbeat interval, so the liveness record of a healthy writer is in
# the trail deterministically (the other boots are too short to promise one).
echo "  waiting 32 s for a heartbeat"
sleep 32
MG4=$(count ".boot_id==\"$B4\" and .stream==\"mgmt\"")
chk_ge  T11-2a "mgmt records in boot 4" 6 "$MG4"
chk     T11-2b "every one says auth=none" "$MG4" "$(count ".boot_id==\"$B4\" and .stream==\"mgmt\" and .actor.auth==\"none\"")"
chk     T11-2c "none names a user" 0 "$(count ".boot_id==\"$B4\" and .stream==\"mgmt\" and (.actor.user != null)")"
chk_ge  T11-2d "the mutations themselves succeeded (ok results)" 3 "$(count ".boot_id==\"$B4\" and .stream==\"mgmt\" and .phase==\"result\" and .outcome.ok==true")"
HB=$(records ".boot_id==\"$B4\" and .event_type==\"sys.heartbeat\"" | tail -n1)
chk_nonempty T11-2e "a heartbeat record of a healthy writer" "$(printf '%s' "$HB" | jq -c '.detail.heartbeat | {seq_high, accepted, write_failures_total}')"
chk     T11-2f "the heartbeat's accepted.mgmt agrees with the boot's mgmt record count" "$MG4" "$(printf '%s' "$HB" | jq -r '.detail.heartbeat.accepted.mgmt')"

# ── T15: canaries are absent everywhere ─────────────────────────────────────
echo ""
echo "T15: canary secrets are absent from every segment and every error body"
chk_ge  T15-0a "segments exist in both directories" 2 "$(docker exec llb1 sh -c "ls $AUDIT_DIR/*.jsonl* $WEDGE_DIR/*.jsonl* 2>/dev/null | wc -l" | tr -d ' ')"
chk_ge  T15-0b "at least one compressed segment is part of the sweep" 1 "$(docker exec llb1 sh -c "ls $AUDIT_DIR/*.jsonl.gz 2>/dev/null | wc -l" | tr -d ' ')"
SWEEP=$WORK/sweep.txt
trail_raw "$AUDIT_DIR" "$WEDGE_DIR" > "$SWEEP"
docker exec llb1 sh -c 'cat /var/log/loxilb.log /tmp/loxilb.out /tmp/loxilb.err 2>/dev/null' > "$WORK/gwlog.txt"
n=0
for c in "${SENT_CANARIES[@]}"; do
  n=$((n+1))
  if grep -qF -- "$c" "$REQLOG"; then ok "T15-1.$n" "canary $n was sent (harness request log)"; else bad "T15-1.$n" "canary $n was sent" "not found in the request log"; fi
done
n=0
for c in "${SENT_CANARIES[@]}" "${RECEIVED_CANARIES[@]}"; do
  n=$((n+1))
  if grep -qF -- "$c" "$SWEEP"; then bad "T15-2.$n" "canary $n absent from every segment" "found: $(grep -F -- "$c" "$SWEEP" | head -n1 | cut -c1-200)"; else ok "T15-2.$n" "canary $n absent from every segment"; fi
  if grep -qF -- "$c" "$ERRBODIES"; then bad "T15-3.$n" "canary $n absent from every error body" "found: $(grep -F -- "$c" "$ERRBODIES" | head -n1 | cut -c1-200)"; else ok "T15-3.$n" "canary $n absent from every error body"; fi
  # The operational log runs at debug on this bed, which the product does
  # not ship; a hit here is reported for the reader, not scored.
  if grep -qF -- "$c" "$WORK/gwlog.txt"; then echo "  [T15-4.$n] NOTE canary $n appears in the debug operational log: $(grep -F -- "$c" "$WORK/gwlog.txt" | head -n1 | cut -c1-160)"; fi
done
chk     T15-5 "no record carries a password field" 0 "$(jq -R 'fromjson? | select(type=="object") | .. | objects | select(has("password"))' "$SWEEP" | grep -c .)"
chk     T15-6 "no query string survived into any recorded path" 0 "$(jq -R -r 'fromjson? | select(type=="object") | .detail.path // empty' "$SWEEP" | grep -c '[?#]')"

# This section runs last on purpose. It is the only part of the scenario that
# seals a segment, and `trail_raw` concatenates *.jsonl before *.jsonl.gz, so
# a sealed-and-compressed segment lands after the active one and every helper
# that takes "the newest record" by position stops being right. Nothing after
# this point may rely on that order.
# ── T-GW-2: the audit policy, the remote sink and sealing on demand ─────────
echo ""
echo "T-GW-2: /audit/policy, /audit/sink and /audit/rotate"

if make_sink_ca "$SINK_CA"; then
    ok T-GW-2-0 "a trust anchor the sink can read is in place"
else
    bad T-GW-2-0 "trust anchor for the sink" "could not place $SINK_CA in llb1"
fi

# The policy endpoint REPLACES the policy rather than patching it, so a
# correct caller reads it, changes one field and writes the whole thing back.
# Anything else silently zeroes the fields it leaves out.
api GET /audit/policy "${AUTH[@]}"
chk     T-GW-2-1a "GET /audit/policy answers 200" 200 "$RESP_CODE"
POL_BEFORE=$RESP_BODY
AGE_BEFORE=$(printf '%s' "$POL_BEFORE" | jq -r '.max_segment_age_seconds // 0')
chk_nonempty T-GW-2-1b "the policy names its segment age ceiling" "$AGE_BEFORE"

AGE_AFTER=$(( AGE_BEFORE + 60 ))
POL_BODY=$(printf '%s' "$POL_BEFORE" | jq -c ".max_segment_age_seconds = $AGE_AFTER")
api POST /audit/policy "${AUTH[@]}" "${CT[@]}" -d "$POL_BODY"
chk     T-GW-2-2a "a policy change is accepted" 204 "$RESP_CODE"
tm_pair T-GW-2-2b "mgmt.audit.policy names the changed field and states the floor did not refuse it" \
        mgmt.audit.policy '.outcome.ok==true and (.detail.changed_fields|index("max_segment_age")!=null) and .detail.floor_rejected==false'
api GET /audit/policy "${AUTH[@]}"
chk     T-GW-2-2c "the running policy carries the new ceiling" "$AGE_AFTER" "$(json '.max_segment_age_seconds')"

# A policy that cannot be satisfied is refused before it is applied, and the
# running policy is left alone: a quota below one segment would have the
# writer delete everything and still be over.
POL_BAD=$(printf '%s' "$POL_BEFORE" | jq -c '.max_segment_bytes = 1048576 | .retention_max_bytes = 4096')
api POST /audit/policy "${AUTH[@]}" "${CT[@]}" -d "$POL_BAD"
chk     T-GW-2-3a "a quota below one segment is refused" 400 "$RESP_CODE"
api GET /audit/policy "${AUTH[@]}"
chk     T-GW-2-3b "the refused change did not touch the running policy" "$AGE_AFTER" "$(json '.max_segment_age_seconds')"

# The sink. A receiver that could not be verified is refused when it is
# configured, not when it first connects.
api GET /audit/sink "${AUTH[@]}"
chk     T-GW-2-4a "GET /audit/sink answers 200" 200 "$RESP_CODE"
chk     T-GW-2-4b "no sink is configured yet" false "$(json '.enabled // false')"

api POST /audit/sink "${AUTH[@]}" "${CT[@]}" -d '{"enabled":true,"address":"siem.example:6514"}'
chk     T-GW-2-5a "a sink with no trust anchor is refused" 400 "$RESP_CODE"
api GET /audit/sink "${AUTH[@]}"
chk     T-GW-2-5b "the refused sink was not installed" false "$(json '.enabled // false')"

# The two numbers are used as an int internally. A value outside its range is
# refused as it arrived, because converting first would replace it with a
# different number rather than fail.
api POST /audit/sink "${AUTH[@]}" "${CT[@]}" \
    -d "{\"enabled\":true,\"address\":\"127.0.0.1:6514\",\"ca_bundle_path\":\"$SINK_CA\",\"facility\":24}"
chk     T-GW-2-6a "a facility outside RFC 5424 table 1 is refused" 400 "$RESP_CODE"
api POST /audit/sink "${AUTH[@]}" "${CT[@]}" \
    -d "{\"enabled\":true,\"address\":\"127.0.0.1:6514\",\"ca_bundle_path\":\"$SINK_CA\",\"max_frame_bytes\":9223372036854775807}"
chk     T-GW-2-6b "a frame cap the framing cannot carry is refused" 400 "$RESP_CODE"
api GET /audit/sink "${AUTH[@]}"
chk     T-GW-2-6c "neither refusal installed a sink" false "$(json '.enabled // false')"

api POST /audit/sink "${AUTH[@]}" "${CT[@]}" \
    -d "{\"enabled\":true,\"address\":\"127.0.0.1:6514\",\"ca_bundle_path\":\"$SINK_CA\",\"server_name\":\"localhost\"}"
chk     T-GW-2-7a "a sink with a readable trust anchor is accepted" 204 "$RESP_CODE"
api GET /audit/sink "${AUTH[@]}"
chk     T-GW-2-7b "the sink reads as configured" true "$(json '.enabled // false')"
chk     T-GW-2-7c "the sink names its receiver" 127.0.0.1:6514 "$(json '.address')"
tm_pair T-GW-2-7d "mgmt.audit.sink names the endpoint and the anchor that vouches for the receiver" \
        mgmt.audit.sink '.outcome.ok==true and .detail.endpoint=="127.0.0.1:6514" and (.detail.tls_ca_id|length)>0'
# The anchor is named, never served: no certificate material may appear in a
# record or in the read-back.
SINK_RECS=$(records '.event_type=="mgmt.audit.sink"')
chk     T-GW-2-7e "no certificate material in any sink record" 0 "$(printf '%s' "$SINK_RECS" | grep -c 'BEGIN CERTIFICATE')"
chk     T-GW-2-7f "no certificate material served by the read" 0 "$(printf '%s' "$RESP_BODY" | grep -c 'BEGIN CERTIFICATE')"

# Sealing on demand. The record names both segments, and the writer really
# did move: the sealed uuid is the one the status reported a moment ago.
SEG_BEFORE=$(printf '%s' "$(astatus)" | jq -r '.segment.uuid')
api POST /audit/rotate "${AUTH[@]}" "${CT[@]}" -d '{}'
chk     T-GW-2-8a "sealing the active segment is accepted" 200 "$RESP_CODE"
SEALED=$(json '.sealed_segment_uuid'); OPENED=$(json '.new_segment_uuid')
chk     T-GW-2-8b "the reply seals the segment the status named" "$SEG_BEFORE" "$SEALED"
chk_ne  T-GW-2-8c "the new segment is not the sealed one" "$SEALED" "$OPENED"
chk     T-GW-2-8d "the status now reports the new segment" "$OPENED" "$(printf '%s' "$(astatus)" | jq -r '.segment.uuid')"
tm_pair T-GW-2-8e "mgmt.audit.rotate_now names the segment sealed and the one now active" \
        mgmt.audit.rotate_now '.outcome.ok==true and (.detail.sealed_segment_uuid|length)>0 and (.detail.new_segment_uuid|length)>0 and .detail.sealed_segment_uuid!=.detail.new_segment_uuid'
# A record written after the seal lands in the new segment, which is what
# makes the seal a boundary rather than a label. The reads of this endpoint
# are deliberately unaudited, so it takes a mutation to produce one.
POL_BODY2=$(printf '%s' "$POL_BEFORE" | jq -c ".max_segment_age_seconds = $(( AGE_AFTER + 60 ))")
api POST /audit/policy "${AUTH[@]}" "${CT[@]}" -d "$POL_BODY2"
chk     T-GW-2-8f "a further policy change is accepted after the seal" 204 "$RESP_CODE"
chk_ge  T-GW-2-8g "a record written after the seal lands in the new segment" 1 \
        "$(count ".event_type==\"mgmt.audit.policy\" and .segment_uuid==\"$OPENED\"")"

# ── T-GW-5: the three CLI paths against a live gateway ──────────────────────
#
# Placement. This section is last, after T-GW-2, for reasons of its own:
#   * it restarts the gateway twice — once with the audit directory made
#     unusable, so that no writer exists, and once back to a healthy one —
#     which nothing earlier could be asked to survive;
#   * T-GW-2 asserts a sink that has never been configured, and this
#     section configures one, so it cannot run before it;
#   * the seal above rearranged the trail's positional order, and nothing
#     here depends on it: every trail assertion selects its record by a
#     value only that arm could have written — a receiver address of its
#     own — never by taking the newest record.
#
# The CLI is the subject; REST and the trail are the oracles. A claim the
# CLI prints is only scored against the same fact read another way.
echo ""
echo "T-GW-5: loxicmd get audit-status, get audit-sink and set audit-sink"

# The three commands are part of the loxicmd release this image pins, so
# their absence is a stale pin rather than a product defect — and it would
# otherwise redden every row below for that one cause.
#
# The probe reads the help TEXT, not the exit status: `loxicmd get <name>
# --help` answers 0 and prints the group's help for any name at all, so a
# status check passes just as happily on a CLI that has never heard of these
# commands (`get totally-bogus --help` also exits 0). Each command's help
# names the route it drives, and only that command's does.
has_cmd() { # has_cmd <group> <command> <route named in its help>
  $dexec llb1 loxicmd "$1" "$2" --help 2>&1 | grep -q -- "$3"
}
if has_cmd get audit-status 'GET /audit/status' &&
   has_cmd get audit-sink   'GET /audit/sink'   &&
   has_cmd set audit-sink   'POST /audit/sink'; then
  ok T-GW-5-0 "the image's loxicmd carries the three audit commands"
  T_GW_5=1
else
  bad T-GW-5-0 "the image's loxicmd carries the three audit commands" \
      "one of get audit-status / get audit-sink / set audit-sink is absent; the image's LOXICMD_TAG predates them"
  T_GW_5=0
fi

t_gw_5() {
  # The anchor T-GW-2 placed is still in the container, but this section does
  # not lean on that: it places its own, which costs nothing and lets the
  # section be read, moved or run on its own. It is placed before the reboots
  # because it is a file in the container, which a gateway restart does not
  # touch.
  if make_sink_ca "$SINK_CA"; then
    ok T-GW-5-0a "a trust anchor the sink can read is in place"
  else
    bad T-GW-5-0a "trust anchor for the sink" "could not place $SINK_CA in llb1"
  fi

  # ---- the writer-less gateway ---------------------------------------------
  # --audit-dir defaults to the healthy directory, so "no writer" is made by
  # pointing it below a regular file: the create fails with ENOTDIR. The
  # --audit-required flag is deliberately absent — with it the process would
  # refuse to boot, and what is under test is the answer a booted gateway
  # gives about an audit trail it does not have.
  echo ""
  echo "Boot 5: the audit directory is unusable — the writer is absent"
  echo "════════════════════════════════════════════════════════════════════════"
  gw_stop || { bad T-GW-5-1 "boot 5" "the gateway would not stop"; return; }
  docker exec llb1 sh -c "rm -rf $NOAUDIT_BLOCK && : > $NOAUDIT_BLOCK"
  gw_start $AIKEY_ARGS --audit-dir "$NOAUDIT_BLOCK/segments" || { bad T-GW-5-1 "boot 5" "the gateway did not come back without a writer"; return; }

  chk_ge  T-GW-5-1a "the operational log says the trail is unavailable" 1 \
          "$(gw_log_grep 'audit trail unavailable' | wc -l | tr -d ' ')"
  # The wire oracle for the row below it: the CLI can only render an answer
  # the gateway actually sends.
  chk     T-GW-5-1b "the gateway's own answer carries the availability field" true \
          "$(astatus | jq -r 'has("available")')"
  chk     T-GW-5-1c "and it says the writer is absent" false "$(astatus | jq -r '.available // false')"
  cli unavail get audit-status
  chk     T-GW-5-1d "get audit-status exits 0 against a writer-less gateway" 0 "$CLI_RC"
  chk     T-GW-5-1e "it renders the unavailable answer" \
          "Audit: NOT AVAILABLE - no writer was configured at start." "$(head -n1 "$CLI_OUT")"
  chk     T-GW-5-1f "and prints no counter, which would be a zero read as a measurement" 0 \
          "$(grep -c 'Sequence high\|Accepted' "$CLI_OUT")"

  # ---- the writer is back --------------------------------------------------
  echo ""
  echo "Boot 6: a healthy writer again — the CLI drives the audit commands"
  echo "════════════════════════════════════════════════════════════════════════"
  gw_stop || { bad T-GW-5-2 "boot 6" "the gateway would not stop"; return; }
  docker exec llb1 rm -f "$NOAUDIT_BLOCK"
  gw_start $AIKEY_ARGS --audit-dir "$AUDIT_DIR" --audit-required || { bad T-GW-5-2 "boot 6" "the gateway did not come back with a writer"; return; }
  B6=$(astatus | jq -r '.boot_id')
  echo "  boot_id $B6"

  # ---- get audit-status on a running writer --------------------------------
  echo ""
  echo "T-GW-5: get audit-status reports the writer, and only the writer"
  cli status get audit-status
  chk     T-GW-5-2a "get audit-status exits 0" 0 "$CLI_RC"
  chk     T-GW-5-2b "the first line reports a running writer" "Audit: available, running" "$(head -n1 "$CLI_OUT")"
  chk     T-GW-5-2c "the boot id it prints is the one the gateway reports" "$B6" \
          "$(sed -n 's/^  Boot id: //p' "$CLI_OUT")"
  chk     T-GW-5-2d "no record content reached the CLI's output" 0 "$(grep -c 'event_type' "$CLI_OUT")"

  # -o json is the gateway's body verbatim, not a re-encoding of the CLI's
  # own struct. The proof is the key ORDER: the body's order is the
  # gateway's, and any re-encode here would impose this CLI's instead. Two
  # reads are needed to compare, so the one counter that can cross zero
  # between them (the 30 s heartbeat) is left out of the comparison.
  cli status-json get audit-status -o json
  chk     T-GW-5-3a "get audit-status -o json exits 0" 0 "$CLI_RC"
  chk_nonempty T-GW-5-3b "the json parses" "$(jq -r '.boot_id // empty' "$CLI_OUT")"
  chk     T-GW-5-3c "it names the same boot as the gateway" "$B6" "$(jq -r '.boot_id // empty' "$CLI_OUT")"
  chk     T-GW-5-3d "the keys are the gateway's, in the gateway's order (printed verbatim)" \
          "$(astatus | jq -r 'keys_unsorted | map(select(. != "heartbeats")) | join(",")')" \
          "$(jq -r 'keys_unsorted | map(select(. != "heartbeats")) | join(",")' "$CLI_OUT")"

  # ---- get audit-sink with nothing configured ------------------------------
  echo ""
  echo "T-GW-5: get audit-sink before and after a sink exists"
  chk     T-GW-5-4a "the boot starts with no sink (the oracle)" false "$(asink | jq -r '.enabled // false')"
  cli sink-off get audit-sink
  chk     T-GW-5-4b "get audit-sink exits 0" 0 "$CLI_RC"
  chk     T-GW-5-4c "an unconfigured sink is reported as such" \
          "Audit sink: not configured - the trail is local only." "$(head -n1 "$CLI_OUT")"
  cli sink-off-json get audit-sink -o json
  chk     T-GW-5-4d "-o json is the gateway's body verbatim" "$(asink)" "$(cat "$CLI_OUT")"

  # ---- the refusals the CLI owns -------------------------------------------
  # Each one names its flag and, the point of the section, never reaches the
  # gateway: POST /audit/sink is audited, so the count of its records is the
  # independent witness that no request was made.
  echo ""
  echo "T-GW-5: a locally refused set names its flag and sends nothing"
  SINK_N0=$(count '.event_type=="mgmt.audit.sink"')
  cli no-ca set audit-sink --address 127.0.0.1:7514
  chk     T-GW-5-5a "no --ca-bundle: exit 2" 2 "$CLI_RC"
  chk_has T-GW-5-5b "and the refusal names the flag" "--ca-bundle is required" "$(cat "$CLI_ERR")"
  cli no-addr set audit-sink --ca-bundle "$SINK_CA"
  chk     T-GW-5-5c "no --address: exit 2" 2 "$CLI_RC"
  chk_has T-GW-5-5d "and the refusal names the flag" "--address is required" "$(cat "$CLI_ERR")"
  cli half-keypair set audit-sink --address 127.0.0.1:7514 --ca-bundle "$SINK_CA" --client-cert "$SINK_CA"
  chk     T-GW-5-5e "half a client keypair: exit 2" 2 "$CLI_RC"
  chk_has T-GW-5-5f "and the refusal names both flags" "--client-cert and --client-key" "$(cat "$CLI_ERR")"
  cli bad-facility set audit-sink --address 127.0.0.1:7514 --ca-bundle "$SINK_CA" --facility 24
  chk     T-GW-5-5g "a facility outside the table: exit 2" 2 "$CLI_RC"
  chk_has T-GW-5-5h "and the refusal names the range" "--facility must be between" "$(cat "$CLI_ERR")"
  cli neg-frame set audit-sink --address 127.0.0.1:7514 --ca-bundle "$SINK_CA" --max-frame-bytes=-1
  chk     T-GW-5-5i "a negative frame cap: exit 2" 2 "$CLI_RC"
  chk_has T-GW-5-5j "and the refusal names the flag" "--max-frame-bytes cannot be negative" "$(cat "$CLI_ERR")"
  chk     T-GW-5-5k "not one of the five reached the gateway (mgmt.audit.sink unchanged)" \
          "$SINK_N0" "$(count '.event_type=="mgmt.audit.sink"')"
  chk     T-GW-5-5l "and none of them installed a sink" false "$(asink | jq -r '.enabled // false')"

  # The contrast: what only the gateway can see stays the gateway's refusal.
  # It is a different exit code (contract mismatch, not bad arguments) and it
  # does reach the gateway, which records it.
  cli unreadable-ca set audit-sink --address 127.0.0.1:7514 --ca-bundle /tmp/no-such-bundle.pem
  chk     T-GW-5-6a "a bundle only the gateway can judge: exit 6, not 2" 6 "$CLI_RC"
  chk_has T-GW-5-6b "the refusal is carried through as the gateway's" "server returned 400" "$(cat "$CLI_ERR")"
  chk_has T-GW-5-6c "and classified as a contract mismatch" "(bad-request, HTTP 400)" "$(cat "$CLI_ERR")"
  chk_gt  T-GW-5-6d "that one did reach the gateway (a record was written)" \
          "$SINK_N0" "$(count '.event_type=="mgmt.audit.sink"')"
  chk     T-GW-5-6e "the refused sink was not installed" false "$(asink | jq -r '.enabled // false')"

  # ---- set audit-sink: configure, replace, disable -------------------------
  echo ""
  echo "T-GW-5: set audit-sink configures, replaces and removes the sink"
  cli sink-set set audit-sink --address 127.0.0.1:7514 --ca-bundle "$SINK_CA" \
      --server-name siem.audit.local --facility 13 --max-frame-bytes 8192
  chk     T-GW-5-7a "set audit-sink exits 0" 0 "$CLI_RC"
  chk     T-GW-5-7b "it reports the receiver and the anchor it is verified against" \
          "Audit sink replaced: 127.0.0.1:7514, verified against $SINK_CA." "$(head -n1 "$CLI_OUT")"
  S=$(asink)
  chk     T-GW-5-7c "the gateway holds the receiver (the oracle)" 127.0.0.1:7514 "$(printf '%s' "$S" | jq -r '.address')"
  chk     T-GW-5-7d "the anchor"        "$SINK_CA"       "$(printf '%s' "$S" | jq -r '.ca_bundle_path')"
  chk     T-GW-5-7e "the expected server name" siem.audit.local "$(printf '%s' "$S" | jq -r '.server_name')"
  chk     T-GW-5-7f "the facility"      13               "$(printf '%s' "$S" | jq -r '.facility')"
  chk     T-GW-5-7g "the frame cap"     8192             "$(printf '%s' "$S" | jq -r '.max_frame_bytes')"
  cli sink-on get audit-sink
  chk_has T-GW-5-7h "get audit-sink now reports it enabled" "Audit sink: enabled," "$(head -n1 "$CLI_OUT")"
  chk_has T-GW-5-7i "and names the receiver" "Receiver: 127.0.0.1:7514" "$(cat "$CLI_OUT")"
  chk     T-GW-5-7j "no certificate material is served to the CLI" 0 "$(grep -c 'BEGIN CERTIFICATE' "$CLI_OUT")"
  # The change is itself audited. The record is selected by the receiver only
  # this arm configured, so no ordering of the segments can pick another.
  chk_ge  T-GW-5-7k "the set appears in the trail as a mgmt.audit.sink result" 1 \
          "$(count '.event_type=="mgmt.audit.sink" and .phase=="result" and .outcome.ok==true and .detail.endpoint=="127.0.0.1:7514"')"
  chk     T-GW-5-7l "the record names the anchor, never its contents" "$SINK_CA" \
          "$(records '.event_type=="mgmt.audit.sink" and .phase=="result" and .detail.endpoint=="127.0.0.1:7514"' | tail -n1 | jq -r '.detail.tls_ca_id')"

  # The endpoint REPLACES. This set leaves out --server-name and
  # --max-frame-bytes, so a correct CLI sends them as their defaults and the
  # gateway forgets what it held — which is the documented contract, and the
  # thing an operator loses a setting to if it is not true.
  cli sink-replace set audit-sink --address 127.0.0.1:7515 --ca-bundle "$SINK_CA"
  chk     T-GW-5-8a "a replacing set exits 0" 0 "$CLI_RC"
  S=$(asink)
  chk     T-GW-5-8b "the receiver moved" 127.0.0.1:7515 "$(printf '%s' "$S" | jq -r '.address')"
  chk     T-GW-5-8c "the server name the previous set held was replaced, not kept" "" \
          "$(printf '%s' "$S" | jq -r '.server_name // ""')"
  chk     T-GW-5-8d "the frame cap likewise" 0 "$(printf '%s' "$S" | jq -r '.max_frame_bytes // 0')"
  chk     T-GW-5-8e "the facility the CLI sends explicitly survives" 13 "$(printf '%s' "$S" | jq -r '.facility')"
  chk_ge  T-GW-5-8f "the replace appears in the trail as its own mgmt.audit.sink result" 1 \
          "$(count '.event_type=="mgmt.audit.sink" and .phase=="result" and .outcome.ok==true and .detail.endpoint=="127.0.0.1:7515"')"
  chk_has T-GW-5-8g "and its changed_fields name what actually moved" address \
          "$(records '.event_type=="mgmt.audit.sink" and .phase=="result" and .detail.endpoint=="127.0.0.1:7515"' | tail -n1 | jq -c '.detail.changed_fields')"

  SEQ_BEFORE=$(astatus | jq -r '.seq_high // 0')
  cli sink-disable set audit-sink --disable
  chk     T-GW-5-9a "--disable exits 0" 0 "$CLI_RC"
  chk     T-GW-5-9b "it says the trail continues locally" \
          "Audit sink removed. The trail is local only." "$(head -n1 "$CLI_OUT")"
  chk     T-GW-5-9c "the gateway holds no sink (the oracle)" false "$(asink | jq -r '.enabled // false')"
  chk     T-GW-5-9d "and no receiver" "" "$(asink | jq -r '.address // ""')"
  cli sink-off-again get audit-sink
  chk     T-GW-5-9e "get audit-sink reports it unconfigured again" \
          "Audit sink: not configured - the trail is local only." "$(head -n1 "$CLI_OUT")"
  # The removal is the one successful sink record naming no receiver, which is
  # how it is told apart from the two sets without using order. Exactly one,
  # not at least one: "at least one" would go on passing on a gateway that had
  # stopped naming the receiver on all three, which is the thing this row and
  # the two above it exist to catch.
  chk     T-GW-5-9f "the removal is the only successful sink record naming no receiver" 1 \
          "$(count '.event_type=="mgmt.audit.sink" and .phase=="result" and .outcome.ok==true and .detail.endpoint==null')"
  chk_has T-GW-5-9g "and its changed_fields say the sink was turned off" enabled \
          "$(records '.event_type=="mgmt.audit.sink" and .phase=="result" and .outcome.ok==true and .detail.endpoint==null' | tail -n1 | jq -c '.detail.changed_fields')"
  # "The trail continues locally" is a claim, so it is measured: the writer
  # is still the one that was running, and it is still advancing.
  cli status-after get audit-status
  chk     T-GW-5-9h "the writer is still available and running after the removal" \
          "Audit: available, running" "$(head -n1 "$CLI_OUT")"
  chk     T-GW-5-9i "still the same boot, not a restart" "$B6" "$(sed -n 's/^  Boot id: //p' "$CLI_OUT")"
  chk_gt  T-GW-5-9j "and the trail advanced across the removal" "$SEQ_BEFORE" "$(astatus | jq -r '.seq_high // 0')"
}
[[ "$T_GW_5" == 1 ]] && t_gw_5

# ── T-GW-6: every admitted management call is answered and has a result ────
echo ""
echo "T-GW-6: no admitted management call is left without an answer or a result"
# gw_start's settle probe, POST /config/loadbalancer with an empty body, is
# the one request every boot sends. Where management authentication is off
# (boots 4 and 6) it reaches the handler itself, so it is the scenario's
# standing check that a malformed create is refused rather than crashing
# the handler -- which drops the connection without an answer and, before
# the gate recorded the result of a handler that panicked, left its durable
# intent without one.
chk     T-GW-6-1 "settle probes that got no HTTP answer, over every boot" 0 "$SETTLE_NOANSWER"
PROBE_F='.event_type=="mgmt.config.mutate" and .phase=="intent" and .detail.method=="POST" and .detail.path=="/netlox/v1/config/loadbalancer" and ((.detail.changed_fields // []) | length) == 0'
PROBES=$(records "$PROBE_F" | jq -r '.event_id')
# One per boot that had a writer to take it: 1, 2 and 4, and 6 when T-GW-5
# ran. Boot 3's are refused by the wedged writer, boot 5 has no writer.
PROBE_FLOOR=3; [[ "$T_GW_5" == 1 ]] && PROBE_FLOOR=4
chk_ge  T-GW-6-2 "settle-probe intents in the trail (the floor that keeps 6-3 from passing empty)" "$PROBE_FLOOR" "$(printf '%s\n' "$PROBES" | grep -c .)"
wait_result "$(printf '%s\n' "$PROBES" | tail -n1)" || true
OPEN_PROBES=$(comm -23 <(printf '%s\n' "$PROBES" | grep . | sort -u) \
                       <(records '.phase=="result"' | jq -r '.event_id' | sort -u))
chk     T-GW-6-3 "settle-probe intents with no result" 0 "$(printf '%s\n' "$OPEN_PROBES" | grep -c .)"
if [[ -n "$OPEN_PROBES" ]]; then echo "  open: $(printf '%s' "$OPEN_PROBES" | tr '\n' ' ')"; fi
echo "  settle-probe results by status: $(records '.phase=="result"' | jq -r --argjson ids "$(printf '%s\n' "$PROBES" | jq -R . | jq -s .)" 'select(.event_id as $e | $ids | index($e)) | .outcome.status' | sort | uniq -c | tr -s ' ' | tr '\n' ',')"
# A later boot's recovery scan is what turns an intent without a result into
# a report. Boot 6 scans boot 4 (boot 5 wrote nothing), so with T-GW-5 run
# the only orphan the trail may carry is the one T20 makes on purpose.
if [[ "$T_GW_5" == 1 ]]; then
  chk   T-GW-6-4 "sys.intent.orphaned in the whole trail: only T20's deliberate crash" 1 "$(count '.event_type=="sys.intent.orphaned"')"
  chk   T-GW-6-5 "and it names T20's intent" "$ORPHAN_ID" "$(records '.event_type=="sys.intent.orphaned"' | jq -r '.detail.intent_event_id' | sort -u | tr '\n' ' ' | sed 's/ $//')"
else
  echo "  (T-GW-6-4/6-5 need boot 6 to scan boot 4; T-GW-5 was skipped)"
fi

# ── Summary ─────────────────────────────────────────────────────────────────
echo ""
echo "Trail summary:"
echo "  records: $(trail "$AUDIT_DIR" "$WEDGE_DIR" | wc -l | tr -d ' ') across boots $B1 $B2 $B3 $B4 $B6"
trail "$AUDIT_DIR" "$WEDGE_DIR" | jq -r '.event_type' | sort | uniq -c | sort -rn | sed 's/^/  /'
echo ""
if [[ $code == 0 ]]; then
  echo "SCENARIO-audit-mgmt [OK]"
else
  echo "SCENARIO-audit-mgmt [FAILED]"
fi
exit $code
