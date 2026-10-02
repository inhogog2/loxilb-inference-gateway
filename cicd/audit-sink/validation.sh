#!/bin/bash
# Validates the audit trail leaving the gateway (stage 2):
#
#   TR   transport: a session only to a receiver the run CA vouches for,
#        octet-counted frames a strict receiver accepts, and MSG bytes that
#        are the local record's bytes
#   ST   /audit/status and /audit/sinks/{name} report the sinks; what cannot
#        be a secondary sink is refused and installs nothing
#   T23  a filtered secondary sink numbers what it sends: contiguous, and
#        never the same number twice — across a clean restart, a kill, a
#        cursor file cut short, the whole state deleted, and a crash placed
#        between two steps of the cursor protocol
#   T5   a receiver outage loses nothing, with or without a gateway restart
#        in the middle of it
#   T6   sealing the segment while the sink is behind keeps the order
#   T16  a segment pruned before a sink had it is put on record first
#   PS   the sinks are part of the persisted configuration: a restart brings
#        them back, a removal stays removed, a restore of a saved document
#        replaces what is live, and each sink continues where it was
#
# The oracle is the receiver. The gateway's status says what the sender
# believes — a write that returned — and is used here only to wait, and for
# the rows that are about the status itself. Whether a record was delivered,
# in what order, under which number, is read from what arrived.
#
# Rules: a count that an empty receiver would satisfy is paired with a
# floor; every wait is bounded and its timeout is a red row, not a hang; a
# fault arm proves the fault fired before it scores anything after it.
#
# The arms before PS configure the sinks again after every boot of the
# gateway (sinks_up), which replaces each sink under its name whether or not
# the boot brought it back. PS is where a boot is left to do that alone.

cd "$(dirname "$0")"
source ../common.sh
source .state
echo SCENARIO-audit-sink
code=0

require_host_tools jq python3 sha256sum || { echo "SCENARIO-audit-sink [FAILED]"; exit 1; }

API=http://127.0.0.1:11111/netlox/v1
GW_BIN=/root/loxilb-io/loxilb/loxilb
CT=(-H 'Content-Type: application/json')
STATE_DIR=$AUDIT_DIR/sink
# The export sequence is reserved in blocks of this size, so it is the most
# a kill can leave unused. It is the product's number, restated here so that
# a change to it has to be made twice.
XSEQ_BLOCK=1024

# ── verdict helpers ─────────────────────────────────────────────────────────
ok()  { echo "  [$1] $2 [OK]"; }
bad() { echo "  [$1] $2 [FAILED] — $3"; code=1; }
chk()     { if [[ "$4" == "$3" ]]; then ok "$1" "$2 = '$4'"; else bad "$1" "$2" "expected '$3' got '$4'"; fi; }
chk_ne()  { if [[ "$4" != "$3" ]]; then ok "$1" "$2 = '$4'"; else bad "$1" "$2" "must not be '$3'"; fi; }
chk_has() { if [[ "$4" == *"$3"* ]]; then ok "$1" "$2"; else bad "$1" "$2" "no '$3' in: ${4:0:240}"; fi; }
chk_ge()  { if [[ "$4" =~ ^[0-9]+$ && "$4" -ge "$3" ]]; then ok "$1" "$2 = $4 (>= $3)"; else bad "$1" "$2" "expected >= $3 got '$4'"; fi; }
chk_gt()  { if [[ "$4" =~ ^[0-9]+$ && "$3" =~ ^[0-9]+$ && "$4" -gt "$3" ]]; then ok "$1" "$2 = $4 (> $3)"; else bad "$1" "$2" "expected > $3 got '$4'"; fi; }
chk_le()  { if [[ "$4" =~ ^[0-9]+$ && "$3" =~ ^[0-9]+$ && "$4" -le "$3" ]]; then ok "$1" "$2 = $4 (<= $3)"; else bad "$1" "$2" "expected <= $3 got '$4'"; fi; }
chk_nonempty() { if [[ -n "$3" ]]; then ok "$1" "$2 = '${3:0:80}'"; else bad "$1" "$2" "empty"; fi; }

# ── requests ────────────────────────────────────────────────────────────────
# api <method> <path> [curl args...]  → RESP_CODE, RESP_BODY
api() {
  local method=$1 path=$2 out; shift 2
  out=$(docker exec llb1 curl -s -m 25 -w '\n%{http_code}' -X "$method" "$API$path" "$@")
  RESP_CODE=${out##*$'\n'}
  RESP_BODY=${out%$'\n'*}
  [[ "$RESP_BODY" == "$out" ]] && RESP_BODY=""
}
json() { printf '%s' "$RESP_BODY" | jq -r "$1" 2>/dev/null; }
astatus() { docker exec llb1 curl -s -m 5 "$API/audit/status"; }
# metric_int <family> [<label substring>] → the sample as a whole number,
# empty when the scrape has no such series
metric_int() {
  docker exec llb1 curl -s -m 5 "$API/metrics" 2>/dev/null |
    awk -v f="$1" -v l="${2:-}" '($1 ~ ("^" f "(\\{|$)")) && (l == "" || index($1, l)) { printf "%d\n", $2; exit }'
}
# metric_wait <family> <label substring> <value> [seconds] → the sample came to the value
metric_wait() {
  local i
  for i in $(seq 1 "${4:-20}"); do
    [[ "$(metric_int "$1" "$2")" == "$3" ]] && return 0
    sleep 1
  done
  return 1
}
# sink_field <name> <jq path> → one field of the sink's row in /audit/status
sink_field() { astatus | jq -r ".sinks[]? | select(.name==\"$1\") | $2"; }
# named <name> <jq path> → one field of GET /audit/sinks/{name}
named() { docker exec llb1 curl -s -m 5 "$API/audit/sinks/$1" | jq -r "$2"; }

# ── the trail ───────────────────────────────────────────────────────────────
trail_raw() {
  docker exec llb1 sh -c "cd '$AUDIT_DIR' 2>/dev/null || exit 0; for f in *.jsonl; do [ -f \"\$f\" ] && cat \"\$f\"; done; for f in *.jsonl.gz; do [ -f \"\$f\" ] && zcat \"\$f\"; done" 2>/dev/null
}
trail() { trail_raw | jq -c -R 'fromjson? | select(type=="object" and .event_type != null)'; }
records() { trail | jq -c "select($1)"; }
count()   { records "$1" | wc -l | tr -d ' '; }
# wait_record <jq filter> [seconds] → waits, bounded, for a matching record
wait_record() {
  local i
  for i in $(seq 1 "${2:-20}"); do
    [[ "$(count "$1")" -ge 1 ]] && return 0
    sleep 1
  done
  return 1
}
# trail_seqs <boot> <after> <upto> → the seq of every local record of that
# boot in (after, upto], one per line
trail_seqs() { trail | jq -r "select(.boot_id==\"$1\" and .seq>$2 and .seq<=$3) | .seq" | sort -u; }

# ── the receivers ───────────────────────────────────────────────────────────
# Three receivers, addressed by role. Each is the same program; the label is
# what rmconfig.sh finds a leftover by.
rcv_ns()   { case "$1" in secondary) echo siem2 ;; *) echo siem1 ;; esac; }
rcv_ctlp() { case "$1" in decoy) echo 6517 ;; *) echo 6515 ;; esac; }
rcv_ctl()  { $hexec "$(rcv_ns "$1")" curl -s -m 8 "http://127.0.0.1:$(rcv_ctlp "$1")/$2"; }
rcv_stat() { rcv_ctl "$1" __stats | jq -r "$2"; }
rcv_start() { # rcv_start <compliance|secondary>
  local ip=$SIEM1; [[ "$1" == secondary ]] && ip=$SIEM2
  $hexec "$(rcv_ns "$1")" python3 "$RCV" --sink "audit-sink-$1" --port 6514 --control 127.0.0.1:6515 --pen "$PEN" \
    --cert "$CERTS/run/$ip.pem" --key "$CERTS/run/$ip.key" \
    --out "/tmp/audit-sink-$1.jsonl" >> "/tmp/audit-sink-$1.log" 2>&1 &
  track_helper
  # Out of the job table: the shell would otherwise announce its death,
  # which this scenario brings about on purpose.
  disown $! 2>/dev/null
  local i
  for i in $(seq 1 20); do
    [[ -n "$(rcv_ctl "$1" __probe)" ]] && return 0
    sleep 0.5
  done
  echo "  the $1 receiver did not come back"; return 1
}
rcv_stop() { # the receiver dies as a SIEM does: no close, no goodbye
  sudo pkill -9 -f -- "[s]yslog_receiver.py --sink audit-sink-$1 " 2>/dev/null
  local i
  for i in $(seq 1 10); do
    [[ -z "$(rcv_ctl "$1" __probe)" ]] && return 0
    sleep 0.5
  done
  echo "  the $1 receiver would not die"; return 1
}
# rcv_seqs <role> <boot> → the seq of every record of that boot that arrived
rcv_seqs() { rcv_ctl "$1" __records | jq -r "select(.boot_id==\"$2\" and .seq!=null) | .seq" | sort -u; }
# missing_at <role> <boot> <after> <upto> → MISSING, how many local records
# of that boot in (after, upto] the receiver does not hold, and LOCAL_N, how
# many there were to hold, for the floor beside it. It sets two values, so
# it is called for its effect and never inside a substitution.
MISSING=unread; LOCAL_N=0
missing_at() {
  local l r
  l=$(trail_seqs "$2" "$3" "$4"); r=$(rcv_seqs "$1" "$2")
  LOCAL_N=$(printf '%s\n' "$l" | grep -c .)
  MISSING=$(comm -23 <(printf '%s\n' "$l") <(printf '%s\n' "$r") | grep -c .)
}
# wait_arrived <role> <boot> <seq> [seconds]
wait_arrived() {
  local i
  for i in $(seq 1 "${4:-60}"); do
    rcv_seqs "$1" "$2" | grep -qx "$3" && return 0
    sleep 1
  done
  return 1
}
# wait_caught <sink> [seconds] → the sender believes it has sent everything
wait_caught() {
  local i st
  for i in $(seq 1 "${2:-60}"); do
    st=$(sink_field "$1" '"\(.state) \(.in_active_segment // false) \(.lag_records // 0)"')
    [[ "$st" == "connected true 0" ]] && return 0
    sleep 1
  done
  echo "  ($1 did not catch up within ${2:-60}s: '$st')"
  return 1
}

# The export sequence, read from what the secondary receiver holds.
exports() { rcv_ctl secondary "__records${1:+?since=$1}" | jq -c 'select(.sd.id=="audit-export" and (.errors|index("sd")|not))'; }
xseq_epochs() { exports | jq -s -r '[.[].sd.xseq_epoch] | unique | map(tostring) | join(" ")'; }
xseq_epoch()  { exports | jq -s -r '[.[].sd.xseq_epoch] | max // 0'; }
xseq_max()    { exports | jq -s -r "[.[] | select(.sd.xseq_epoch==$1) | .sd.xseq] | max // 0"; }
xseq_min()    { exports | jq -s -r "[.[] | select(.sd.xseq_epoch==$1) | .sd.xseq] | min // 0"; }
xseq_n()      { exports | jq -s -r "[.[] | select(.sd.xseq_epoch==$1)] | length"; }
# A number that arrived twice under one epoch, whatever it carried.
xseq_reuse()  { exports | jq -s -r '[.[] | "\(.sd.xseq_epoch)/\(.sd.xseq)"] | group_by(.) | map(select(length>1)) | length'; }
# first_export <since index> → "epoch xseq" of the first export after it
first_export() { exports "$1" | head -n1 | jq -r '"\(.sd.xseq_epoch) \(.sd.xseq)"'; }

# ── the sinks ───────────────────────────────────────────────────────────────
sec_body() { printf '{"address":"%s:6514","ca_bundle_path":"%s","server_name":"%s","enterprise_number":%s,"filter":{"streams":["mgmt"]}}' "$SIEM2" "$SINK_CA" "$SIEM2" "$PEN"; }
compliance_up() {
  api POST /audit/sink "${CT[@]}" \
    -d "{\"enabled\":true,\"address\":\"$SIEM1:6514\",\"ca_bundle_path\":\"$SINK_CA\",\"server_name\":\"$SIEM1\"}"
  [[ "$RESP_CODE" == 204 ]]
}
secondary_up() {
  api PUT /audit/sinks/secondary "${CT[@]}" -d "$(sec_body)"
  [[ "$RESP_CODE" == 204 ]]
}
sinks_up() {
  compliance_up || { echo "  (POST /audit/sink answered $RESP_CODE)"; return 1; }
  secondary_up  || { echo "  (PUT /audit/sinks/secondary answered $RESP_CODE)"; return 1; }
}
# The sinks are in the configuration document the gateway writes through to
# disk a quiet period after a change, and replays when it starts.
# snap → the configuration document as the gateway captures it now
snap() { docker exec llb1 curl -s -m 10 "$API/config/snapshot"; }
# persisted <jq path> → read from the document the gateway wrote to disk
persisted() { sudo cat llb1_config/snapshot.json 2>/dev/null | jq -c "$1" 2>/dev/null; }
# wait_persisted <jq path> <value> [seconds] → the write-through got there
wait_persisted() {
  local i
  for i in $(seq 1 "${3:-30}"); do
    [[ "$(persisted "$1")" == "$2" ]] && return 0
    sleep 1
  done
  return 1
}

# ── traffic ─────────────────────────────────────────────────────────────────
# drive <n> → n audited management changes, an intent and a result each on
# the management stream. The knob is how many segments one prune pass may
# remove, flipped between two values: a real change every time, and one
# that moves nothing this scenario measures.
DRIVE_FAILED=0
DRIVE_STRICT=1
drive() {
  local i pol
  for i in $(seq 1 "$1"); do
    api GET /audit/policy
    pol=$(printf '%s' "$RESP_BODY" | jq -c '.retention_max_prune_per_pass = (if .retention_max_prune_per_pass == 2 then 3 else 2 end)' 2>/dev/null)
    api POST /audit/policy "${CT[@]}" -d "$pol"
    if [[ "$RESP_CODE" != 204 && "$DRIVE_STRICT" == 1 ]]; then
      DRIVE_FAILED=$((DRIVE_FAILED + 1))
      echo "  (a driven policy change answered $RESP_CODE: ${RESP_BODY:0:160})"
    fi
  done
}

# ── the gateway process (the audit-mgmt pattern) ────────────────────────────
gw_wait_dead() {
  local i
  for i in $(seq 1 "$1"); do
    docker exec llb1 pgrep -f "$GW_BIN" >/dev/null 2>&1 || return 0
    sleep 1
  done
  return 1
}
gw_stop() { # orderly: the tailers save their cursors, then the writer closes
  docker exec llb1 pkill -f "$GW_BIN" >/dev/null 2>&1
  gw_wait_dead 20 && return 0
  echo "  (the gateway survived SIGTERM for 20s; escalating)"
  docker exec llb1 pkill -9 -f "$GW_BIN" >/dev/null 2>&1
  gw_wait_dead 10 && return 0
  echo "  FATAL: the old gateway process would not die"; return 1
}
gw_crash() { # SIGKILL only: nothing is saved on the way out
  docker exec llb1 pkill -9 -f "$GW_BIN" >/dev/null 2>&1
  gw_wait_dead 10
}
gw_start() { # gw_start [env assignments...] — the flags come from .state
  local i ifc envs="$*"
  docker exec llb1 ip link del llb0 >/dev/null 2>&1
  for ifc in $(docker exec llb1 ip -o link show | awk -F': ' '{print $2}' | cut -d'@' -f1); do
    [ "$ifc" = "lo" ] && continue
    docker exec llb1 ip link set dev "$ifc" xdpgeneric off >/dev/null 2>&1
    docker exec llb1 tc qdisc del dev "$ifc" clsact >/dev/null 2>&1
  done
  docker exec llb1 umount /opt/loxilb/dp >/dev/null 2>&1
  # Appending, not truncating: the fault arms read their proof out of it.
  docker exec -d llb1 bash -c "ulimit -l unlimited; $envs $GW_BIN -p --loglevel debug $GW_ARGS >> /tmp/loxilb.out 2>> /tmp/loxilb.err"
  for i in $(seq 1 40); do
    docker exec llb1 curl -sf -m 3 "$API/version" >/dev/null 2>&1 && break
    sleep 2
  done
  if ! docker exec llb1 curl -sf -m 3 "$API/version" >/dev/null 2>&1; then
    echo "  the gateway did not come back; stderr tail:"
    docker exec llb1 tail -20 /tmp/loxilb.err
    return 1
  fi
  for i in $(seq 1 40); do
    if ! docker exec llb1 curl -s -m 3 -X POST "$API/config/loadbalancer" "${CT[@]}" -d '{}' \
         | grep -qE 'boot config replay settles|frozen while a snapshot restore is in progress'; then
      BOOT=$(astatus | jq -r '.boot_id')
      return 0
    fi
    sleep 2
  done
  echo "  boot config replay never settled"; return 1
}
fatal() { echo "  FATAL: $1"; echo "SCENARIO-audit-sink [FAILED]"; exit 1; }

# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "Preflight"
echo "════════════════════════════════════════════════════════════════════════"
ST=$(astatus)
chk PRE-1 "the trail is available" true "$(printf '%s' "$ST" | jq -r '.available')"
chk PRE-2 "the writer is running"  true "$(printf '%s' "$ST" | jq -r '.running')"
BOOT=$(printf '%s' "$ST" | jq -r '.boot_id')
chk_nonempty PRE-3 "the status names the boot" "$BOOT"
# Before any sink is configured nothing may have arrived anywhere: every
# count below is of what this scenario caused.
chk PRE-4 "no sink is configured and the status says so" "false 0" \
  "$(printf '%s' "$ST" | jq -r '"\(.compliance_sink // false) \(.sinks | length)"')"
chk PRE-5 "the receivers have been sent nothing" "0 0 0" \
  "$(rcv_ctl compliance __probe) $(rcv_ctl decoy __probe) $(rcv_ctl secondary __probe)"

BUILD_TAGS=$(docker exec llb1 sh -c "$GW_BIN --version 2>/dev/null" | awk -F': ' '/build tags/ {print $2}')
FAULTS_AVAILABLE=no
case "$BUILD_TAGS" in
  *audit_faults*) FAULTS_AVAILABLE=yes ;;
esac
echo "  [PRE-6] gateway build tags = '${BUILD_TAGS:-none}', fault points available = $FAULTS_AVAILABLE"

# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "ST: what cannot be a secondary sink is refused"
echo "════════════════════════════════════════════════════════════════════════"
# Before any sink exists, so that "installed nothing" is read off an empty
# list and not off a list that happens to look the same.
api PUT /audit/sinks/compliance "${CT[@]}" -d "$(sec_body)"
chk ST-1a "the name of the compliance sink is refused for a secondary" 400 "$RESP_CODE"
api PUT /audit/sinks/Bad.Name "${CT[@]}" -d "$(sec_body)"
chk ST-1b "a name that could not be a file name is refused" 400 "$RESP_CODE"
api PUT /audit/sinks/nopen "${CT[@]}" -d "$(sec_body | jq -c 'del(.enterprise_number)')"
chk ST-1c "a secondary with no private enterprise number is refused" 400 "$RESP_CODE"
api PUT /audit/sinks/noca "${CT[@]}" -d "$(sec_body | jq -c 'del(.ca_bundle_path)')"
chk ST-1d "a secondary with no trust anchor is refused" 400 "$RESP_CODE"
api PUT /audit/sinks/badfilter "${CT[@]}" -d "$(sec_body | jq -c '.filter.streams = ["nosuchstream"]')"
chk ST-1e "a filter naming a stream that does not exist is refused" 400 "$RESP_CODE"
chk ST-1f "none of the refusals installed a sink" 0 "$(astatus | jq -r '.sinks | length')"
for n in nopen noca badfilter; do
  api GET "/audit/sinks/$n"
  chk ST-1g "the refused sink '$n' cannot be read back" 404 "$RESP_CODE"
done
api DELETE /audit/sinks/nopen
chk ST-1h "removing a sink that does not exist says so" 404 "$RESP_CODE"

# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "TR: the session, the framing and the bytes"
echo "════════════════════════════════════════════════════════════════════════"
compliance_up; chk TR-1a "the compliance sink is accepted" 204 "$RESP_CODE"
secondary_up;  chk TR-1b "the secondary sink is accepted"  204 "$RESP_CODE"
drive 5
wait_caught compliance 60; chk TR-1c "the compliance sink caught up with the trail" 0 $?
wait_caught secondary 60;  chk TR-1d "the secondary sink caught up with the trail"  0 $?
SEQH=$(astatus | jq -r '.seq_high')
wait_arrived compliance "$BOOT" "$SEQH" 30 || true

chk_ge TR-2a "the compliance receiver holds a verified session" 1 "$(rcv_stat compliance '.connections')"
chk_ge TR-2b "and frames arrived over it" 10 "$(rcv_stat compliance '.frames')"
for role in compliance secondary; do
  chk TR-3a "[$role] every frame was octet-counted, parsed as RFC 5424 and carried the envelope" "0 0 0 0" \
    "$(rcv_stat $role '"\(.framing_errors) \(.header_errors) \(.json_errors) \(.oversized)"')"
  chk TR-3b "[$role] HOSTNAME is the instance, APP-NAME loxilb-igw, MSGID the stream" 0 "$(rcv_stat $role '.header_mismatch')"
  chk TR-3c "[$role] no STRUCTURED-DATA the receiver does not know, none under another number" 0 "$(rcv_stat $role '.sd_errors')"
done

# Byte identity. The receiver's side is read first: a record that arrived
# is already in the trail, and the reverse is not true.
RCV_H=$(rcv_ctl compliance __records | jq -r 'select(.seq!=null) | "\(.boot_id)/\(.seq) \(.msg_sha256)"' | sort -u)
LOC_H=$(trail_raw | python3 -c '
import sys, hashlib, json
for raw in sys.stdin.buffer:
    line = raw.rstrip(b"\n")
    try:
        o = json.loads(line)
    except ValueError:
        continue
    if isinstance(o, dict) and "event_type" in o:
        print("%s/%s %s" % (o.get("boot_id"), o.get("seq"), hashlib.sha256(line).hexdigest()))
' | sort -u)
chk_ge TR-4a "records to compare byte for byte" 10 "$(printf '%s\n' "$RCV_H" | grep -c .)"
chk    TR-4b "every MSG that arrived is a local record's bytes, unchanged (sha256)" 0 \
  "$(comm -23 <(printf '%s\n' "$RCV_H") <(printf '%s\n' "$LOC_H") | grep -c .)"
missing_at compliance "$BOOT" 0 "$SEQH"
chk    TR-4c "the compliance sink received every record of the boot so far" 0 "$MISSING"
chk_ge TR-4d "and there were records to receive" 10 "$LOCAL_N"

CONN=$(records '.event_type=="sys.sink.connect" and .detail.resource=="audit_sink:compliance"' | head -n1)
chk_nonempty TR-5a "the trail records the session" "$(printf '%s' "$CONN" | jq -r '.event_type // empty')"
chk_has TR-5b "naming the certificate the receiver presented" "audit-sink-receiver-$SIEM1" "$(printf '%s' "$CONN" | jq -r '.detail.peer_subject // empty')"
chk_nonempty TR-5c "and until when it is valid" "$(printf '%s' "$CONN" | jq -r '.detail.cert_not_after // empty')"

# The wrong-CA control. Same host, same receiver program, same sink code;
# the one thing that differs is which authority signed the certificate.
api PUT /audit/sinks/decoy "${CT[@]}" \
  -d "{\"address\":\"$SIEM1:6516\",\"ca_bundle_path\":\"$SINK_CA\",\"server_name\":\"$SIEM1\",\"enterprise_number\":$PEN}"
chk TR-6a "a sink pointed at the decoy is accepted as configuration" 204 "$RESP_CODE"
for i in $(seq 1 30); do
  [[ "$(rcv_stat decoy '[.tls_peers[] | select(.handshake_error)] | length')" -ge 1 ]] && break
  sleep 1
done
chk_ge TR-6b "the gateway did attempt the decoy" 1 "$(rcv_stat decoy '[.tls_peers[] | select(.handshake_error)] | length')"
chk    TR-6c "and no session was ever established to it" 0 "$(rcv_stat decoy '.connections')"
chk    TR-6d "so not one frame reached it" 0 "$(rcv_stat decoy '.frames')"
chk_ne TR-6e "the sink does not report itself connected" connected "$(named decoy '.state')"
chk_has TR-6f "and says why" certificate "$(named decoy '.last_error // empty')"
wait_record '.event_type=="sys.sink.disconnect" and .detail.resource=="audit_sink:decoy"' 20
chk    TR-6g "the trail records that the decoy could not be reached" 0 $?
api DELETE /audit/sinks/decoy
chk TR-6h "the decoy sink is removed" 204 "$RESP_CODE"
api GET /audit/sinks/decoy
chk TR-6i "and can no longer be read back" 404 "$RESP_CODE"

# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "ST: the status reports the sinks"
echo "════════════════════════════════════════════════════════════════════════"
wait_caught compliance 30; wait_caught secondary 30
ST=$(astatus)
chk ST-2a "the status says a compliance sink is configured" true "$(printf '%s' "$ST" | jq -r '.compliance_sink')"
chk ST-2b "the sinks are listed, the compliance sink first" "compliance secondary" "$(printf '%s' "$ST" | jq -r '[.sinks[].name] | join(" ")')"
chk ST-2c "only the compliance sink is marked as one" "true false" "$(printf '%s' "$ST" | jq -r '[.sinks[] | (.compliance // false)] | map(tostring) | join(" ")')"
chk ST-2d "both report a session" "connected connected" "$(printf '%s' "$ST" | jq -r '[.sinks[].state] | join(" ")')"
SEG=$(printf '%s' "$ST" | jq -r '.segment.uuid')
chk ST-2e "a sink that has caught up names the segment being written" "$SEG $SEG" "$(printf '%s' "$ST" | jq -r '[.sinks[].cursor.segment_uuid] | join(" ")')"
api GET /audit/sinks/secondary
chk ST-3a "the secondary sink reads back" 200 "$RESP_CODE"
chk ST-3b "with its receiver, its number and its filter" "$SIEM2:6514 $PEN mgmt" "$(json '"\(.address) \(.enterprise_number) \(.filter.streams | join(","))"')"
chk ST-3c "no certificate material is served by the read" 0 "$(printf '%s' "$RESP_BODY" | grep -c 'BEGIN CERTIFICATE')"
chk_ge ST-3d "the change is on the trail, naming the receiver" 1 \
  "$(count ".event_type==\"mgmt.audit.sink\" and .phase==\"result\" and .outcome.ok==true and .detail.endpoint==\"$SIEM2:6514\"")"
# The same on the scrape, one series per sink.
chk    MT-1a "the scrape says the compliance sink has its receiver" 1 "$(metric_int loxilb_audit_sink_connected 'sink="compliance"')"
chk    MT-1b "and the secondary sink" 1 "$(metric_int loxilb_audit_sink_connected 'sink="secondary"')"
metric_wait loxilb_audit_sink_cursor_lag_bytes 'sink="compliance"' 0 20
chk    MT-1c "nothing of the trail is behind a sink that caught up" 0 $?
chk_ge MT-1d "the secondary sink's exported count is what its receiver was sent" "$(rcv_stat secondary '.frames')" "$(metric_int loxilb_audit_sink_records_exported_total 'sink="secondary"')"

# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "T23 arm 1: a filtered sink numbers what it sends"
echo "════════════════════════════════════════════════════════════════════════"
E1=$(xseq_epoch)
chk_ge T23-1a "the secondary receiver holds exported records" 10 "$(xseq_n "$E1")"
chk    T23-1b "every frame it holds is an export under the configured number" "$(rcv_stat secondary '.frames')" "$(rcv_stat secondary '.exports')"
chk    T23-1c "none of them is off the management stream" 0 "$(rcv_ctl secondary __records | jq -c 'select(.msgid!="mgmt")' | grep -c .)"
# The control for 1c: the records the filter withholds do exist, and the
# unfiltered sink received them over the same interval.
chk_ge T23-1d "the compliance receiver holds the audit_system records the filter withholds" 1 \
  "$(rcv_ctl compliance __records | jq -c 'select(.msgid=="audit_system")' | grep -c .)"
chk_ge T23-1e "and the secondary sink counts what its filter kept from it" 1 "$(named secondary '.filtered // 0')"
chk    T23-1f "one epoch so far" 1 "$(xseq_epochs | wc -w | tr -d ' ')"
chk    T23-1g "the sequence starts at 1" 1 "$(xseq_min "$E1")"
chk    T23-1h "and is contiguous: the highest number is the count" "$(xseq_n "$E1")" "$(xseq_max "$E1")"
chk    T23-1i "no number arrived twice" 0 "$(xseq_reuse)"
chk    T23-1j "the compliance sink sends no export element: seq is its sequence" 0 "$(rcv_stat compliance '.exports')"

# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "T5 (a): the receiver is down, then back"
echo "════════════════════════════════════════════════════════════════════════"
S0=$(astatus | jq -r '.seq_high')
rcv_stop compliance || code=1
drive 10
for i in $(seq 1 40); do
  [[ "$(sink_field compliance '.state')" == disconnected ]] && break
  sleep 1
done
chk T5-1a "the sink reports the loss of its receiver" disconnected "$(sink_field compliance '.state')"
chk    MT-2a "the scrape says the compliance sink has no receiver" 0 "$(metric_int loxilb_audit_sink_connected 'sink="compliance"')"
chk_ge MT-2b "its failed submissions are counted" 1 "$(metric_int loxilb_audit_sink_export_failures_total 'sink="compliance"')"
chk_ge MT-2c "bytes of the trail are behind it" 1 "$(metric_int loxilb_audit_sink_cursor_lag_bytes 'sink="compliance"')"
sleep 2
chk_ge MT-2d "and the oldest record it could not send has an age" 1 "$(metric_int loxilb_audit_sink_cursor_lag_seconds 'sink="compliance"')"
chk    MT-2e "the other sink is not touched by that" 1 "$(metric_int loxilb_audit_sink_connected 'sink="secondary"')"
S1=$(astatus | jq -r '.seq_high')
# The receiver that comes back remembers nothing, so the claim is about the
# range written during the outage, not about holes counted from 1.
rcv_start compliance || code=1
wait_arrived compliance "$BOOT" "$S1" 120
chk    T5-1b "the last record written during the outage arrived after it" 0 $?
missing_at compliance "$BOOT" "$S0" "$S1"
chk    T5-1c "and so did every record written during it" 0 "$MISSING"
chk_ge T5-1d "there were records written during it" 20 "$LOCAL_N"
DISC=$(records ".event_type==\"sys.sink.disconnect\" and .detail.resource==\"audit_sink:compliance\" and .boot_id==\"$BOOT\" and .seq>$S0" | head -n1)
DSEQ=$(printf '%s' "$DISC" | jq -r '.seq // 0')
chk_gt T5-1e "the trail records the disconnect" "$S0" "$DSEQ"
chk    T5-1f "and how far back the sink will go when it reconnects" 64 "$(printf '%s' "$DISC" | jq -r '.detail.reconnect_window_records')"
wait_record ".event_type==\"sys.sink.connect\" and .detail.resource==\"audit_sink:compliance\" and .boot_id==\"$BOOT\" and .seq>$DSEQ" 30
chk    T5-1g "followed by the reconnect: a pair, not a silent gap" 0 $?
wait_caught compliance 60 || code=1
metric_wait loxilb_audit_sink_cursor_lag_bytes 'sink="compliance"' 0 20
chk    MT-2f "with the receiver back nothing is behind the sink" 0 $?
chk    MT-2g "and it holds no unsent record" 0 "$(metric_int loxilb_audit_sink_cursor_lag_seconds 'sink="compliance"')"

# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "T5 (b): the gateway restarts in the middle of the outage"
echo "════════════════════════════════════════════════════════════════════════"
wait_caught secondary 30
P0=$(astatus | jq -r '.seq_high')
BOOT_PREV=$BOOT
rcv_stop compliance || code=1
drive 5
gw_stop  || fatal "the gateway could not be stopped"
P_END=$(trail | jq -s "[.[] | select(.boot_id==\"$BOOT_PREV\") | .seq] | max")
gw_start || fatal "the gateway did not come back"
chk_ne T5-2a "a new boot" "$BOOT_PREV" "$BOOT"
rcv_start compliance || code=1
sinks_up; chk T5-2b "the sinks are configured again on the new boot" 0 $?
wait_arrived compliance "$BOOT_PREV" "$P_END" 120
chk    T5-2c "the previous boot's last record arrived under the previous boot" 0 $?
missing_at compliance "$BOOT_PREV" "$P0" "$P_END"
chk    T5-2d "and so did every record that boot wrote during the outage" 0 "$MISSING"
chk_ge T5-2e "there were records that boot wrote during it" 10 "$LOCAL_N"
wait_caught compliance 60; chk T5-2f "the sink goes on into the new boot's records" 0 $?
chk_ge T5-2g "which arrive under the new boot" 1 "$(rcv_seqs compliance "$BOOT" | grep -c .)"

# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "T6: the segment is sealed while the sink is behind"
echo "════════════════════════════════════════════════════════════════════════"
wait_caught compliance 30
R0=$(astatus | jq -r '.seq_high')
rcv_ctl compliance '__slow?bps=3000' >/dev/null
drive 8
api POST /audit/rotate "${CT[@]}" -d '{}'; chk T6-1a "the first seal is accepted" 200 "$RESP_CODE"
drive 8
api POST /audit/rotate "${CT[@]}" -d '{}'; chk T6-1b "the second seal is accepted" 200 "$RESP_CODE"
drive 3
R1=$(astatus | jq -r '.seq_high')
chk_ge T6-1c "the receiver was behind when the segments were sealed" 1 "$(( R1 - $(rcv_seqs compliance "$BOOT" | sort -n | tail -n1) ))"
rcv_ctl compliance '__slow?bps=0' >/dev/null
wait_arrived compliance "$BOOT" "$R1" 120
chk    T6-2a "the last record arrived" 0 $?
missing_at compliance "$BOOT" "$R0" "$R1"
chk    T6-2b "nothing was skipped at a segment boundary" 0 "$MISSING"
chk_ge T6-2c "the interval spans three segments" 3 \
  "$(trail | jq -r "select(.boot_id==\"$BOOT\" and .seq>$R0 and .seq<=$R1) | .segment_uuid" | sort -u | grep -c .)"
chk    T6-2d "the records arrived in the order they were written" true \
  "$(rcv_ctl compliance __records | jq -s "[.[] | select(.boot_id==\"$BOOT\" and .seq>$R0 and .seq<=$R1) | .seq] | . == sort")"
wait_caught compliance 60; chk T6-2e "the sink's cursor reached the segment now being written" 0 $?

# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "T23 arm 2: the sequence across a clean restart and across a kill"
echo "════════════════════════════════════════════════════════════════════════"
# restart_secondary <stop|crash> [command run inside llb1 while it is down]
# → RMAX and EPOCH as the receiver held them before, FIRST = "epoch xseq" of
#   the first export after.
restart_secondary() {
  wait_caught secondary 60 || code=1
  sleep 1
  EPOCH=$(xseq_epoch); RMAX=$(xseq_max "$EPOCH"); N0=$(rcv_ctl secondary __probe)
  if [[ "$1" == crash ]]; then gw_crash; else gw_stop; fi || fatal "the gateway could not be stopped"
  [[ -n "${2:-}" ]] && docker exec llb1 sh -c "$2"
  gw_start || fatal "the gateway did not come back"
  sinks_up || code=1
  drive 2
  wait_caught secondary 90 || code=1
  sleep 1
  FIRST=$(first_export "$N0")
}

restart_secondary stop
chk_ge T23-2a "the receiver held a sequence before the restart" 1 "$RMAX"
chk    T23-2b "after a clean stop the sequence continues at the next number, in the same epoch" "$EPOCH $((RMAX + 1))" "$FIRST"
chk    T23-2c "no number arrived twice" 0 "$(xseq_reuse)"

restart_secondary crash
chk    T23-2d "after a kill the epoch is the same" "$EPOCH" "${FIRST% *}"
chk_gt T23-2e "the sequence continues above every number already sent" "$RMAX" "${FIRST#* }"
chk_le T23-2f "and the numbers it gave up are at most one reserved block" "$XSEQ_BLOCK" "$(( ${FIRST#* } - RMAX - 1 ))"
chk    T23-2g "no number arrived twice" 0 "$(xseq_reuse)"

# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "T23 arm 3: the cursor file is cut short, or gone"
echo "════════════════════════════════════════════════════════════════════════"
chk T23-3a "the sink's two state files are where the scenario reaches for them" "2" \
  "$(docker exec llb1 sh -c "ls $STATE_DIR/secondary.cursor $STATE_DIR/secondary.xseq 2>/dev/null | wc -l" | tr -d ' ')"

restart_secondary stop "truncate -s 7 $STATE_DIR/secondary.cursor"
RESET=$(records ".event_type==\"sys.sink.cursor_reset\" and .detail.resource==\"audit_sink:secondary\" and .boot_id==\"$BOOT\"" | head -n1)
chk_nonempty T23-3b "a cursor file cut short is reported on the trail, not passed over" "$(printf '%s' "$RESET" | jq -r '.event_type // empty')"
chk    T23-3c "the place was taken from the reservation" reservation "$(printf '%s' "$RESET" | jq -r '.detail.method // empty')"
chk    T23-3d "the record names the epoch it continues under" "$EPOCH" "$(printf '%s' "$RESET" | jq -r '.detail.new_cursor.xseq_epoch // empty')"
chk    T23-3e "and the exports continue in that epoch" "$EPOCH" "${FIRST% *}"
chk_gt T23-3f "above every number already sent" "$RMAX" "${FIRST#* }"
chk    T23-3g "no number arrived twice" 0 "$(xseq_reuse)"

restart_secondary stop "rm -f $STATE_DIR/secondary.cursor"
chk_ge T23-3h "a missing cursor file beside a readable reservation is reported the same way" 1 \
  "$(count ".event_type==\"sys.sink.cursor_reset\" and .detail.resource==\"audit_sink:secondary\" and .boot_id==\"$BOOT\" and .detail.method==\"reservation\"")"
chk    T23-3i "and the exports continue in the same epoch" "$EPOCH" "${FIRST% *}"
chk_gt T23-3j "above every number already sent" "$RMAX" "${FIRST#* }"
chk    T23-3k "no number arrived twice" 0 "$(xseq_reuse)"

# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "T23 arm 4: the whole of the sink's state is gone"
echo "════════════════════════════════════════════════════════════════════════"
# An epoch is taken from the clock in seconds. The pause keeps the new one
# from being asked for inside the second the old one was made in.
restart_secondary stop "sleep 2; rm -f $STATE_DIR/secondary.cursor $STATE_DIR/secondary.xseq"
E_NEW=${FIRST% *}
chk_gt T23-4a "with nothing left to prove which numbers were used, the epoch is a greater one" "$EPOCH" "$E_NEW"
chk    T23-4b "and the sequence starts at 1 under it" 1 "${FIRST#* }"
chk    T23-4c "contiguous under the new epoch: the highest number is the count" "$(xseq_n "$E_NEW")" "$(xseq_max "$E_NEW")"
chk    T23-4d "no number arrived twice under any epoch" 0 "$(xseq_reuse)"

# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "T23 arm 5: a crash between two steps of the cursor protocol"
echo "════════════════════════════════════════════════════════════════════════"
# fault_arm <id> <point> <frames expected from the stopped boot: yes|no>
#
# The sink is removed and management records are written while it is gone,
# so the boot that carries the fault finds records to send the moment the
# sink is configured: the crash then falls after a submission and before
# the cursor that would have recorded it, which is the interval the arm is
# about. Removing a sink keeps its state, so nothing is reset by this.
fault_arm() {
  local id=$1 point=$2 sent=$3 before after n_before
  wait_caught secondary 60 || code=1
  api DELETE /audit/sinks/secondary
  chk "$id-a" "the secondary sink is removed, its state kept" 204 "$RESP_CODE"
  # A boot replays the sinks of the document on disk, and the fault point
  # is in every sink's cursor. So the boot that carries the fault starts
  # with no sink: the compliance sink is ended as well, both removals are
  # on disk before the gateway stops, and it is the request below that
  # brings the secondary sink, and the fault, into play.
  api POST /audit/sink "${CT[@]}" -d '{"enabled":false}'
  chk "$id-o" "the compliance sink is ended for the faulty boot" 204 "$RESP_CODE"
  wait_persisted '[.domains.auditsink[]?.name]' '[]' 30
  chk "$id-p" "the document on disk has no sink" 0 $?
  drive 3
  sleep 1
  EPOCH=$(xseq_epoch); RMAX=$(xseq_max "$EPOCH"); N0=$(rcv_ctl secondary __probe)
  before=$(docker exec llb1 grep -c "fault point $point: exiting" /tmp/loxilb.err 2>/dev/null); before=${before:-0}
  gw_stop || fatal "the gateway could not be stopped"
  gw_start "LOXILB_AUDIT_FAULT=$point" || fatal "the gateway did not come up with $point armed"
  secondary_up
  chk "$id-b" "the sink is configured on the boot that carries the fault" 204 "$RESP_CODE"
  gw_wait_dead 40
  chk "$id-c" "the gateway process ended" 0 $?
  after=$(docker exec llb1 grep -c "fault point $point: exiting" /tmp/loxilb.err 2>/dev/null); after=${after:-0}
  chk "$id-d" "and it ended at $point: the fault fired, once" 1 "$((after - before))"
  n_before=$(exports "$N0" | grep -c .)
  if [[ "$sent" == yes ]]; then
    chk_ge "$id-e" "records were sent under their numbers before the crash, and no cursor saved behind them" 1 "$n_before"
  else
    chk    "$id-e" "the crash fell before the first submission" 0 "$n_before"
  fi
  gw_start || fatal "the gateway did not come back after $point"
  sinks_up || code=1
  drive 2
  wait_caught secondary 90 || code=1
  sleep 1
  chk    "$id-f" "the epoch did not change" "$EPOCH" "$(xseq_epoch)"
  chk_gt "$id-g" "exports arrived after the crash" "$n_before" "$(exports "$N0" | grep -c .)"
  chk_gt "$id-h" "above every number sent before it" "$RMAX" "$(exports "$N0" | jq -s '[.[].sd.xseq] | min // 0')"
  chk    "$id-i" "and no number arrived twice" 0 "$(xseq_reuse)"
}

if [[ "$FAULTS_AVAILABLE" != yes ]]; then
  bad T23-5 "the fault points are compiled in" \
    "this image has build tags '${BUILD_TAGS:-none}'; rebuild with HAVE_AUDIT_FAULTS=1 (a crash cannot be placed between two steps of the cursor protocol without them)"
else
  fault_arm T23-5w sink.cursor.before_write yes
  fault_arm T23-5r sink.cursor.after_rename no
fi
chk T23-6 "over the whole run the secondary receiver never saw a number twice" 0 "$(rcv_stat secondary '[.xseq[].reuse_count] | add // 0')"

# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "T16: a segment pruned before a sink had it"
echo "════════════════════════════════════════════════════════════════════════"
# The secondary's receiver is taken away and the trail is given a quota of
# one small segment, so segments sealed from here on are pruned while the
# secondary has not been sent them. The compliance sink keeps up, which is
# the other half of the record: one sink named as having it, one as not.
#
# Segments sealed before the quota was lowered keep the terms they were
# written under; they are not what is pruned here.
wait_caught compliance 60 || code=1
wait_caught secondary 60 || code=1
api GET /audit/policy
POL0=$RESP_BODY
LOST0=$(count '.event_type=="sys.segment.lost_to_retention"')
rcv_stop secondary || code=1
api POST /audit/policy "${CT[@]}" -d "$(printf '%s' "$POL0" | jq -c '.max_segment_bytes = 4096 | .retention_max_bytes = 4096')"
chk T16-1a "a quota of one small segment is accepted" 204 "$RESP_CODE"
drive 20
# Prune passes run with the writer's heartbeat, every 30 seconds. The
# records are captured the moment they appear: under this quota the segment
# that holds them is itself pruned a few passes later.
LOST=""; PRUNE=""
for i in $(seq 1 60); do
  T=$(trail)
  LOST=$(printf '%s\n' "$T" | jq -c 'select(.event_type=="sys.segment.lost_to_retention")' | tail -n +$((LOST0 + 1)) | head -n1)
  if [[ -n "$LOST" ]]; then
    RES=$(printf '%s' "$LOST" | jq -r '.detail.resource')
    PRUNE=$(printf '%s\n' "$T" | jq -c "select(.event_type==\"sys.segment.prune\" and .detail.resource==\"$RES\")" | head -n1)
    [[ -n "$PRUNE" ]] && break
  fi
  sleep 2
done
api POST /audit/policy "${CT[@]}" -d "$POL0"
chk T16-1b "the policy is put back" 204 "$RESP_CODE"

chk_nonempty T16-2a "the loss is on the trail" "$(printf '%s' "$LOST" | jq -r '.event_type // empty')"
chk    T16-2b "naming the sink that had not been sent the segment" '["secondary"]' "$(printf '%s' "$LOST" | jq -c '.detail.sinks_pending')"
LFROM=$(printf '%s' "$LOST" | jq -r '.detail.seq_from // 0'); LTO=$(printf '%s' "$LOST" | jq -r '.detail.seq_to // 0')
chk_ge T16-2c "and the range of records a receiver will find missing: its first" 1 "$LFROM"
chk_ge T16-2d "and its last" "$LFROM" "$LTO"
chk_nonempty T16-2e "the prune of that segment is on the trail" "$(printf '%s' "$PRUNE" | jq -r '.event_type // empty')"
chk_gt T16-2f "after the record of the loss, never before it" "$(printf '%s' "$LOST" | jq -r '.seq // 0')" "$(printf '%s' "$PRUNE" | jq -r '.seq // 0')"
chk    T16-2g "naming the sink that did have it" '["compliance"]' "$(printf '%s' "$PRUNE" | jq -c '.detail.exported_to')"
# What the prune record claims is checked at the receiver it names.
LBOOT=$(printf '%s' "$LOST" | jq -r '.boot_id')
chk    T16-2h "the compliance receiver does hold every record of that range" "$((LTO - LFROM + 1))" \
  "$(rcv_seqs compliance "$LBOOT" | awk -v a="$LFROM" -v b="$LTO" '$1>=a && $1<=b' | grep -c .)"
chk_ge T16-2i "the status counts the pruned segments" 1 "$(astatus | jq -r '.pruned // 0')"
# The pass that prunes also writes, and what it writes can seal the segment
# the compliance sink is reading. A sink that kept up is never called behind.
AGAINST=$(printf '%s\n' "$T" | jq -c 'select(.event_type=="sys.segment.lost_to_retention" and (.detail.sinks_pending | index("compliance")))')
chk    T16-2j "no loss is recorded against the sink that kept up" 0 "$(printf '%s' "$AGAINST" | grep -c .)"
# A red row here is either a loss that did not happen or a sink that did
# fall behind; what the receiver holds of each range tells the two apart.
while IFS= read -r rec; do
  [[ -z "$rec" ]] && continue
  a=$(printf '%s' "$rec" | jq -r '.detail.seq_from // 0'); b=$(printf '%s' "$rec" | jq -r '.detail.seq_to // 0')
  held=$(rcv_seqs compliance "$(printf '%s' "$rec" | jq -r '.boot_id')" | awk -v a="$a" -v b="$b" '$1>=a && $1<=b' | grep -c .)
  echo "    loss at seq $(printf '%s' "$rec" | jq -r '.seq') names compliance for $a..$b; its receiver holds $held of $((b - a + 1)): $(printf '%s' "$rec" | jq -c '.detail')"
done <<< "$AGAINST"

rcv_start secondary || code=1
wait_caught secondary 120; chk T16-3a "with its receiver back the secondary sink catches up" 0 $?
chk_ge T16-3b "and reports that the segment it was in was removed under it" 1 "$(named secondary '.lag_drops // 0')"
chk    T16-3c "the receiver that came back saw no number twice" 0 "$(xseq_reuse)"
chk_ge MT-3a "the scrape counts the records lost to retention" "$((LTO - LFROM + 1))" "$(metric_int loxilb_audit_records_lost_to_retention_total)"
chk    MT-3b "and the removals under the secondary sink, as the sink reports them" "$(named secondary '.lag_drops // 0')" "$(metric_int loxilb_audit_sink_lag_drops_total 'sink="secondary"')"

# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "PS: the sinks are part of the persisted configuration"
echo "════════════════════════════════════════════════════════════════════════"
compliance_cfg() { docker exec llb1 curl -s -m 5 "$API/audit/sink" | jq -r '"\(.enabled) \(.address) \(.ca_bundle_path)"'; }
secondary_cfg()  { named secondary '"\(.address) \(.enterprise_number) \(.filter.streams | tojson)"'; }
SEC_CFG="$SIEM2:6514 $PEN [\"mgmt\"]"
# restore <document> → RESP_CODE, RESP_BODY of a commit restore of the sinks
restore() {
  local out
  out=$(printf '%s' "$1" | docker exec -i llb1 curl -s -m 60 -w '\n%{http_code}' -X POST \
        "$API/config/restore?mode=commit&components=auditsink" "${CT[@]}" --data-binary @-)
  RESP_CODE=${out##*$'\n'}
  RESP_BODY=${out%$'\n'*}
}

sinks_up || code=1
wait_caught compliance 60 || code=1
wait_caught secondary 60 || code=1
# No persist is asked for: the write-through follows a sink change.
wait_persisted '[.domains.auditsink[]?.name]' '["compliance","secondary"]' 30
chk    PS-1a "the document on disk names both sinks, with no persist asked for" 0 $?
DOC=$(snap)
chk    PS-1b "the captured document names them too, the compliance sink first" '["compliance","secondary"]' \
  "$(printf '%s' "$DOC" | jq -c '[.domains.auditsink[]?.name]')"
chk    PS-1c "the secondary sink with its receiver, its number and its selection" "$SEC_CFG" \
  "$(printf '%s' "$DOC" | jq -r '.domains.auditsink[]? | select(.name=="secondary") | "\(.address) \(.enterprise_number) \(.filter.streams | tojson)"')"
chk    PS-1d "the CA bundle is named by its path" "$SINK_CA $SINK_CA" \
  "$(printf '%s' "$DOC" | jq -r '[.domains.auditsink[]?.ca_bundle_path] | join(" ")')"
chk    PS-1e "and no certificate is in the document" 0 "$(printf '%s' "$DOC" | grep -c 'BEGIN ')"
chk    PS-1f "the file the sinks name is declared as needed for a recovery" "[\"$SINK_CA\"]" \
  "$(printf '%s' "$DOC" | jq -c '[.recovery_dependencies[]? | select(.type=="audit-sink-file" and .required) | .id]')"
chk    PS-1g "nothing a sink has done is in the document" 0 \
  "$(printf '%s' "$DOC" | jq -c '.domains.auditsink' | grep -c -e cursor -e xseq -e submitted -e state)"

# A restart, and nothing configures the sinks afterwards.
sleep 1
EPOCH=$(xseq_epoch); RMAX=$(xseq_max "$EPOCH"); N0=$(rcv_ctl secondary __probe)
BOOT_PREV=$BOOT; P0=$(astatus | jq -r '.seq_high')
drive 3
gw_stop  || fatal "the gateway could not be stopped"
P_END=$(trail | jq -s "[.[] | select(.boot_id==\"$BOOT_PREV\") | .seq] | max")
gw_start || fatal "the gateway did not come back"
chk_ne PS-2a "a new boot" "$BOOT_PREV" "$BOOT"
chk    PS-2b "the compliance sink is there without having been configured" "true $SIEM1:6514 $SINK_CA" "$(compliance_cfg)"
chk    PS-2c "so is the secondary sink, as it was" "$SEC_CFG" "$(secondary_cfg)"
drive 2
wait_caught secondary 90; chk PS-2d "the secondary sink catches up" 0 $?
sleep 1
chk_ge PS-2e "the receiver held a sequence before the restart" 1 "$RMAX"
chk_gt PS-2f "exports arrived after it" "$N0" "$(rcv_ctl secondary __probe)"
SENT=$(exports | jq -s "[.[] | select(.sd.xseq_epoch==$EPOCH and .sd.xseq>$RMAX) | .sd.xseq] | sort")
chk    PS-2g "its sequence goes on from the next number, in the same epoch, with none left out" true \
  "$(printf '%s' "$SENT" | jq --argjson a "$RMAX" 'length > 0 and . == [range($a + 1; $a + 1 + length)]')"
chk    PS-2h "no number arrived twice" 0 "$(xseq_reuse)"
wait_arrived compliance "$BOOT_PREV" "$P_END" 120
chk    PS-2i "the compliance receiver has the previous boot's last record" 0 $?
missing_at compliance "$BOOT_PREV" "$P0" "$P_END"
chk    PS-2j "and every record that boot wrote before it ended" 0 "$MISSING"
chk_ge PS-2k "there were such records" 6 "$LOCAL_N"
wait_caught compliance 60; chk PS-2l "the compliance sink goes on into the new boot's records" 0 $?
chk_ge PS-2m "which arrive under the new boot" 1 "$(rcv_seqs compliance "$BOOT" | grep -c .)"

# A sink that is removed stays removed.
api DELETE /audit/sinks/secondary; chk PS-3a "the secondary sink is removed" 204 "$RESP_CODE"
wait_persisted '[.domains.auditsink[]?.name]' '["compliance"]' 30
chk    PS-3b "the document on disk follows the removal" 0 $?
gw_stop  || fatal "the gateway could not be stopped"
gw_start || fatal "the gateway did not come back"
api GET /audit/sinks/secondary; chk PS-3c "after a restart the removed sink is not there" 404 "$RESP_CODE"
chk    PS-3d "and the compliance sink is" "true $SIEM1:6514 $SINK_CA" "$(compliance_cfg)"

# Restoring the document saved while both sinks ran brings the secondary
# sink back, and it continues the sequence it left.
EPOCH=$(xseq_epoch); RMAX=$(xseq_max "$EPOCH")
restore "$DOC"
chk    PS-4a "the saved document is restored" "200 ok" "$RESP_CODE $(json .result)"
chk    PS-4b "the secondary sink is back as the document has it" "$SEC_CFG" "$(secondary_cfg)"
chk    PS-4c "the compliance sink is the document's too" "true $SIEM1:6514 $SINK_CA" "$(compliance_cfg)"
drive 2
wait_caught secondary 90; chk PS-4d "the secondary sink catches up" 0 $?
sleep 1
SENT=$(exports | jq -s "[.[] | select(.sd.xseq_epoch==$EPOCH and .sd.xseq>$RMAX) | .sd.xseq] | sort")
chk    PS-4e "its sequence goes on from the next number, in the same epoch, with none left out" true \
  "$(printf '%s' "$SENT" | jq --argjson a "$RMAX" 'length > 0 and . == [range($a + 1; $a + 1 + length)]')"
chk    PS-4f "the epoch is the one it had" "$EPOCH" "$(xseq_epoch)"
chk    PS-4g "no number arrived twice" 0 "$(xseq_reuse)"

# A document whose sinks name a file this node cannot read is refused
# before any sink is stopped.
wait_caught compliance 60 || code=1
docker exec llb1 mv "$SINK_CA" "$SINK_CA.away"
T_SEC=$(named secondary '.submitted')
restore "$DOC"
docker exec llb1 mv "$SINK_CA.away" "$SINK_CA"
chk    PS-5a "the restore is refused" 400 "$RESP_CODE"
chk_has PS-5b "and says which file" "$SINK_CA" "$RESP_BODY"
chk    PS-5c "the sinks are still configured" "true $SIEM1:6514 $SINK_CA|$SEC_CFG" "$(compliance_cfg)|$(secondary_cfg)"
drive 2
wait_caught secondary 60; chk PS-5d "and still sending: the secondary sink was never stopped" 0 $?
chk_gt PS-5e "its count of records sent went on from where it was" "$T_SEC" "$(named secondary '.submitted')"
chk    PS-5f "no number arrived twice" 0 "$(xseq_reuse)"

# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "Integrity"
echo "════════════════════════════════════════════════════════════════════════"
for role in compliance secondary; do
  chk INT-1 "[$role] no frame was malformed over the receiver's life" "0 0 0 0 0 0" \
    "$(rcv_stat $role '"\(.framing_errors) \(.header_errors) \(.header_mismatch) \(.json_errors) \(.sd_errors) \(.oversized)"')"
done
chk INT-2 "the decoy never held a session" "0 0" "$(rcv_stat decoy '"\(.connections) \(.frames)"')"
TOTAL_LINES=$(trail_raw | wc -l | tr -d ' ')
PARSED=$(trail_raw | jq -c -R 'fromjson? | select(type=="object")' | wc -l | tr -d ' ')
chk_ge INT-3 "the trail has records to read" 1 "$PARSED"
chk    INT-4 "every line of every segment parses" "$TOTAL_LINES" "$PARSED"
chk    INT-5 "every management change this scenario drove was accepted" 0 "$DRIVE_FAILED"

echo ""
echo "Event types in the trail:"
trail | jq -r '.event_type' | sort | uniq -c | sort -rn | sed 's/^/  /'

echo ""
if [ "$code" -eq 0 ]; then
  echo "SCENARIO-audit-sink [OK]"
else
  echo "--- sink lines of the gateway log (to explain a failure; no row reads them) ---"
  docker exec llb1 sh -c 'cat /var/log/loxilb.log /tmp/loxilb.out /tmp/loxilb.err 2>/dev/null' | grep -a 'audit' | grep -a -i 'sink' | tail -40
  echo "SCENARIO-audit-sink [FAILED]"
fi
exit $code
