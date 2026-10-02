#!/bin/bash
# leg.sh vllm|sglang <profileId> — one strict P/D chat leg against the RUNNING gateway and a RUNNING engine
# pair (engine.sh). Exit 0 = green. Every log assert is scoped to lines written after this run's offsets, so an
# older run's lines can never turn a leg green.
#   0  preconditions: both engines up, serving the profile's model at the manifest's engine version; the engine's
#      manifest installed (restored to the vLLM one on exit); the engine's fixture set present
#   1  strict P/D rule (kvExactMode=1, kvExactApiMode=both — chat where admission refuses completions, the profile) -> ladder READY in this run's trail
#   2  chat x3 through the VIP -> tier-1.5 exact hits +2 and the P/D split proven by COUNTERS: the gateway's P/D
#      counters for this model, each engine's request counter and the decode engine's KV-transfer counter all
#      move (an absent series fails; see below for the one absent-before case)
#   3  red arm: one flipped expected id in the staged chat-user-only fixture -> a fresh rule must NOT reach READY,
#      must report token_mismatch, and the failing probe lines must name the prefill endpoint and never the decode
#      endpoint; the fixture is restored and its md5 checked
set -u
source "$(dirname "$0")/env.sh"
ENG=$1 PROF=$2
MODEL=$(profile_field "$PROF" baseModel)
ENC_MODEL=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "$MODEL")
GWLOG=${LOGD}/loxilb$(hostname).log
case $ENG in
  vllm)   VER=$VLLM_VERSION; MSRC=$FIX/manifests/$PROF.yaml; FSUB=""
          GWC='^loxilb_ai_pd_(prefill_duration|decode_ttft)_seconds_count'; GWMIN=6
          EREQ_P='^vllm:request_success_total'; EREQ_D='^vllm:request_success_total'; XFER='^vllm:nixl_xfer_time_seconds_count' ;;
  sglang) VER=$SGL_VERSION; MSRC=$FIX/manifests-sglang/$PROF.yaml; FSUB="/sglang"
          # decode exposes no num_requests_total; each transferred request bootstraps once and allocates once
          GWC='^loxilb_ai_pd_requests_total'; GWMIN=3
          EREQ_P='^sglang:num_requests_total'; EREQ_D='^sglang:kv_transfer_bootstrap_ms_count'; XFER='^sglang:kv_transfer_alloc_ms_count' ;;
  *) echo "usage: $0 vllm|sglang <profileId>"; exit 64 ;;
esac
# Strict surfaces: both. Where the engine encodes completions its own way (engineQuirks.<contract>), the gateway's
# encoder for that engine reproduces it; step 2b proves it with exact hits on the completions surface.
API=both
SALT="kvmc${ENG}$(date +%s)$RANDOM"; TS=$(date +%Y%m%dT%H%M%S)
EV=${EVROOT}/${ENG}-pd-${PROF}-${TS}; mkdir -p "${EV}"
echo "RUN_ID=${ENG}-pd-${PROF}-${TS}"
state() { curl -s -m 5 "${LB}/externalipaddress/${VIP}/port/${PORT}/protocol/tcp/kvexactstatus" \
  | python3 -c "import json,sys; d=json.load(sys.stdin); a=d['kvExactStatusAttr'][0]; print(a['enforcedState'], ','.join(a.get('reasonCodes') or []))" 2>/dev/null; }
hits() { curl -s -m 5 "${MET}" | grep -E "tier15_hits" | grep -v "^#" \
  | python3 -c "import sys; print(int(sum(float(l.rsplit(None,1)[1]) for l in sys.stdin)))" 2>/dev/null; }
settle() { local a b; a=$(hits); while :; do sleep 12; b=$(hits); [[ -n "$a" && "$a" == "$b" ]] && { echo "$b"; return; }; a=$b; done; }
del_rule() { curl -s -m 10 -o /dev/null -X DELETE "${LB}/hosturl/${VIP}/externalipaddress/${VIP}/port/${PORT}/protocol/tcp?model_name=${ENC_MODEL}"; sleep 2; }
pd_rule() { curl -s -m 10 -o "${EV}/rule-create-$1.json" -w "%{http_code}" -X POST "${LB}" -H 'Content-Type: application/json' -d "{
  \"serviceArguments\": { \"externalIP\": \"${VIP}\", \"port\": ${PORT}, \"protocol\": \"tcp\", \"sel\": 0,
    \"mode\": 4, \"host\": \"${VIP}\", \"probeRetries\": 1, \"pd_disagg_mode\": true, \"kvExactMode\": 1, \"kvBlockSize\": 16,
    \"kvEngineType\": \"${ENG}\", \"model_name\": \"${MODEL}\", \"kvExactApiMode\": \"${API}\", \"kvModelProfile\": \"${PROF}\" },
  \"endpoints\": [ { \"endpointIP\": \"${PREFILL}\", \"targetPort\": ${EPORT}, \"weight\": 1, \"ep_role\": 1 },
                   { \"endpointIP\": \"${DECODE}\", \"targetPort\": ${EPORT}, \"weight\": 1, \"ep_role\": 2 } ] }"; }
since() { tail -n +$(( $2 + 1 )) "$1"; }
# msum <url> <regex>: sum of every sample whose name+labels match; EMPTY when none match (absent never reads as 0)
msum() { curl -s -m 5 "$1" | grep -v "^#" | grep -E "$2" | awk '{s+=$NF; n++} END {if (n) printf "%d", s}'; }
restore_manifest() { install -o root -g root -m 0644 "$FIX/manifests/$PROF.yaml" "$REG/manifests/$PROF.yaml"; }
trap restore_manifest EXIT

echo "=== 0. preconditions ==="
docker inspect -f '{{.State.Running}}' "$GW_CTR" 2>/dev/null | grep -qx true || { echo "GATEWAY_NOT_RUNNING $GW_CTR"; exit 2; }
docker inspect -f '{{.Config.Image}}' "$GW_CTR" | tee "${EV}/gateway-image.txt"
[ -s "$GWLOG" ] || { echo "GATEWAY_LOG_MISSING $GWLOG"; exit 2; }
for w in ${PREFILL} ${DECODE}; do
  # SGLang decode answers /health 503 for ~20 s after /v1/models is up (warm-up); wait, bounded
  for _ in $(seq 1 36); do curl -fsS -m 5 "http://${w}:${EPORT}/health" >/dev/null 2>&1 && break; sleep 5; done
  curl -fsS -m 5 "http://${w}:${EPORT}/health" >/dev/null || { echo "ENGINE_DOWN ${w}"; exit 1; }
  sid=$(curl -s -m 8 "http://${w}:${EPORT}/v1/models" | python3 -c "import json,sys; print(json.load(sys.stdin)['data'][0]['id'])" 2>/dev/null)
  [[ "$sid" == "$MODEL" ]] || { echo "WRONG_MODEL ${w}: ${sid}"; exit 1; }
done
if [ "$ENG" = vllm ]; then
  for w in ${PREFILL} ${DECODE}; do
    v=$(curl -s -m 8 "http://${w}:${EPORT}/version" | python3 -c "import json,sys; print(json.load(sys.stdin)['version'])")
    [[ "$v" == "$VER" ]] || { echo "ENGINE_VERSION ${w} $v (want $VER)"; exit 1; }
  done
else
  curl -s -m 8 "http://${PREFILL}:${EPORT}/server_info" > "${EV}/server_info-prefill.json"
  python3 -c "
import json,sys; d=json.load(open('${EV}/server_info-prefill.json')); ke=d.get('kv_events') or {}
print('  prefill version=%s page=%s disagg=%s revision=%s' % (d.get('version'), d.get('page_size'), d.get('disaggregation_mode'), d.get('revision')))
sys.exit(0 if d.get('version')=='$VER' and d.get('page_size')==16 and ke.get('endpoint_port_base')==5557 and d.get('revision') else 1)" \
    || { echo "SELF_DESC_MISMATCH ${PREFILL}"; exit 1; }
fi
install -o root -g root -m 0644 "${MSRC}" "${REG}/manifests/${PROF}.yaml"
grep -q "\"${VER}\"" "${REG}/manifests/${PROF}.yaml" || { echo "MANIFEST_NOT_${ENG}"; exit 1; }
cp "${REG}/manifests/${PROF}.yaml" "${EV}/manifest-used.yaml"; cp "${REG}/${PROF}.yaml" "${EV}/profile-used.yaml"
FXD=${REG}/probefixtures/${PROF}${FSUB}
ls "${FXD}/chat-user-only.expect.json" >/dev/null || { echo "FIXTURES_MISSING ${FXD}"; exit 1; }
echo "  pair up, served ${MODEL}, manifest ${ENG} ${VER}, fixtures $(ls "${FXD}"/*.expect.json | wc -l)"

echo "=== 1. strict P/D rule -> READY in this run's trail ==="
del_rule
G0=$(wc -l < "${GWLOG}")
http=$(pd_rule green); echo "  create -> ${http} $(head -c 160 "${EV}/rule-create-green.json")"
[[ "$http" == 200 ]] || { echo RULE_CREATE_FAILED; exit 3; }
es=""; for _ in $(seq 1 100); do es=$(state); [[ "$es" == READY* ]] && break; sleep 3; done
echo "  state: ${es}"
curl -s -m 5 "${LB}/externalipaddress/${VIP}/port/${PORT}/protocol/tcp/kvexactstatus" > "${EV}/kvexactstatus-ready.json"
[[ "$es" == READY* ]] || { echo LADDER_NOT_READY; since "${GWLOG}" "$G0" | grep -a kv-attest | tail -15; del_rule; exit 4; }
sleep 12
since "${GWLOG}" "$G0" | grep -aE "kv-attest" > "${EV}/gateway-attest-lines.log"
grep -q "READY" "${EV}/gateway-attest-lines.log" || { echo ATTEST_TRAIL_EMPTY_THIS_RUN; del_rule; exit 4; }
echo "  READY in this run's trail"

echo "=== 2. chat x3 through the P/D split ==="
CHAT_USER="${SALT} pd chat probe. Summarize prefill decode separation in one sentence. Filler: alpha bravo charlie delta echo foxtrot golf hotel india juliett kilo lima mike november oscar papa quebec romeo sierra tango uniform victor whiskey xray yankee zulu one two three four five six seven eight nine ten."
h0=$(settle)
MS=$(python3 -c "import sys; print(sys.argv[1].replace('/','_'))" "$MODEL")
g0=$(msum "${MET}" "${GWC}\\{model=\"${MS}\"[,}]"); p0=$(msum "http://${PREFILL}:${EPORT}/metrics" "$EREQ_P")
d0=$(msum "http://${DECODE}:${EPORT}/metrics" "$EREQ_D"); x0=$(msum "http://${DECODE}:${EPORT}/metrics" "$XFER")
# A Prometheus label child exists only after its first increment, and client_golang drops a family with no
# child from the exposition entirely (no HELP line either): right after a gateway restart the family is
# invisible. So an absent child before the traffic reads 0 when the scrape itself answered; the child must then
# EXIST after the traffic (g1 ABSENT fails below) and have moved by >= GWMIN. An unregistered family or a dead
# writer stays absent at g1 and fails the leg.
if [[ -z "$g0" ]] && curl -s -m 5 "${MET}" | grep -q "^loxilb_"; then g0=0; echo "  gateway P/D counter: no child for ${MS} yet (scrape answered) -> 0"; fi
echo "  counters before: gw_pd=${g0:-ABSENT} prefill_req=${p0:-ABSENT} decode_req=${d0:-ABSENT} decode_xfer=${x0:-ABSENT}"
for i in 1 2 3; do
  curl -s -m 90 -X POST "http://${VIP}:${PORT}/v1/chat/completions" -H 'Content-Type: application/json' \
    -d "{\"model\": \"${MODEL}\", \"messages\": [{\"role\": \"user\", \"content\": \"${CHAT_USER}\"}], \"max_tokens\": 8, \"temperature\": 0}" > "${EV}/pdchat-r${i}.json"
  python3 -c "import json;d=json.load(open('${EV}/pdchat-r${i}.json'));u=d['usage'];print('  r${i} prompt=%s' % u.get('prompt_tokens'))" \
    || { echo PD_CHAT_REQ_FAILED; head -c 300 "${EV}/pdchat-r${i}.json"; del_rule; exit 5; }
  sleep 2
done
h1=""; for _ in $(seq 1 15); do h1=$(hits); [[ -n "$h1" && "$h1" -ge $((h0+2)) ]] && break; sleep 2; done
[[ -n "$h1" && "$h1" -ge $((h0+2)) ]] || { echo "PD_CHAT_NO_EXACT_HITS ${h0}->${h1}"; del_rule; exit 5; }
h1=$(settle); echo "  tier15_hits ${h0}->${h1}"
sleep 12
g1=$(msum "${MET}" "${GWC}\\{model=\"${MS}\"[,}]"); p1=$(msum "http://${PREFILL}:${EPORT}/metrics" "$EREQ_P")
d1=$(msum "http://${DECODE}:${EPORT}/metrics" "$EREQ_D"); x1=$(msum "http://${DECODE}:${EPORT}/metrics" "$XFER")
echo "  counters after:  gw_pd=${g1:-ABSENT} prefill_req=${p1:-ABSENT} decode_req=${d1:-ABSENT} decode_xfer=${x1:-ABSENT}"
{ curl -s -m5 "${MET}" | grep -E "loxilb_ai_pd_"; curl -s -m5 "http://${PREFILL}:${EPORT}/metrics" | grep -E "$EREQ_P"
  curl -s -m5 "http://${DECODE}:${EPORT}/metrics" | grep -E "$EREQ_D|$XFER"; } > "${EV}/pd-counters.prom"
PDF=0
for v in g0 g1 p0 p1 d0 d1 x0 x1; do [[ -n "${!v}" ]] || { echo "  PD_COUNTER_ABSENT ${v}"; PDF=1; }; done
if [[ $PDF == 0 ]]; then
  [[ $((g1-g0)) -ge $GWMIN ]] || { echo "  gateway P/D counters +$((g1-g0)) (want >= $GWMIN)"; PDF=1; }
  [[ $((p1-p0)) -ge 3 ]] || { echo "  prefill engine requests +$((p1-p0)) (want >= 3)"; PDF=1; }
  [[ $((d1-d0)) -ge 3 ]] || { echo "  decode engine requests +$((d1-d0)) (want >= 3)"; PDF=1; }
  [[ $((x1-x0)) -ge 3 ]] || { echo "  decode KV transfers +$((x1-x0)) (want >= 3)"; PDF=1; }
fi
[[ $PDF == 0 ]] || { echo PD_SPLIT_NOT_PROVEN; del_rule; exit 5; }
echo "  P/D split proven: gateway +$((g1-g0)), prefill +$((p1-p0)), decode +$((d1-d0)), KV transfers +$((x1-x0))"

echo "=== 2b. completions x3: exact hits on the completions surface ==="
# A TEXT prompt: the gateway hashes its own encoding of it, the engine caches its own. A hit needs both to agree
# on every id of a block, an engine-added BOS included (it shifts every block boundary by one).
COMP_PROMPT="${SALT} pd completions probe. ${CHAT_USER#* }"
c0=$(settle)
for i in 1 2 3; do
  python3 -c "import json,sys; print(json.dumps({'model': sys.argv[1], 'prompt': sys.argv[2], 'max_tokens': 8, 'temperature': 0}))" "$MODEL" "$COMP_PROMPT" \
    | curl -s -m 90 -X POST "http://${VIP}:${PORT}/v1/completions" -H 'Content-Type: application/json' -d @- > "${EV}/pdcompl-r${i}.json"
  python3 -c "import json;d=json.load(open('${EV}/pdcompl-r${i}.json'));u=d['usage'];print('  r${i} prompt=%s' % u.get('prompt_tokens'))" \
    || { echo PD_COMPL_REQ_FAILED; head -c 300 "${EV}/pdcompl-r${i}.json"; del_rule; exit 7; }
  sleep 2
done
c1=""; for _ in $(seq 1 15); do c1=$(hits); [[ -n "$c1" && "$c1" -ge $((c0+2)) ]] && break; sleep 2; done
[[ -n "$c1" && "$c1" -ge $((c0+2)) ]] || { echo "PD_COMPL_NO_EXACT_HITS ${c0}->${c1}"; del_rule; exit 7; }
c1=$(settle); echo "  tier15_hits ${c0}->${c1}"
del_rule

echo "=== 3. red arm: one flipped expected id -> not READY, token_mismatch on the prefill endpoint only ==="
T=${FXD}/chat-user-only.expect.json; cp "$T" "${EV}/fixture.bak"; M0=$(md5sum < "$T")
python3 - "$T" <<'PY'
import json, sys
p = sys.argv[1]; d = json.load(open(p)); d["expectedTokenIds"][2] += 1; json.dump(d, open(p, "w"))
PY
G2=$(wc -l < "${GWLOG}")
pd_rule red >/dev/null; es=""
for _ in $(seq 1 30); do es=$(state); [[ "$es" == READY* ]] && break; sleep 3; done
since "${GWLOG}" "$G2" | grep -a "kv-attest" > "${EV}/red-attest-lines.log"
install -o root -g root -m 0644 "${EV}/fixture.bak" "$T"; M1=$(md5sum < "$T")
del_rule
[[ "$M0" == "$M1" ]] || { echo FIXTURE_RESTORE_MISMATCH; exit 6; }
grep -a "token_mismatch" "${EV}/red-attest-lines.log" > "${EV}/red-mismatch-lines.log"
np=$(grep -c "ep ${PREFILL}:${EPORT}" "${EV}/red-mismatch-lines.log"); nd=$(grep -c "${DECODE}:${EPORT}" "${EV}/red-mismatch-lines.log")
if [[ "$es" != READY* && "$es" == *token_mismatch* && "$np" -ge 1 && "$nd" == 0 ]]; then
  echo "  red arm: state '${es}'; ${np} token_mismatch probe lines name the prefill endpoint, 0 the decode endpoint; fixture restored"
else
  echo "  RED_ARM_FAILED: state '${es}', mismatch lines prefill=${np} decode=${nd}"; exit 6
fi
(cd "${EV}" && sha256sum -- * > SHA256SUMS)
echo "PD_LEG_GREEN ${ENG} ${PROF} evidence=${EV}"
