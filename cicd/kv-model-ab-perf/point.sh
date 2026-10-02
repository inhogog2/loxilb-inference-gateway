#!/bin/bash
# point.sh vllm|sglang <profileId> <pointId> <corpus.jsonl> <rate req/s> <repeat> [chat|completions]
#
# One A/B point against a RUNNING fleet (validation.sh fleet-up) and the RUNNING gateway: REPS repetitions, the
# two arms in alternating order (exact-baseline, baseline-exact, exact-baseline). Before EVERY arm the engines
# are restarted (empty caches), the rule is created fresh, and every prompt family is seeded directly on its
# owner prefill engine and on every decode engine. Then the same requests are offered open-loop at the same rate through the VIP.
#   exact     strict KV-exact rule on the model's profile (the rule a supported row describes)
#   baseline  the same rule without KV-exact: round-robin over the prefill engines
# A point is banked (ab-summary.json) only when, in every repetition:
#   - every request of both arms completes (HTTP 200, SSE done);
#   - exact arm: the rule is READY before seeding, every prefill has a connected KV subscriber, tier-1.5 hits
#     rise by exactly the number of timed requests and the fall-through counter does not move;
#   - baseline arm: tier-1.5 hits do not move;
#   - exact arm: the first round is as fast as the later ones (the seeded prefixes are the ones hit) and no
#     engine is left without a request; no arm straddles 00:00 UTC;
#   - the prefill engines' own request counters show the arm's routing: equal shares for exact (every owner has
#     the same number of families), a spread over every prefill for the baseline.
# Anything else stops the point with a typed line and leaves no summary. A banked point is skipped on re-run.
set -u
source "$(dirname "$0")/env.sh"
ENG=$1 PROF=$2 ID=$3 CORPUS=$4 RATE=$5 REPEAT=$6 API=${7:-chat}
MODEL=$(profile_field "$PROF" baseModel)
ENC_MODEL=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "$MODEL")
OUT=${AB_BASE:-${ABROOT}/${ENG}-${PROF}}/${ID}
PNAME=kvmc-$ENG-$ROLE1                        # container of an engine the rule routes the prompt to
[ -s "$OUT/ab-summary.json" ] && { echo "POINT_ALREADY_BANKED $OUT"; exit 0; }
rm -rf "$OUT"; mkdir -p "$OUT"; cp "$CORPUS" "$OUT/corpus.jsonl"
case $ENG in
  vllm)   MSRC=$FIX/manifests/$PROF.yaml ;;
  sglang) MSRC=$FIX/manifests-sglang/$PROF.yaml ;;
  *) echo "engine must be vllm|sglang"; exit 64 ;;
esac
restore_manifest() { install -o root -g root -m 0644 "$FIX/manifests/$PROF.yaml" "$REG/manifests/$PROF.yaml"; }
del_rule() { curl -s -m 10 -o /dev/null -X DELETE "${LB}/hosturl/${VIP}/externalipaddress/${VIP}/port/${PORT}/protocol/tcp?model_name=${ENC_MODEL}"; sleep 2; }
trap 'del_rule; restore_manifest' EXIT
install -o root -g root -m 0644 "$MSRC" "$REG/manifests/$PROF.yaml"
NREQ=$(( $(wc -l < "$CORPUS") * REPEAT ))
state() { curl -s -m 5 "${LB}/externalipaddress/${VIP}/port/${PORT}/protocol/tcp/kvexactstatus" \
  | python3 -c "import json,sys; d=json.load(sys.stdin); a=d['kvExactStatusAttr'][0]; print(a['enforcedState'], ','.join(a.get('reasonCodes') or []))" 2>/dev/null; }
# msum <file> <metric name>: sum over every label child; a metric with no sample reads 0 only for a scrape that answered
msum() { awk -v m="$2" '$1 ~ ("^" m "({|$)") {s += $NF} END {printf "%d", s + 0}' "$1"; }
scrape() { curl -fsS -m 10 "${MET}" > "$1" && grep -q "^loxilb_" "$1" || { echo "GATEWAY_SCRAPE_FAILED $1"; return 1; }; }
rule() { # rule exact|baseline <dir>
  python3 - "$1" "$VIP" "$PORT" "$ENG" "$MODEL" "$PROF" "$EPORT" "$PREFILLS" "$DECODES" "$TOPOLOGY" > "$2/rule.json" <<'PY'
import json, sys
arm, vip, port, eng, model, prof, eport, pre, dec, topo = sys.argv[1:]
sa = {"externalIP": vip, "port": int(port), "protocol": "tcp", "sel": 0, "mode": 4, "host": vip, "probeRetries": 1,
      "sse_mode": True, "model_name": model, "kvExactMode": 0}
if topo == "pd":
    sa["pd_disagg_mode"] = True
if arm == "exact":   # exact mode 1 = prefill/decode rule, 3 = converged (role-less endpoints)
    sa.update(kvExactMode=1 if topo == "pd" else 3, kvBlockSize=16, kvEngineType=eng, kvExactApiMode="both", kvModelProfile=prof)
if topo == "pd":
    eps = [{"endpointIP": n, "targetPort": int(eport), "weight": 1, "ep_role": 1} for n in pre.split()]
    eps += [{"endpointIP": n, "targetPort": int(eport), "weight": 1, "ep_role": 2} for n in dec.split()]
else:
    eps = [{"endpointIP": n, "targetPort": int(eport), "weight": 1} for n in pre.split()]
print(json.dumps({"serviceArguments": sa, "endpoints": eps}, indent=1))
PY
  curl -s -m 10 -o "$2/rule-create.json" -w "%{http_code}" -X POST "${LB}" -H 'Content-Type: application/json' --data-binary "@$2/rule.json"
}
restart_fleet() {
  local n
  for n in "${PNODES[@]}"; do $SSH -n root@"$n" "docker restart $PNAME >/dev/null" & done
  for n in "${DNODES[@]}"; do $SSH -n root@"$n" "docker restart kvmc-$ENG-decode >/dev/null" & done
  wait
  for _ in $(seq 1 120); do
    local up=0
    for n in "${PNODES[@]}" "${DNODES[@]}"; do
      curl -s -m 3 "http://$n:$EPORT/v1/models" | grep -qF "\"id\":\"$MODEL\"" && curl -fsS -m 3 "http://$n:$EPORT/health" >/dev/null 2>&1 && up=$((up+1))
    done
    [ $up = $(( ${#PNODES[@]} + ${#DNODES[@]} )) ] && return 0
    sleep 5
  done
  echo "FLEET_NOT_READY after restart"; return 1
}
case $ENG in vllm) EREQ=vllm:request_success_total ;; sglang) EREQ=sglang:num_requests_total ;; esac
# served <dir> <node>: requests the engine finished during the timed window (its own counter, after - before)
served() {
  grep -q "^$EREQ" "$1/after-engine-$2.prom" || { echo "ENGINE_METRIC_MISSING $EREQ on $2" >&2; return 1; }
  echo $(( $(msum "$1/after-engine-$2.prom" "$EREQ") - $(msum "$1/before-engine-$2.prom" "$EREQ") ))
}
engines_snapshot() { local n; for n in "${PNODES[@]}" "${DNODES[@]}"; do curl -s -m 10 "http://$n:$EPORT/metrics" > "$1/$2-engine-$n.prom"; done; }
# The prefill engines' own logs for the arm (the containers were restarted at its start): the access lines name
# the client of every request, so a request the scenario did not send can be attributed.
engine_logs() { local n; for n in "${PNODES[@]}"; do $SSH -n root@"$n" "docker logs $PNAME 2>&1" | gzip > "$1/engine-$n.log.gz"; done; }

arm() { # arm <repetition> exact|baseline
  local rep=$1 a=$2 d="$OUT/repetition-$1/$2" http es t
  mkdir -p "$d"
  # A chat template may print today's date at the top of the prompt. Seeds rendered before 00:00 UTC then share
  # no block with requests rendered after it, so an arm must not straddle that instant: start it on the far side.
  local left=$(( 86400 - $(date -u +%s) % 86400 ))
  [ "$left" -lt $(( ARM_SECONDS + 240 )) ] && { echo "    waiting ${left}s for 00:00 UTC before the arm"; sleep $(( left + 5 )); }
  echo "--- repetition $rep, arm $a ($(date -Is)) ---"
  del_rule
  restart_fleet || return 1
  http=$(rule "$a" "$d"); [ "$http" = 200 ] || { echo "RULE_CREATE_FAILED $a $http $(head -c 200 "$d/rule-create.json")"; return 1; }
  if [ "$a" = exact ]; then
    es=""; for _ in $(seq 1 100); do es=$(state); [[ "$es" == READY* ]] && break; sleep 3; done
    echo "$es" > "$d/state.txt"
    [[ "$es" == READY* ]] || { echo "EXACT_RULE_NOT_READY '$es'"; return 1; }
    sleep 3; scrape "$d/subscribers.prom" || return 1
    local sub; sub=$(grep -c '^loxilb_kv_subscriber_connected{.*} 1$' "$d/subscribers.prom")
    [ "$sub" -ge ${#PNODES[@]} ] || { echo "KV_SUBSCRIBERS $sub connected, want ${#PNODES[@]}"; return 1; }
  else
    sleep 5
  fi
  local day0; day0=$(date -u +%F)
  t=(); for n in "${PNODES[@]}"; do t+=(--target "http://$n:$EPORT"); done
  python3 "$AB_DIR/seed.py" --corpus "$CORPUS" --output "$d/seed-receipts.jsonl" --model "$MODEL" --api "$API" "${t[@]}" \
    || { echo "SEED_FAILED $a"; return 1; }
  # The decode engines get every family too, in both arms. A decode engine that has never seen a prefix pulls it
  # whole from the prefill engine, and that first pull costs more than the prefill either arm can save; with it
  # in the timed window the tail measures decode warm-up, not routing. Seeded, the arms differ only in which
  # prefill engine is asked.
  for n in "${DNODES[@]}"; do
    t=(); for _ in "${PNODES[@]}"; do t+=(--target "http://$n:$EPORT"); done
    python3 "$AB_DIR/seed.py" --corpus "$CORPUS" --output "$d/seed-receipts-decode-$n.jsonl" --model "$MODEL" --api "$API" "${t[@]}" \
      || { echo "SEED_FAILED $a decode $n"; return 1; }
  done
  sleep 12   # KV events of the seeds reach the gateway inventory
  scrape "$d/before-gateway.prom" || return 1; engines_snapshot "$d" before
  local gwlog l0=0; gwlog=$(ls -t "$LOGD"/loxilb*.log 2>/dev/null | grep -v 'loxilbdp\|/loxilb\.log$' | head -1)
  [ -n "$gwlog" ] && l0=$(wc -l < "$gwlog")
  python3 "$AB_DIR/bench.py" --corpus "$CORPUS" --output "$d/requests.jsonl" --url "http://${VIP}:${PORT}" --model "$MODEL" \
    --arm "$a" --api "$API" --repetition "$rep" --max-tokens "$MAX_TOKENS" --repeat-count "$REPEAT" --request-rate "$RATE" --order-seed "$rep"
  local brc=$?
  [ "$(date -u +%F)" = "$day0" ] || { echo "ARM_CROSSED_UTC_MIDNIGHT $a: seeded on $day0"; return 1; }
  sleep 12
  scrape "$d/after-gateway.prom" || return 1; engines_snapshot "$d" after
  engine_logs "$d"
  # With LOXILB_KV_TLOAD_LOG=1 on the gateway, its selector logs the in-flight total and the candidate count of
  # every decision; keep the arm's lines (an empty file when the variable is not set).
  [ -n "$gwlog" ] && tail -n +"$((l0 + 1))" "$gwlog" | grep -a 'totalLoad=' | gzip > "$d/selector-load.log.gz"
  [ $brc = 0 ] || { echo "REQUESTS_INCOMPLETE $a: $(grep -c '"completed": false' "$d/requests.jsonl") of $NREQ"; return 1; }
  local h=$(( $(msum "$d/after-gateway.prom" loxilb_pd_kv_tier15_hits_total) - $(msum "$d/before-gateway.prom" loxilb_pd_kv_tier15_hits_total) ))
  local f=$(( $(msum "$d/after-gateway.prom" loxilb_pd_kv_tier15_fallthrough_total) - $(msum "$d/before-gateway.prom" loxilb_pd_kv_tier15_fallthrough_total) ))
  echo "$h" > "$d/tier15-hit-delta.txt"; echo "$f" > "$d/tier15-fallthrough-delta.txt"
  if [ "$a" = exact ]; then
    [ "$h" = "$NREQ" ] || { echo "EXACT_HITS $h, want $NREQ"; return 1; }
    [ "$f" = 0 ] || { echo "EXACT_FALLTHROUGH +$f"; return 1; }
    # A hit on every request does not say the seeded prefix was the one hit: see round1.py.
    if [ "$REPEAT" -gt 1 ]; then
      # The arm's spill count goes on the line: a cold round has two causes this check cannot tell apart from the
      # arm's own files (see README), and a spill count far below the cold count rules one of them out.
      python3 "$AB_DIR/round1.py" "$d/requests.jsonl" > "$d/round1.txt" || {
        echo "EXACT_ROUND1_COLD $(cat "$d/round1.txt"); the arm spilled $(( $(msum "$d/after-gateway.prom" loxilb_pd_kv_tier15_spills_total) - $(msum "$d/before-gateway.prom" loxilb_pd_kv_tier15_spills_total) )) of $NREQ requests"; return 1; }
    fi
  else
    [ "$h" = 0 ] || { echo "BASELINE_HITS +$h (the baseline rule must not route by cache)"; return 1; }
  fi
  # Where the requests went, from the prefill engines' own counters. Exact arm: every prefill engine served the
  # requests the gateway counted as tier-1.5 hits on that endpoint (endpoint index = position in the rule, the
  # prefill engines first). Equal shares are not required: when two engines hold blocks of a prompt, the
  # gateway's bounded-load selection may spill past a loaded owner, and the engine it spilled to then holds the
  # prefix too. The spill count is stored with the arm. Baseline arm: the requests must spread over every prefill
  # engine, or it is not a round-robin baseline.
  local share=$(( NREQ / ${#PNODES[@]} )) s spread="" off i=0 hi
  local sp=$(( $(msum "$d/after-gateway.prom" loxilb_pd_kv_tier15_spills_total) - $(msum "$d/before-gateway.prom" loxilb_pd_kv_tier15_spills_total) ))
  echo "$sp" > "$d/tier15-spill-delta.txt"
  for n in "${PNODES[@]}"; do
    s=$(served "$d" "$n") || return 1; spread+="$n=$s "
    if [ "$a" = exact ]; then
      hi=$(( $(msum "$d/after-gateway.prom" "loxilb_pd_kv_tier15_hits_total{ep_idx=\"$i\"}") - $(msum "$d/before-gateway.prom" "loxilb_pd_kv_tier15_hits_total{ep_idx=\"$i\"}") ))
      off=$(( s > hi ? s - hi : hi - s ))
      [ "$off" -le 2 ] || { echo "EXACT_PREFILL_SHARE $n served $s, the gateway counted $hi hits on endpoint $i"; return 1; }
      # Every engine owns families, so an engine that served nothing was never chosen for its own prefixes.
      [ "$s" -gt 0 ] || { echo "EXACT_ENGINE_IDLE $n served 0 of $NREQ"; return 1; }
      i=$((i+1))
    else
      [ "$s" -ge $((share * 8 / 10)) ] || { echo "BASELINE_NOT_SPREAD $n served $s of $NREQ"; return 1; }
    fi
  done
  echo "$spread" > "$d/prefill-served.txt"
  echo "    arm $a ok: $NREQ requests, tier-1.5 hits +$h, fall-through +$f, spills +$sp, prefill served: $spread"
  del_rule
}

echo "=== point $ID: $ENG x $PROF, $TOPOLOGY, $API, rate $RATE req/s, $NREQ requests per arm, ${#PNODES[@]} $ROLE1 + ${#DNODES[@]} decode ==="
docker inspect -f '{{.Config.Image}}' "$GW_CTR" > "$OUT/gateway-image.txt" || { echo GATEWAY_NOT_RUNNING; exit 2; }
printf '%s\n' "engine=$ENG profile=$PROF topology=$TOPOLOGY model=$MODEL api=$API rate=$RATE repeat=$REPEAT requests_per_arm=$NREQ" \
  "prefill=$PREFILLS" "decode=$DECODES" "max_tokens=$MAX_TOKENS" > "$OUT/point.txt"
for rep in $(seq 1 "$REPS"); do
  if [ $((rep % 2)) = 1 ]; then order="exact baseline"; else order="baseline exact"; fi
  for a in $order; do arm "$rep" "$a" || { echo "POINT_VOID $ID (repetition $rep, arm $a)"; exit 1; }; done
done
python3 "$AB_DIR/analyze.py" --input-dir "$OUT" --summary "$OUT/ab-summary.json" --self-test || { rm -f "$OUT/ab-summary.json"; echo "POINT_VOID $ID (analysis)"; exit 1; }
(cd "$OUT" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
echo "POINT_BANKED $ID evidence=$OUT"
