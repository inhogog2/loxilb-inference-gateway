#!/bin/bash
# validation.sh — A/B performance, KV-exact routing against round-robin, per model (LIVE GPU fleet).
#
#   ./validation.sh model <vllm|sglang> <profileId>     fleet up -> corpus -> calibration -> three points -> fleet down
#   ./validation.sh fleet-up|fleet-down <engine> <profileId>
#   ./validation.sh report <engine> <profileId>          print the banked points as manifest `perf` entries
#
# `model` runs, for one model on one engine:
#   1. the prefill/decode fleet from PREFILLS / DECODES (launch arguments from ../kv-model-compat-pd/engine.sh);
#   2. a long-prefix corpus sized for THIS model's tokenizer (TARGET_TOKENS prompt tokens) and a short-prefix one;
#   3. a capacity calibration: closed-loop, cold (unique prefixes, nothing seeded), through the round-robin rule.
#      Rates do not carry over between models or GPUs, so the offered rates are fractions of this number;
#   4. three points (point.sh): long prefix at 40 % and at 80 % of the calibrated rate, and the short-prefix
#      control at 80 %. The control has no cache benefit to win: it bounds the routing overhead and the noise.
# Needs the profile staged in the gateway registry (kv-model-compat-pd/config.sh or scripts/models/install-models.sh)
# and the model's weights on every node. One gateway, one rule port: nothing else may use the port meanwhile.
set -u
source "$(dirname "$0")/env.sh"
MODE=${1:-}; ENG=${2:-}; PROF=${3:-}
[ -n "$PROF" ] || { echo "usage: $0 model|fleet-up|fleet-down|report <vllm|sglang> <profileId>"; exit 64; }
MODEL=$(profile_field "$PROF" baseModel)
BASE=${ABROOT}/${ENG}-${PROF}; mkdir -p "$BASE"
code=0

fleet_up() {
  local n pids=() rc=0
  for n in "${PNODES[@]}"; do PREFILL=$n "$COMPAT/engine.sh" start "$ENG" prefill "$PROF" & pids+=($!); done
  for n in "${DNODES[@]}"; do DECODE=$n "$COMPAT/engine.sh" start "$ENG" decode "$PROF" & pids+=($!); done
  for p in "${pids[@]}"; do wait "$p" || rc=1; done
  return $rc
}
fleet_down() {
  local n
  for n in "${PNODES[@]}"; do PREFILL=$n EVROOT=$BASE "$COMPAT/engine.sh" stop "$ENG" prefill "$PROF"; done
  for n in "${DNODES[@]}"; do DECODE=$n EVROOT=$BASE "$COMPAT/engine.sh" stop "$ENG" decode "$PROF"; done
}
# prompt tokens of one long-prefix chat prompt with <reps> paragraph repetitions, as the first prefill counts them
ptok() {
  python3 "$AB_DIR/gen_corpus.py" --output "$BASE/size-$1.jsonl" --families "${#PNODES[@]}" --owners "${#PNODES[@]}" --prefix-repetitions "$1" --salt "size$1-"
  head -1 "$BASE/size-$1.jsonl" > "$BASE/size-one.jsonl"
  python3 "$AB_DIR/seed.py" --corpus "$BASE/size-one.jsonl" --output "$BASE/size-$1.receipt.jsonl" --model "$MODEL" --target "http://${PNODES[0]}:$EPORT" >/dev/null
  python3 -c "import json,sys; print(json.loads(open(sys.argv[1]).readline())['usage']['prompt_tokens'])" "$BASE/size-$1.receipt.jsonl"
}
corpora() {
  local a b reps
  a=$(ptok 20) && b=$(ptok 60) || { echo "CORPUS_SIZING_FAILED"; return 1; }
  reps=$(python3 -c "import sys; a,b,t=map(int,sys.argv[1:]); per=(b-a)/40; print(int((t-(a-20*per))//per))" "$a" "$b" "$TARGET_TOKENS")
  echo "  tokens: 20 repetitions -> $a, 60 -> $b; $reps repetitions for ~$TARGET_TOKENS prompt tokens"
  [ "$reps" -ge 20 ] || { echo "CORPUS_SIZING_FAILED reps=$reps"; return 1; }
  echo "$reps" > "$BASE/prefix-repetitions.txt"
  python3 "$AB_DIR/gen_corpus.py" --output "$BASE/corpus-long.jsonl" --families "$FAMILIES" --owners "${#PNODES[@]}" --prefix-repetitions "$reps"
  python3 "$AB_DIR/gen_corpus.py" --output "$BASE/corpus-short.jsonl" --families "$FAMILIES" --owners "${#PNODES[@]}" --shape short
  python3 "$AB_DIR/gen_corpus.py" --output "$BASE/corpus-cal.jsonl" --families $((FAMILIES * 2)) --owners "${#PNODES[@]}" --prefix-repetitions "$reps" --salt "cal$(date +%s)-"
}
calibrate() {
  [ -s "$BASE/calibration.json" ] && { echo "  calibration already banked"; return 0; }
  local enc; enc=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "$MODEL")
  python3 - "$VIP" "$PORT" "$MODEL" "$EPORT" "$PREFILLS" "$DECODES" > "$BASE/cal-rule.json" <<'PY'
import json, sys
vip, port, model, eport, pre, dec = sys.argv[1:]
eps = [{"endpointIP": n, "targetPort": int(eport), "weight": 1, "ep_role": 1} for n in pre.split()]
eps += [{"endpointIP": n, "targetPort": int(eport), "weight": 1, "ep_role": 2} for n in dec.split()]
print(json.dumps({"serviceArguments": {"externalIP": vip, "port": int(port), "protocol": "tcp", "sel": 0, "mode": 4, "host": vip,
      "probeRetries": 1, "pd_disagg_mode": True, "sse_mode": True, "model_name": model, "kvExactMode": 0}, "endpoints": eps}))
PY
  local http; http=$(curl -s -m 10 -o "$BASE/cal-rule-create.json" -w "%{http_code}" -X POST "${LB}" -H 'Content-Type: application/json' --data-binary "@$BASE/cal-rule.json")
  [ "$http" = 200 ] || { echo "CAL_RULE_CREATE_FAILED $http"; return 1; }
  sleep 5
  python3 "$AB_DIR/bench.py" --corpus "$BASE/corpus-cal.jsonl" --output "$BASE/cal-requests.jsonl" --url "http://${VIP}:${PORT}" \
    --model "$MODEL" --arm baseline --repetition 0 --max-tokens "$MAX_TOKENS" --concurrency "${CAL_CONCURRENCY:-32}"
  local rc=$?
  curl -s -m 10 -o /dev/null -X DELETE "${LB}/hosturl/${VIP}/externalipaddress/${VIP}/port/${PORT}/protocol/tcp?model_name=${enc}"
  [ $rc = 0 ] || { echo "CAL_REQUESTS_INCOMPLETE"; return 1; }
  python3 - "$BASE/cal-requests.jsonl" "$BASE/calibration.json" <<'PY'
import json, statistics, sys
r = [json.loads(l) for l in open(sys.argv[1])]
dur = max(x["ended_at_unix"] for x in r) - min(x["started_at_unix"] for x in r)
rps = len(r) / dur
out = {"requests": len(r), "duration_sec": round(dur, 2), "cold_closed_loop_rps": round(rps, 2),
       "ttft_p50_ms": round(statistics.median(x["ttft_ms"] for x in r), 1),
       "prompt_tokens_median": statistics.median(x["prompt_tokens"] for x in r),
       "rate_low": max(0.5, round(rps * 0.4 * 2) / 2), "rate_high": max(1.0, round(rps * 0.8 * 2) / 2)}
json.dump(out, open(sys.argv[2], "w"), indent=1); print("  calibration:", json.dumps(out))
PY
}
cal() { python3 -c "import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])" "$BASE/calibration.json" "$1"; }
repeat_for() { python3 -c "import math,sys; print(max(3, math.ceil(float(sys.argv[1]) * $ARM_SECONDS / $FAMILIES)))" "$1"; }
point() { "$AB_DIR/point.sh" "$ENG" "$PROF" "$1" "$2" "$3" "$(repeat_for "$3")" "${4:-chat}" || { code=1; return 1; }; }
report() {
  python3 - "$BASE" "$ENG" <<'PY'
import glob, json, os, sys
base, eng = sys.argv[1:]
for f in sorted(glob.glob(base + "/*/ab-summary.json")):
    d = os.path.dirname(f); s = json.load(open(f)); meta = dict(x.split("=", 1) for x in open(d + "/point.txt").readline().split())
    e, b, fx = s["arms"]["exact"], s["arms"]["baseline"], s["effects"]
    npre = len(open(d + "/point.txt").read().split("prefill=")[1].split("\n")[0].split()); ndec = len(open(d + "/point.txt").read().split("decode=")[1].split("\n")[0].split())
    print(f"# {os.path.basename(d)}: p95 {fx['ttft_p95_delta_percent']:+.1f}% ({fx['ttft_p95_separation']}), CI {fx['ttft_p95_delta_95ci_percent']}, "
          f"p50 {fx['ttft_p50_delta_percent']:+.1f}% ({fx['ttft_p50_separation']}), TPOT p95 {fx['tpot_p95_delta_percent']:+.1f}%, tokens/s {fx['output_tokens_per_sec_delta_percent']:+.1f}%")
    print(f"- {{topology: pd-{npre}p{ndec}d, surface: {meta['api']}, corpus: {os.path.basename(d).split('-')[0]}, rateRps: {meta['rate']}, "
          f"requestsPerArm: {e['requests']}, exactTtftP95Ms: {e['ttft_p95_ms']}, baselineTtftP95Ms: {b['ttft_p95_ms']}, "
          f"exactTtftP50Ms: {e['ttft_p50_ms']}, baselineTtftP50Ms: {b['ttft_p50_ms']}, date: \"{os.popen('date -r ' + f + ' +%F').read().strip()}\"}}")
PY
}

case $MODE in
  fleet-up) fleet_up || code=1 ;;
  fleet-down) fleet_down ;;
  report) report ;;
  model)
    echo "=== A/B $ENG x $PROF ($MODEL): ${#PNODES[@]} prefill [$PREFILLS] + ${#DNODES[@]} decode [$DECODES] ==="
    if fleet_up && corpora && calibrate; then
      lo=$(cal rate_low); hi=$(cal rate_high)
      point "long-r$lo" "$BASE/corpus-long.jsonl" "$lo"
      point "long-r$hi" "$BASE/corpus-long.jsonl" "$hi"
      point "short-r$hi" "$BASE/corpus-short.jsonl" "$hi"
      report
    else code=1; fi
    fleet_down ;;
  *) echo "usage: $0 model|fleet-up|fleet-down|report <vllm|sglang> <profileId>"; exit 64 ;;
esac
[ $code = 0 ] && echo "SCENARIO kv-model-ab-perf: PASS ($MODE $ENG $PROF)" || echo "SCENARIO kv-model-ab-perf: FAIL ($MODE $ENG $PROF)"
exit $code
