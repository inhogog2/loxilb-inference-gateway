#!/bin/bash
# validation.sh — A/B performance, KV-exact routing against round-robin, per model (LIVE GPU fleet).
#
#   ./validation.sh model <vllm|sglang|trtllm> <profileId>   fleet up -> corpus -> calibration -> three points -> fleet down
#   ./validation.sh fleet-up|fleet-down <engine> <profileId>
#   ./validation.sh report <engine> <profileId>          print the banked points as manifest `perf` entries
#
# `model` runs, for one model on one engine:
#   1. the prefill/decode fleet from PREFILLS / DECODES (launch arguments from ../kv-model-compat-pd/engine.sh);
#   2. a long-prefix corpus sized for THIS model's tokenizer (TARGET_TOKENS prompt tokens) and a short-prefix one;
#   3. a capacity calibration: closed-loop, cold (unique prefixes, nothing seeded), through the round-robin rule,
#      at the highest concurrency of 32, 16, 8, 4 at which every request completes.
#      Rates do not carry over between models or GPUs, so the offered rates are fractions of this number;
#   4. three points (point.sh): long prefix at 40 % and at 80 % of the calibrated rate, and the short-prefix
#      control at 80 %. The control has no cache benefit to win: it bounds the routing overhead and the noise.
# Needs the profile staged in the gateway registry (kv-model-compat-pd/config.sh or scripts/models/install-models.sh)
# and the model's weights on every node. One gateway, one rule port: nothing else may use the port meanwhile.
set -u
source "$(dirname "$0")/env.sh"
MODE=${1:-}; ENG=${2:-}; PROF=${3:-}
[ -n "$PROF" ] || { echo "usage: $0 model|fleet-up|fleet-down|report <vllm|sglang|trtllm> <profileId>"; exit 64; }
ab_engine_check "$ENG" || exit 64
MODEL=$(profile_field "$PROF" baseModel)
[ "$TOPOLOGY" = pd ] && BASE=${ABROOT}/${ENG}-${PROF} || BASE=${ABROOT}/${ENG}-${PROF}-${TOPOLOGY}
mkdir -p "$BASE"; export AB_BASE=$BASE
code=0
DCACHE=$(sgl_decode_cache_plan "$ENG" "$TOPOLOGY" "$PROF"); DCACHE_ARG=""
[ "$DCACHE" = on ] && DCACHE_ARG=$SGL_DECODE_CACHE_ARG
# The argument handed in by SGL_EXTRA_DECODE for a profile that would run without it: recorded as what ran.
case "$DCACHE/ ${SGL_EXTRA_DECODE:-} " in off/*" $SGL_DECODE_CACHE_ARG "*|refused/*" $SGL_DECODE_CACHE_ARG "*|unmeasured/*" $SGL_DECODE_CACHE_ARG "*) DCACHE=forced ;; esac
# A fleet that starts without the cache says so, and why: never a silent off.
decode_cache_line() {
  case $DCACHE in
  on) echo "  decode-side prefix cache: on ($SGL_DECODE_CACHE_ARG on every decode engine)" ;;
  forced) echo "  decode-side prefix cache: on, from SGL_EXTRA_DECODE" ;;
  off) echo "DECODE_CACHE_OFF SGL_DECODE_CACHE=0: the decode engines start without the decode-side prefix cache" ;;
  refused) echo "DECODE_CACHE_SKIPPED refused: SGLang $SGL_VERSION does not start a decode engine of $PROF with $SGL_DECODE_CACHE_ARG; the decode engines start without it" ;;
  unmeasured) echo "DECODE_CACHE_SKIPPED unmeasured: no decode engine of $PROF was started with $SGL_DECODE_CACHE_ARG on SGLang $SGL_VERSION (sgl_decode_cache_plan, env.sh); the decode engines start without it" ;;
  esac
}

fleet_up() {
  local n pids=() rc=0
  for n in "${PNODES[@]}"; do PREFILL=$n CONVERGED=$n EVROOT=$BASE/node-$n "$COMPAT/engine.sh" start "$ENG" "$ROLE1" "$PROF" & pids+=($!); done
  # The decode engines' own SGLang arguments: the decode-side prefix cache when this model takes it (env.sh),
  # then SGL_EXTRA_DECODE. The state is kept with the evidence: points with and without it are not comparable.
  echo "$DCACHE" > "$BASE/decode-cache.txt"
  for n in "${DNODES[@]}"; do DECODE=$n EVROOT=$BASE/node-$n SGL_EXTRA="${SGL_EXTRA:-} $DCACHE_ARG ${SGL_EXTRA_DECODE:-}" "$COMPAT/engine.sh" start "$ENG" decode "$PROF" & pids+=($!); done
  for p in "${pids[@]}"; do wait "$p" || rc=1; done
  return $rc
}
fleet_down() {
  local n
  for n in "${PNODES[@]}"; do PREFILL=$n CONVERGED=$n EVROOT=$BASE/node-$n "$COMPAT/engine.sh" stop "$ENG" "$ROLE1" "$PROF"; done
  for n in "${DNODES[@]}"; do DECODE=$n EVROOT=$BASE/node-$n "$COMPAT/engine.sh" stop "$ENG" decode "$PROF"; done
}
# An SGLang prefill engine serves a request only when it is paired with a decode engine (seed.py --pair-decode).
pair_decode() { [ "$ENG" = sglang ] && [ "$TOPOLOGY" = pd ] && [ -n "$1" ] && echo "--pair-decode http://$1:$EPORT"; return 0; }
# prompt tokens of one long-prefix chat prompt with <reps> paragraph repetitions, as the first prefill counts them
ptok() {
  python3 "$AB_DIR/gen_corpus.py" --output "$BASE/size-$1.jsonl" --families "${#PNODES[@]}" --owners "${#PNODES[@]}" --prefix-repetitions "$1" --salt "size$1-"
  head -1 "$BASE/size-$1.jsonl" > "$BASE/size-one.jsonl"
  python3 "$AB_DIR/seed.py" --corpus "$BASE/size-one.jsonl" --output "$BASE/size-$1.receipt.jsonl" --model "$MODEL" --target "http://${PNODES[0]}:$EPORT" $(pair_decode "${DNODES[0]:-}") >/dev/null
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
}
cal_snapshot() { local n; for n in "${PNODES[@]}" "${DNODES[@]}"; do curl -s -m 10 "http://$n:$EPORT$(engine_metrics_path "$ENG")" > "$BASE/$1-engine-$n.prom"; done; }
calibrate() {
  [ -s "$BASE/calibration.json" ] && { echo "  calibration already banked"; return 0; }
  local enc; enc=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "$MODEL")
  python3 "$AB_DIR/rule.py" calibration "$VIP" "$PORT" "$ENG" "$MODEL" "$PROF" "$EPORT" "$PREFILLS" "$DECODES" "$TOPOLOGY" > "$BASE/cal-rule.json"
  # Closed loop at falling concurrency until every request completes. Too many cold prefills at once is not a
  # capacity number: the decode engines pull each prefix late, the prefill engine's KV lease runs out, and the
  # engine ends those streams with no token. Every attempt gets a fleet with nothing queued and prefixes used
  # nowhere else.
  local http c n rc=1
  for c in ${CAL_CONCURRENCY:-32 16 8 4}; do
    python3 "$AB_DIR/gen_corpus.py" --output "$BASE/corpus-cal.jsonl" --families $((FAMILIES * 2)) --owners "${#PNODES[@]}" \
      --prefix-repetitions "$(cat "$BASE/prefix-repetitions.txt")" --salt "cal$c-$(date +%s)-"
    # CAL_WARMUP=1: one long prompt with its own prefix on every prefill engine before the timed run. A freshly
    # started SGLang engine takes seconds for its first long prefill; inside the window that stall is counted as
    # capacity the fleet does not have, and the point rates come out too low.
    if [ "${CAL_WARMUP:-0}" = 1 ]; then
      local w=(); for n in "${PNODES[@]}"; do w+=(--target "http://$n:$EPORT"); done
      python3 "$AB_DIR/gen_corpus.py" --output "$BASE/corpus-cal-warmup.jsonl" --families "${#PNODES[@]}" --owners "${#PNODES[@]}" \
        --prefix-repetitions "$(cat "$BASE/prefix-repetitions.txt")" --salt "warm$c-$(date +%s)-"
      python3 "$AB_DIR/seed.py" --corpus "$BASE/corpus-cal-warmup.jsonl" --output "$BASE/cal-warmup-c$c.receipt.jsonl" --model "$MODEL" \
        "${w[@]}" $(pair_decode "${DNODES[0]:-}") || { echo "CAL_WARMUP_FAILED"; return 1; }
      # A decode engine that keeps its own prefix cache has a first long request of its own: warm the others too.
      for n in "${DNODES[@]:1}"; do
        python3 "$AB_DIR/seed.py" --corpus "$BASE/corpus-cal-warmup.jsonl" --output "$BASE/cal-warmup-c$c-decode-$n.receipt.jsonl" --model "$MODEL" \
          "${w[@]}" $(pair_decode "$n") || { echo "CAL_WARMUP_FAILED decode $n"; return 1; }
      done
    fi
    http=$(curl -s -m 10 -o "$BASE/cal-rule-create.json" -w "%{http_code}" -X POST "${LB}" -H 'Content-Type: application/json' --data-binary "@$BASE/cal-rule.json")
    [ "$http" = 200 ] || { echo "CAL_RULE_CREATE_FAILED $http"; return 1; }
    sleep 5
    # The engines' counters around the calibration run are kept: a rate that came out low is read from them
    # (transfers, queue, computed tokens), not guessed. No gate reads them.
    cal_snapshot "cal-c$c-before"
    python3 "$AB_DIR/bench.py" --corpus "$BASE/corpus-cal.jsonl" --output "$BASE/cal-requests.jsonl" --url "http://${VIP}:${PORT}" \
      --model "$MODEL" --arm baseline --repetition 0 --max-tokens "$MAX_TOKENS" --concurrency "$c" --timeout 120
    rc=$?
    cal_snapshot "cal-c$c-after"
    curl -s -m 10 -o /dev/null -X DELETE "${LB}/hosturl/${VIP}/externalipaddress/${VIP}/port/${PORT}/protocol/tcp?model_name=${enc}"
    [ $rc = 0 ] && { echo "$c" > "$BASE/cal-concurrency.txt"; break; }
    cp "$BASE/cal-requests.jsonl" "$BASE/cal-requests-c$c-incomplete.jsonl"
    echo "  calibration at concurrency $c: $(grep -c '"completed": false' "$BASE/cal-requests.jsonl") incomplete requests; fleet restart, next step"
    fleet_up >/dev/null || { echo "CAL_FLEET_RESTART_FAILED"; return 1; }
  done
  [ $rc = 0 ] || { echo "CAL_REQUESTS_INCOMPLETE at every concurrency"; return 1; }
  # The point rates have floors. A fleet whose measured capacity is below a floored rate would be offered more than
  # it can serve in every arm: that is refused here, with no calibration banked.
  python3 "$AB_DIR/calib.py" "$BASE/cal-requests.jsonl" "$BASE/calibration.json" "$BASE/cal-concurrency.txt"
}
cal() { python3 -c "import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])" "$BASE/calibration.json" "$1"; }
repeat_for() { python3 -c "import math,sys; print(max(3, math.ceil(float(sys.argv[1]) * $ARM_SECONDS / $FAMILIES)))" "$1"; }
point() { "$AB_DIR/point.sh" "$ENG" "$PROF" "$1" "$2" "$3" "$(repeat_for "$3")" "${4:-chat}" || { code=1; return 1; }; }
report() {
  [ -s "$BASE/decode-cache.txt" ] && [ "$(cat "$BASE/decode-cache.txt")" != none ] && echo "# decode-side prefix cache: $(cat "$BASE/decode-cache.txt")"
  python3 - "$BASE" "$ENG" <<'PY'
import glob, json, os, sys
base, eng = sys.argv[1:]
for f in sorted(glob.glob(base + "/*/ab-summary.json")):
    d = os.path.dirname(f); s = json.load(open(f)); meta = dict(x.split("=", 1) for x in open(d + "/point.txt").readline().split())
    e, b, fx = s["arms"]["exact"], s["arms"]["baseline"], s["effects"]
    npre = len(open(d + "/point.txt").read().split("prefill=")[1].split("\n")[0].split()); ndec = len(open(d + "/point.txt").read().split("decode=")[1].split("\n")[0].split())
    topo = f"pd-{npre}p{ndec}d" if ndec else f"converged-{npre}e"
    print(f"# {os.path.basename(d)}: p95 {fx['ttft_p95_delta_percent']:+.1f}% ({fx['ttft_p95_separation']}), CI {fx['ttft_p95_delta_95ci_percent']}, "
          f"p50 {fx['ttft_p50_delta_percent']:+.1f}% ({fx['ttft_p50_separation']}), TPOT p95 {fx['tpot_p95_delta_percent']:+.1f}%, tokens/s {fx['output_tokens_per_sec_delta_percent']:+.1f}%")
    if "slow_request_percent" in e:
        na = lambda v: "n/a" if v is None else f"{v}%"
        print(f"#   slow requests (TTFT >= {s['slow_request_ttft_ms']} ms) {na(e['slow_request_percent'])} exact vs {na(b['slow_request_percent'])} baseline; "
              f"prompt tokens computed {na(e['computed_prompt_token_percent'])} exact vs {na(b['computed_prompt_token_percent'])} baseline")
    if e.get("kv_transfers") is not None and b.get("kv_transfers") is not None:
        kv = lambda a: f"{a['kv_transfers']} of {a['kv_transfer_mb_each']} MB and {a['kv_transfer_ms_each']} ms each, {a['kv_transfer_failed']} failed"
        print(f"#   KV transfers: exact {kv(e)}; baseline {kv(b)}")
    print(f"- {{topology: {topo}, surface: {meta['api']}, corpus: {os.path.basename(d).split('-')[0]}, rateRps: {meta['rate']}, "
          f"requestsPerArm: {e['requests']}, exactTtftP95Ms: {e['ttft_p95_ms']}, baselineTtftP95Ms: {b['ttft_p95_ms']}, "
          f"exactTtftP50Ms: {e['ttft_p50_ms']}, baselineTtftP50Ms: {b['ttft_p50_ms']}, date: \"{os.popen('date -r ' + f + ' +%F').read().strip()}\"}}")
PY
}

case $MODE in
  fleet-up) decode_cache_line; fleet_up || code=1 ;;
  fleet-down) fleet_down ;;
  report) report ;;
  model)
    echo "=== A/B $ENG x $PROF ($MODEL), $TOPOLOGY: ${#PNODES[@]} $ROLE1 [$PREFILLS] + ${#DNODES[@]} decode [$DECODES] ==="
    decode_cache_line
    if fleet_up && corpora && calibrate; then
      lo=$(cal rate_low); hi=$(cal rate_high)
      point "long-r$lo" "$BASE/corpus-long.jsonl" "$lo"
      point "long-r$hi" "$BASE/corpus-long.jsonl" "$hi"
      point "short-r$hi" "$BASE/corpus-short.jsonl" "$hi"
      report
    else code=1; fi
    fleet_down ;;
  *) echo "usage: $0 model|fleet-up|fleet-down|report <vllm|sglang|trtllm> <profileId>"; exit 64 ;;
esac
[ $code = 0 ] && echo "SCENARIO kv-model-ab-perf: PASS ($MODE $ENG $PROF)" || echo "SCENARIO kv-model-ab-perf: FAIL ($MODE $ENG $PROF)"
exit $code
