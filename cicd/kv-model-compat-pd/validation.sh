#!/bin/bash
# validation.sh [preflight|admission|pd|all] — candidate-model qualification on a live GPU pair.
#
#   preflight  the gateway's latest registry publish holds at least every committed candidate profile
#   admission  engine-renderer admission matrix (no engine needed: admission refuses before any probe):
#              ministral3 (model_type mistral3) strict chat/both refused on vllm + sglang with the
#              mistral_common sentence; gptoss (model_type gpt_oss) refused on vllm + trtllm with the Harmony
#              sentence; completions admitted everywhere; the engines that render the pinned template admit chat.
#              Every admitted rule is deleted at once.
#   pd         strict P/D chat legs, each run TWICE (engine pair launched per model, stopped after):
#                vllm   gemma3-1b-it-v1  phi4-mini-instruct-v1  granite42-3b-v1
#                sglang phi4-mini-instruct-v1
#              Not in the list, with the reason: SGLang 0.5.18 x {gemma-3, granite-4.2, gpt-oss} — the engine's
#              /v1/tokenize answers 500 for tokenizers whose model_max_length is 1e30 (fixed upstream in 0.5.19), so
#              the token-parity probe fails closed and the rule can never reach READY.
#              Override with PD_LEGS="vllm:<profileId> sglang:<profileId> ...".
#   all        preflight, admission, pd (default)
set -u
source "$(dirname "$0")/env.sh"
cd "$SCENARIO_DIR"
MODE=${1:-all}
code=0
check() { if [ "$2" = "0" ]; then echo "  PASS: $1"; else echo "  FAIL: $1"; code=1; fi; }

preflight() {
  echo "=== preflight: registry publish ==="
  local want line n
  want=$(ls "${FIX}/profiles"/*.yaml | wc -l)
  line=$(docker exec "$GW_CTR" sh -c 'grep -ah "kv-profile: published generation" /var/log/loxilb*.log' 2>/dev/null | tail -1)
  n=$(echo "$line" | sed -n 's/.*(\([0-9]*\) profiles.*/\1/p')
  echo "  ${line:-no publish line}"
  local missing=0
  for p in "${FIX}/profiles"/*.yaml; do [ -f "$REG/$(basename "$p")" ] || { echo "  not staged: $(basename "$p")"; missing=1; }; done
  [ -n "$n" ] && [ "$n" -ge "$want" ] && [ $missing = 0 ]
  check "gateway published >= ${want} profiles and every committed candidate profile is staged (run ./config.sh, restart the gateway)" $?
}

admission_one() {  # admission_one <profileId> <sentence> <refusing engines...>
  local prof=$1 sentence=$2; shift 2
  local refusing=" $* " model enc eng api out st want ok
  model=$(profile_field "$prof" baseModel)
  enc=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "$model")
  for eng in vllm sglang trtllm; do for api in both chat completions; do
    out=$(curl -s -m 10 -w '\nHTTPSTATUS:%{http_code}' -X POST "${LB}" -H 'Content-Type: application/json' -d "{
  \"serviceArguments\": { \"externalIP\": \"${VIP}\", \"port\": ${PORT}, \"protocol\": \"tcp\", \"sel\": 0,
    \"mode\": 4, \"host\": \"${VIP}\", \"probeRetries\": 1, \"pd_disagg_mode\": true, \"kvExactMode\": 1, \"kvBlockSize\": 16,
    \"kvEngineType\": \"${eng}\", \"model_name\": \"${model}\", \"kvExactApiMode\": \"${api}\", \"kvModelProfile\": \"${prof}\" },
  \"endpoints\": [ { \"endpointIP\": \"${PREFILL}\", \"targetPort\": ${EPORT}, \"weight\": 1, \"ep_role\": 1 },
                   { \"endpointIP\": \"${DECODE}\", \"targetPort\": ${EPORT}, \"weight\": 1, \"ep_role\": 2 } ] }")
    st=$(echo "$out" | sed -n 's/^HTTPSTATUS://p')
    [ "$st" = 200 ] && curl -s -m 10 -o /dev/null -X DELETE "${LB}/hosturl/${VIP}/externalipaddress/${VIP}/port/${PORT}/protocol/tcp?model_name=${enc}"
    want=admit; [[ "$refusing" == *" $eng "* && $api != completions ]] && want=refuse
    if [ $want = refuse ]; then [ "$st" != 200 ] && echo "$out" | grep -qF "$sentence"; ok=$?
    else [ "$st" = 200 ]; ok=$?; fi
    [ $ok = 0 ] || echo "    reply: HTTP $st $(echo "$out" | grep -v HTTPSTATUS: | head -c 240)"
    check "admission ${prof} ${eng} kvExactApiMode=${api}: ${want}" $ok
  done; done
}

admission() {
  echo "=== admission: engine-renderer matrix ==="
  curl -s -m 5 "${LB}/all" | grep -q "\"port\":${PORT}" && { check "rule port ${PORT} free before the matrix" 1; return; }
  admission_one ministral3-3b-v1 "renders this model's chat with mistral_common" vllm sglang
  admission_one gptoss-20b-v1 "renders this model's chat with the Harmony encoder" vllm trtllm
  curl -s -m 5 "${LB}/all" | grep -q "\"port\":${PORT}"; [ $? != 0 ]
  check "no rule left on port ${PORT}" $?
}

pd() {
  local legs=${PD_LEGS:-"vllm:gemma3-1b-it-v1 vllm:phi4-mini-instruct-v1 vllm:granite42-3b-v1 sglang:phi4-mini-instruct-v1"}
  local leg eng prof run
  for leg in $legs; do
    eng=${leg%%:*}; prof=${leg##*:}
    echo "=== pd: ${eng} x ${prof} ==="
    if ! { ./engine.sh start "$eng" prefill "$prof" && ./engine.sh start "$eng" decode "$prof"; }; then
      check "pd ${eng} ${prof}: engine pair up" 1
    else
      for run in 1 2; do ./leg.sh "$eng" "$prof"; check "pd ${eng} ${prof} run ${run}" $?; done
    fi
    ./engine.sh stop "$eng" prefill "$prof"; ./engine.sh stop "$eng" decode "$prof"
  done
}

case $MODE in
  preflight) preflight ;;
  admission) admission ;;
  pd) pd ;;
  all) preflight; [ $code = 0 ] && { admission; pd; } ;;
  *) echo "usage: $0 [preflight|admission|pd|all]"; exit 64 ;;
esac
[ $code = 0 ] && echo "SCENARIO kv-model-compat-pd: PASS ($MODE)" || echo "SCENARIO kv-model-compat-pd: FAIL ($MODE)"
exit $code
