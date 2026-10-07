#!/bin/bash
# env.sh — settings for the kv-model-ab-perf scenario (sourced, never run).
#
# TOPOLOGY=pd: a list of prefill nodes and a list of decode nodes. TOPOLOGY=converged: a list of engines that
# each do both. An A/B needs at least two engines to choose from (with one, both routing modes pick the same). Engines are launched by ../kv-model-compat-pd/engine.sh,
# one call per node, so every per-model launch argument proven there applies here unchanged.
: "${TOPOLOGY:=pd}"                                  # pd (prefill + decode engines) | converged (one role per engine)
case $TOPOLOGY in
pd)
  : "${PREFILLS:?set PREFILLS to the prefill node addresses (space separated, at least two)}"
  : "${DECODES:?set DECODES to the decode node addresses (space separated)}"
  ROLE1=prefill ;;
converged)
  : "${ENGINES:?set ENGINES to the converged engine node addresses (space separated, at least two)}"
  PREFILLS=$ENGINES DECODES="" ROLE1=converged ;;
*) echo "TOPOLOGY must be pd|converged" >&2; exit 64 ;;
esac
# PNODES = the engines the rule routes the prompt to (the prefill engines, or every converged engine).
read -r -a PNODES <<<"$PREFILLS"; read -r -a DNODES <<<"$DECODES"
[ ${#PNODES[@]} -ge 2 ] || { echo "an A/B needs at least two engines to choose from" >&2; exit 64; }
export PREFILL=${PNODES[0]} DECODE=${DNODES[0]:-${PNODES[0]}}     # the compat scenario's single-pair variables
AB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPAT="${AB_DIR}/../kv-model-compat-pd"
source "${COMPAT}/env.sh"
# ab_engine_check <engine> [api] — the engines the scenario drives, and the shapes it drives each in.
# TensorRT-LLM is measured as one pool of converged engines on the chat surface: that is what its rows in
# scripts/models/validated-models.yaml claim, and ../kv-model-compat-pd/engine.sh launches no other role of it.
ab_engine_check() {
  case $1 in vllm|sglang) return 0 ;; trtllm) ;; *) echo "engine must be vllm|sglang|trtllm" >&2; return 64 ;; esac
  [ "$TOPOLOGY" = converged ] || { echo "TRTLLM_TOPOLOGY_UNSUPPORTED $TOPOLOGY: TensorRT-LLM is measured converged only (TOPOLOGY=converged ENGINES=...)" >&2; return 64; }
  [ "${2:-chat}" = chat ] || { echo "TRTLLM_SURFACE_UNSUPPORTED $2: TensorRT-LLM is measured on the chat surface only" >&2; return 64; }
}
ABROOT=${ABROOT:-/var/tmp/kv-model-ab-perf}        # evidence root
FAMILIES=${FAMILIES:-60}                           # prompt families (a multiple of the prefill count)
TARGET_TOKENS=${TARGET_TOKENS:-3400}               # long-prefix prompt size, under the engines' 4096 context
ARM_SECONDS=${ARM_SECONDS:-150}                    # offered-load duration of one arm
MAX_TOKENS=${MAX_TOKENS:-32}
REPS=${REPS:-3}
# SGLang decode-side prefix cache on a prefill/decode fleet: a decode engine keeps the prefixes it received, so a
# later request of the same family transfers only what is missing. On by default for the models whose decode
# engine was started with it; SGL_DECODE_CACHE=0 turns it off for points comparable with rows measured without.
SGL_DECODE_CACHE=${SGL_DECODE_CACHE:-1}
case $SGL_DECODE_CACHE in 0|1) ;; *) echo "SGL_DECODE_CACHE must be 0|1" >&2; exit 64 ;; esac
SGL_DECODE_CACHE_ARG="--disaggregation-decode-enable-radix-cache"
# sgl_decode_cache_plan <engine> <topology> <profileId> — on | off | refused | unmeasured | none
# Per SGLang version and profile, each row measured by starting a decode engine with the argument. SGLang refuses
# it at start for sliding-window attention (gemma-4) and for state-space layers (Qwen3.8): the engine exits with
# a ValueError. A profile with no row runs without the cache until its row is measured.
sgl_decode_cache_plan() {
  [ "$1" = sglang ] && [ "$2" = pd ] || { echo none; return 0; }
  [ "$SGL_DECODE_CACHE" = 1 ] || { echo off; return 0; }
  case $SGL_VERSION/$3 in
  0.5.18/r1-distill-qwen-15b-v1|0.5.18/exaone4-12b-v1|0.5.18/granite42-3b-v1|0.5.18/olmo2-0425-1b-v1|\
  0.5.18/phi4-mini-instruct-v1|0.5.18/gemma3-1b-it-v1|0.5.18/llama32-1b-v1|0.5.18/ax31-light-v1) echo on ;;
  0.5.18/gemma4-e2b-it-v1|0.5.18/qwen38-27b-fp8-v1) echo refused ;;
  *) echo unmeasured ;;
  esac
}
# sgl_second_seed_plan <engine> <topology> <profileId> — second | none
# SGLang keeps a state-space model's recurrent state only where a request saved one: a seed saves it at its own
# end, and the state at the end of the shared prefix is saved by the first later request that branches there.
# With one seed per family the first timed request of every family is computed in full and the first-round check
# refuses the arm. For the profiles listed, each measured on one pool of SGLang 0.5.18 engines, every family is
# seeded a second time with another ending, in both arms.
sgl_second_seed_plan() {
  [ "$1" = sglang ] && [ "$2" = converged ] || { echo none; return 0; }
  case $SGL_VERSION/$3 in
  0.5.18/qwen38-27b-fp8-v1) echo second ;;
  *) echo none ;;
  esac
}
