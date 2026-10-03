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
ABROOT=${ABROOT:-/var/tmp/kv-model-ab-perf}        # evidence root
FAMILIES=${FAMILIES:-60}                           # prompt families (a multiple of the prefill count)
TARGET_TOKENS=${TARGET_TOKENS:-3400}               # long-prefix prompt size, under the engines' 4096 context
ARM_SECONDS=${ARM_SECONDS:-150}                    # offered-load duration of one arm
MAX_TOKENS=${MAX_TOKENS:-32}
REPS=${REPS:-3}
