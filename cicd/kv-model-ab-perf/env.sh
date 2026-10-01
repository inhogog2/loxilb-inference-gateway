#!/bin/bash
# env.sh — settings for the kv-model-ab-perf scenario (sourced, never run).
#
# The fleet is a list of prefill nodes and a list of decode nodes; an A/B needs at least two prefill engines
# (with one, both routing modes pick the same engine). Engines are launched by ../kv-model-compat-pd/engine.sh,
# one call per node, so every per-model launch argument proven there applies here unchanged.
: "${PREFILLS:?set PREFILLS to the prefill node addresses (space separated, at least two)}"
: "${DECODES:?set DECODES to the decode node addresses (space separated)}"
read -r -a PNODES <<<"$PREFILLS"; read -r -a DNODES <<<"$DECODES"
[ ${#PNODES[@]} -ge 2 ] || { echo "an A/B needs at least two prefill engines" >&2; exit 64; }
export PREFILL=${PNODES[0]} DECODE=${DNODES[0]}     # the compat scenario's single-pair variables
AB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPAT="${AB_DIR}/../kv-model-compat-pd"
source "${COMPAT}/env.sh"
ABROOT=${ABROOT:-/var/tmp/kv-model-ab-perf}        # evidence root
FAMILIES=${FAMILIES:-60}                           # prompt families (a multiple of the prefill count)
TARGET_TOKENS=${TARGET_TOKENS:-3400}               # long-prefix prompt size, under the engines' 4096 context
ARM_SECONDS=${ARM_SECONDS:-150}                    # offered-load duration of one arm
MAX_TOKENS=${MAX_TOKENS:-32}
REPS=${REPS:-3}
