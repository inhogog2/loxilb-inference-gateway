#!/bin/bash
# env.sh — shared settings for the kv-model-compat-pd scenario (sourced, never run).
#
# The scenario drives a LIVE GPU pair (one prefill node, one decode node) and a gateway already running on the
# host that executes these scripts. Every site-specific value comes from the environment; the required ones
# have no default so a run on the wrong bed fails before it touches anything.

: "${PREFILL:?set PREFILL to the prefill engine node address}"
: "${DECODE:?set DECODE to the decode engine node address}"
: "${VIP:?set VIP to the gateway address the P/D rule listens on}"

PORT=${PORT:-8080}                    # rule port on the VIP (must be free; the legs create and delete it)
EPORT=${EPORT:-8000}                  # engine HTTP port on both nodes
GW_CTR=${GW_CTR:-loxilb}              # gateway container on this host (host network)
GW_API=${GW_API:-http://127.0.0.1:11111/netlox/v1}
REG=${REG:-/etc/loxilb/kvprofiles}    # host path mounted read-only at the gateway's /etc/loxilb/kvprofiles
TOKDIR=${TOKDIR:-/etc/loxilb/tokenizers}
LOGD=${LOGD:?set LOGD to the host directory mounted at the gateway container /var/log}
HF_CACHE=${HF_CACHE:-/root/.cache/huggingface}   # on the engine nodes; weights at the pinned revisions
SSH=${SSH:-ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new}   # e.g. "ssh -i <key>"
EVROOT=${EVROOT:-/var/tmp/kv-model-compat-pd}

# Engine images the committed manifests pin (manifests/, manifests-sglang/).
VLLM_IMAGE='vllm/vllm-openai@sha256:61fc8a896b0a4fbbbdc063bc4b0dbc25ce98e02b5050c24aeb7830ac02039b14'
VLLM_VERSION=0.28.0
SGL_IMAGE='lmsysorg/sglang@sha256:9e148f5ac788e856a06166bd6347a831831eb9fcfab4d1770874823a7c29a1a1'
SGL_VERSION=0.5.18

SCENARIO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIX="${SCENARIO_DIR}/../common/kv_hash/fixtures"
LB="${GW_API}/config/loadbalancer"
MET="${GW_API}/metrics"

# profile_field <profileId> <yaml key> — one scalar from a committed profile
profile_field() { sed -n "s/^$2: *//p" "${FIX}/profiles/$1.yaml" | tr -d '"'; }
# snapshot <hf-id> <rev> — the engine-node path of a pinned snapshot
snapshot() { echo "${HF_CACHE}/hub/models--${1//\//--}/snapshots/$2"; }
