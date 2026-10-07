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
# TensorRT-LLM has no registry image: it is built locally from the release wheel, so the pin is the image id and
# engine.sh compares it with the id of TRT_IMAGE on the node before every launch (a tag can name any image).
TRT_IMAGE=${TRT_IMAGE:-loxilb-trtllm:1.3.0rc24-r3}
TRT_IMAGE_ID=sha256:a867619fd56c85225927dac27e2111ae90ff66e23c59d9c5f8b9f345577cab6d
TRT_VERSION=1.3.0rc24
TRT_LIBS=${TRT_LIBS:-/usr/local/lib/python3.12/dist-packages/tensorrt_llm/libs}   # the wheel's bundled libraries, in the image
# SGLang /v1/tokenize fix (engine.sh SGL_TOKPATCH). The action is chosen by the sha256 of the serving_tokenize.py
# the image itself ships, never by a version string: rebuilt, post-release and forked images are identified
# exactly, and a file nobody has reviewed is refused. The committed fix file is SGLang v0.5.19's, unmodified.
SGL_TOKPATCH_TARGET=/sgl-workspace/sglang/python/sglang/srt/entrypoints/openai/serving_tokenize.py
SGL_TOKPATCH_FILE_SHA=7ef745d2d1ba1bee722a3ddc3ec0feb700a6e0aef40645ad67b7d04876e921f2
# sgl_tokpatch_plan <stock sha256> — mount | fixed | nochat | unknown
sgl_tokpatch_plan() {
  case $1 in
  # v0.5.12 - v0.5.18 (one identical file): /v1/tokenize answers 500 when model_max_length is int(1e30).
  f1791dbe89245cf80f2ae3c3f052e944c0b602deaf45909a31d2e4aabfc95711) echo mount ;;
  # v0.5.19 - v0.5.20: fixed upstream (sgl-project/sglang#37054); this IS the committed file.
  7ef745d2d1ba1bee722a3ddc3ec0feb700a6e0aef40645ad67b7d04876e921f2) echo fixed ;;
  # v0.5.4 - v0.5.11: /v1/tokenize has no `messages` form, so a strict chat rule cannot attest at all.
  9202c10bc6bf8f5e93d869b99efe036948e3b7dbe87abadb7be2eb079849cfed) echo nochat ;;
  *) echo unknown ;;
  esac
}

SCENARIO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIX="${SCENARIO_DIR}/../common/kv_hash/fixtures"
SGL_TOKPATCH_FILE="${SCENARIO_DIR}/sglang-tokenize-fix/serving_tokenize.py"
TRT_CONVERGED_YAML="${SCENARIO_DIR}/trtllm/converged.yaml"
LB="${GW_API}/config/loadbalancer"
MET="${GW_API}/metrics"

# sgl_static_mem <role> <profileId> — the --mem-fraction-static of an SGLang engine (SGL_MEM overrides it).
# Per version, profile and role, each row measured.
# Qwen3.8-27B-FP8 (0.5.18, one L40S, converged): at 0.70 the pool of recurrent states is 12 slots, 5 per running
# request, so the engine runs two requests at most and a second request in flight evicts the saved states of the
# other prefixes (their next request is computed in full). At 0.85 it is 36 slots and 7 running requests, with
# 4.7 GB of the GPU left free.
sgl_static_mem() {
  case $SGL_VERSION/$2/$1 in
  0.5.18/qwen38-27b-fp8-v1/converged) echo 0.85 ;;
  *) echo 0.70 ;;
  esac
}
# trt_blocked <profileId> — the reason TensorRT-LLM TRT_VERSION cannot serve the model under a strict chat rule,
# or nothing. Each row was observed on the engine (scripts/models/validated-models.yaml carries the same rows).
trt_blocked() {
  case $TRT_VERSION/$1 in
  1.3.0rc24/olmo2-0425-1b-v1) echo "architecture_unsupported: the engine's model registry has no Olmo2ForCausalLM" ;;
  1.3.0rc24/granite42-3b-v1) echo "architecture_unsupported: the engine's model registry has no GraniteForCausalLM" ;;
  1.3.0rc24/gemma4-e2b-it-v1) echo "hardware_unsupported: the engine's attention kernel for this model does not run on Ada-generation GPUs" ;;
  1.3.0rc24/ministral3-3b-v1) echo "checkpoint_format: the official checkpoint is per-tensor FP8; the engine's loader accepts block FP8 only" ;;
  1.3.0rc24/gptoss-20b-v1) echo "engine_renderer: the engine renders chat for this model with the Harmony encoder, not the chat template" ;;
  esac
}
# trt_port_free <node> — wait until the node holds no socket on the engine port. trtllm-serve binds the port
# without SO_REUSEADDR before it loads the model, so a start within a minute of the previous engine's stop finds
# the port held by that engine's closed connections (TIME_WAIT) and exits with "Address already in use".
trt_port_free() {
  local _
  for _ in $(seq 1 60); do
    [ "$($SSH -n root@"$1" "ss -Htan 'sport = :$EPORT' | wc -l")" = 0 ] && return 0
    sleep 2
  done
  echo "ENGINE_PORT_HELD $1:$EPORT"; return 1
}
# engine_metrics_path <engine> — where the engine serves Prometheus text. TensorRT-LLM's /metrics is a JSON
# queue of iteration statistics that a read empties; its Prometheus text is at /prometheus/metrics.
engine_metrics_path() { [ "$1" = trtllm ] && echo /prometheus/metrics || echo /metrics; }
# profile_field <profileId> <yaml key> — one scalar from a committed profile
profile_field() { sed -n "s/^$2: *//p" "${FIX}/profiles/$1.yaml" | tr -d '"'; }
# snapshot <hf-id> <rev> — the engine-node path of a pinned snapshot
snapshot() { echo "${HF_CACHE}/hub/models--${1//\//--}/snapshots/$2"; }
