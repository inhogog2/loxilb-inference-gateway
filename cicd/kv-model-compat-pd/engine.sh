#!/bin/bash
# engine.sh start|stop vllm|sglang|trtllm prefill|decode|converged <profileId> — one P/D pair member on its node,
# or one converged engine (prefill and decode in one process, KV events on) on the node in CONVERGED.
#
# Launch lines are the P/D-proven ones: offline (HF_HUB_OFFLINE=1), digest-pinned image, UTC, block/page 16,
# KV events on the prefill member. vLLM runs with PYTHONHASHSEED=0 (NONE_HASH seed) and NIXL; SGLang with
# mooncake transfer.
#
# SGLang is launched from the snapshot PATH plus --revision. --revision is what makes /server_info report
# `revision`, which the gateway's identity probe compares with the manifest. The path matters as much: with a
# hub id as --model-path, SGLang 0.5.18 (transformers 5.12.1) builds a GPT2Tokenizer (Phi-4-mini) with a bare
# ByteLevel pre-tokenizer instead of the tokenizer.json split regex, so /v1/tokenize and the chat serving path
# both disagree with the pinned tokenizer (punctuation and newlines stop merging) and attestation fails closed.
#
# SGLang 0.5.12 - 0.5.18's /v1/tokenize answers 500 for a tokenizer whose model_max_length is transformers'
# "unlimited" sentinel int(1e30) (gemma-3, granite-4.2, gpt-oss): orjson cannot encode an integer that large, and
# the gateway's token-parity probe fails closed. sglang-tokenize-fix/serving_tokenize.py is v0.5.19's file, where
# upstream substitutes the model's context length; only the tokenize endpoint changes, never the serving path.
# SGL_TOKPATCH (SGLang only):
#   auto (default)  read the sha256 of the image's own file and act on sgl_tokpatch_plan (env.sh): mount the fix
#                   over an affected file, launch unchanged when the image is already fixed, refuse otherwise
#   1               require the mount (refused unless the image's file is an affected one)
#   0               never mount (the red twin: the probe must then fail on the engine's 500)
# A mounted file's sha256 is checked on the node before launch and inside the running container after readiness.
#
# TensorRT-LLM (PyTorch backend) runs converged only: its prefill/decode pair is not driven here. The image is a
# local build pinned by id (env.sh). The engine publishes KV events on its own HTTP port (/kv_cache_events, a
# queue the gateway drains: nothing else may read it), with 32 tokens per block. It is ready when it serves the
# model id and /health answers. A model the engine cannot serve is refused before anything starts (trt_blocked).
set -eu
source "$(dirname "$0")/env.sh"
ACT=$1 ENG=$2 ROLE=$3 PROF=$4
MODEL=$(profile_field "$PROF" baseModel); REV=$(profile_field "$PROF" tokenizerRevision)
case $ROLE in prefill) NODE=$PREFILL ;; decode) NODE=$DECODE ;; converged) NODE=${CONVERGED:?set CONVERGED to the converged engine node address} ;;
  *) echo "role must be prefill|decode|converged"; exit 64 ;; esac
NAME=kvmc-$ENG-$ROLE
# Keep the engine's own log: a crash after readiness is diagnosable only from it, and rm destroys it. A start
# replaces a container of the same name, so it keeps that container's log too: a relaunch after a failed attempt
# (a calibration step, a leg) is otherwise the moment the attempt's evidence is lost.
keep_log() {
  $SSH -n root@"$NODE" "docker inspect $NAME >/dev/null 2>&1" || return 0
  mkdir -p "$EVROOT/engine-logs"; local lf="$EVROOT/engine-logs/$NAME-$PROF-$(date -u +%Y%m%dT%H%M%SZ).log"
  $SSH -n root@"$NODE" "docker logs $NAME" > "$lf" 2>&1 && echo "$NAME log: $lf" || echo "$NAME log not kept ($lf)"
}
if [ "$ACT" = stop ]; then
  keep_log
  $SSH root@"$NODE" "docker rm -f $NAME >/dev/null 2>&1 || true"; exit 0
fi
[ "$ACT" = start ] || { echo "usage: $0 start|stop vllm|sglang|trtllm prefill|decode|converged <profileId>"; exit 64; }
if [ "$ENG" = trtllm ]; then
  [ "$ROLE" = converged ] || { echo "ENGINE_ROLE_UNSUPPORTED trtllm $ROLE: TensorRT-LLM is launched converged only"; exit 64; }
  why=$(trt_blocked "$PROF"); [ -z "$why" ] || { echo "ENGINE_MODEL_BLOCKED trtllm $TRT_VERSION x $PROF: $why"; exit 1; }
  got=$($SSH -n root@"$NODE" "docker image inspect -f '{{.Id}}' $TRT_IMAGE 2>/dev/null")
  [ "$got" = "$TRT_IMAGE_ID" ] || { echo "ENGINE_IMAGE_MISMATCH $NODE: $TRT_IMAGE is ${got:-absent}, pinned $TRT_IMAGE_ID"; exit 1; }
fi
SNAP=$(snapshot "$MODEL" "$REV")
# Per-version, per-profile SGLang launch arguments, each measured (a flag one release lacks stops its launch).
# gemma-3 (0.5.18, L4): the prefill member's prefill CUDA graph ("breakable" backend) pads a ragged prefill batch,
# and flashinfer's ragged prefill then raises "q.shape[0] (48) does not match qo_indptr[-1] (39)" on the first
# real prefill; the scheduler dies and the engine exits. Disabling only the prefill graph keeps decode CUDA graphs.
# EXAONE-4 (0.5.18): Exaone4ForCausalLM accepts only the fa3, triton or trtllm_mha attention backends, and fa3
# needs Hopper; on Ada the default leaves none selected and the launch asserts.
# OLMo-2 (0.5.18): the decode member's decode CUDA graph capture fails ("Capture cuda graph failed:
# scheduler_metadata must have shape (metadata_size)") and the engine exits before readiness.
case $ENG/$SGL_VERSION/$PROF in
sglang/0.5.18/gemma3-1b-it-v1) SGL_PROFILE_ARGS="--cuda-graph-backend-prefill=disabled" ;;
sglang/0.5.18/exaone4-12b-v1) SGL_PROFILE_ARGS="--attention-backend triton" ;;
sglang/0.5.18/olmo2-0425-1b-v1) SGL_PROFILE_ARGS="--disable-cuda-graph" ;;
*) SGL_PROFILE_ARGS="" ;;
esac
SGL_STATIC_MEM=${SGL_MEM:-$(sgl_static_mem "$ROLE" "$PROF")}
# Per-version, per-profile vLLM launch arguments, each measured.
# Qwen3.6 / Qwen3.8 27B-FP8 (0.28.0, one L40S): hybrid Mamba; the default 256 sequences exceed the Mamba cache
# blocks left after the weights ("max_num_seqs (256) exceeds available Mamba cache blocks (180)"), and the NIXL
# connector refuses to start without the DS conv-state layout ("3-read Mamba conv transfer requires DS conv state
# layout. Set VLLM_SSM_CONV_STATE_LAYOUT=DS").
case $ENG/$VLLM_VERSION/$PROF in
vllm/0.28.0/qwen36-27b-fp8-v1|vllm/0.28.0/qwen38-27b-fp8-v1)
  VLLM_PROFILE_ARGS="--max-num-seqs 64" VLLM_PROFILE_ENV="-e VLLM_SSM_CONV_STATE_LAYOUT=DS" ;;
*) VLLM_PROFILE_ARGS="" VLLM_PROFILE_ENV="" ;;
esac
TOKMNT="" TOKP=${SGL_TOKPATCH:-auto}
case $TOKP in auto|0|1) ;; *) echo "SGL_TOKPATCH must be auto|0|1"; exit 64 ;; esac
[ "$ENG" = sglang ] || { [ "$TOKP" = 1 ] && { echo "SGL_TOKPATCH applies to sglang only"; exit 64; }; TOKP=0; }
if [ "$TOKP" != 0 ]; then
  stock=$($SSH root@"$NODE" "docker run --rm --entrypoint sha256sum $SGL_IMAGE $SGL_TOKPATCH_TARGET" | cut -c1-64)
  plan=$(sgl_tokpatch_plan "$stock")
  case $TOKP/$plan in
  */mount) ;;
  auto/fixed) echo "$NAME: image already ships the fixed serving_tokenize.py (${stock:0:12}); no mount" ;;
  1/fixed) echo "TOKENIZE_PATCH_NOT_NEEDED $NODE image file ${stock:0:12} is already fixed"; exit 1 ;;
  */nochat) echo "TOKENIZE_NO_CHAT $NODE image file ${stock:0:12}: this SGLang (0.5.4 - 0.5.11) has no chat /v1/tokenize; strict chat cannot attest"; exit 1 ;;
  *) echo "TOKENIZE_STOCK_UNKNOWN $NODE image file ${stock:-unreadable}: review it and add a row to sgl_tokpatch_plan (env.sh)"; exit 1 ;;
  esac
fi
if [ "${plan:-}" = mount ]; then
  src=$SGL_TOKPATCH_FILE dst=/var/tmp/kvmc/serving_tokenize.py
  [ "$(sha256sum < "$src" | cut -c1-64)" = "$SGL_TOKPATCH_FILE_SHA" ] || { echo "TOKENIZE_PATCH_SHA_MISMATCH $src"; exit 1; }
  $SSH root@"$NODE" "install -d -m 0755 ${dst%/*} && cat > $dst" < "$src"
  got=$($SSH root@"$NODE" "sha256sum < $dst" | cut -c1-64)
  [ "$got" = "$SGL_TOKPATCH_FILE_SHA" ] || { echo "TOKENIZE_PATCH_COPY_MISMATCH $NODE"; exit 1; }
  TOKMNT="-v $dst:$SGL_TOKPATCH_TARGET:ro"
fi
$SSH root@"$NODE" "test -f $SNAP/config.json" || { echo "WEIGHTS_MISSING $NODE $SNAP"; exit 1; }
keep_log
EVENTS='{"enable_kv_cache_events":true,"publisher":"zmq","endpoint":"tcp://*:5557","replay_endpoint":null,"topic":""}'
case $ENG/$ROLE in
vllm/prefill) KVT='{"kv_connector":"NixlConnector","kv_role":"kv_producer","kv_buffer_device":"cpu","kv_load_failure_policy":"fail"}'; EVX="--kv-events-config '$EVENTS'" ;;
vllm/decode)  KVT='{"kv_connector":"NixlConnector","kv_role":"kv_consumer","kv_buffer_device":"cpu","kv_load_failure_policy":"fail"}'; EVX="" ;;
sglang/prefill) DIS="--disaggregation-mode prefill --disaggregation-transfer-backend mooncake --disaggregation-bootstrap-port 8998 --kv-events-config '{\"publisher\":\"zmq\",\"endpoint\":\"tcp://*:5557\"}'" ;;
sglang/decode)  DIS="--disaggregation-mode decode --disaggregation-transfer-backend mooncake" ;;
vllm/converged) KVT=""; EVX="--kv-events-config '$EVENTS'" ;;
sglang/converged) DIS="--kv-events-config '{\"publisher\":\"zmq\",\"endpoint\":\"tcp://*:5557\"}'" ;;
trtllm/converged) ;;
*) echo "engine must be vllm|sglang|trtllm"; exit 64 ;;
esac
# SGLang builds its page-hash extension at the first prompt longer than one page and keeps the result in the
# container; a node directory per image makes that one build per node instead of one per container.
SGL_EXT_CACHE=${SGL_EXT_CACHE:-/root/.cache/sglang-torch-extensions/${SGL_IMAGE##*:}}
if [ "$ENG" = vllm ]; then
  $SSH root@"$NODE" "docker rm -f $NAME >/dev/null 2>&1; docker run -d --name $NAME --gpus all --ipc=host --network host --ulimit memlock=-1 \
    -e UCX_TLS=tcp -e UCX_NET_DEVICES=all -e PYTHONHASHSEED=0 -e VLLM_KV_EVENTS_USE_INT_BLOCK_HASHES=1 -e HF_HUB_OFFLINE=1 \
    -e HF_HOME=$HF_CACHE -e VLLM_NIXL_SIDE_CHANNEL_HOST=$NODE -e VLLM_NIXL_SIDE_CHANNEL_PORT=5600 $VLLM_PROFILE_ENV \
    -v $HF_CACHE:$HF_CACHE $VLLM_IMAGE --model $MODEL --revision $REV --tokenizer-revision $REV \
    --served-model-name $MODEL --host 0.0.0.0 --port $EPORT --max-model-len 4096 --gpu-memory-utilization 0.85 \
    --enable-prefix-caching --prefix-caching-hash-algo sha256_cbor --block-size 16 --prefix-match-unit 16 --enforce-eager \
    ${KVT:+--kv-transfer-config '$KVT'} $EVX $VLLM_PROFILE_ARGS ${VLLM_EXTRA:-}" >/dev/null
elif [ "$ENG" = trtllm ]; then
  cfg=/var/tmp/kvmc/trtllm-converged.yaml
  $SSH root@"$NODE" "install -d -m 0755 ${cfg%/*} && cat > $cfg" < "$TRT_CONVERGED_YAML"
  $SSH -n root@"$NODE" "docker rm -f $NAME >/dev/null 2>&1 || true"
  trt_port_free "$NODE" || exit 1
  $SSH root@"$NODE" "docker run -d --name $NAME --gpus all --network host --ipc=host --shm-size 16g \
    -v $HF_CACHE:$HF_CACHE -v $cfg:/cfg/trt.yaml:ro -e HF_HOME=$HF_CACHE -e HF_HUB_OFFLINE=1 -e NIXL_PLUGIN_DIR=$TRT_LIBS/nixl/plugins \
    -e LD_LIBRARY_PATH=$TRT_LIBS/ucx:$TRT_LIBS/nixl:/usr/local/lib/python3.12/dist-packages/torch/lib:/usr/local/lib/python3.12/dist-packages/torch_tensorrt/lib:/usr/local/cuda/compat/lib:/usr/local/nvidia/lib:/usr/local/nvidia/lib64 \
    $TRT_IMAGE trtllm-serve $SNAP --served_model_name $MODEL --host 0.0.0.0 --port $EPORT --backend pytorch --max_seq_len 4096 \
    --extra_llm_api_options /cfg/trt.yaml ${TRT_EXTRA:-}" >/dev/null
else
  $SSH root@"$NODE" "docker rm -f $NAME >/dev/null 2>&1; docker run -d --name $NAME --gpus all --network host --ipc=host --shm-size 16g \
    -v $HF_CACHE:$HF_CACHE -v $SGL_EXT_CACHE:/root/.cache/torch_extensions $TOKMNT -e HF_HOME=$HF_CACHE -e HF_HUB_OFFLINE=1 $SGL_IMAGE \
    python3 -m sglang.launch_server --model-path $SNAP --revision $REV --served-model-name $MODEL --host 0.0.0.0 --port $EPORT \
    --page-size 16 --enable-metrics --context-length 4096 --mem-fraction-static $SGL_STATIC_MEM $DIS $SGL_PROFILE_ARGS ${SGL_EXTRA:-}" >/dev/null
fi
# Ready = the SERVED model id answers on /v1/models (a 200 from a stray engine on the port is not readiness).
for _ in $(seq 1 120); do
  # SGLang answers /v1/models before its own start-up warm-up has run; it is ready when it says so.
  if curl -s -m 3 "http://$NODE:$EPORT/v1/models" | grep -qF "\"id\":\"$MODEL\"" &&
     { [ "$ENG" != sglang ] || $SSH root@"$NODE" "docker logs $NAME 2>&1 | grep -q \"The server is fired up\""; } &&
     { [ "$ENG" != trtllm ] || curl -fsS -m 3 "http://$NODE:$EPORT/health" >/dev/null 2>&1; }; then
    if [ -n "$TOKMNT" ]; then
      got=$($SSH root@"$NODE" "docker exec $NAME sha256sum $SGL_TOKPATCH_TARGET" | cut -c1-64)
      [ "$got" = "$SGL_TOKPATCH_FILE_SHA" ] || { echo "TOKENIZE_PATCH_NOT_MOUNTED $NAME ${got:-unreadable}"; exit 1; }
      echo "$NAME: serving_tokenize.py ${stock:0:12} replaced by the v0.5.19 file (${got:0:12})"
    fi
    echo "$NAME ready on $NODE ($MODEL@${REV:0:12})"; exit 0
  fi
  $SSH root@"$NODE" "docker ps -q -f name=^$NAME\$" | grep -q . || { echo "ENGINE_EXITED $NAME"; $SSH root@"$NODE" "docker logs --tail 30 $NAME"; exit 1; }
  sleep 5
done
echo "ENGINE_NOT_READY $NAME on $NODE"; exit 1
