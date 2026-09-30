#!/bin/bash
# engine.sh start|stop vllm|sglang prefill|decode <profileId> — one P/D pair member on its node.
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
set -eu
source "$(dirname "$0")/env.sh"
ACT=$1 ENG=$2 ROLE=$3 PROF=$4
MODEL=$(profile_field "$PROF" baseModel); REV=$(profile_field "$PROF" tokenizerRevision)
case $ROLE in prefill) NODE=$PREFILL ;; decode) NODE=$DECODE ;; *) echo "role must be prefill|decode"; exit 64 ;; esac
NAME=kvmc-$ENG-$ROLE
if [ "$ACT" = stop ]; then $SSH root@"$NODE" "docker rm -f $NAME >/dev/null 2>&1 || true"; exit 0; fi
[ "$ACT" = start ] || { echo "usage: $0 start|stop vllm|sglang prefill|decode <profileId>"; exit 64; }
SNAP=$(snapshot "$MODEL" "$REV")
$SSH root@"$NODE" "test -f $SNAP/config.json" || { echo "WEIGHTS_MISSING $NODE $SNAP"; exit 1; }
EVENTS='{"enable_kv_cache_events":true,"publisher":"zmq","endpoint":"tcp://*:5557","replay_endpoint":null,"topic":""}'
case $ENG/$ROLE in
vllm/prefill) KVT='{"kv_connector":"NixlConnector","kv_role":"kv_producer","kv_buffer_device":"cpu","kv_load_failure_policy":"fail"}'; EVX="--kv-events-config '$EVENTS'" ;;
vllm/decode)  KVT='{"kv_connector":"NixlConnector","kv_role":"kv_consumer","kv_buffer_device":"cpu","kv_load_failure_policy":"fail"}'; EVX="" ;;
sglang/prefill) DIS="--disaggregation-mode prefill --disaggregation-transfer-backend mooncake --disaggregation-bootstrap-port 8998 --kv-events-config '{\"publisher\":\"zmq\",\"endpoint\":\"tcp://*:5557\"}'" ;;
sglang/decode)  DIS="--disaggregation-mode decode --disaggregation-transfer-backend mooncake" ;;
*) echo "engine must be vllm|sglang"; exit 64 ;;
esac
if [ "$ENG" = vllm ]; then
  $SSH root@"$NODE" "docker rm -f $NAME >/dev/null 2>&1; docker run -d --name $NAME --gpus all --ipc=host --network host --ulimit memlock=-1 \
    -e UCX_TLS=tcp -e UCX_NET_DEVICES=all -e PYTHONHASHSEED=0 -e VLLM_KV_EVENTS_USE_INT_BLOCK_HASHES=1 -e HF_HUB_OFFLINE=1 \
    -e HF_HOME=$HF_CACHE -e VLLM_NIXL_SIDE_CHANNEL_HOST=$NODE -e VLLM_NIXL_SIDE_CHANNEL_PORT=5600 \
    -v $HF_CACHE:$HF_CACHE $VLLM_IMAGE --model $MODEL --revision $REV --tokenizer-revision $REV \
    --served-model-name $MODEL --host 0.0.0.0 --port $EPORT --max-model-len 4096 --gpu-memory-utilization 0.85 \
    --enable-prefix-caching --prefix-caching-hash-algo sha256_cbor --block-size 16 --prefix-match-unit 16 --enforce-eager \
    --kv-transfer-config '$KVT' $EVX ${VLLM_EXTRA:-}" >/dev/null
else
  $SSH root@"$NODE" "docker rm -f $NAME >/dev/null 2>&1; docker run -d --name $NAME --gpus all --network host --ipc=host --shm-size 16g \
    -v $HF_CACHE:$HF_CACHE -e HF_HOME=$HF_CACHE -e HF_HUB_OFFLINE=1 $SGL_IMAGE \
    python3 -m sglang.launch_server --model-path $SNAP --revision $REV --served-model-name $MODEL --host 0.0.0.0 --port $EPORT \
    --page-size 16 --enable-metrics --context-length 4096 --mem-fraction-static ${SGL_MEM:-0.70} $DIS ${SGL_EXTRA:-}" >/dev/null
fi
# Ready = the SERVED model id answers on /v1/models (a 200 from a stray engine on the port is not readiness).
for _ in $(seq 1 120); do
  curl -s -m 3 "http://$NODE:$EPORT/v1/models" | grep -qF "\"id\":\"$MODEL\"" && { echo "$NAME ready on $NODE ($MODEL@${REV:0:12})"; exit 0; }
  $SSH root@"$NODE" "docker ps -q -f name=^$NAME\$" | grep -q . || { echo "ENGINE_EXITED $NAME"; $SSH root@"$NODE" "docker logs --tail 30 $NAME"; exit 1; }
  sleep 5
done
echo "ENGINE_NOT_READY $NAME on $NODE"; exit 1
