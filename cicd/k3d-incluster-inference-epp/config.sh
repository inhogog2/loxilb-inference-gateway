#!/bin/bash
# k3d-incluster-inference-epp: loxilb (in-cluster DaemonSet) asks an Endpoint
# Picker (EPP) where each request goes. The EPP is cmd/epp-fake — a pure-Go
# ext_proc server that names a fixed pod for every request and plays the
# response phase like the llm-d EPP — so the scenario needs neither the
# InferencePool CRDs nor kube-loxilb: the rules go in over REST (decision D1).
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/../common/k8s-inference/k3d_common.sh"
REPO="$(cd "$HERE/../.." && pwd)"

igw_cluster_up igw-epp            || exit 1
# Only the loxilb image: this scenario needs no kube-loxilb (rules over REST).
docker image inspect "$IGW_IMAGE" >/dev/null 2>&1 || docker pull -q "$IGW_IMAGE" >/dev/null || exit 1
say "importing $IGW_IMAGE"; "$K3D" image import "$IGW_IMAGE" -c "$CLUSTER" >/dev/null || exit 1
say "loxilb (in-cluster DaemonSet)";      igw_deploy_loxilb      || exit 1
# The shared manifest names :latest and runs without the Prometheus thread;
# this scenario tests the image it was given and reads the EPP metrics.
cname=$(kubectl -n kube-system get ds loxilb-lb -o jsonpath='{.spec.template.spec.containers[0].name}')
kubectl -n kube-system patch ds loxilb-lb --type=json -p '[{"op":"add","path":"/spec/template/spec/containers/0/command/-","value":"--prometheus"}]' >/dev/null || exit 1
kubectl -n kube-system set image "ds/loxilb-lb" "$cname=$IGW_IMAGE" >/dev/null || exit 1
kubectl -n kube-system rollout status ds/loxilb-lb --timeout=180s >/dev/null || exit 1
for i in $(seq 1 30); do
  curl -s --max-time 3 "http://$NODE_IP:11111/netlox/v1/version" | grep -q '"product":"loxilb-inference-gateway"' && break
  sleep 2
done
say "loxilb runs $IGW_IMAGE with --prometheus"
say "mock vLLM servers";                  igw_deploy_mock        || exit 1
say "client container";                   igw_client_up          || exit 1

say "epp-fake (the Endpoint Picker, on this host)"
command -v go >/dev/null 2>&1 || { echo "FATAL: go is needed to build cmd/epp-fake"; exit 1; }
mkdir -p "$HERE/.work"
( cd "$REPO" && CGO_ENABLED=0 go build -o "$HERE/.work/epp-fake" ./cmd/epp-fake/ ) || exit 1
# The loxilb pod runs on the host network of the k3d node (a container on the
# cluster's docker network); this host is its gateway on that network.
EPP_IP=$(docker network inspect "k3d-$CLUSTER" -f '{{(index .IPAM.Config 0).Gateway}}')
[ -n "$EPP_IP" ] || { echo "FATAL: no gateway on k3d-$CLUSTER"; exit 1; }
EPP_PORT=9002
# The EPP names the LAST pod (sorted by IP) for every request; the rule
# carries every pod, so the choice is the EPP's, not the selector's.
PODS=$(kubectl -n llm get pods -l app=vllm-qwen3 -o json | jq -r '[.items[].status.podIP] | sort | join(",")')
EPP_DEST="$(echo "$PODS" | tr ',' '\n' | tail -1):8000"
epp_start() { # <mode>
  nohup "$HERE/.work/epp-fake" -listen "$EPP_IP:$EPP_PORT" -dest "$EPP_DEST" -mode "$1" \
    > "$HERE/.work/epp-fake.log" 2>&1 &
  echo $! > "$HERE/.work/epp-fake.pid"
}
epp_start echo
sleep 1
kill -0 "$(cat "$HERE/.work/epp-fake.pid")" 2>/dev/null || { cat "$HERE/.work/epp-fake.log"; exit 1; }
say "epp-fake on $EPP_IP:$EPP_PORT -> $EPP_DEST"

igw_env_save "$HERE"
cat >> "$HERE/.env" <<ENV
EPP_IP=$EPP_IP
EPP_PORT=$EPP_PORT
EPP_DEST=$EPP_DEST
ENV
say "testbed up (VIP $NODE_IP, EPP $EPP_IP:$EPP_PORT)"
