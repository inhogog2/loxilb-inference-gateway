#!/bin/bash
# CICD scenario: audit-sink
#
# The audit trail leaving the gateway: a strict RFC 5425 receiver stands in
# for the SIEM, and validation.sh scores what ARRIVED there, never what the
# sender believes it sent.
#
# No --userservice, no PostgreSQL and no data path. The subject is the
# follower of the trail, and the management stream alone drives it: the
# secondary sink is filtered to that stream, and the writer's own
# audit_system records are what the filter has to keep away from it.
#
# Topology:
#   llb1 ---- siem1 (33.33.33.1)  compliance receiver :6514, control :6515
#        |                        decoy receiver      :6516, control :6517
#        |                        (the decoy's certificate is from another CA)
#        ---- siem2 (34.34.34.1)  secondary receiver  :6514, control :6515
#
# The receivers are host processes inside a namespace, restarted by
# validation.sh; each carries a --sink label so that rmconfig.sh can find
# the ones a failed run left behind.

source ../common.sh

AUDIT_DIR=/var/log/loxilb/audit
SIEM1=33.33.33.1
SIEM2=34.34.34.1
# No number is built into the product. This one is from the range RFC 5612
# reserves for documentation, so no deployment can mistake it for its own.
PEN=32473
SINK_CA=/etc/loxilb/sink-ca.pem
CERTS="$(pwd)/sinkcerts"
RCV="$(pwd)/syslog_receiver.py"

echo SCENARIO-audit-sink-config

require_host_tools jq openssl python3 sha256sum iptables || exit 1

echo "#########################################"
echo "Minting the receivers' certificates"
echo "#########################################"

# Two authorities. The gateway is told about the first only, so a receiver
# presenting a certificate from the second is the wrong-CA control with the
# address, the port family and the receiver code all held the same.
mkca() { # mkca <dir> <cn>
  mkdir -p "$1"
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -keyout "$1/ca.key" -out "$1/ca.pem" -subj "/CN=$2" >/dev/null 2>&1
}
mkcert() { # mkcert <ca dir> <ip>
  local d=$1 ip=$2
  openssl req -newkey rsa:2048 -nodes -keyout "$d/$ip.key" -out "$d/$ip.csr" \
    -subj "/CN=audit-sink-receiver-$ip" >/dev/null 2>&1
  printf 'subjectAltName=IP:%s\nextendedKeyUsage=serverAuth\n' "$ip" > "$d/$ip.ext"
  openssl x509 -req -in "$d/$ip.csr" -CA "$d/ca.pem" -CAkey "$d/ca.key" -CAcreateserial \
    -days 2 -extfile "$d/$ip.ext" -out "$d/$ip.pem" >/dev/null 2>&1
  openssl verify -CAfile "$d/ca.pem" "$d/$ip.pem" >/dev/null 2>&1
}
rm -rf "$CERTS"
mkca "$CERTS/run"   audit-sink-run-ca
mkca "$CERTS/other" audit-sink-other-ca
mkcert "$CERTS/run"   "$SIEM1" || { echo "FATAL: could not mint the compliance receiver's certificate"; exit 1; }
mkcert "$CERTS/run"   "$SIEM2" || { echo "FATAL: could not mint the secondary receiver's certificate"; exit 1; }
mkcert "$CERTS/other" "$SIEM1" || { echo "FATAL: could not mint the decoy's certificate"; exit 1; }
# The decoy's certificate must NOT verify under the run CA, or the control
# it exists for would be a second healthy receiver.
if openssl verify -CAfile "$CERTS/run/ca.pem" "$CERTS/other/$SIEM1.pem" >/dev/null 2>&1; then
  echo "FATAL: the decoy's certificate verifies under the run CA"; exit 1
fi
echo "  run CA, other CA and three receiver certificates minted"

echo "#########################################"
echo "Preparing the loxilb config directory"
echo "#########################################"

# pick_config=yes mounts $(pwd)/llb1_config as /etc/loxilb/ inside the
# container. Only the run CA's certificate goes in: it is what a receiver is
# verified against, never a credential of the gateway's.
pick_config=yes
rm -rf llb1_config
mkdir -p llb1_config
cp "$CERTS/run/ca.pem" llb1_config/sink-ca.pem

GW_ARGS="--audit-dir $AUDIT_DIR --audit-required"

echo "#########################################"
echo "Spawning the topology"
echo "#########################################"

spawn_docker_host --dock-type loxilb --dock-name llb1 --extra-args "$GW_ARGS"
spawn_docker_host --dock-type host   --dock-name siem1
spawn_docker_host --dock-type host   --dock-name siem2

connect_docker_hosts siem1 llb1
connect_docker_hosts siem2 llb1

sleep 5

# pick_config did its job at spawn. Left set, config_docker_host skips the
# loxilb host and llb1's own interfaces never get an address.
pick_config=""

config_docker_host --host1 siem1 --host2 llb1  --ptype phy --addr $SIEM1/24 --gw 33.33.33.254
config_docker_host --host1 siem2 --host2 llb1  --ptype phy --addr $SIEM2/24 --gw 34.34.34.254
config_docker_host --host1 llb1  --host2 siem1 --ptype phy --addr 33.33.33.254/24
config_docker_host --host1 llb1  --host2 siem2 --ptype phy --addr 34.34.34.254/24

echo "#########################################"
echo "Starting the receivers"
echo "#########################################"

# start_rcv <ns> <label> <port> <control port> <ca dir> <ip>
start_rcv() {
  $hexec "$1" python3 "$RCV" --sink "$2" --port "$3" --control "127.0.0.1:$4" --pen "$PEN" \
    --cert "$CERTS/$5/$6.pem" --key "$CERTS/$5/$6.key" \
    --out "/tmp/$2.jsonl" > "/tmp/$2.log" 2>&1 &
  track_helper
}
start_rcv siem1 audit-sink-compliance 6514 6515 run   "$SIEM1"
start_rcv siem1 audit-sink-decoy      6516 6517 other "$SIEM1"
start_rcv siem2 audit-sink-secondary  6514 6515 run   "$SIEM2"

for spec in "siem1 6515 compliance" "siem1 6517 decoy" "siem2 6515 secondary"; do
  set -- $spec
  for i in $(seq 1 20); do
    # "0" is the receiver saying it is up and has been sent nothing.
    [ "$($hexec "$1" curl -s -m 2 "http://127.0.0.1:$2/__probe")" = "0" ] && { echo "  $3 receiver ready (${i})"; break; }
    if [ "$i" -eq 20 ]; then
      echo "FATAL: the $3 receiver did not come up:"; tail -5 "/tmp/audit-sink-$3.log"; exit 1
    fi
    sleep 1
  done
done

echo "#########################################"
echo "Waiting for the loxilb REST API"
echo "#########################################"

API=http://127.0.0.1:11111/netlox/v1
for i in $(seq 1 30); do
  if docker exec llb1 curl -sf -m 3 $API/version >/dev/null 2>&1; then
    echo "loxilb REST API ready (${i})"
    break
  fi
  sleep 2
done

# The REST listener answers before the boot config replay settles, and until
# it does the freeze middleware 503s every mutation. Probe the freeze itself
# with a write that can never apply.
for i in $(seq 1 40); do
  if ! docker exec llb1 curl -s -m 3 -X POST $API/config/loadbalancer \
       -H 'Content-Type: application/json' -d '{}' \
       | grep -qE 'boot config replay settles|frozen while a snapshot restore is in progress'; then
    echo "  boot config settled (${i})"; break
  fi
  if [ "$i" -eq 40 ]; then
    echo "  FATAL: boot config replay never settled"; exit 1
  fi
  sleep 2
done

echo "#########################################"
echo "The audit trail is up, and the gateway reaches both receivers"
echo "#########################################"

STATUS=$(docker exec llb1 curl -s -m 5 $API/audit/status)
echo "  $STATUS" | cut -c1-200
if ! printf '%s' "$STATUS" | jq -e '.available == true and .running == true' >/dev/null 2>&1; then
  echo "  FATAL: the audit writer is not running; nothing below can be measured"
  exit 1
fi
# An image without the named-sink routes cannot run this scenario at all,
# and would otherwise fail every row for a reason none of them names.
if [ "$(docker exec llb1 curl -s -m 5 -o /dev/null -w '%{http_code}' $API/audit/sinks/none)" != "404" ]; then
  echo "  FATAL: GET /audit/sinks/{name} is not served by this image; it predates secondary sinks"
  exit 1
fi
# A bare TCP connect from inside llb1, closed at once: the receiver counts
# it as a handshake that never happened, not as a session.
for ip in $SIEM1 $SIEM2; do
  docker exec llb1 timeout 5 bash -c "exec 3<>/dev/tcp/$ip/6514" >/dev/null 2>&1 || {
    echo "  FATAL: llb1 cannot reach $ip; a sink that never connects would read as a product defect"; exit 1; }
done
docker exec llb1 grep -q 'BEGIN CERTIFICATE' "$SINK_CA" 2>/dev/null || {
  echo "  FATAL: the run CA is not readable at llb1:$SINK_CA"; exit 1; }

cat > .state <<EOF
AUDIT_DIR='$AUDIT_DIR'
GW_ARGS='$GW_ARGS'
SIEM1='$SIEM1'
SIEM2='$SIEM2'
PEN='$PEN'
SINK_CA='$SINK_CA'
CERTS='$CERTS'
RCV='$RCV'
EOF

echo "#########################################"
echo "audit-sink testbed ready"
echo "#########################################"
echo "  Control plane API: http://llb1:11111/netlox/v1"
echo "  Audit directory:   llb1:$AUDIT_DIR"
echo "  Receivers:         $SIEM1:6514 (compliance), $SIEM1:6516 (decoy), $SIEM2:6514 (secondary)"
