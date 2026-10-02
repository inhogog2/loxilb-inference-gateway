#!/bin/bash
source ../common.sh
echo SCENARIO-audit-sink-cleanup

stop_helpers
# validation.sh restarts the receivers, and one it started in a run that was
# killed is in no pid record. They are host processes that only borrow a
# namespace, so they are found by the label each was started with. The
# bracket keeps the pattern from matching the command that carries it.
sudo pkill -9 -f -- '[s]yslog_receiver.py --sink audit-sink-' 2>/dev/null
sleep 1

disconnect_docker_hosts llb1 siem1
disconnect_docker_hosts llb1 siem2

delete_docker_host siem2
delete_docker_host siem1
delete_docker_host llb1

rm -f .state
rm -rf llb1_config sinkcerts
sudo rm -f /tmp/audit-sink-compliance.jsonl /tmp/audit-sink-decoy.jsonl /tmp/audit-sink-secondary.jsonl \
           /tmp/audit-sink-compliance.log   /tmp/audit-sink-decoy.log   /tmp/audit-sink-secondary.log

echo SCENARIO-audit-sink-cleanup [OK]
