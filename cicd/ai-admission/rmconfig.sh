#!/bin/bash
source ../common.sh
echo SCENARIO-ai-admission-cleanup

stop_helpers
sleep 1

disconnect_docker_hosts llb1 l3h1
disconnect_docker_hosts llb1 l3ep1

delete_docker_host l3ep1
delete_docker_host l3h1
delete_docker_host llb1

docker rm -f pg-ai-admission >/dev/null 2>&1

rm -rf cert __pycache__ .h1_signal

echo SCENARIO-ai-admission-cleanup [OK]
