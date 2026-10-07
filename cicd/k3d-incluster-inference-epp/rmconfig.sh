#!/bin/bash
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/../common/k8s-inference/k3d_common.sh"
[ -f "$HERE/.work/epp-fake.pid" ] && kill "$(cat "$HERE/.work/epp-fake.pid")" 2>/dev/null
rm -rf "$HERE/.work"
igw_teardown igw-epp "$HERE"
echo "testbed removed"
