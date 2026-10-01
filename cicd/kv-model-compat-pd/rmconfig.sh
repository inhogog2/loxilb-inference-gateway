#!/bin/bash
# rmconfig.sh — scoped teardown: stop this scenario's engine containers (kvmc-*) on both nodes and delete any
# rule the scenario may have left on PORT. Staged profiles stay in the registry (they are inert until a strict
# rule names them); remove them by hand if the registry must shrink. Safe to re-run.
set -u
source "$(dirname "$0")/env.sh"
for n in "$PREFILL" "$DECODE"; do
  $SSH root@"$n" "docker ps -aq -f name=^kvmc- | xargs -r docker rm -f >/dev/null" || echo "could not reach $n"
done
curl -s -m 5 "${LB}/all" | python3 -c "
import json, sys, urllib.parse
for r in json.load(sys.stdin).get('lbAttr') or []:
    s = r.get('serviceArguments', {})
    if s.get('port') == ${PORT} and s.get('externalIP') == '${VIP}':
        print(urllib.parse.quote(s.get('model_name') or '', safe=''))
" 2>/dev/null | while read -r enc; do
  curl -s -m 10 -o /dev/null -X DELETE "${LB}/hosturl/${VIP}/externalipaddress/${VIP}/port/${PORT}/protocol/tcp?model_name=${enc}"
  echo "deleted rule ${VIP}:${PORT} model=${enc}"
done
echo "kv-model-compat-pd teardown done"
