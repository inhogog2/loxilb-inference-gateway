#!/bin/bash
# config.sh [profileId ...] — stage the candidate-model profiles into the gateway's trusted registry.
#
# Additive: only the named profiles (default: every committed candidate profile) are written; nothing else in
# REG is touched. For each profile it installs, root-owned 0644 as the registry's trusted-file checks require:
#   REG/<id>.yaml                           the committed profile
#   REG/manifests/<id>.yaml                 the vLLM manifest (a leg swaps in the SGLang one for its run)
#   REG/probefixtures/<id>/[sglang/]        the committed probe fixtures
#   REG/artifacts/sha256/<sha>              the tokenizer.json and the chat template, content-addressed
#   TOKDIR/<org__name>/tokenizer.json       the tokenizer the serving path loads
#
# tokenizer.json is not committed (tens of MB per model). It is read from TOKSRC/<org__name>/tokenizer.json
# when TOKSRC is set, else from the pinned snapshot on the PREFILL node, and refused unless its sha256 equals
# the profile's tokenizerSha256 — a drifted or wrong-revision file never reaches the registry.
#
# The registry is read only when the gateway starts: restart it after staging, then run
# `./validation.sh preflight`, which requires the published generation to hold every staged profile.
set -eu
source "$(dirname "$0")/env.sh"
IDS=("$@"); [ ${#IDS[@]} -gt 0 ] || IDS=($(cd "${FIX}/profiles" && ls *.yaml | sed 's/\.yaml$//'))
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
install -d -o root -g root -m 0755 "$REG" "$REG/manifests" "$REG/probefixtures" "$REG/artifacts/sha256" "$TOKDIR"
for id in "${IDS[@]}"; do
  P="${FIX}/profiles/$id.yaml"; [ -f "$P" ] || { echo "NO_PROFILE $id"; exit 1; }
  model=$(profile_field "$id" baseModel); rev=$(profile_field "$id" tokenizerRevision); slug=${model//\//__}
  toksha=$(profile_field "$id" tokenizerSha256); tplsha=$(profile_field "$id" templateSha256)
  tpl="${FIX}/templates/$slug/chat_template.jinja"
  [ "$(sha256sum < "$tpl" | cut -c1-64)" = "$tplsha" ] || { echo "TEMPLATE_SHA_MISMATCH $id"; exit 1; }
  if [ -n "${TOKSRC:-}" ]; then
    cp "$TOKSRC/$slug/tokenizer.json" "$TMP/tok.json"
  else
    $SSH root@"$PREFILL" "cat $(snapshot "$model" "$rev")/tokenizer.json" > "$TMP/tok.json"
  fi
  [ "$(sha256sum < "$TMP/tok.json" | cut -c1-64)" = "$toksha" ] || { echo "TOKENIZER_SHA_MISMATCH $id (want $toksha)"; exit 1; }
  install -o root -g root -m 0644 "$TMP/tok.json" "$REG/artifacts/sha256/$toksha"
  install -o root -g root -m 0644 "$tpl" "$REG/artifacts/sha256/$tplsha"
  install -o root -g root -m 0644 "$P" "$REG/$id.yaml"
  install -o root -g root -m 0644 "${FIX}/manifests/$id.yaml" "$REG/manifests/$id.yaml"
  rm -rf "${REG:?}/probefixtures/$id"
  install -d -o root -g root -m 0755 "$REG/probefixtures/$id"
  install -o root -g root -m 0644 "${FIX}/probefixtures/$id"/*.json "$REG/probefixtures/$id/"
  if [ -d "${FIX}/probefixtures/$id/sglang" ]; then
    install -d -o root -g root -m 0755 "$REG/probefixtures/$id/sglang"
    install -o root -g root -m 0644 "${FIX}/probefixtures/$id/sglang"/*.json "$REG/probefixtures/$id/sglang/"
  fi
  install -d -o root -g root -m 0755 "$TOKDIR/$slug"
  install -o root -g root -m 0644 "$TMP/tok.json" "$TOKDIR/$slug/tokenizer.json"
  echo "STAGED $id ($model@${rev:0:12}) tokenizer=${toksha:0:12} template=${tplsha:0:12}"
done
echo "staged ${#IDS[@]} profile(s) into $REG ($(ls "$REG"/*.yaml | wc -l) in the registry)."
echo "Restart the gateway so it loads them, then run: ./validation.sh preflight"
