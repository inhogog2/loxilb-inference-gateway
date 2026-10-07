#!/usr/bin/env bash
#
# install-models.sh — stage supported models for strict KV-exact routing.
#
# Reads scripts/models/validated-models.yaml (the supported-models manifest; docs/SUPPORTED-MODELS.md is its
# rendered form) and, for each selected model:
#   - verifies the committed profile, engine manifest, probe fixtures and chat template against the manifest;
#   - downloads tokenizer.json at the PINNED revision (never a branch) and refuses it unless its sha256 is the
#     pinned one;
#   - stages the profile registry the gateway loads (files 0644):
#       <registry>/<profileId>.yaml               <registry>/manifests/<profileId>.yaml
#       <registry>/probefixtures/<profileId>/...  <registry>/artifacts/sha256/<sha256>
#       <tokenizers>/<org>__<name>/tokenizer.json
#   - with --weights-dir, downloads the pinned snapshot into <dir>/<org>__<name>/<revision>/ (resumes a partial
#     file, skips a verified one) and verifies every file against the committed weights index;
#   - with --pull-image, pulls the engine image by digest.
#
# Usage:
#   install-models.sh --list
#   install-models.sh [--dry-run] [--engine vllm|sglang|trtllm] [--models id[,id...]] [--include-candidates]
#                     [--registry-dir DIR] [--tokenizer-dir DIR] [--weights-dir DIR] [--pull-image]
#                     [--hf-token-file FILE]
#
#   --engine              which engine's manifest to stage (default vllm). A registry holds one engine
#                         manifest per profile.
#   --models              profile ids from --list (default: every model selectable for the engine)
#   --include-candidates  also install rows in state "candidate". They are NOT supported; without this flag
#                         only "validated" rows are installed and everything else is skipped, loudly.
#   --registry-dir        default /etc/loxilb/kvprofiles   (the host path mounted there for a container)
#   --tokenizer-dir       default /etc/loxilb/tokenizers
#   --hf-token-file       access token for gated repositories, mode 600 (or HF_TOKEN_FILE). The token is read
#                         from the file and sent as a request header; it is never taken from the command line
#                         and never printed. A gated model without a token is skipped: SKIP_GATED_NO_TOKEN.
#   --dry-run             print what would be downloaded and staged; write nothing
#
# Re-running is safe: a tokenizer or weight file that is already present and verified is not downloaded again.
# Any verification failure refuses with a typed code (REFUSED <CODE>: ...) and a non-zero exit; a refused
# model is never partly staged ahead of its tokenizer check. Install roots must be absolute and must not be,
# or sit under, a symlink.
#
# The gateway reads the registry when it starts: restart it after staging.
# Needs: python3 with PyYAML.
set -eu
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
case "${1:-}" in
  -h|--help) sed -n '2,/^set -eu$/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
esac
command -v python3 >/dev/null 2>&1 || { echo "install-models: python3 not found" >&2; exit 2; }
exec python3 "${DIR}/modelctl.py" install "$@"
