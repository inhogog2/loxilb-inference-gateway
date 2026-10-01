#!/bin/bash
# validation.sh — the supported-models manifest, its drift gate and the model installer (no GPU, no gateway).
#
#   D1     drift gate green on the committed tree
#   D2..   drift-gate red twins, each one edit on a scratch copy of the tree: hand-edited page, moved revision,
#          edited template, edited weights index, edited engine digest, a profile dropped from the manifest,
#          a row promoted with a gate that did not run, a row promoted on an engine the catalog has not
#          validated — every one must be reported, by name
#   I1..   installer against a local hub stand-in (hf_stub.py): --list; default run installs no candidate;
#          --dry-run writes nothing; an install stages the registry with verified digests and 0644 files and
#          verifies the weights; a re-run with the hub DOWN succeeds without a download; a partial download
#          resumes with a Range request
#   N1..   installer red twins: tampered tokenizer, tampered weight file, symlinked and relative install
#          roots, a symlink in the committed fixtures, unknown model, blocked row, gated model without a
#          token, token file readable by others, a hub that denies the request; with a token the request
#          carries it and the output does not
#   R1     (REAL=1, default) one real install from the hub at the pinned revision: tokenizer.json verified
#          against the committed profile. With REF_REG=<a registry a gateway has loaded> the staged files
#          must be byte-identical to that registry's.
#
# Usage: ./validation.sh            REAL=0 skips R1 (no network)
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
PID_OK=r1-distill-qwen-15b-v1        # ungated, a candidate row on vllm
PID_GATED=gemma3-1b-it-v1
PID_BLOCKED=ministral3-3b-v1
REAL=${REAL:-1}
code=0
TMP=$(mktemp -d); STUB_PID=""
cleanup() { [ -n "$STUB_PID" ] && kill "$STUB_PID" 2>/dev/null; rm -rf "$TMP"; }
trap cleanup EXIT

ok()   { echo "  [OK] $1"; }
bad()  { echo "  [FAILED] $1"; code=1; }
# run <label> <want rc> <regex the output must match> -- <command...>; output kept in $OUT
run() {
  local label=$1 want=$2 re=$3; shift 4
  OUT=$("$@" 2>&1); local rc=$?
  if [ "$rc" = "$want" ] && grep -qE -- "$re" <<<"$OUT"; then ok "$label"; else
    bad "$label — want rc $want and /$re/, got rc $rc: $(tail -3 <<<"$OUT" | tr '\n' ' ')"; fi
}
python3 -c 'import yaml' 2>/dev/null || { echo "python3 with PyYAML is required"; exit 1; }

# A scratch copy of everything the tool reads; twins edit the copy, never the repository.
fresh_tree() {
  rm -rf "$TMP/tree"; mkdir -p "$TMP/tree/docs" "$TMP/tree/engine-contracts" "$TMP/tree/cicd/common/kv_hash"
  cp -r "$REPO/scripts" "$TMP/tree/scripts"
  cp "$REPO/docs/SUPPORTED-MODELS.md" "$TMP/tree/docs/"
  cp "$REPO/engine-contracts/support-catalog.yaml" "$TMP/tree/engine-contracts/"
  cp -r "$REPO/cicd/common/kv_hash/fixtures" "$TMP/tree/cicd/common/kv_hash/fixtures"
}
T="$TMP/tree"; MAN="$T/scripts/models/validated-models.yaml"; FIXT="$T/cicd/common/kv_hash/fixtures"
ctl()  { python3 "$T/scripts/models/modelctl.py" "$@"; }
field() { python3 - "$MAN" "$1" "$2" <<'PY'
import sys, yaml
m = yaml.safe_load(open(sys.argv[1]))
print([x for x in m["models"] if x["profileId"] == sys.argv[2]][0][sys.argv[3]])
PY
}

echo "=== D. drift gate ==="
run "D1 committed tree agrees" 0 "agree" -- python3 "$REPO/scripts/models/modelctl.py" check
fresh_tree
run "D1b the scratch copy agrees before any twin" 0 "agree" -- ctl check
REV=$(field $PID_OK revision); TPL="$FIXT/templates/deepseek-ai__DeepSeek-R1-Distill-Qwen-1.5B/chat_template.jinja"

fresh_tree; echo "hand edit" >> "$T/docs/SUPPORTED-MODELS.md"
run "D2 hand-edited page" 1 "SUPPORTED-MODELS.md is not the manifest's render" -- ctl check
fresh_tree; sed -i "s/$REV/$(tr '0-9a-f' '1-9a-f0' <<<"${REV:0:1}")${REV:1}/" "$MAN"
run "D3 moved revision" 1 "$PID_OK: manifest revision .* != profile tokenizerRevision" -- ctl check
grep -qE "SOURCES.json revision" <<<"$OUT" && grep -qE "modelRevision != manifest revision" <<<"$OUT" \
  && ok "D3b the same edit is also reported against SOURCES.json and the engine manifests" || bad "D3b"
fresh_tree; echo "x" >> "$TPL"
run "D4 edited banked template" 1 "$PID_OK: banked chat template is missing or its sha256 is not templateSha256" -- ctl check
fresh_tree; sed -i '1s/ [0-9]* / 1 /' "$T/scripts/models/weights/$PID_OK.index"
run "D5 edited weights index" 1 "$PID_OK: weights index sha256 is not weightsIndexSha256" -- ctl check
fresh_tree; sed -i '0,/digest: sha256:6/s//digest: sha256:7/' "$MAN"
run "D6 edited engine digest" 1 "engine vllm v0.28.0: digest .* != catalog platformDigest" -- ctl check
grep -qE "manifests imageDigest .* != engine digest" <<<"$OUT" && ok "D6b also against the committed engine manifests" || bad "D6b"
fresh_tree; rm "$FIXT/profiles/$PID_OK.yaml"
run "D7 manifest row without a committed profile" 1 "$PID_OK: manifest row has no committed profile" -- ctl check
fresh_tree; python3 - "$MAN" $PID_OK <<'PY'
import sys
s = open(sys.argv[1]).read()
i = s.index("  - profileId: " + sys.argv[2] + "\n"); j = s.index("  - profileId:", i + 1)
open(sys.argv[1], "w").write(s[:i] + s[j:])
PY
run "D8 committed profile without a manifest row" 1 "$PID_OK: committed profile has no manifest row" -- ctl check
# promotion rules. promote <perf: yes|no> flips the R1 x vllm row (every other gate is "pass") to validated,
# with or without a performance point.
promote() { python3 - "$MAN" "$1" <<'PY'
import sys
s = open(sys.argv[1]).read()
i = s.index("profileId: r1-distill-qwen-15b-v1"); k = s.index("state: candidate", i)
s = s[:k] + "state: validated" + s[k + len("state: candidate"):]
if sys.argv[2] == "yes":
    k = s.index("abPerf: not_run}", k); e = s.index("\n", s.index("lastValidated:", k))
    point = ("\n        perf:\n          - {topology: pd-3p2d, surface: chat, corpus: long, rateRps: 6, requestsPerArm: 100,"
             " exactTtftP95Ms: 100, baselineTtftP95Ms: 200, exactTtftP50Ms: 90, baselineTtftP50Ms: 95, date: \"2026-01-01\"}")
    s = s[:k] + "abPerf: pass}" + s[k + len("abPerf: not_run}"):e] + point + s[e:]
open(sys.argv[1], "w").write(s)
PY
}
fresh_tree; promote no
run "D9 promoted without an A/B performance point" 2 "MANIFEST_INVALID: $PID_OK x vllm v0.28.0: validated needs evidence.abPerf = pass \\(is not_run\\)$" -- ctl check
fresh_tree; promote yes; ctl render >/dev/null
run "D9a a fully evidenced promoted row is accepted" 0 "agree" -- ctl check
grep -q "| DeepSeek-R1-Distill-Qwen-1.5B | vllm v0.28.0 | pd-3p2d | chat | long | 6 | 100 | 100 | 200 | -50.0% |" "$T/docs/SUPPORTED-MODELS.md" \
  && ok "D9a2 the page carries the point and its delta" || bad "D9a2 perf row not rendered"
sed -i '0,/pdCompletions: pass, abPerf: pass/s//pdCompletions: not_run, abPerf: pass/' "$MAN"
run "D9b promoted with a gate that did not run" 2 "MANIFEST_INVALID.*validated needs evidence.pdCompletions = pass" -- ctl check
fresh_tree; sed -i '0,/abPerf: not_run/s//abPerf: pass/' "$MAN"
run "D9c a performance verdict without its numbers" 2 "MANIFEST_INVALID.*abPerf = pass needs perf points" -- ctl check
fresh_tree; promote yes; ctl render >/dev/null; python3 - "$T/engine-contracts/support-catalog.yaml" <<'PY'
import sys
c = open(sys.argv[1]).read()
i = c.index("version: v0.28.0"); k = c.index("promotion: validated", i)
open(sys.argv[1], "w").write(c[:k] + "promotion: candidate" + c[k + len("promotion: validated"):])
PY
run "D10 promoted on an engine the catalog has not validated" 1 "$PID_OK x vllm v0.28.0: validated on an engine entry the catalog has not validated" -- ctl check
grep -c "^DRIFT" <<<"$OUT" | grep -qx 1 && ok "D10b and that is the only disagreement" || bad "D10b other drift reported"

echo "=== I. installer against the local hub stand-in ==="
# The stand-in serves made-up files, so the scratch tree's pins are moved to them (profile, manifest, index).
fresh_tree
REPO_ID=$(field $PID_OK repo); OLDTOK=$(field $PID_OK tokenizerSha256)
HUB="$TMP/hub"; SNAP="$HUB/$REPO_ID/resolve/$REV"; mkdir -p "$SNAP"
head -c 300000 /dev/urandom > "$SNAP/model.safetensors"; echo '{"stub": true}' > "$SNAP/tokenizer.json"; echo '{}' > "$SNAP/config.json"
NEWTOK=$(sha256sum < "$SNAP/tokenizer.json" | cut -c1-64)
sed -i "s/$OLDTOK/$NEWTOK/g" "$MAN" "$FIXT/profiles/$PID_OK.yaml"
IDX="$T/scripts/models/weights/$PID_OK.index"
{ echo "gitblob:$(git hash-object "$SNAP/config.json") $(stat -c %s "$SNAP/config.json") config.json"
  echo "sha256:$(sha256sum < "$SNAP/model.safetensors" | cut -c1-64) 300000 model.safetensors"
  echo "sha256:$NEWTOK $(stat -c %s "$SNAP/tokenizer.json") tokenizer.json"; } > "$IDX"
sed -i "s/$(field $PID_OK weightsIndexSha256)/$(sha256sum < "$IDX" | cut -c1-64)/" "$MAN"
cp -r "$T" "$TMP/tree.stub"                      # the stub-pinned tree, restored before each twin
stub_tree() { rm -rf "$T"; cp -r "$TMP/tree.stub" "$T"; }
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
start_stub() { python3 "$HERE/hf_stub.py" "$HUB" "$PORT" ${1:-} > "$TMP/stub.out" 2>&1 & STUB_PID=$!
  for _ in $(seq 1 50); do (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null && return; sleep 0.1; done; bad "stub did not start"; }
stop_stub() { kill "$STUB_PID" 2>/dev/null; wait "$STUB_PID" 2>/dev/null; STUB_PID=""; }
export HF_ENDPOINT="http://127.0.0.1:$PORT"
REG="$TMP/reg"; TOK="$TMP/tok"; WD="$TMP/weights"
inst() { ctl install --registry-dir "$REG" --tokenizer-dir "$TOK" "$@"; }
start_stub

run "I1 --list shows every manifest row" 0 "$PID_OK .*vllm=candidate" -- ctl install --list
[ "$(grep -c . <<<"$OUT")" = "$(grep -c '^  - profileId:' "$MAN")" ] && ok "I1b one line per model" || bad "I1b line count"
run "I2 default run installs no candidate" 0 "$PID_OK: SKIP_CANDIDATE" -- inst --models $PID_OK
grep -q "installed 0 model" <<<"$OUT" && [ ! -e "$REG" ] && ok "I2b nothing staged, and it says so" || bad "I2b"
run "I3 --dry-run" 0 "would install 1 model" -- inst --dry-run --include-candidates --models $PID_OK --weights-dir "$WD"
[ ! -e "$REG" ] && [ ! -e "$TOK" ] && [ ! -e "$WD" ] && ok "I3b dry run wrote nothing" || bad "I3b dry run wrote files"
run "I4 install with weights" 0 "installed 1 model" -- inst --include-candidates --models $PID_OK --weights-dir "$WD"
W="$WD/${REPO_ID//\//__}/$REV"; TPLSHA=$(field $PID_OK templateSha256)
[ "$(sha256sum < "$REG/artifacts/sha256/$NEWTOK" | cut -c1-64)" = "$NEWTOK" ] \
  && [ "$(sha256sum < "$REG/artifacts/sha256/$TPLSHA" | cut -c1-64)" = "$TPLSHA" ] \
  && cmp -s "$REG/$PID_OK.yaml" "$FIXT/profiles/$PID_OK.yaml" \
  && cmp -s "$REG/manifests/$PID_OK.yaml" "$FIXT/manifests/$PID_OK.yaml" \
  && cmp -s "$TOK/${REPO_ID//\//__}/tokenizer.json" "$SNAP/tokenizer.json" \
  && diff -r "$REG/probefixtures/$PID_OK" "$FIXT/probefixtures/$PID_OK" >/dev/null \
  && ok "I4b registry files are the committed and the verified ones" || bad "I4b staged registry differs"
[ -z "$(find "$REG" "$TOK" -type f ! -perm 644)" ] && ok "I4c every staged file is 0644" || bad "I4c file modes"
cmp -s "$W/model.safetensors" "$SNAP/model.safetensors" && cmp -s "$W/config.json" "$SNAP/config.json" \
  && ok "I4d weights downloaded" || bad "I4d weights"
run "I5 --engine sglang stages the sglang engine manifest" 0 "installed 1 model" -- inst --include-candidates --engine sglang --models $PID_OK
cmp -s "$REG/manifests/$PID_OK.yaml" "$FIXT/manifests-sglang/$PID_OK.yaml" && ok "I5b" || bad "I5b manifest set"
stop_stub
run "I6 re-run with the hub down" 0 "installed 1 model" -- inst --include-candidates --models $PID_OK --weights-dir "$WD"
grep -q "already staged and verified" <<<"$OUT" && grep -q "3/3 files already verified" <<<"$OUT" \
  && ok "I6b nothing was downloaded again" || bad "I6b re-run tried to download"
start_stub
rm "$W/model.safetensors"; head -c 100000 "$SNAP/model.safetensors" > "$W/model.safetensors.part"; : > "$HUB/requests.log"
run "I7 partial download resumes" 0 "verified model.safetensors" -- inst --include-candidates --models $PID_OK --weights-dir "$WD"
grep -q "model.safetensors range=bytes=100000-" "$HUB/requests.log" && cmp -s "$W/model.safetensors" "$SNAP/model.safetensors" \
  && ok "I7b the request carried Range and the file verifies" || bad "I7b resume"

echo "=== N. installer refusals (red twins) ==="
n=0; newdirs() { n=$((n+1)); REG2="$TMP/r$n"; TOK2="$TMP/k$n"; }   # every twin starts from empty roots
newdirs
inst2() { ctl install --registry-dir "$REG2" --tokenizer-dir "$TOK2" --include-candidates "$@"; }
cp "$SNAP/tokenizer.json" "$TMP/tok.keep"; echo '{"stub": "tampered"}' > "$SNAP/tokenizer.json"
run "N1 tampered tokenizer" 2 "REFUSED TOKENIZER_SHA_MISMATCH" -- inst2 --models $PID_OK
[ ! -e "$REG2/$PID_OK.yaml" ] && [ ! -e "$TOK2" ] && ok "N1b nothing of the refused model was staged" || bad "N1b partial stage"
cp "$TMP/tok.keep" "$SNAP/tokenizer.json"
cp "$SNAP/model.safetensors" "$TMP/w.keep"; printf 'X' | dd of="$SNAP/model.safetensors" bs=1 seek=5 conv=notrunc 2>/dev/null
newdirs
run "N2 tampered weight file" 2 "REFUSED WEIGHT_SHA_MISMATCH" -- inst2 --models $PID_OK --weights-dir "$TMP/w2"
W2="$TMP/w2/${REPO_ID//\//__}/$REV"
[ -e "$W2/model.safetensors.rejected" ] && [ ! -e "$W2/model.safetensors" ] && ok "N2b the bad file is set aside, never left in place" || bad "N2b"
cp "$TMP/w.keep" "$SNAP/model.safetensors"
newdirs; mkdir -p "$TMP/elsewhere" "$REG2"; ln -s "$TMP/elsewhere" "$REG2/manifests"
run "N3 a symlink beneath the install root" 2 "REFUSED UNSAFE_PATH: .*/manifests is a symlink" -- inst2 --models $PID_OK
[ -z "$(ls -A "$TMP/elsewhere")" ] && [ ! -e "$REG2/$PID_OK.yaml" ] && [ ! -e "$REG2/artifacts" ] \
  && ok "N3b nothing written through it, nothing staged beside it" || bad "N3b"
newdirs
run "N4 relative install root" 2 "REFUSED UNSAFE_PATH" -- ctl install --registry-dir reg --tokenizer-dir "$TOK2" --include-candidates --models $PID_OK
run "N5 '..' in an install root" 2 "REFUSED UNSAFE_PATH" -- ctl install --registry-dir "$TMP/a/../reg" --tokenizer-dir "$TOK2" --include-candidates --models $PID_OK
newdirs; stub_tree; mv "$FIXT/profiles/$PID_OK.yaml" "$TMP/p.yaml"; ln -s "$TMP/p.yaml" "$FIXT/profiles/$PID_OK.yaml"
run "N6 symlink in the committed fixtures" 2 "REFUSED COMMITTED_FILE" -- inst2 --models $PID_OK
stub_tree
run "N7 unknown model" 2 "REFUSED UNKNOWN_MODEL" -- inst2 --models no-such-model
run "N8 blocked row" 0 "$PID_BLOCKED: SKIP_BLOCKED engine_renderer" -- inst2 --models $PID_BLOCKED
run "N9 gated model without a token" 0 "$PID_GATED: SKIP_GATED_NO_TOKEN" -- inst2 --models $PID_GATED
grep -q "installed 0 model" <<<"$OUT" && ok "N9b skipped, not installed" || bad "N9b"
sed -i "s/^    revision: $REV/    revision: main/" "$MAN"
run "N10 a branch name instead of a pinned commit" 2 "MANIFEST_INVALID.*revision must be a full 40-hex commit" -- inst2 --models $PID_OK
stub_tree
stop_stub; start_stub s3cr3t-stub-token; : > "$HUB/requests.log"; newdirs
run "N11 the hub denies an anonymous request" 2 "REFUSED DOWNLOAD_DENIED" -- inst2 --models $PID_OK
printf 's3cr3t-stub-token\n' > "$TMP/token"; chmod 644 "$TMP/token"
run "N12 token file readable by others" 2 "REFUSED TOKEN_FILE_MODE" -- inst2 --models $PID_OK --hf-token-file "$TMP/token"
chmod 600 "$TMP/token"; : > "$HUB/requests.log"; newdirs
run "N13 with a token file" 0 "installed 1 model" -- inst2 --models $PID_OK --hf-token-file "$TMP/token"
grep -q "tokenizer.json range=None bearer=yes" "$HUB/requests.log" && ! grep -q "s3cr3t" <<<"$OUT" \
  && ok "N13b the request carried the token; the output does not" || bad "N13b token handling"
run "N13c HF_TOKEN_FILE is honoured" 0 "installed 1 model" -- env HF_TOKEN_FILE="$TMP/token" python3 "$T/scripts/models/modelctl.py" install --registry-dir "$TMP/reg3" --tokenizer-dir "$TMP/tok3" --include-candidates --models $PID_OK
stop_stub; unset HF_ENDPOINT

if [ "$REAL" = 1 ]; then
  echo "=== R. one real install from the hub at the pinned revision ==="
  RR="$TMP/rreg"; RT="$TMP/rtok"
  run "R1 real install" 0 "installed 1 model" -- python3 "$REPO/scripts/models/modelctl.py" install \
    --registry-dir "$RR" --tokenizer-dir "$RT" --include-candidates --models $PID_OK
  want=$(sed -n 's/^tokenizerSha256: *//p' "$REPO/cicd/common/kv_hash/fixtures/profiles/$PID_OK.yaml")
  [ "$(sha256sum < "$RT/${REPO_ID//\//__}/tokenizer.json" | cut -c1-64)" = "$want" ] \
    && ok "R1b the hub's tokenizer.json at the pinned revision is the profile's" || bad "R1b tokenizer sha"
  if [ -n "${REF_REG:-}" ]; then
    d=0
    for f in "$PID_OK.yaml" "artifacts/sha256/$want" "artifacts/sha256/$TPLSHA"; do cmp -s "$RR/$f" "$REF_REG/$f" || d=1; done
    diff -r "$RR/probefixtures/$PID_OK" "$REF_REG/probefixtures/$PID_OK" >/dev/null || d=1
    [ $d = 0 ] && ok "R1c byte-identical to the registry at $REF_REG" || bad "R1c differs from $REF_REG"
  fi
else
  echo "=== R. skipped (REAL=0) ==="
fi

if [ $code = 0 ]; then echo "SCENARIO kv-model-install: PASS"; else echo "SCENARIO kv-model-install: FAIL"; fi
exit $code
