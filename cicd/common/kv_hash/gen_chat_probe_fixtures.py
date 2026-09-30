#!/usr/bin/env python3
"""Generate committed chat-surface probe fixtures from the HF render-parity goldens.

Each fixture = chat-<case>.request.json (the exact chat request bytes the
attestor re-derives) + chat-<case>.expect.json {requestSha256,
expectedTokenIds, api:"chat"}. The expected IDs are the goldens'
`templated_ids` — apply_chat_template(tokenize=True) from the offline HF
oracle (gen_chat_render_fixtures.py) — so no live engine is consulted.
Every consumed case must carry encode_rendered_matches_templated=true (the
one-tokenizer-path invariant the goldens proved), and the banked template
artifact must still hash to the goldens' template_sha256: fixtures derived
from drifted inputs would pin a parity the executor can no longer reproduce.

The optional goldens file selects the oracle (default: the banked-model
goldens; kv_chat_render_candidates.json for candidate models). A case the
template itself refuses (`error`) has no token array to pin and is skipped
by name. A template that reads the clock renders the current date, so its
token array holds only at the instant the goldens were rendered: each chat
fixture of such a template pins that instant as "oracleNow" (the goldens'
frozen_now, read as UTC), and the attestor re-derives today's ids through
the gateway's own render while checking the banked ids at oracleNow. Goldens
without a frozen_now cannot pin one, so a clock template is refused there.

Usage: gen_chat_probe_fixtures.py <fixtures_dir> <model_slug> <out_dir> [goldens.json]
"""
import datetime, hashlib, json, os, sys

fixtures_dir, slug, out_dir = sys.argv[1], sys.argv[2], sys.argv[3]
goldens = sys.argv[4] if len(sys.argv) > 4 else "kv_chat_render_parity.json"

with open(os.path.join(fixtures_dir, goldens)) as f:
    parity = json.load(f)
with open(os.path.join(fixtures_dir, "templates", "SOURCES.json")) as f:
    sources = json.load(f)

model = parity["models"][slug]
served = sources["templates"][slug]["model"]

tpl_path = os.path.join(fixtures_dir, "templates", slug, "chat_template.jinja")
with open(tpl_path, "rb") as f:
    tpl_sha = hashlib.sha256(f.read()).hexdigest()
if tpl_sha != model["template_sha256"]:
    sys.exit(f"banked template {tpl_path} digest {tpl_sha} != goldens' "
             f"{model['template_sha256']} — regenerate the goldens first")

# At least one fixture must open without a system message: a template that
# injects a default system prompt renders that request differently from an
# engine renderer that does not (mistral_common), and only such a fixture lets
# the attestation probe see it.
if not any(c["messages"] and c["messages"][0]["role"] != "system"
           for c in model["cases"].values()):
    sys.exit(f"{slug}: every case opens with a system message — the fixture "
             "set could not detect an engine that skips the template's "
             "default system prompt")

oracle_now = None
with open(tpl_path, encoding="utf-8") as f:
    if "strftime_now" in f.read():
        frozen = parity.get("frozen_now")
        if not frozen:
            sys.exit(f"{slug}: template reads strftime_now but {goldens} records "
                     "no frozen_now — no instant to pin the token arrays to")
        at = datetime.datetime.fromisoformat(frozen)
        if at.tzinfo is None:
            at = at.replace(tzinfo=datetime.timezone.utc)
        oracle_now = at.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

os.makedirs(out_dir, exist_ok=True)
for name, case in sorted(model["cases"].items()):
    if "error" in case:
        print(f"chat-{name}: SKIPPED — template refuses: {case['error']}")
        continue
    if not case["encode_rendered_matches_templated"]:
        sys.exit(f"case {name}: goldens record encode(render) != templated ids "
                 "— the invariant this fixture would pin does not hold")
    msgs = []
    for m in case["messages"]:
        if sorted(m.keys()) != ["content", "role"]:
            sys.exit(f"case {name}: message keys {sorted(m.keys())} beyond "
                     "role/content — the gateway parse would drop fields")
        msgs.append({"role": m["role"], "content": m["content"]})
    req = json.dumps({"model": served, "messages": msgs},
                     ensure_ascii=False).encode("utf-8")
    exp = {
        "requestSha256": hashlib.sha256(req).hexdigest(),
        "expectedTokenIds": case["templated_ids"],
        "api": "chat",
    }
    if oracle_now:
        exp["oracleNow"] = oracle_now
    with open(os.path.join(out_dir, f"chat-{name}.request.json"), "wb") as f:
        f.write(req)
    with open(os.path.join(out_dir, f"chat-{name}.expect.json"), "w") as f:
        json.dump(exp, f, indent=1)
    print(f"chat-{name}: {len(case['templated_ids'])} tokens"
          + (f" (oracleNow {oracle_now})" if oracle_now else ""))
