#!/usr/bin/env python3
"""Generate strict KV-exact model profiles, engine manifests and probe fixtures for the candidate models.

For each (profileId, template slug, content format) in MODELS, every value is read from a pinned input:

  tokenizerSha256   sha256 of <artifacts>/<slug>/tokenizer.json (the file the tokenizer pool loads)
  templateSha256    sha256 of fixtures/templates/<slug>/chat_template.jinja, which must equal the
                    candidate goldens' template_sha256 (drifted inputs are refused)
  bos/eos, revision the candidate goldens (kv_chat_render_candidates.json)
  modelType         <artifacts>/<slug>/config.json "model_type" (admission reads it to refuse a strict
                    chat surface on engines that render chat with their own encoder)
  clockPolicy       utc-date when the template reads strftime_now
  engineQuirks      the profile's entry in ENGINE_QUIRKS (measured on the live engine; see there)

templateContentFormat is the engines' content-format verdict for the template (vLLM's detector; openai =
a loop over message content parts), fixed per model below.

Written under <fixtures>: profiles/<id>.yaml, manifests/<id>.yaml (vLLM), manifests-sglang/<id>.yaml,
probefixtures/<id>/ (completions fixtures from gen_probe_fixtures.py + chat fixtures from
gen_chat_probe_fixtures.py) and probefixtures/<id>/sglang/, the same set minus every chat case that ends on
an assistant turn: SGLang renders a trailing assistant message as a user turn, and the gateway refuses such
strict chat requests, so the engine is never asked to agree on that render.

For an openai-format template the top (vLLM) set also leaves out every chat case whose render depends on the
content shape: vLLM hands such a template a string content as one text part (null as []), the gateway renders
both shapes and refuses the request when they differ, so the case is never hashed on vLLM and banking the
string-shape ids would hold a strict vLLM rule below READY forever. SGLang keeps a string content a string, so
its subset keeps these cases. The shape check renders with transformers' own Jinja compiler (it must be
importable wherever this runs).

Usage: gen_model_profiles.py <fixtures_dir> <artifacts_dir> [profileId ...]
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys

MODELS = [
    # profileId, template slug, templateContentFormat
    ("olmo2-0425-1b-v1", "allenai__OLMo-2-0425-1B-Instruct", "string"),
    ("r1-distill-qwen-15b-v1", "deepseek-ai__DeepSeek-R1-Distill-Qwen-1.5B", "string"),
    ("gemma3-1b-it-v1", "google__gemma-3-1b-it", "openai"),
    ("gemma4-e2b-it-v1", "google__gemma-4-E2B-it", "openai"),
    ("granite42-3b-v1", "ibm-granite__granite-4.2-3b", "string"),
    ("exaone4-12b-v1", "LGAI-EXAONE__EXAONE-4.0-1.2B", "string"),
    ("llama32-1b-v1", "meta-llama__Llama-3.2-1B-Instruct", "string"),
    ("phi4-mini-instruct-v1", "microsoft__Phi-4-mini-instruct", "string"),
    ("ministral3-3b-v1", "mistralai__Ministral-3-3B-Instruct-2512", "openai"),
    ("gptoss-20b-v1", "openai__gpt-oss-20b", "string"),
    ("qwen36-27b-fp8-v1", "Qwen__Qwen3.6-27B-FP8", "openai"),
    ("qwen38-27b-fp8-v1", "Qwen__Qwen3.8-27B-FP8", "openai"),
    ("ax31-light-v1", "skt__A.X-3.1-Light", "string"),
]

# Engine images the manifests pin (the identity probe compares engineVersion and modelRevision).
ENGINES = (
    ("manifests", "sha256:61fc8a896b0a4fbbbdc063bc4b0dbc25ce98e02b5050c24aeb7830ac02039b14", "0.28.0"),
    ("manifests-sglang", "sha256:9e148f5ac788e856a06166bd6347a831831eb9fcfab4d1770874823a7c29a1a1", "0.5.18"),
)
GOLDENS = "kv_chat_render_candidates.json"
HERE = os.path.dirname(os.path.abspath(__file__))


def sha256_file(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


# Engine x model behaviour measured on the live engine, keyed by engine-contract profile id
# (engine-contracts/contracts.yaml); only quirks that are set are listed, the gateway refuses an empty entry.
# completionsBos: the engine encodes the completions prompt with a BOS that the gateway's tokenizer does not add.
#   SGLang v0.5.18 restores tokenizer_config.json's add_bos_token (transformers v5 drops it) and rebuilds the
#   post-processor; vLLM v0.28.0 does not. Measured (/v1/completions return_token_ids and /v1/tokenize on the
#   pinned snapshot), not derived: gemma-4 also asks for a BOS through a v4 Gemma class and SGLang's standalone
#   get_tokenizer adds one, yet the served multimodal path does not (its P/D leg attests with BOS-less
#   completions fixtures). A model missing here fails the SGLang P/D leg's completions probe (token_mismatch,
#   one token long), never silently.
ENGINE_QUIRKS = {
    "r1-distill-qwen-15b-v1": {"sglang-kv-rank-v1": {"completionsBos": True}},
}


def quirks_yaml(pid):
    lines = []
    for contract, quirks in sorted(ENGINE_QUIRKS.get(pid, {}).items()):
        lines.append(f"  {contract}:")
        lines += [f"    {k}: true" for k, v in sorted(quirks.items()) if v]
    return ["engineQuirks:"] + lines if lines else []


def profile_yaml(pid, g, mtype, toksha, tplsha, fmt, clock):
    lines = [
        f"profileId: {pid}",
        f"baseModel: {g['model']}",
        f"modelType: {mtype}",
    ] + quirks_yaml(pid) + [
        f"tokenizerRevision: {g['revision']}",
        f"tokenizerArtifact: sha256/{toksha}",
        f"tokenizerSha256: {toksha}",
        f"templateArtifact: sha256/{tplsha}",
        f"templateSha256: {tplsha}",
        f"templateContentFormat: {fmt}",
        "renderPolicy:",
        "  addGenerationPrompt: true",
    ]
    if g["bos_token"]:
        lines.append("  bosToken: " + json.dumps(g["bos_token"], ensure_ascii=False))
    if g["eos_token"]:
        lines.append("  eosToken: " + json.dumps(g["eos_token"], ensure_ascii=False))
    if clock:
        lines.append("  clockPolicy: utc-date")
    lines += ["supportedApis:", "  - completions", "  - chat", "aliasPolicy: base_model_only"]
    return "\n".join(lines) + "\n"


def sglang_subset(out):
    sub = os.path.join(out, "sglang")
    os.makedirs(sub)
    for fn in sorted(os.listdir(out)):
        if not fn.endswith(".request.json"):
            continue
        if fn.startswith("chat-"):
            with open(os.path.join(out, fn)) as f:
                msgs = json.load(f)["messages"]
            if msgs and msgs[-1]["role"] == "assistant":
                continue
        base = fn[: -len(".request.json")]
        for suffix in (".request.json", ".expect.json"):
            shutil.copy(os.path.join(out, base + suffix), sub)


def vllm_shape_dependent(template, g):
    """Chat case names whose render changes when each content takes vLLM's openai shape (or that then raise)."""
    import datetime as dt
    from transformers.utils import chat_template_utils as ctu

    frozen = dt.datetime(2026, 3, 5, 7, 8, 9)

    class _Frozen(dt.datetime):
        @classmethod
        def now(cls, tz=None):
            return frozen

    ctu.datetime = _Frozen
    compiled = ctu._compile_jinja_template(template)
    kw = {"add_generation_prompt": True, "bos_token": g.get("bos_token"), "eos_token": g.get("eos_token")}

    def vllm_shape(msgs):
        out = []
        for m in msgs:
            m = dict(m)
            c = m.get("content")
            m["content"] = [] if c is None else ([{"type": "text", "text": c}] if isinstance(c, str) else c)
            out.append(m)
        return out

    dep = set()
    for name, case in g["cases"].items():
        if "error" in case:
            continue
        try:
            same = compiled.render(messages=vllm_shape(case["messages"]), **kw) == \
                compiled.render(messages=case["messages"], **kw)
        except Exception:  # noqa: BLE001 — a raise in either shape is a refusal too
            same = False
        if not same:
            dep.add(name)
    return dep


def drop_vllm_shape_dependent(out, g):
    dropped = []
    for name in sorted(vllm_shape_dependent(g["template"], g)):
        base = os.path.join(out, "chat-" + name)
        if os.path.exists(base + ".request.json"):
            for suffix in (".request.json", ".expect.json"):
                os.remove(base + suffix)
            dropped.append("chat-" + name)
    return dropped


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    fixtures, artifacts, only = sys.argv[1], sys.argv[2], set(sys.argv[3:])
    with open(os.path.join(fixtures, GOLDENS)) as f:
        gold = json.load(f)["models"]
    for pid, slug, fmt in MODELS:
        if only and pid not in only:
            continue
        g = gold[slug]
        tok = os.path.join(artifacts, slug, "tokenizer.json")
        tpl = os.path.join(fixtures, "templates", slug, "chat_template.jinja")
        toksha, tplsha = sha256_file(tok), sha256_file(tpl)
        if tplsha != g["template_sha256"]:
            sys.exit(f"{slug}: banked template {tplsha} != goldens {g['template_sha256']}")
        with open(os.path.join(artifacts, slug, "config.json")) as f:
            mtype = json.load(f)["model_type"]
        with open(tpl, encoding="utf-8") as f:
            clock = "strftime_now" in f.read()
        for sub in ("profiles",) + tuple(e[0] for e in ENGINES):
            os.makedirs(os.path.join(fixtures, sub), exist_ok=True)
        with open(os.path.join(fixtures, "profiles", pid + ".yaml"), "w") as f:
            f.write(profile_yaml(pid, g, mtype, toksha, tplsha, fmt, clock))
        for sub, digest, version in ENGINES:
            with open(os.path.join(fixtures, sub, pid + ".yaml"), "w") as f:
                f.write(f'profileId: {pid}\nimageDigest: "{digest}"\nengineVersion: "{version}"\n'
                        f'modelRevision: "{g["revision"]}"\n')
        out = os.path.join(fixtures, "probefixtures", pid)
        shutil.rmtree(out, ignore_errors=True)
        subprocess.run([sys.executable, os.path.join(HERE, "gen_probe_fixtures.py"), tok, out, g["model"]],
                       check=True, stdout=subprocess.DEVNULL)
        r = subprocess.run([sys.executable, os.path.join(HERE, "gen_chat_probe_fixtures.py"), fixtures, slug,
                            out, GOLDENS], capture_output=True, text=True)
        if r.returncode:
            sys.exit(f"{pid}: chat fixtures refused: {r.stderr.strip()}")
        sglang_subset(out)
        dropped = drop_vllm_shape_dependent(out, g) if fmt == "openai" else []
        n = len([fn for fn in os.listdir(out) if fn.endswith(".json")])
        print(f"{pid}: type={mtype} format={fmt} clock={clock} tokenizer={toksha[:12]} "
              f"template={tplsha[:12]} fixtures={n} refused-cases={r.stdout.count('SKIPPED')} "
              f"vllm-shape-dropped={','.join(dropped) or '-'}")


if __name__ == "__main__":
    main()
