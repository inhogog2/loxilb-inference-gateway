#!/usr/bin/env python3
"""modelctl.py — the supported-models manifest, its generated page, its drift gate and the installer.

One committed file, scripts/models/validated-models.yaml, is the source for all of them:

  render        write docs/SUPPORTED-MODELS.md from the manifest
  check         drift gate: the page, the manifest, the committed model profiles and engine manifests, the
                banked template provenance (SOURCES.json), the weights indexes and
                engine-contracts/support-catalog.yaml must agree; exits non-zero on any disagreement
  verify-weights  check a snapshot directory you already have against a model's committed weights index
  pin-weights   (maintainers) write scripts/models/weights/<profileId>.index from the Hugging Face file tree
                of the pinned revision and print its sha256 for the manifest
  install       stage the profile-registry trust root for the selected models, optionally download the
                pinned weights and pull the digest-pinned engine image (see install-models.sh --help)

A model row is added or promoted by editing the manifest, then `render`; nothing else carries a support claim.
Needs python3 with PyYAML. The access token is read from a file and sent as a request header only.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("modelctl: PyYAML is required (python3-yaml / pip install pyyaml)")

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
MANIFEST = os.path.join(HERE, "validated-models.yaml")
WEIGHTS_DIR = os.path.join(HERE, "weights")
DOC = os.path.join(ROOT, "docs", "SUPPORTED-MODELS.md")
FIX = os.path.join(ROOT, "cicd", "common", "kv_hash", "fixtures")
CATALOG = os.path.join(ROOT, "engine-contracts", "support-catalog.yaml")
SCHEMA = "models.loxilb.io/v1alpha1"
HF = os.environ.get("HF_ENDPOINT", "https://huggingface.co").rstrip("/")

STATES = ("validated", "candidate", "blocked")
GATES = ("renderDifferential", "pdChat", "pdCompletions", "abPerf")
PERF_KEYS = ("topology", "surface", "corpus", "rateRps", "requestsPerArm", "exactTtftP95Ms", "baselineTtftP95Ms",
             "exactTtftP50Ms", "baselineTtftP50Ms", "date")
GATE_VALUES = ("pass", "fail", "not_run", "n_a")
# The engine manifest set a registry stages for each engine (the identity probe compares it with the engine).
MANIFEST_SETS = {"vllm": "manifests", "sglang": "manifests-sglang"}
ID_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,62}$")
REPO_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
# Files of a snapshot an engine never reads; everything else at the top level of the pinned tree is indexed.
SKIP_FILE = re.compile(r"(^\.gitattributes$|^README|^LICENSE|^NOTICE|^USE_POLICY|^USAGE_POLICY|\.md$"
                       r"|\.(png|jpe?g|gif|pdf)$)", re.I)


class Refusal(Exception):
    """A typed refusal: code first, detail after."""

    def __init__(self, code, detail):
        super().__init__(f"{code}: {detail}")
        self.code = code


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def gitblob_file(path):
    h = hashlib.sha1(b"blob %d\0" % os.path.getsize(path))
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_yaml(path):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def slug(repo):
    return repo.replace("/", "__")


# ---------------------------------------------------------------- manifest

def load_manifest(path=MANIFEST):
    """Parse and validate the manifest's own shape; every later step trusts these fields."""
    m = load_yaml(path)
    errs = []
    if not isinstance(m, dict) or m.get("schemaVersion") != SCHEMA:
        raise Refusal("MANIFEST_SCHEMA", f"{path}: schemaVersion must be {SCHEMA}")
    engines = {}
    for e in m.get("engines") or []:
        key = (e.get("engine"), e.get("version"))
        if key in engines:
            errs.append(f"engine {key} listed twice")
        if e.get("digest") is not None and not DIGEST.match(str(e.get("digest"))):
            errs.append(f"engine {key}: digest is not sha256:<64 hex>")
        engines[key] = e
    seen = set()
    for mod in m.get("models") or []:
        pid = str(mod.get("profileId"))
        if not ID_RE.match(pid):
            errs.append(f"profileId {pid!r} is not a safe id")
        if pid in seen:
            errs.append(f"profileId {pid} listed twice")
        seen.add(pid)
        if not REPO_RE.match(str(mod.get("repo"))) or ".." in str(mod.get("repo")):
            errs.append(f"{pid}: repo {mod.get('repo')!r} is not <org>/<name>")
        if not HEX40.match(str(mod.get("revision"))):
            errs.append(f"{pid}: revision must be a full 40-hex commit, never a branch")
        for k in ("tokenizerSha256", "templateSha256", "weightsIndexSha256"):
            if not HEX64.match(str(mod.get(k))):
                errs.append(f"{pid}: {k} is not 64 hex")
        if mod.get("gated") not in (True, False):
            errs.append(f"{pid}: gated must be true or false")
        tseen = set()
        for t in mod.get("tuples") or []:
            key = (t.get("engine"), t.get("engineVersion"))
            where = f"{pid} x {key[0]} {key[1]}"
            if key not in engines:
                errs.append(f"{where}: engine/version is not in the manifest's engines list")
            if key in tseen:
                errs.append(f"{where}: listed twice")
            tseen.add(key)
            if t.get("state") not in STATES:
                errs.append(f"{where}: state must be one of {STATES}")
            if t.get("state") == "blocked" and not (t.get("reason") and t.get("detail")):
                errs.append(f"{where}: a blocked row needs reason and detail")
            if t.get("state") != "blocked":
                ev = t.get("evidence") or {}
                for g in GATES:
                    if ev.get(g) not in GATE_VALUES:
                        errs.append(f"{where}: evidence.{g} must be one of {GATE_VALUES}")
                if not t.get("apis") or any(a not in ("chat", "completions") for a in t["apis"]):
                    errs.append(f"{where}: apis must list chat and/or completions")
                if not t.get("modes") or any(x not in ("converged", "pd") for x in t["modes"]):
                    errs.append(f"{where}: modes must list converged and/or pd")
                if not re.match(r"^\d{4}-\d{2}-\d{2}$", str(t.get("lastValidated"))):
                    errs.append(f"{where}: lastValidated must be YYYY-MM-DD")
                for n, pt in enumerate(t.get("perf") or []):
                    missing = [k for k in PERF_KEYS if pt.get(k) is None]
                    if missing:
                        errs.append(f"{where}: perf[{n}] lacks {', '.join(missing)}")
                # the gate and the numbers travel together: no pass without a point, no point without a verdict
                if (ev.get("abPerf") == "pass") != bool(t.get("perf")):
                    errs.append(f"{where}: evidence.abPerf = pass needs perf points, and perf points need abPerf = pass")
            if t.get("state") == "validated":
                # A gate that was not run is not a pass: every gate of a surface the row claims must have passed.
                ev = t.get("evidence") or {}
                need = ["renderDifferential"] if "chat" in (t.get("apis") or []) else []
                if "pd" in (t.get("modes") or []):
                    need += ["pdChat"] if "chat" in t["apis"] else []
                    need += ["pdCompletions"] if "completions" in t["apis"] else []
                need.append("abPerf")  # every promoted row carries a measured A/B point
                for g in need:
                    if ev.get(g) != "pass":
                        errs.append(f"{where}: validated needs evidence.{g} = pass (is {ev.get(g)})")
    if errs:
        raise Refusal("MANIFEST_INVALID", "; ".join(errs))
    m["_engines"] = engines
    return m


def read_index(pid):
    """A weights index: one `<algo>:<hex> <size> <path>` line per file of the pinned snapshot."""
    path = os.path.join(WEIGHTS_DIR, pid + ".index")
    rows = []
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            parts = line.rstrip("\n").split(" ", 2)
            if len(parts) != 3:
                raise Refusal("INDEX_INVALID", f"{path}:{n}: want '<algo>:<hex> <size> <path>'")
            digest, size, name = parts
            algo, _, hexd = digest.partition(":")
            if algo not in ("sha256", "gitblob") or not re.match(r"^[0-9a-f]+$", hexd) or not size.isdigit():
                raise Refusal("INDEX_INVALID", f"{path}:{n}: bad digest or size")
            if "/" in name or name in (".", "..") or name.startswith("-") or not name:
                raise Refusal("INDEX_UNSAFE_PATH", f"{path}:{n}: {name!r}")
            rows.append((algo, hexd, int(size), name))
    return path, rows


# ---------------------------------------------------------------- render

GATE_MARK = {"pass": "pass", "fail": "FAIL", "not_run": "not run", "n_a": "n/a"}


def gb(nbytes):
    return f"{nbytes / 1e9:.1f} GB"


def render(m):
    eng = m["_engines"]
    out = [
        "# Supported models for KV-exact routing",
        "",
        "<!-- GENERATED by scripts/models/modelctl.py render from scripts/models/validated-models.yaml.",
        "     Do not edit: change the manifest and regenerate. `modelctl.py check` fails on a hand edit. -->",
        "",
        "This page lists every model × engine combination that has been qualified for strict KV-exact",
        "routing (`kvExactMode` with a model profile), with its exact identity and its state.",
        "",
        "**The support contract.** A row is supported only in the state `validated`. A `candidate` row has",
        "evidence but has not been promoted and is **not supported**. A `blocked` row is refused, with the",
        "reason shown. A model that is not on this page is not supported for strict KV-exact routing: the",
        "gateway has no profile for it and refuses a strict rule that names it with a typed error instead of",
        "guessing a tokenizer or a chat template. Engines other than the versions listed are not covered by a row.",
        "",
        "## Engines",
        "",
        "| Engine | Version | Image (digest-pinned) | Contract profile |",
        "|---|---|---|---|",
    ]
    for (name, ver), e in eng.items():
        img = f"`{e['image']}@{e['digest']}`" if e.get("image") and e.get("digest") else e.get("imageNote", "—")
        out.append(f"| {name} | {ver} | {img} | `{e['contract']}` |")
    out += [
        "",
        "llama.cpp has no KV-exact plane (no cache events); it is served by plain load balancing and has no rows here.",
        "",
        "## Models",
        "",
        "| Model | Revision | Profile | Gated | Snapshot size |",
        "|---|---|---|---|---|",
    ]
    for mod in m["models"]:
        _, rows = read_index(mod["profileId"])
        out.append(f"| [{mod['repo']}]({HF_PUBLIC}/{mod['repo']}/tree/{mod['revision']}) | `{mod['revision'][:12]}` "
                   f"| `{mod['profileId']}` | {'yes' if mod['gated'] else 'no'} | {gb(sum(r[2] for r in rows))} |")
    out += [
        "",
        "## Qualification matrix",
        "",
        "Evidence columns: **render** = the gateway's rendered and tokenized chat prompt compared with the",
        "engine's own serving path over the probe corpus (zero mismatches); **P/D chat** and **P/D completions**",
        "= a live prefill/decode pair reaching READY through the attestation ladder and scoring exact cache",
        "hits on that API surface, run twice; **A/B perf** = a measured comparison against round-robin on the",
        "same fleet (see below). `not run` is not a pass, and a row is not promoted without all of them.",
        "",
        "| Model | Engine | State | Modes | APIs | render | P/D chat | P/D completions | A/B perf | Last validated |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    notes = []
    for mod in m["models"]:
        name = mod["repo"].split("/", 1)[1]
        for t in mod["tuples"]:
            engv = f"{t['engine']} {t['engineVersion']}"
            if t["state"] == "blocked":
                out.append(f"| {name} | {engv} | **blocked** (`{t['reason']}`) | — | — | — | — | — | — | — |")
                notes.append((name, engv, t["detail"]))
                continue
            ev = t["evidence"]
            out.append(f"| {name} | {engv} | {t['state']} | {', '.join(t['modes'])} | {', '.join(t['apis'])} "
                       f"| {GATE_MARK[ev['renderDifferential']]} | {GATE_MARK[ev['pdChat']]} "
                       f"| {GATE_MARK[ev['pdCompletions']]} | {GATE_MARK[ev['abPerf']]} | {t['lastValidated']} |")
            if t.get("detail"):
                notes.append((name, engv, t["detail"]))
    out += ["", "### Blocked rows and notes", ""]
    out += [f"- **{n} × {e}** — {d}" for n, e, d in notes]
    out += ["", "## A/B performance: KV-exact routing against round-robin", "",
            "Each point compares the two routing modes on the same engines, with the same requests at the same",
            "offered rate, three repetitions in alternating order, engines restarted and caches re-seeded before",
            "every run. A point counts only when every request succeeds on both arms and the exact arm scores every",
            "expected cache hit with no fall-through. TTFT = time to first token. A short-prefix corpus is the",
            "control: no cache benefit is expected there, so it shows the routing overhead.", ""]
    pts = [(mod, t, pt) for mod in m["models"] for t in mod["tuples"] for pt in (t.get("perf") or [])]
    if not pts:
        out.append("No point has been measured for the rows on this page yet.")
    else:
        out += ["| Model | Engine | Topology | Surface | Corpus | Rate (req/s) | Requests/arm | TTFT p95 exact (ms) "
                "| TTFT p95 round-robin (ms) | Δ p95 | TTFT p50 exact / round-robin (ms) | Date |",
                "|---|---|---|---|---|---|---|---|---|---|---|---|"]
        for mod, t, pt in pts:
            d = 100.0 * (pt["exactTtftP95Ms"] - pt["baselineTtftP95Ms"]) / pt["baselineTtftP95Ms"]
            out.append(f"| {mod['repo'].split('/', 1)[1]} | {t['engine']} {t['engineVersion']} | {pt['topology']} "
                       f"| {pt['surface']} | {pt['corpus']} | {pt['rateRps']} | {pt['requestsPerArm']} "
                       f"| {pt['exactTtftP95Ms']} | {pt['baselineTtftP95Ms']} | {d:+.1f}% "
                       f"| {pt['exactTtftP50Ms']} / {pt['baselineTtftP50Ms']} | {pt['date']} |")
    out += ["", "## Required launch arguments", "",
            "Arguments beyond the engine's usual KV-event settings. A row without an entry needs none.", "",
            "| Model | Engine | Requirement |", "|---|---|---|"]
    for mod in m["models"]:
        name = mod["repo"].split("/", 1)[1]
        for t in mod["tuples"]:
            for req in t.get("launch") or []:
                out.append(f"| {name} | {t['engine']} {t['engineVersion']} | {req} |")
    out += ["", "Every engine, every model:", ""]
    out += [f"- {x}" for x in m.get("launchAll") or []]
    out += ["", "## Request features a strict rule refuses", "",
            "These hold for every model on this page; the request is refused with a typed error, never hashed approximately.",
            ""]
    out += [f"- {x}" for x in m.get("excludedFeatures") or []]
    out += [
        "",
        "## Installing a model",
        "",
        "```bash",
        "scripts/models/install-models.sh --list                       # what the manifest holds",
        "scripts/models/install-models.sh --dry-run --models <id>       # what would be staged",
        "sudo scripts/models/install-models.sh --engine vllm --models <id>",
        "```",
        "",
        "The installer stages the profile registry (profile, engine manifest, probe fixtures, tokenizer and chat",
        "template, each verified against the sha256 pinned here) and, with `--weights-dir`, downloads the pinned",
        "snapshot and verifies every file. It installs `validated` rows only; `--include-candidates` is an",
        "explicit opt-in to rows that are not supported. The gateway reads the registry when it starts: restart",
        "it after staging.",
        "",
        "## Adding or updating a model",
        "",
        "1. **Pin** the Hugging Face revision; bank its chat template under",
        "   `cicd/common/kv_hash/fixtures/templates/` with its provenance in `SOURCES.json`.",
        "2. **Goldens**: the template must render byte-exactly through the gateway's template executor against",
        "   the engine renderer's goldens; a new construct needs goldens and a mutation test.",
        "3. **Profile**: generate the profile, engine manifests and probe fixtures",
        "   (`cicd/common/kv_hash/gen_model_profiles.py`).",
        "4. **Live legs**: run the render comparison against each engine's serving path, then the",
        "   prefill/decode scenario `cicd/kv-model-compat-pd`, twice, then an A/B performance point.",
        "5. **Manifest**: add the model and one row per engine to `scripts/models/validated-models.yaml` as",
        "   `candidate` with the evidence gates that actually ran; `modelctl.py pin-weights <profileId>`",
        "   writes the weights index.",
        "6. **Promotion** to `validated` is a reviewed change to the manifest by the code owners; a green leg",
        "   never promotes a row by itself.",
        "7. `modelctl.py render`, then `modelctl.py check`.",
        "",
    ]
    return "\n".join(out)


HF_PUBLIC = "https://huggingface.co"


# ---------------------------------------------------------------- drift gate

def check(m, doc_path=DOC):
    """Every disagreement between the manifest and what it describes. Empty list = no drift."""
    errs = []
    cat = {(e["engine"], str(e["version"])): e for e in load_yaml(CATALOG)["entries"]}
    for (name, ver), e in m["_engines"].items():
        c = cat.get((name, ver))
        if c is None:
            errs.append(f"engine {name} {ver}: no entry in support-catalog.yaml")
            continue
        if c.get("profile") != e.get("contract"):
            errs.append(f"engine {name} {ver}: contract {e.get('contract')} != catalog profile {c.get('profile')}")
        cdig = (c.get("image") or {}).get("platformDigest")
        if e.get("digest") != cdig:
            errs.append(f"engine {name} {ver}: digest {e.get('digest')} != catalog platformDigest {cdig}")
    sources = json.load(open(os.path.join(FIX, "templates", "SOURCES.json"), encoding="utf-8"))["templates"]
    committed = {f[:-5] for f in os.listdir(os.path.join(FIX, "profiles")) if f.endswith(".yaml")}
    listed = {mod["profileId"] for mod in m["models"]}
    for pid in sorted(committed - listed):
        errs.append(f"{pid}: committed profile has no manifest row")
    for pid in sorted(listed - committed):
        errs.append(f"{pid}: manifest row has no committed profile")
    for mod in m["models"]:
        pid = mod["profileId"]
        if pid not in committed:
            continue
        p = load_yaml(os.path.join(FIX, "profiles", pid + ".yaml"))
        for mk, pk in (("repo", "baseModel"), ("revision", "tokenizerRevision"),
                       ("tokenizerSha256", "tokenizerSha256"), ("templateSha256", "templateSha256")):
            if mod[mk] != p.get(pk):
                errs.append(f"{pid}: manifest {mk} {mod[mk]} != profile {pk} {p.get(pk)}")
        s = sources.get(slug(mod["repo"]))
        if s is None:
            errs.append(f"{pid}: no SOURCES.json entry for {slug(mod['repo'])}")
        else:
            for mk, sk in (("repo", "model"), ("revision", "revision"), ("templateSha256", "sha256")):
                if mod[mk] != s.get(sk):
                    errs.append(f"{pid}: manifest {mk} {mod[mk]} != SOURCES.json {sk} {s.get(sk)}")
        tpl = os.path.join(FIX, "templates", slug(mod["repo"]), "chat_template.jinja")
        if not os.path.isfile(tpl) or sha256_file(tpl) != mod["templateSha256"]:
            errs.append(f"{pid}: banked chat template is missing or its sha256 is not templateSha256")
        if not os.path.isdir(os.path.join(FIX, "probefixtures", pid)):
            errs.append(f"{pid}: no committed probe fixtures")
        try:
            ipath, rows = read_index(pid)
            if sha256_file(ipath) != mod["weightsIndexSha256"]:
                errs.append(f"{pid}: weights index sha256 is not weightsIndexSha256")
            tok = [r for r in rows if r[3] == "tokenizer.json"]
            # A tokenizer.json stored as a plain git blob carries no sha256 in the index; the installer still
            # verifies the downloaded file against tokenizerSha256.
            if len(tok) != 1 or (tok[0][0] == "sha256" and tok[0][1] != mod["tokenizerSha256"]):
                errs.append(f"{pid}: weights index tokenizer.json is missing or is not tokenizerSha256")
        except (OSError, Refusal) as e:
            errs.append(f"{pid}: weights index: {e}")
        for t in mod["tuples"]:
            key = (t["engine"], t["engineVersion"])
            where = f"{pid} x {key[0]} {key[1]}"
            c = cat.get(key)
            if t["state"] == "validated" and (c is None or c.get("promotion") != "validated"):
                errs.append(f"{where}: validated on an engine entry the catalog has not validated")
            if t["state"] == "blocked":
                continue
            for a in t["apis"]:
                if a not in (p.get("supportedApis") or []):
                    errs.append(f"{where}: api {a} is not in the profile's supportedApis")
            mset = MANIFEST_SETS.get(t["engine"])
            if mset:
                mp = os.path.join(FIX, mset, pid + ".yaml")
                if not os.path.isfile(mp):
                    errs.append(f"{where}: no committed engine manifest {mset}/{pid}.yaml")
                    continue
                em = load_yaml(mp)
                e = m["_engines"].get(key, {})
                if em.get("imageDigest") != e.get("digest"):
                    errs.append(f"{where}: {mset} imageDigest {em.get('imageDigest')} != engine digest {e.get('digest')}")
                if "v" + str(em.get("engineVersion")) != str(key[1]):
                    errs.append(f"{where}: {mset} engineVersion {em.get('engineVersion')} != {key[1]}")
                if em.get("modelRevision") != mod["revision"]:
                    errs.append(f"{where}: {mset} modelRevision != manifest revision")
    want = render(m)
    have = open(doc_path, encoding="utf-8").read() if os.path.isfile(doc_path) else ""
    if have != want:
        errs.append(f"{os.path.relpath(doc_path, ROOT)} is not the manifest's render (run: modelctl.py render)")
    return errs


# ---------------------------------------------------------------- network

def read_token(path):
    if not path:
        return None
    st = os.stat(path)
    if st.st_mode & 0o077:
        raise Refusal("TOKEN_FILE_MODE", f"{path} must not be readable by group or others (chmod 600)")
    with open(path, encoding="utf-8") as f:
        tok = f.read().strip()
    if not tok:
        raise Refusal("TOKEN_FILE_EMPTY", path)
    return tok


def http_open(url, token, start=0):
    req = urllib.request.Request(url)
    if token:
        req.add_header("Authorization", "Bearer " + token)
    if start:
        req.add_header("Range", f"bytes={start}-")
    return urllib.request.urlopen(req, timeout=60)


def fetch(url, dest, token, size=None):
    """Download to dest, resuming a partial dest.part. The caller verifies the digest."""
    part = dest + ".part"
    start = os.path.getsize(part) if os.path.exists(part) else 0
    if size is not None and start > size:
        os.remove(part)
        start = 0
    if size is None or start < size:
        try:
            r = http_open(url, token, start)
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                raise Refusal("DOWNLOAD_DENIED", f"HTTP {e.code} for {url} (gated repository or bad token)")
            raise Refusal("DOWNLOAD_FAILED", f"HTTP {e.code} for {url}")
        except urllib.error.URLError as e:
            raise Refusal("DOWNLOAD_FAILED", f"{url}: {e.reason}")
        resumed = start and r.status == 206
        with r, open(part, "ab" if resumed else "wb") as f:
            shutil.copyfileobj(r, f, 1 << 20)
    os.replace(part, dest)


def resolve_url(repo, rev, name):
    return f"{HF}/{repo}/resolve/{rev}/{name}"


# ---------------------------------------------------------------- install

def safe_dir(path, label):
    """An install root is the operator's choice: it must be absolute and free of '..'."""
    if not os.path.isabs(path) or ".." in path.split(os.sep):
        raise Refusal("UNSAFE_PATH", f"{label} {path!r} must be absolute without '..'")
    return os.path.normpath(path)


def no_symlink_below(root, dest):
    """Nothing the installer writes may be, or be reached through, a symlink beneath its install root."""
    rel = os.path.relpath(dest, root)
    if rel.startswith("..") or os.path.isabs(rel):
        raise Refusal("UNSAFE_PATH", f"{dest} is outside {root}")
    probe = root
    for part in rel.split(os.sep):
        probe = os.path.join(probe, part)
        if os.path.islink(probe):
            raise Refusal("UNSAFE_PATH", f"{probe} is a symlink")


def commit(plan, dry):
    """Write a model's planned files. Every destination is checked before the first one is written."""
    for _, dest, root in plan:
        no_symlink_below(root, dest)
    if dry:
        return
    for src, dest, _ in plan:
        os.makedirs(os.path.dirname(dest), mode=0o755, exist_ok=True)
        if os.path.abspath(src) == os.path.abspath(dest):
            continue
        tmp = dest + ".tmp"
        shutil.copyfile(src, tmp)
        os.chmod(tmp, 0o644)
        os.replace(tmp, dest)


def committed_file(*parts):
    """A file of the committed fixture tree; a symlink there is refused, never followed."""
    path = os.path.join(FIX, *parts)
    if os.path.islink(path) or not os.path.isfile(path):
        raise Refusal("COMMITTED_FILE", f"{os.path.relpath(path, ROOT)} is missing or a symlink")
    return path


def verify_weight(path, algo, hexd, size):
    if os.path.getsize(path) != size:
        return False
    return (sha256_file(path) if algo == "sha256" else gitblob_file(path)) == hexd


def select(m, args):
    """(model, tuple, action) for the requested engine; action is install or a typed skip."""
    wanted = [x for x in (args.models or "").split(",") if x]
    known = {mod["profileId"] for mod in m["models"]}
    for w in wanted:
        if w not in known:
            raise Refusal("UNKNOWN_MODEL", f"{w} is not in the manifest (see --list)")
    picks = []
    for mod in m["models"]:
        if wanted and mod["profileId"] not in wanted:
            continue
        rows = [t for t in mod["tuples"] if t["engine"] == args.engine]
        if not rows:
            picks.append((mod, None, f"SKIP_NO_ROW no {args.engine} row"))
            continue
        t = rows[-1]
        if t["state"] == "blocked":
            picks.append((mod, t, f"SKIP_BLOCKED {t['reason']}: {t['detail']}"))
        elif t["state"] == "candidate" and not args.include_candidates:
            picks.append((mod, t, "SKIP_CANDIDATE not supported; --include-candidates opts in"))
        else:
            picks.append((mod, t, "install"))
    return picks


def install_one(mod, m, args, token, work):
    pid, repo, rev = mod["profileId"], mod["repo"], mod["revision"]
    plan = []
    mset = MANIFEST_SETS.get(args.engine)
    if not mset:
        raise Refusal("NO_ENGINE_MANIFEST", f"no committed engine manifest set for {args.engine}")
    profile = committed_file("profiles", pid + ".yaml")
    engine_manifest = committed_file(mset, pid + ".yaml")
    template = committed_file("templates", slug(repo), "chat_template.jinja")
    if sha256_file(template) != mod["templateSha256"]:
        raise Refusal("TEMPLATE_SHA_MISMATCH", f"{pid}: banked chat template is not {mod['templateSha256']}")
    p = load_yaml(profile)
    if p.get("tokenizerSha256") != mod["tokenizerSha256"] or p.get("tokenizerRevision") != rev:
        raise Refusal("PROFILE_DRIFT", f"{pid}: the committed profile does not carry the manifest's pins")
    ipath, rows = read_index(pid)
    if sha256_file(ipath) != mod["weightsIndexSha256"]:
        raise Refusal("INDEX_SHA_MISMATCH", f"{pid}: weights index is not {mod['weightsIndexSha256']}")
    fixtures = []
    fxroot = os.path.join(FIX, "probefixtures", pid)
    for sub in ("", "sglang"):
        d = os.path.join(fxroot, sub)
        if not os.path.isdir(d) or os.path.islink(d):
            continue
        for name in sorted(os.listdir(d)):
            if name.endswith(".json"):
                fixtures.append((sub, committed_file("probefixtures", pid, sub, name)))
    if not fixtures:
        raise Refusal("COMMITTED_FILE", f"{pid}: no committed probe fixtures")

    reg, tokdir = args.registry_dir, args.tokenizer_dir
    art = os.path.join(reg, "artifacts", "sha256", mod["tokenizerSha256"])
    tok_src = None
    no_symlink_below(reg, art)
    if os.path.isfile(art) and sha256_file(art) == mod["tokenizerSha256"]:
        tok_src = art
        print(f"  tokenizer.json already staged and verified ({mod['tokenizerSha256'][:12]})")
    elif not args.dry_run:
        tok_src = os.path.join(work, pid + ".tokenizer.json")
        fetch(resolve_url(repo, rev, "tokenizer.json"), tok_src, token)
        got = sha256_file(tok_src)
        if got != mod["tokenizerSha256"]:
            raise Refusal("TOKENIZER_SHA_MISMATCH", f"{pid}: downloaded {got}, pinned {mod['tokenizerSha256']}")
        print(f"  tokenizer.json downloaded and verified ({got[:12]})")
    else:
        print(f"  would download {resolve_url(repo, rev, 'tokenizer.json')}")

    dry = args.dry_run
    tok_src = tok_src or os.devnull  # dry run without a staged tokenizer: planned, never copied
    plan.append((tok_src, art, reg))
    plan.append((template, os.path.join(reg, "artifacts", "sha256", mod["templateSha256"]), reg))
    plan.append((profile, os.path.join(reg, pid + ".yaml"), reg))
    plan.append((engine_manifest, os.path.join(reg, "manifests", pid + ".yaml"), reg))
    fxdest = os.path.join(reg, "probefixtures", pid)
    for sub, src in fixtures:
        plan.append((src, os.path.join(fxdest, sub, os.path.basename(src)), reg))
    plan.append((tok_src, os.path.join(tokdir, slug(repo), "tokenizer.json"), tokdir))
    no_symlink_below(reg, fxdest)
    for _, dest, root in plan:
        no_symlink_below(root, dest)
    if not dry and os.path.isdir(fxdest):
        shutil.rmtree(fxdest)  # a fixture dropped from the committed set must not survive a re-install
    commit(plan, dry)
    print(f"  {'would stage' if dry else 'staged'} {len(plan)} registry files under {reg} and {tokdir}")

    if args.weights_dir:
        wdir = os.path.join(args.weights_dir, slug(repo), rev)
        todo = []
        for algo, hexd, size, name in rows:
            dest = os.path.join(wdir, name)
            no_symlink_below(args.weights_dir, dest)
            if os.path.isfile(dest) and verify_weight(dest, algo, hexd, size):
                continue
            todo.append((algo, hexd, size, name, dest))
        need = sum(r[2] for r in todo)
        print(f"  weights: {len(rows) - len(todo)}/{len(rows)} files already verified, {gb(need)} to download into {wdir}")
        if dry or not todo:
            return
        os.makedirs(wdir, mode=0o755, exist_ok=True)
        free = shutil.disk_usage(wdir).free
        partial = sum(os.path.getsize(d + ".part") for *_, d in todo if os.path.exists(d + ".part"))
        if free < need - partial + (1 << 30):
            raise Refusal("DISK_SPACE", f"{wdir}: {gb(free)} free, {gb(need - partial)} needed plus 1 GB margin")
        for algo, hexd, size, name, dest in todo:
            fetch(resolve_url(repo, rev, name), dest, token, size)
            if not verify_weight(dest, algo, hexd, size):
                os.replace(dest, dest + ".rejected")
                raise Refusal("WEIGHT_SHA_MISMATCH", f"{pid}: {name} does not match the index (kept as .rejected)")
            print(f"    verified {name} ({gb(size)})")


def cmd_install(args):
    m = load_manifest(args.manifest)
    if args.list:
        for mod in m["models"]:
            states = ", ".join(f"{t['engine']}={t['state']}" for t in mod["tuples"])
            print(f"{mod['profileId']:28} {mod['repo']}@{mod['revision'][:12]}  gated={'yes' if mod['gated'] else 'no'}  {states}")
        return 0
    if args.engine not in {k[0] for k in m["_engines"]}:
        raise Refusal("UNKNOWN_ENGINE", args.engine)
    args.registry_dir = safe_dir(args.registry_dir, "--registry-dir")
    args.tokenizer_dir = safe_dir(args.tokenizer_dir, "--tokenizer-dir")
    if args.weights_dir:
        args.weights_dir = safe_dir(args.weights_dir, "--weights-dir")
    token = read_token(args.hf_token_file or os.environ.get("HF_TOKEN_FILE"))
    picks = select(m, args)
    done = skipped = 0
    with tempfile.TemporaryDirectory(prefix="modelctl-") as work:
        for mod, t, action in picks:
            pid = mod["profileId"]
            if action != "install":
                print(f"{pid}: {action}")
                skipped += 1
                continue
            if mod["gated"] and not token and not args.dry_run:
                print(f"{pid}: SKIP_GATED_NO_TOKEN {mod['repo']} is gated; pass --hf-token-file")
                skipped += 1
                continue
            print(f"{pid}: {mod['repo']}@{mod['revision'][:12]} for {args.engine} ({t['state']})")
            install_one(mod, m, args, token, work)
            done += 1
    if args.pull_image:
        e = [e for (name, _), e in m["_engines"].items() if name == args.engine][-1]
        if not (e.get("image") and e.get("digest")):
            print(f"image: SKIP_NO_PULLABLE_IMAGE {args.engine}: {e.get('imageNote', 'no registry image')}")
        elif args.dry_run:
            print(f"image: would pull {e['image']}@{e['digest']}")
        else:
            subprocess.run(["docker", "pull", f"{e['image']}@{e['digest']}"], check=True)
    verb = "would install" if args.dry_run else "installed"
    print(f"{verb} {done} model(s), skipped {skipped}.")
    if done and not args.dry_run:
        print("The gateway reads the registry when it starts: restart it to load the staged profiles.")
    if not done and not args.dry_run and not args.pull_image:
        print("Nothing was installed.")
    return 0


def cmd_verify_weights(args):
    """Read-only: every indexed file must be present in the directory with the indexed size and digest."""
    load_manifest(args.manifest)
    ipath, rows = read_index(args.profile)
    bad = 0
    for algo, hexd, size, name in rows:
        path = os.path.join(args.dir, name)
        if not os.path.isfile(path):
            print(f"MISSING  {name}")
            bad += 1
        elif not verify_weight(path, algo, hexd, size):
            print(f"MISMATCH {name}")
            bad += 1
    print(f"{args.profile}: {len(rows) - bad}/{len(rows)} files match {os.path.relpath(ipath, ROOT)}")
    return 1 if bad else 0


# ---------------------------------------------------------------- pin-weights

def cmd_pin_weights(args):
    m = load_manifest(args.manifest) if os.path.isfile(args.manifest) else None
    token = read_token(args.hf_token_file or os.environ.get("HF_TOKEN_FILE"))
    for spec in args.targets:
        pid, repo, rev = spec.split("=", 1)[0], None, None
        if "=" in spec:
            repo, rev = spec.split("=", 1)[1].split("@")
        else:
            mod = [x for x in m["models"] if x["profileId"] == pid][0]
            repo, rev = mod["repo"], mod["revision"]
        with http_open(f"{HF}/api/models/{repo}/tree/{rev}?recursive=1", token) as r:
            tree = json.load(r)
        lines = []
        for f in sorted(tree, key=lambda x: x["path"]):
            if f["type"] != "file" or "/" in f["path"] or SKIP_FILE.search(f["path"]):
                continue
            lfs = f.get("lfs")
            digest = f"sha256:{lfs['oid']}" if lfs else f"gitblob:{f['oid']}"
            if not re.match(r"^(sha256:[0-9a-f]{64}|gitblob:[0-9a-f]{40})$", digest):
                # a gated repository masks its digests for an anonymous caller
                raise Refusal("TREE_DIGEST_MASKED", f"{repo}: {f['path']} has no readable digest; pass --hf-token-file")
            lines.append(f"{digest} {f['size']} {f['path']}")
        os.makedirs(WEIGHTS_DIR, exist_ok=True)
        path = os.path.join(WEIGHTS_DIR, pid + ".index")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        print(f"{pid} weightsIndexSha256: {sha256_file(path)}  ({len(lines)} files)")
    return 0


def main():
    ap = argparse.ArgumentParser(prog="modelctl.py", description=__doc__.split("\n\n")[0])
    ap.add_argument("--manifest", default=MANIFEST)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("render")
    c = sub.add_parser("check")
    c.add_argument("--doc", default=DOC)
    p = sub.add_parser("pin-weights")
    p.add_argument("targets", nargs="+", help="<profileId> or <profileId>=<repo>@<revision>")
    p.add_argument("--hf-token-file")
    v = sub.add_parser("verify-weights")
    v.add_argument("profile")
    v.add_argument("dir", help="a snapshot directory (symlinks into a download cache are followed)")
    i = sub.add_parser("install")
    i.add_argument("--list", action="store_true")
    i.add_argument("--dry-run", action="store_true")
    i.add_argument("--models", help="comma-separated profile ids (default: every selectable model)")
    i.add_argument("--include-candidates", action="store_true")
    i.add_argument("--engine", default="vllm")
    i.add_argument("--pull-image", action="store_true")
    i.add_argument("--registry-dir", default="/etc/loxilb/kvprofiles")
    i.add_argument("--tokenizer-dir", default="/etc/loxilb/tokenizers")
    i.add_argument("--weights-dir")
    i.add_argument("--hf-token-file")
    args = ap.parse_args()
    try:
        if args.cmd == "render":
            text = render(load_manifest(args.manifest))
            with open(DOC, "w", encoding="utf-8") as f:
                f.write(text)
            print(f"wrote {os.path.relpath(DOC, ROOT)}")
            return 0
        if args.cmd == "check":
            errs = check(load_manifest(args.manifest), args.doc)
            for e in errs:
                print("DRIFT: " + e)
            print("supported-models: " + ("%d disagreement(s)" % len(errs) if errs else "manifest, page, profiles, "
                  "engine manifests, template provenance, weights indexes and support catalog agree"))
            return 1 if errs else 0
        if args.cmd == "verify-weights":
            return cmd_verify_weights(args)
        if args.cmd == "pin-weights":
            return cmd_pin_weights(args)
        return cmd_install(args)
    except Refusal as e:
        print(f"REFUSED {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
