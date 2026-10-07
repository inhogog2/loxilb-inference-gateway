# kv-model-compat-pd — candidate-model qualification on a live GPU pair

Qualifies the candidate chat models' strict KV-exact profiles
(`cicd/common/kv_hash/fixtures/profiles/`) against real engines, through a running gateway:

| Mode | What it proves | GPU |
|---|---|---|
| `preflight` | the gateway's latest registry publish holds every committed candidate profile | no |
| `admission` | engine-renderer admission: a strict chat surface is refused where the engine renders the model's chat with its own encoder (Ministral-3 on vLLM/SGLang = `mistral_common`; gpt-oss on vLLM/TRT-LLM = Harmony), admitted where the engine renders the pinned template, completions admitted there; and both surfaces are admitted on every engine where the engine encodes completions with a BOS the tokenizer file does not add (R1-distill on SGLang, `engineQuirks.sglang-kv-rank-v1.completionsBos`): the gateway's SGLang encoder prepends it | no |
| `pd` | strict P/D legs on both surfaces, each run twice: ladder READY, three chats whose prefill/decode split is proven by counters (gateway P/D counters, both engines' request counters, the decode engine's KV-transfer counter), three text completions that must score exact hits, then a red arm (one flipped expected token id → the rule must stop at `token_mismatch`, blamed on the prefill endpoint only) | yes |

Default P/D run list: vLLM × {gemma-3-1b-it, Phi-4-mini, granite-4.2-3b (hybrid Mamba)}, SGLang × Phi-4-mini.
SGLang 0.5.18 × {gemma-3, granite-4.2, gpt-oss} is left out on purpose: that engine's `/v1/tokenize` answers
500 for tokenizers whose `model_max_length` is 1e30 (fixed upstream in 0.5.19), so the token-parity probe fails
closed and the rule can never reach READY.

## Prerequisites

- A gateway running with host networking on the host that runs these scripts, with the registry directory
  (`REG`, default `/etc/loxilb/kvprofiles`) and the tokenizer directory (`TOKDIR`, default
  `/etc/loxilb/tokenizers`) mounted read-only at the same paths, and its `/var/log` mounted at `LOGD`.
- Two GPU nodes reachable over ssh as root (prefill, decode) with the engine images pinned in `env.sh`, and the
  model weights at the pinned revisions (the profile's `tokenizerRevision`) in the HF cache (`HF_CACHE`). The
  engines run offline.
- `PORT` (default 8080) free on the `VIP`.

## Run

```sh
export PREFILL=<prefill node> DECODE=<decode node> VIP=<gateway address> LOGD=<gateway /var/log on the host>
export GW_CTR=<gateway container> SSH="ssh -i <key>"
./config.sh                 # stage every committed candidate profile (or name profile ids)
# restart the gateway: the registry is read only at start
./validation.sh             # preflight, admission, pd   (or one mode)
./rmconfig.sh
```

`config.sh` does not commit or download tokenizers: it reads `tokenizer.json` from `TOKSRC/<org>__<name>/`
when `TOKSRC` is set, otherwise from the pinned snapshot on the prefill node, and refuses any file whose sha256
differs from the profile's `tokenizerSha256`.

Evidence per leg (request/response bodies, attestation trail, counters, manifest and profile used,
`SHA256SUMS`) is written under `EVROOT`.

## Launch requirement (SGLang)

`engine.sh` launches SGLang with `--model-path <snapshot path> --revision <rev>`. `--revision` makes
`/server_info` report the revision the gateway's identity probe compares with the manifest. The snapshot path
matters too: launched with a hub id, SGLang 0.5.18 (transformers 5.12.1) builds Phi-4-mini's tokenizer with a
bare byte-level pre-tokenizer instead of `tokenizer.json`'s split rule, so both `/v1/tokenize` and the chat
serving path produce different ids from the pinned tokenizer and attestation fails closed.

## SGLang tokenize fix

SGLang 0.5.12 - 0.5.18's `/v1/tokenize` answers 500 for gemma-3, granite-4.2 and gpt-oss: their tokenizer's
`model_max_length` is transformers' `int(1e30)` sentinel, which orjson cannot encode. The token-parity probe
fails closed on the 500, so a strict rule on these models never reaches READY. Upstream fixed it in 0.5.19.

`engine.sh` reads the sha256 of the `serving_tokenize.py` the image ships and acts on the table in `env.sh`
(`sgl_tokpatch_plan`), never on a version string:

| Image file | Releases | `SGL_TOKPATCH=auto` (default) |
|---|---|---|
| `f1791dbe…` | 0.5.12 - 0.5.18 | mount [`sglang-tokenize-fix/`](sglang-tokenize-fix/README.md) (v0.5.19's file) read-only |
| `7ef745d2…` | 0.5.19 - 0.5.20 | launch unchanged (already fixed) |
| `9202c10b…` | 0.5.4 - 0.5.11 | refuse: no chat form of `/v1/tokenize`, so strict chat cannot attest |
| anything else | — | refuse until the file is reviewed and a row is added |

`SGL_TOKPATCH=1` requires the mount; `SGL_TOKPATCH=0` never mounts. A `sglang-notokpatch:<profileId>` leg
runs with `0` and must fail at the probe with the engine's 500: the fix's red twin. The mounted file's
sha256 is checked on the node before launch and inside the running container after readiness.

An SGLang engine is ready when it serves the model id and its log says `The server is fired up`: it answers
`/v1/models` seconds before its own start-up request has run. At the first prompt longer than one page it
builds a hashing extension once (about 8 s on an L4); `engine.sh` keeps the build in a node directory per
image (`SGL_EXT_CACHE`, default `/root/.cache/sglang-torch-extensions/<image digest>`), so a node builds it
once, not once per container.

Supporting another SGLang release takes three pinned pieces: an image whose file has a row in the table
above, a `manifests-sglang` set carrying its `engineVersion` (the identity probe compares it exactly), and
the per-version launch arguments in `engine.sh`, re-measured with one live leg per model.

gemma-3 on SGLang 0.5.18 also needs `--cuda-graph-backend-prefill=disabled` (set per profile in `engine.sh`):
the prefill member's prefill CUDA graph pads a ragged prefill batch, flashinfer then raises
`q.shape[0] (48) does not match qo_indptr[-1] (39)` on the first real prefill, and the engine exits. Decode
CUDA graphs stay on. `engine.sh stop` saves each engine's log under `EVROOT/engine-logs/` before removing it.

Other measured per-version, per-profile launch arguments (`engine.sh`; the failure each one prevents was observed on the bed):

| Engine / version | Profile | Argument | Without it |
|---|---|---|---|
| SGLang 0.5.18 | exaone4-12b-v1 | `--attention-backend triton` | Exaone4ForCausalLM accepts only fa3 / triton / trtllm_mha; fa3 needs Hopper, so on Ada the launch asserts |
| SGLang 0.5.18 | olmo2-0425-1b-v1 | `--disable-cuda-graph` | decode member exits before readiness: `Capture cuda graph failed: scheduler_metadata must have shape (metadata_size)` |
| vLLM 0.28.0 | qwen36-27b-fp8-v1, qwen38-27b-fp8-v1 | `--max-num-seqs 64` | hybrid Mamba on one 48 GB GPU: `max_num_seqs (256) exceeds available Mamba cache blocks` |
| vLLM 0.28.0 | qwen36-27b-fp8-v1, qwen38-27b-fp8-v1 | env `VLLM_SSM_CONV_STATE_LAYOUT=DS` | NIXL connector start fails: `3-read Mamba conv transfer requires DS conv state layout` |

`engine.sh` also launches TensorRT-LLM (PyTorch backend), converged only, for the A/B scenario
(`../kv-model-ab-perf`); the legs of this scenario do not drive it. The image is a local build from the release
wheel, so `env.sh` pins its image id and the launch refuses a node whose tag names another image
(`ENGINE_IMAGE_MISMATCH`). The engine options are `trtllm/converged.yaml` (block reuse, the KV event buffer the
gateway drains, the Prometheus text). The engine is ready when it serves the model id and `/health` answers,
minutes after the container starts. Models it cannot serve are refused before anything starts
(`ENGINE_MODEL_BLOCKED`, `trt_blocked` in `env.sh`).

## Regenerating the fixtures

Profiles, manifests and probe fixtures are generated from pinned inputs by
`cicd/common/kv_hash/gen_model_profiles.py <fixtures_dir> <artifacts_dir>` (artifacts = per-model
`tokenizer.json` + `config.json`). Regeneration is a profile-revision event: re-run this scenario afterwards.

The vLLM fixture set of an openai-format template leaves out every chat case whose render changes when each
content takes vLLM's shape (a string becomes one text part): the gateway refuses such requests at serve time,
so banking their string-shape ids would hold a strict vLLM rule below READY for good (gemma-4's system turns).
The `sglang/` subset keeps them, since SGLang hands the template a string content as a string, and leaves out
every chat case ending on an assistant turn instead. The `trtllm/` subset is the same selection: TensorRT-LLM
joins a text-only content into one string before it renders. Its completions fixtures carry no engine-added
BOS (the engine encodes a text prompt with the tokenizer as loaded). The gateway attests a TensorRT-LLM rule
against this set only; without it the rule stops below READY.
