# kv-model-compat-pd — candidate-model qualification on a live GPU pair

Qualifies the candidate chat models' strict KV-exact profiles
(`cicd/common/kv_hash/fixtures/profiles/`) against real engines, through a running gateway:

| Mode | What it proves | GPU |
|---|---|---|
| `preflight` | the gateway's latest registry publish holds every committed candidate profile | no |
| `admission` | engine-renderer admission: a strict chat surface is refused where the engine renders the model's chat with its own encoder (Ministral-3 on vLLM/SGLang = `mistral_common`; gpt-oss on vLLM/TRT-LLM = Harmony), admitted where the engine renders the pinned template, completions admitted everywhere | no |
| `pd` | strict P/D chat legs, each run twice: ladder READY, three chats whose prefill/decode split is proven by counters (gateway P/D counters, both engines' request counters, the decode engine's KV-transfer counter), then a red arm (one flipped expected token id → the rule must stop at `token_mismatch`, blamed on the prefill endpoint only) | yes |

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

## Regenerating the fixtures

Profiles, manifests and probe fixtures are generated from pinned inputs by
`cicd/common/kv_hash/gen_model_profiles.py <fixtures_dir> <artifacts_dir>` (artifacts = per-model
`tokenizer.json` + `config.json`). Regeneration is a profile-revision event: re-run this scenario afterwards.
