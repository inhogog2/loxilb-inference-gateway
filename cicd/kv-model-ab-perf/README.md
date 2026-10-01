# kv-model-ab-perf — KV-exact routing against round-robin, per model

Measures, on one live GPU fleet and one gateway, what strict KV-exact routing changes for a model compared with
round-robin over the same prefill engines. The two arms differ in the rule only: same engines, same requests,
same offered rate.

```bash
python3 selftest.py                                   # no GPU, no gateway: analyzer verdicts and load generator

export PREFILLS="<node> <node>" DECODES="<node> <node>" VIP=<gateway address> LOGD=<gateway log dir>
./validation.sh model vllm <profileId>                # fleet up, corpus, calibration, three points, fleet down
./validation.sh report vllm <profileId>               # the banked points as `perf` entries for the manifest
./validation.sh fleet-up|fleet-down vllm <profileId>  # the fleet alone; then point.sh by hand
```

A run of `model` takes about 80 minutes for a small model on two prefill engines. It needs the profile staged
in the gateway registry (`../kv-model-compat-pd/config.sh` or `scripts/models/install-models.sh`), the model's
weights on every node, and the rule port free: one gateway, one model at a time. Settings are in `env.sh` here
and in `../kv-model-compat-pd/env.sh`; engines are launched by `../kv-model-compat-pd/engine.sh`, so every
per-model launch argument proven there applies unchanged. Evidence goes to `/var/tmp/kv-model-ab-perf/<engine>-<profileId>/`.

## What a run does

1. **Fleet**: one engine per node in `PREFILLS` and `DECODES`. An A/B needs at least two prefill engines; with
   one, both arms pick the same engine.
2. **Corpus**: `FAMILIES` prompt families, each with a shared prefix and an owner prefill engine (family *n*
   belongs to prefill *n* mod N). The long-prefix corpus is sized for this model's tokenizer to `TARGET_TOKENS`
   prompt tokens, from two sizing requests; the short-prefix corpus is the control.
3. **Calibration**: closed loop, cold (prefixes used nowhere else), through the round-robin rule. Rates do not
   carry over between models or GPUs, so the offered rates are fractions of this number.
4. **Three points**: long prefix at 40 % and at 80 % of the calibrated rate, short prefix at 80 %. Each point is
   `REPS` repetitions of both arms in alternating order (exact-baseline, baseline-exact, exact-baseline). Before
   every arm the engines are restarted, the rule is created fresh, and every family is seeded directly on its
   owner prefill engine and on every decode engine (a decode engine's first pull of a prefix would otherwise
   dominate the tail of both arms). Then every family is requested `repeat` times, open loop, in a seeded shuffled order that is the same
   for both arms of a repetition.

## When a point counts

A point is banked (`ab-summary.json`) only when all of this holds in every repetition; otherwise the run stops
with the typed line and leaves no summary.

| Check | Typed line when it fails |
|---|---|
| every request of both arms: HTTP 200, tokens, usage, `[DONE]` | `REQUESTS_INCOMPLETE` |
| exact arm: the rule is READY before seeding | `EXACT_RULE_NOT_READY` |
| exact arm: one connected KV subscriber per prefill engine | `KV_SUBSCRIBERS` |
| exact arm: tier-1.5 hits rise by exactly the number of timed requests | `EXACT_HITS` |
| exact arm: the fall-through counter does not move | `EXACT_FALLTHROUGH` |
| exact arm: every prefill engine served its owners' share (its own request counter), give or take the requests the gateway reports as spilled past a loaded owner | `EXACT_PREFILL_SHARE` |
| baseline arm: tier-1.5 hits do not move | `BASELINE_HITS` |
| baseline arm: every prefill engine served at least 80 % of an equal share | `BASELINE_NOT_SPREAD` |
| three repetitions, every request present in both arms, no duplicate | `POINT_VOID` (analysis) |

## Reading the result

`ab-summary.json` has, per arm, TTFT p50/p95, per-token time p95 and output tokens per second, overall and per
repetition. A difference is **claimed** only when the arms' per-repetition values do not overlap
(`ttft_p95_separation`: `exact_lower`, `baseline_lower`); `overlap` means the numbers stand and the claim does
not. The short-prefix control has no cache benefit to win: it bounds the routing overhead and the noise, and a
long-prefix result is read against it.

What the long-prefix points measure: the baseline pays one cold prefill for a family on every prefill engine
that is not its owner, the first time round-robin sends the family there; after that the engine holds the
prefix too. So the baseline's cold share is (prefill engines − 1) / `repeat`, and `repeat` is part of the
workload: it is printed in the point header and stored in `point.txt`. A result is a statement about that
reuse count, on a fleet whose caches are large enough to hold every family.
