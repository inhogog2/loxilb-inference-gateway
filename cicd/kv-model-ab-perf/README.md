# kv-model-ab-perf — KV-exact routing against round-robin, per model

Measures, on one live GPU fleet and one gateway, what strict KV-exact routing changes for a model compared with
round-robin over the same prefill engines. The two arms differ in the rule only: same engines, same requests,
same offered rate.

```bash
python3 selftest.py                                   # no GPU, no gateway: analyzer, load generator, rules, seeding, decode-engine arguments

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
   carry over between models or GPUs, so the offered rates are fractions of this number. The point rates have
   floors (0.5 and 1.0 req/s): a fleet measured below the higher point rate is refused
   (`CAPACITY_BELOW_RATE_FLOOR`, the measurement is kept as `calibration-refused.json`) instead of being offered
   more than it completes. Every fleet restart keeps the replaced engines' logs under `node-<address>/engine-logs/`.
   `CAL_WARMUP=1` sends one long prompt with its own prefix to every prefill engine before each timed attempt.
   A freshly started SGLang engine takes seconds for its first long prefill; inside the timed window that
   stall lowers the measured capacity and with it every point rate. Off by default: rates measured with and
   without it are not comparable (`CAL_WARMUP_FAILED` when a warm-up request is refused).
   On a prefill/decode fleet the warm-up prompt is sent once per decode engine, so no decode engine meets its
   first long request inside the window. The engines' metrics around every timed attempt are kept as
   `cal-c<concurrency>-{before,after}-engine-<address>.prom`; no check reads them.
4. **Three points**: long prefix at 40 % and at 80 % of the calibrated rate, short prefix at 80 %. Each point is
   `REPS` repetitions of both arms in alternating order (exact-baseline, baseline-exact, exact-baseline). Before
   every arm the engines are restarted, the rule is created fresh, and every family is seeded directly on its
   owner prefill engine and on every decode engine (a decode engine's first pull of a prefix would otherwise
   dominate the tail of both arms). On an SGLang prefill/decode fleet a seed is a prefill + decode pair, the way
   SGLang's own router sends a request (`seed.py --pair-decode`): a prefill engine refuses a request that
   names no bootstrap room and keeps no prefix for one sent alone. Then every family is requested `repeat` times, open loop, in a seeded shuffled order that is the same
   for both arms of a repetition.

On an SGLang prefill/decode fleet the decode engines start with `--disaggregation-decode-enable-radix-cache`: a
decode engine keeps the prefixes it received, so a later request of the same family transfers only what is
missing. SGLang refuses the argument at start for some model architectures, so the scenario adds it per profile
(`sgl_decode_cache_plan` in `env.sh`), each row measured by starting a decode engine with it on SGLang 0.5.18:

| Decode-side prefix cache | Profiles |
|---|---|
| on | `r1-distill-qwen-15b-v1`, `exaone4-12b-v1`, `granite42-3b-v1`, `olmo2-0425-1b-v1`, `phi4-mini-instruct-v1`, `gemma3-1b-it-v1`, `llama32-1b-v1`, `ax31-light-v1` |
| refused by SGLang, left off | `gemma4-e2b-it-v1` (sliding-window attention), `qwen38-27b-fp8-v1` (state-space layers) |
| not measured, left off | every other profile |

A fleet that starts without it prints `DECODE_CACHE_SKIPPED refused|unmeasured` or `DECODE_CACHE_OFF`, and the
state is kept in `decode-cache.txt` beside the points and printed by `report`. `SGL_DECODE_CACHE=0` turns it off:
points measured with and without it are not comparable. `SGL_EXTRA_DECODE` holds further SGLang arguments for
the decode engines only; it can carry the argument for a profile that has no row yet, recorded as `forced`.

On a prefill/decode fleet the report prints the KV transfers of each arm from the engines' own counters: how
many, MB each, ms each, failed. vLLM counts them on the decode engines, SGLang on the prefill engines. SGLang's
time is its latency metric, which also holds the wait for the prefill scheduler's next pass: an upper bound.

The rule of every arm comes from `rule.py`. The baseline and calibration rules have exact routing off; on a
prefill/decode fleet of SGLang engines they still name the engine type, because the gateway picks the
prefill/decode dialect from it and an SGLang fleet driven the vLLM way answers every request with an empty
stream.

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
| exact arm: every prefill engine served the requests the gateway counted as hits on it (the engine's own request counter); spills past a loaded owner are recorded, not refused | `EXACT_PREFILL_SHARE` |
| exact arm: every prefill engine is an endpoint of the rule as the gateway lists it (its endpoint index is read from that listing: the gateway orders a rule's endpoints by address) | `RULE_READBACK_NO_ENDPOINT` |
| exact arm: the first round is not slower than the later ones (median TTFT ratio under 2) | `EXACT_ROUND1_COLD`, with the number of cold round-1 requests and the arm's spill count. Two causes: the seeds were not the prefixes hit (a date in the template across 00:00 UTC), or the seeds were hit and the gateway sent requests past a busy owner to an engine that had not seen the family (a request outlives the arrival gap: offer a lower rate or use more engines). The arm's files do not say which engine served a request, so the line does not choose; a spill count below the cold count rules the second out, and seed plus timed prompt sent to one engine directly settles it. |
| exact arm: no prefill engine is left without a request | `EXACT_ENGINE_IDLE` |
| no arm is seeded on one UTC day and timed on the next (a chat template may print the date; an arm that would straddle 00:00 UTC waits for it) | `ARM_CROSSED_UTC_MIDNIGHT` |
| baseline arm: tier-1.5 hits do not move | `BASELINE_HITS` |
| baseline arm: every prefill engine served at least 80 % of an equal share | `BASELINE_NOT_SPREAD` |
| three repetitions, every request present in both arms, no duplicate | `POINT_VOID` (analysis) |

## Reading the result

`ab-summary.json` has, per arm, TTFT p50/p95, per-token time p95 and output tokens per second, overall and per
repetition. It also has two shares, because p50 and p95 say nothing when the slow requests of both arms fall on
the same side of the rank: `slow_request_percent` (TTFT at least twice the lower arm's median) and
`computed_prompt_token_percent` (prompt tokens the engines computed instead of reading from their cache, from
the engine scrapes of the arm: vLLM's prompt tokens by source, SGLang's uncached prompt-token sum without the
decode engines, which repeat what their prefill engine reported). A difference is **claimed** only when the arms' per-repetition values do not overlap
(`ttft_p95_separation`: `exact_lower`, `baseline_lower`); `overlap` means the numbers stand and the claim does
not. The short-prefix control has no cache benefit to win: it bounds the routing overhead and the noise, and a
long-prefix result is read against it.

What the long-prefix points measure: the baseline pays one cold prefill for a family on every prefill engine
that is not its owner, the first time round-robin sends the family there; after that the engine holds the
prefix too. So the baseline's cold share is (prefill engines − 1) / `repeat`, and `repeat` is part of the
workload: it is printed in the point header and stored in `point.txt`. A result is a statement about that
reuse count, on a fleet whose caches are large enough to hold every family.
