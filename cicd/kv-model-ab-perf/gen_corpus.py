#!/usr/bin/env python3
"""Generate a deterministic repeated-prefix corpus for the A/B run.

Each row is one prompt FAMILY: a prefix shared by its seed request and by every timed request, assigned to
one prefill engine (its owner). `long` prefixes repeat a paragraph --prefix-repetitions times; `short` ones
are a few blocks long and are the control (no cache benefit to win). --salt makes every prefix unique to
this corpus, so a calibration corpus shares nothing with a measured one.

A row also carries a second seed request: the same prefix with a third ending. An engine that keeps a reusable
state at the end of the shared prefix only once a second request has branched there (SGLang with a
state-space model) needs it; seed.py sends it with --second-touch.
"""
import argparse
import hashlib
import json

PARAGRAPH = ("An AI inference operator checks identity readiness routing inventory "
             "transfer completion latency rollback and evidence before changing service. ")
SHORT = ("AB short control {salt}{family}. This bounded prompt spans several complete sixteen-token blocks and "
         "is identical for the seed and for every timed request. The operator records readiness inventory "
         "receipts and rollback evidence before traffic.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", required=True)
    ap.add_argument("--families", type=int, default=60)
    ap.add_argument("--owners", type=int, required=True, help="number of prefill engines")
    ap.add_argument("--shape", choices=("long", "short"), default="long")
    ap.add_argument("--prefix-repetitions", type=int, default=150)
    ap.add_argument("--salt", default="")
    a = ap.parse_args()
    if a.families % a.owners:
        ap.error("--families must be a multiple of --owners (every owner seeds the same number)")
    with open(a.output, "w", encoding="utf-8") as out:
        for n in range(a.families):
            family = f"family-{n:03d}"
            if a.shape == "short":
                prefix = SHORT.format(salt=a.salt, family=family)
                seed = seed2 = timed = prefix
            else:
                prefix = f"AB deterministic prefix {a.salt}{family}.\n" + PARAGRAPH * a.prefix_repetitions
                seed = prefix + "\nSeed this prefix and answer with one word."
                seed2 = prefix + "\nBranch from this prefix once more and answer with one word."
                timed = prefix + f"\nTimed continuation {family}: list two safe change-control checks."
            out.write(json.dumps({
                "schema_version": 1, "prompt_id": family, "owner": n % a.owners,
                "seed_prompt": seed, "seed2_prompt": seed2, "timed_prompt": timed,
                "seed_messages": [{"role": "user", "content": seed}],
                "seed2_messages": [{"role": "user", "content": seed2}],
                "timed_messages": [{"role": "user", "content": timed}],
                "workload_shape": a.shape, "prefix_sha256": hashlib.sha256(prefix.encode()).hexdigest(),
            }, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
