#!/usr/bin/env python3
"""Validate one A/B point's request rows and summarize it.

A point is void unless every request of both arms completed, every (repetition, prompt) is present in both
arms, and there are three repetitions. A TTFT difference is CLAIMED only when the arms' per-repetition values
do not overlap: the worst exact repetition must beat the best baseline repetition (or the reverse). Anything
else is reported as "overlap" — the measured numbers stand, the claim does not.
"""
import argparse
import json
import math
import pathlib
import random
import statistics
import sys


def percentile(values, q):
    v = sorted(values)
    pos = (len(v) - 1) * q
    lo, hi = math.floor(pos), math.ceil(pos)
    return v[lo] if lo == hi else v[lo] + (v[hi] - v[lo]) * (pos - lo)


def validate(rows):
    if not rows:
        raise ValueError("no request rows")
    seen, arms = set(), {}
    for r in rows:
        key = (r["repetition"], r["arm"], r["prompt_id"])
        if key in seen:
            raise ValueError(f"duplicate request row {key}")
        seen.add(key)
        arms.setdefault((r["repetition"], r["prompt_id"]), set()).add(r["arm"])
        if not r.get("completed") or r.get("http_status") != 200 or not r.get("sse_done"):
            raise ValueError(f"incomplete request row {key}")
        for m in ("ttft_ms", "tpot_ms", "e2e_ms"):
            if not isinstance(r.get(m), (int, float)) or r[m] < 0:
                raise ValueError(f"invalid {m} in {key}")
    bad = [k for k, a in arms.items() if a != {"exact", "baseline"}]
    if bad:
        raise ValueError(f"unpaired requests, e.g. {bad[:3]}")
    if len({r["repetition"] for r in rows}) < 3:
        raise ValueError("at least three repetitions are required")


def arm_summary(rows):
    per_run = []
    for rep in sorted({r["repetition"] for r in rows}):
        run = [r for r in rows if r["repetition"] == rep]
        dur = max(r["ended_at_unix"] for r in run) - min(r["started_at_unix"] for r in run)
        per_run.append({
            "repetition": rep, "requests": len(run), "duration_sec": round(dur, 3),
            "request_per_sec": round(len(run) / dur, 3),
            "output_tokens_per_sec": round(sum(int(r["completion_tokens"]) for r in run) / dur, 3),
            "ttft_p50_ms": round(statistics.median(r["ttft_ms"] for r in run), 1),
            "ttft_p95_ms": round(percentile([r["ttft_ms"] for r in run], 0.95), 1),
            "tpot_p95_ms": round(percentile([r["tpot_ms"] for r in run], 0.95), 2),
            "schedule_delay_p95_ms": round(percentile([r.get("schedule_delay_ms") or 0 for r in run], 0.95), 1),
        })
    return {
        "requests": len(rows), "success_rate": sum(bool(r["completed"]) for r in rows) / len(rows),
        "ttft_p50_ms": round(statistics.median(r["ttft_ms"] for r in rows), 1),
        "ttft_p95_ms": round(percentile([r["ttft_ms"] for r in rows], 0.95), 1),
        "tpot_p95_ms": round(percentile([r["tpot_ms"] for r in rows], 0.95), 2),
        "output_tokens_per_sec_median": statistics.median(x["output_tokens_per_sec"] for x in per_run),
        "prompt_tokens_median": statistics.median(int(r["prompt_tokens"]) for r in rows),
        "per_run": per_run,
    }


def separation(exact, base, key):
    """exact_lower | baseline_lower | overlap, from the per-repetition values of one metric."""
    e, b = [x[key] for x in exact["per_run"]], [x[key] for x in base["per_run"]]
    if max(e) < min(b):
        return "exact_lower"
    if max(b) < min(e):
        return "baseline_lower"
    return "overlap"


def bootstrap(pairs, stat, samples=5000):
    rng = random.Random(20261001)
    est = []
    for _ in range(samples):
        d = [pairs[rng.randrange(len(pairs))] for _ in pairs]
        b = stat([x[1] for x in d])
        est.append((stat([x[0] for x in d]) - b) / b * 100)
    return [round(percentile(est, 0.025), 1), round(percentile(est, 0.975), 1)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input-dir", required=True)
    ap.add_argument("--summary", required=True)
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    rows = []
    for p in sorted(pathlib.Path(a.input_dir).glob("repetition-*/*/requests.jsonl")):
        rows += [json.loads(line) for line in p.read_text().splitlines() if line]
    validate(rows)
    if a.self_test:  # the validator must reject a row it should reject, and an unpaired set
        for mutate in (lambda m: m[0].__setitem__("sse_done", False), lambda m: m.pop(0)):
            m = [dict(r) for r in rows]
            mutate(m)
            try:
                validate(m)
            except ValueError:
                continue
            raise RuntimeError("the validator accepted a mutated row set")
    arm = {x: arm_summary([r for r in rows if r["arm"] == x]) for x in ("exact", "baseline")}
    base = {(r["repetition"], r["prompt_id"]): r["ttft_ms"] for r in rows if r["arm"] == "baseline"}
    pairs = [(r["ttft_ms"], base[(r["repetition"], r["prompt_id"])]) for r in rows if r["arm"] == "exact"]
    e, b = arm["exact"], arm["baseline"]
    pct = lambda x, y: round((x - y) / y * 100, 1)
    summary = {
        "schema_version": 2, "arms": arm,
        "effects": {
            "ttft_p95_delta_percent": pct(e["ttft_p95_ms"], b["ttft_p95_ms"]),
            "ttft_p95_delta_95ci_percent": bootstrap(pairs, lambda v: percentile(v, 0.95)),
            "ttft_p95_separation": separation(e, b, "ttft_p95_ms"),
            "ttft_p50_delta_percent": pct(e["ttft_p50_ms"], b["ttft_p50_ms"]),
            "ttft_p50_separation": separation(e, b, "ttft_p50_ms"),
            "tpot_p95_delta_percent": pct(e["tpot_p95_ms"], b["tpot_p95_ms"]),
            "output_tokens_per_sec_delta_percent": pct(e["output_tokens_per_sec_median"], b["output_tokens_per_sec_median"]),
        },
        "validation": {"paired_requests": len(pairs), "repetitions": len({r["repetition"] for r in rows}),
                       "all_http_200_sse_done": True, "negative_mutations_rejected": bool(a.self_test)},
    }
    pathlib.Path(a.summary).write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary["effects"], sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ValueError as err:
        print(f"POINT_VOID {err}", file=sys.stderr)
        sys.exit(1)
