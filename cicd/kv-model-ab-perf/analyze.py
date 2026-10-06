#!/usr/bin/env python3
"""Validate one A/B point's request rows and summarize it.

A point is void unless every request of both arms completed, every (repetition, prompt) is present in both
arms, and there are three repetitions. A TTFT difference is CLAIMED only when the arms' per-repetition values
do not overlap: the worst exact repetition must beat the best baseline repetition (or the reverse). Anything
else is reported as "overlap" — the measured numbers stand, the claim does not.

Two shares are reported next to the percentiles, because a percentile says nothing when the slow requests of
both arms sit on the same side of its rank: the share of slow requests (TTFT at least twice the lower arm's
median) and, when the arm directories hold vLLM or SGLang engine scrapes, the share of prompt tokens the engines
computed instead of taking from their cache. On a prefill/decode fleet the same scrapes give the KV transfers of
each arm: how many, how large, how long.
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


# Prompt tokens an engine computed, per engine family. vLLM counts prompt tokens by source; SGLang observes
# prompt_tokens - cached_tokens of every finished request into a histogram, whose sum is the same quantity.
# An SGLang decode engine observes the split its prefill engine reported for the same request, so its series
# repeats tokens already counted there and is left out.
COMPUTED = (("vllm:prompt_tokens_by_source_total", 'source="local_compute"', None),
            ("sglang:uncached_prompt_tokens_histogram_sum", "", 'engine_type="decode"'))


def computed_tokens(arm_dir):
    """Prompt tokens the engines computed during one arm (after - before, all engines), or None without scrapes."""
    def total(path):
        for metric, label, repeated in COMPUTED:
            lines = [line for line in path.read_text().splitlines()
                     if line.startswith(metric) and line[len(metric):len(metric) + 1] in ("{", " ") and label in line]
            if lines:
                return sum(float(line.rsplit(" ", 1)[1]) for line in lines if not (repeated and repeated in line))
        return None
    out, after = 0.0, sorted(arm_dir.glob("after-engine-*.prom"))
    for a in after:
        before = a.with_name(a.name.replace("after-", "before-", 1))
        hi, lo = total(a), total(before) if before.exists() else None
        if hi is None or lo is None:
            return None
        out += hi - lo
    return out if after else None


# KV transfers from a prefill to a decode engine, per engine family: count, payload and its factor to MB, time
# and its factor to ms, failed transfers. vLLM counts on the pulling (decode) engine, SGLang on the sending
# (prefill) engine; the engines of the other role read 0. SGLang's time is its own latency metric, which runs
# until the prefill scheduler next looks at the request: an upper bound of the transfer, not the transfer.
TRANSFER = (("vllm:nixl_bytes_transferred_count", "vllm:nixl_bytes_transferred_sum", 1 / 2 ** 20,
             "vllm:nixl_xfer_time_seconds_sum", 1000.0, "vllm:nixl_num_failed_transfers_total"),
            ("sglang:kv_transfer_total_mb_count", "sglang:kv_transfer_total_mb_sum", 1.0,
             "sglang:kv_transfer_latency_ms_sum", 1.0, "sglang:num_transfer_failed_reqs_total"))


def series_sum(text, metric):
    """Sum over the label children of exactly this metric name, or None when the scrape has no such series."""
    v = [float(line.rsplit(" ", 1)[1]) for line in text.splitlines()
         if line.startswith(metric) and line[len(metric):len(metric) + 1] in ("{", " ")]
    return sum(v) if v else None


def kv_transfers(arm_dir):
    """KV transfers during one arm (after - before, all engines), or None when no engine scrape counts them."""
    out, seen = {"count": 0.0, "mb": 0.0, "ms": 0.0, "failed": 0.0}, False
    for a in sorted(arm_dir.glob("after-engine-*.prom")):
        before = a.with_name(a.name.replace("after-", "before-", 1))
        hi, lo = a.read_text(), before.read_text() if before.exists() else ""
        for count, size, to_mb, time, to_ms, failed in TRANSFER:
            if series_sum(hi, count) is None:
                continue
            if series_sum(lo, count) is None:
                return None
            seen = True
            for key, metric, factor in (("count", count, 1), ("mb", size, to_mb), ("ms", time, to_ms), ("failed", failed, 1)):
                out[key] += ((series_sum(hi, metric) or 0.0) - (series_sum(lo, metric) or 0.0)) * factor
    return out if seen else None


def transfer_fields(known):
    """Summary fields from the per-repetition transfer readings; all None unless every repetition has one."""
    if not known or None in known:
        return {"kv_transfers": None, "kv_transfer_mb": None, "kv_transfer_mb_each": None,
                "kv_transfer_ms_each": None, "kv_transfer_failed": None}
    n = sum(x["count"] for x in known)
    each = lambda key: round(sum(x[key] for x in known) / n, 1) if n else None
    return {"kv_transfers": round(n), "kv_transfer_mb": round(sum(x["mb"] for x in known), 1), "kv_transfer_mb_each": each("mb"),
            "kv_transfer_ms_each": each("ms"), "kv_transfer_failed": round(sum(x["failed"] for x in known))}


def share(part, whole):
    return None if part is None else round(part / whole * 100, 1)


def arm_summary(rows, slow_ms, computed, transfers):
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
            "slow_request_percent": share(sum(r["ttft_ms"] >= slow_ms for r in run), len(run)),
            "computed_prompt_token_percent": share(computed.get(rep), sum(int(r["prompt_tokens"]) for r in run)),
            **transfer_fields([transfers.get(rep)]),
        })
    known = [computed.get(x["repetition"]) for x in per_run]
    return {
        "slow_request_percent": share(sum(r["ttft_ms"] >= slow_ms for r in rows), len(rows)),
        "computed_prompt_token_percent": share(None if None in known else sum(known),
                                               sum(int(r["prompt_tokens"]) for r in rows)),
        **transfer_fields([transfers.get(x["repetition"]) for x in per_run]),
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
    slow_ms = 2 * min(statistics.median(r["ttft_ms"] for r in rows if r["arm"] == x) for x in ("exact", "baseline"))
    computed, transfers = ({x: {} for x in ("exact", "baseline")} for _ in range(2))
    for d in pathlib.Path(a.input_dir).glob("repetition-*/*"):
        if d.name in computed and d.parent.name.split("-")[1].isdigit():
            computed[d.name][int(d.parent.name.split("-")[1])] = computed_tokens(d)
            transfers[d.name][int(d.parent.name.split("-")[1])] = kv_transfers(d)
    arm = {x: arm_summary([r for r in rows if r["arm"] == x], slow_ms, computed[x], transfers[x]) for x in ("exact", "baseline")}
    base = {(r["repetition"], r["prompt_id"]): r["ttft_ms"] for r in rows if r["arm"] == "baseline"}
    pairs = [(r["ttft_ms"], base[(r["repetition"], r["prompt_id"])]) for r in rows if r["arm"] == "exact"]
    e, b = arm["exact"], arm["baseline"]
    pct = lambda x, y: round((x - y) / y * 100, 1)
    summary = {
        "schema_version": 4, "arms": arm, "slow_request_ttft_ms": round(slow_ms, 1),
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
