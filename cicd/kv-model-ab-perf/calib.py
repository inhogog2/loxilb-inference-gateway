#!/usr/bin/env python3
"""calib.py <cal-requests.jsonl> <calibration.json> <cal-concurrency.txt>

Turn the completed closed-loop calibration run into the point rates: 40 % and 80 % of the cold closed-loop
capacity, rounded to 0.5 req/s, with floors of 0.5 and 1.0 req/s.

A floor is a rate the fleet was not measured to serve. When the higher point rate is above the measured
capacity the arms would be offered more than the fleet completes, and every point would end as incomplete
requests: that is refused here (CAPACITY_BELOW_RATE_FLOOR, exit 3). The measurement is then written next to the
calibration file as calibration-refused.json, and no calibration is banked, so a re-run measures again.
"""
import json
import os
import statistics
import sys

RATE_LOW_FLOOR, RATE_HIGH_FLOOR = 0.5, 1.0


def calibration(rows, concurrency):
    dur = max(x["ended_at_unix"] for x in rows) - min(x["started_at_unix"] for x in rows)
    rps = len(rows) / dur
    return {"requests": len(rows), "duration_sec": round(dur, 2), "cold_closed_loop_rps": round(rps, 2),
            "ttft_p50_ms": round(statistics.median(x["ttft_ms"] for x in rows), 1),
            "prompt_tokens_median": statistics.median(x["prompt_tokens"] for x in rows),
            "concurrency": concurrency,
            "rate_low": max(RATE_LOW_FLOOR, round(rps * 0.4 * 2) / 2),
            "rate_high": max(RATE_HIGH_FLOOR, round(rps * 0.8 * 2) / 2)}


def refused(out):
    """The higher point rate is above what the fleet was measured to complete."""
    return out["rate_high"] > out["cold_closed_loop_rps"]


def main():
    requests, target, conc = sys.argv[1:]
    out = calibration([json.loads(l) for l in open(requests)], int(open(conc).read()))
    if refused(out):
        json.dump(out, open(os.path.join(os.path.dirname(target), "calibration-refused.json"), "w"), indent=1)
        print(f"CAPACITY_BELOW_RATE_FLOOR cold capacity {out['cold_closed_loop_rps']} req/s at concurrency "
              f"{out['concurrency']}, point rates {out['rate_low']} / {out['rate_high']} req/s: {json.dumps(out)}")
        return 3
    json.dump(out, open(target, "w"), indent=1)
    print("  calibration:", json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
