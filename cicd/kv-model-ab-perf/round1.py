#!/usr/bin/env python3
"""round1.py <requests.jsonl> [limit] -- was the first round of an exact arm served warm?

Every family is seeded on its owner before the timed window, so in the exact arm the first request of a family
finds its prefix cached, like every later one. When the seeds do not match the timed prompts (a chat template
that prints the date, seeded on one side of 00:00 UTC and timed on the other; a seed sent to the wrong engine)
the first round is cold on every engine while the gateway still counts a tier-1.5 hit for every request.
Compares the median TTFT of round 1 with the median of all later rounds; exit 1 when the ratio reaches the
limit, exit 2 when the file has no later round to compare with.
"""
import json
import statistics
import sys


def main():
    limit = float(sys.argv[2]) if len(sys.argv) > 2 else 2.0
    first, later = [], []
    for line in open(sys.argv[1]):
        r = json.loads(line)
        if r.get("ttft_ms") is None or "-repeat-" not in r["prompt_id"]:
            continue
        (first if r["prompt_id"].endswith("-repeat-001") else later).append(r["ttft_ms"])
    if not first or not later:
        print(f"round 1: {len(first)} requests, later rounds: {len(later)} -- nothing to compare")
        return 2
    a, b = statistics.median(first), statistics.median(later)
    ratio = a / b if b > 0 else float("inf")
    cold = sum(1 for t in first if t >= limit * b)
    print(f"round-1 TTFT p50 {a:.0f} ms, later rounds {b:.0f} ms, ratio {ratio:.2f} (limit {limit}), "
          f"round-1 requests cold {cold} of {len(first)}")
    return 1 if ratio >= limit else 0


if __name__ == "__main__":
    sys.exit(main())
