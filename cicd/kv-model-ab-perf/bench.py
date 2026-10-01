#!/usr/bin/env python3
"""Measure request-level TTFT, TPOT, E2E latency, and completion receipts."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


def timed_request(
    sequence: int,
    row: dict[str, Any],
    *,
    url: str,
    model: str,
    arm: str,
    repetition: int,
    timeout: float,
    max_tokens: int,
    api: str,
    scheduled_at_perf: float | None,
    scheduled_at_unix: float | None,
) -> dict[str, Any]:
    request_id = f"ab-r{repetition}-{arm}-{row['prompt_id']}"
    payload: dict[str, Any] = {
        "model": model,
        "max_tokens": max_tokens,
        "temperature": 0,
        "stream": True,
        "stream_options": {"include_usage": True},
    }
    if api == "chat":
        payload["messages"] = row["timed_messages"]
    else:
        payload["prompt"] = row["timed_prompt"]
    request = urllib.request.Request(
        url + ("/v1/chat/completions" if api == "chat" else "/v1/completions"),
        data=json.dumps(payload).encode(),
        headers={
            "Content-Type": "application/json",
            "X-AB-Request-ID": request_id,
        },
        method="POST",
    )
    if scheduled_at_perf is not None:
        delay = scheduled_at_perf - time.perf_counter()
        if delay > 0:
            time.sleep(delay)
    started_wall = time.time()
    started = time.perf_counter()
    result: dict[str, Any] = {
        "schema_version": 1,
        "sequence": sequence,
        "arm": arm,
        "repetition": repetition,
        "prompt_id": row["prompt_id"],
        "owner": row["owner"],
        "prefix_sha256": row["prefix_sha256"],
        "client_request_id": request_id,
        "started_at_unix": started_wall,
        "scheduled_at_unix": scheduled_at_unix,
        "schedule_delay_ms": (
            round((started_wall - scheduled_at_unix) * 1000, 3)
            if scheduled_at_unix is not None
            else None
        ),
        "http_status": None,
        "sse_done": False,
        "first_token_unix": None,
        "last_token_unix": None,
        "chunk_count": 0,
        "prompt_tokens": None,
        "completion_tokens": None,
        "error": None,
    }
    first_token_elapsed: float | None = None
    last_token_elapsed: float | None = None
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            result["http_status"] = response.status
            for raw_line in response:
                line = raw_line.decode("utf-8", errors="replace").strip()
                if not line.startswith("data:"):
                    continue
                data = line[5:].strip()
                now_elapsed = time.perf_counter() - started
                if data == "[DONE]":
                    result["sse_done"] = True
                    continue
                try:
                    event = json.loads(data)
                except json.JSONDecodeError:
                    result["error"] = "invalid_sse_json"
                    continue
                usage = event.get("usage")
                if usage:
                    result["prompt_tokens"] = usage.get("prompt_tokens")
                    result["completion_tokens"] = usage.get("completion_tokens")
                if api == "chat":
                    text = "".join(
                        choice.get("delta", {}).get("content") or ""
                        for choice in event.get("choices", [])
                    )
                else:
                    text = "".join(
                        choice.get("text", "") for choice in event.get("choices", [])
                    )
                if text:
                    result["chunk_count"] += 1
                    if first_token_elapsed is None:
                        first_token_elapsed = now_elapsed
                        result["first_token_unix"] = started_wall + now_elapsed
                    last_token_elapsed = now_elapsed
                    result["last_token_unix"] = started_wall + now_elapsed
    except (OSError, ValueError, urllib.error.HTTPError) as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    ended_elapsed = time.perf_counter() - started
    result["ended_at_unix"] = started_wall + ended_elapsed
    result["e2e_ms"] = round(ended_elapsed * 1000, 3)
    result["ttft_ms"] = (
        round(first_token_elapsed * 1000, 3) if first_token_elapsed is not None else None
    )
    completion_tokens = result.get("completion_tokens")
    if (
        first_token_elapsed is not None
        and last_token_elapsed is not None
        and isinstance(completion_tokens, int)
        and completion_tokens > 1
    ):
        result["tpot_ms"] = round(
            (last_token_elapsed - first_token_elapsed) * 1000 / (completion_tokens - 1), 3
        )
    else:
        result["tpot_ms"] = None
    result["completed"] = (
        result["http_status"] == 200
        and result["sse_done"]
        and result["error"] is None
        and result["ttft_ms"] is not None
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--api", choices=("chat", "completions"), default="chat")
    parser.add_argument("--arm", choices=("exact", "baseline"), required=True)
    parser.add_argument("--repetition", type=int, required=True)
    parser.add_argument("--concurrency", type=int, default=6)
    parser.add_argument("--max-tokens", type=int, default=32)
    parser.add_argument("--timeout", type=float, default=300)
    parser.add_argument(
        "--repeat-count",
        type=int,
        default=1,
        help="repeat every corpus row with a unique sample id",
    )
    parser.add_argument(
        "--request-rate",
        type=float,
        default=0,
        help="open-loop offered requests/second; 0 keeps closed-loop concurrency",
    )
    args = parser.parse_args()
    if args.concurrency < 1:
        parser.error("--concurrency must be positive")
    if args.repeat_count < 1:
        parser.error("--repeat-count must be positive")
    if args.request_rate < 0:
        parser.error("--request-rate must be non-negative")

    source_rows = [json.loads(line) for line in args.corpus.read_text().splitlines() if line]
    rows: list[dict[str, Any]] = []
    for repeat_index in range(args.repeat_count):
        for source in source_rows:
            row = dict(source)
            if args.repeat_count > 1:
                row["source_prompt_id"] = source["prompt_id"]
                row["prompt_id"] = f"{source['prompt_id']}-repeat-{repeat_index + 1:03d}"
            rows.append(row)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, Any]] = []
    scheduled_base_perf = time.perf_counter()
    scheduled_base_unix = time.time()
    max_workers = len(rows) if args.request_rate > 0 else args.concurrency
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [
            pool.submit(
                timed_request,
                sequence,
                row,
                url=args.url.rstrip("/"),
                model=args.model,
                arm=args.arm,
                repetition=args.repetition,
                timeout=args.timeout,
                max_tokens=args.max_tokens,
                api=args.api,
                scheduled_at_perf=(
                    scheduled_base_perf + sequence / args.request_rate
                    if args.request_rate > 0
                    else None
                ),
                scheduled_at_unix=(
                    scheduled_base_unix + sequence / args.request_rate
                    if args.request_rate > 0
                    else None
                ),
            )
            for sequence, row in enumerate(rows)
        ]
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())
    results.sort(key=lambda item: item["sequence"])
    with args.output.open("w", encoding="utf-8") as stream:
        for item in results:
            stream.write(json.dumps(item, sort_keys=True) + "\n")
    return 0 if all(item["completed"] for item in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
