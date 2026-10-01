#!/usr/bin/env python3
"""Seed each prompt family directly on its owner prefill engine and write one receipt per family."""
import argparse
import json
import sys
import time
import urllib.error
import urllib.request


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--api", choices=("chat", "completions"), default="chat")
    ap.add_argument("--target", action="append", required=True, help="owner engine base URL, in owner order")
    ap.add_argument("--timeout", type=float, default=180)
    a = ap.parse_args()
    rows = [json.loads(line) for line in open(a.corpus, encoding="utf-8") if line.strip()]
    failures = 0
    with open(a.output, "w", encoding="utf-8") as out:
        for row in rows:
            target = a.target[row["owner"]]
            payload = {"model": a.model, "max_tokens": 1, "temperature": 0, "stream": False}
            if a.api == "chat":
                payload["messages"] = row["seed_messages"]
            else:
                payload["prompt"] = row["seed_prompt"]
            receipt = {"prompt_id": row["prompt_id"], "owner": row["owner"], "target": target, "started_at_unix": time.time()}
            try:
                req = urllib.request.Request(
                    target + ("/v1/chat/completions" if a.api == "chat" else "/v1/completions"),
                    data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}, method="POST")
                with urllib.request.urlopen(req, timeout=a.timeout) as r:
                    body = json.loads(r.read())
                    receipt.update(http_status=r.status, completed=r.status == 200, usage=body.get("usage"))
            except (OSError, ValueError, urllib.error.HTTPError) as e:
                failures += 1
                receipt.update(completed=False, error=f"{type(e).__name__}: {e}")
            receipt["ended_at_unix"] = time.time()
            out.write(json.dumps(receipt, sort_keys=True) + "\n")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
