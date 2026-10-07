#!/usr/bin/env python3
"""Seed each prompt family directly on its owner prefill engine and write one receipt per family.

--pair-decode is for an SGLang prefill/decode fleet. An SGLang prefill engine refuses a request that carries no
bootstrap room, and does not keep the prefix of one sent with its warm-up bootstrap host, so a family can only be
seeded the way SGLang's own router serves a request: the same body, with bootstrap_host / bootstrap_port /
bootstrap_room, sent to the owner prefill engine and to a decode engine at the same time.

--second-touch sends the row's second seed request (the same prefix, another ending) instead of the first.
"""
import argparse
import concurrent.futures
import json
import random
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


def post(url, payload, timeout):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, json.loads(r.read())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--api", choices=("chat", "completions"), default="chat")
    ap.add_argument("--target", action="append", required=True, help="owner engine base URL, in owner order")
    ap.add_argument("--timeout", type=float, default=180)
    ap.add_argument("--pair-decode", help="SGLang prefill/decode: decode engine base URL paired with every seed")
    ap.add_argument("--bootstrap-port", type=int, default=8998)
    ap.add_argument("--second-touch", action="store_true", help="send the second seed request of every family")
    a = ap.parse_args()
    rows = [json.loads(line) for line in open(a.corpus, encoding="utf-8") if line.strip()]
    failures = 0
    field = "seed2" if a.second_touch else "seed"
    with open(a.output, "w", encoding="utf-8") as out:
        for row in rows:
            target = a.target[row["owner"]]
            payload = {"model": a.model, "max_tokens": 1, "temperature": 0, "stream": False}
            if a.api == "chat":
                payload["messages"] = row[field + "_messages"]
            else:
                payload["prompt"] = row[field + "_prompt"]
            receipt = {"prompt_id": row["prompt_id"], "owner": row["owner"], "target": target, "started_at_unix": time.time()}
            if a.second_touch:
                receipt["touch"] = 2
            path = "/v1/chat/completions" if a.api == "chat" else "/v1/completions"
            try:
                if a.pair_decode:
                    payload.update(bootstrap_host=urllib.parse.urlsplit(target).hostname,
                                   bootstrap_port=a.bootstrap_port, bootstrap_room=random.getrandbits(62))
                    receipt["pair_decode"] = a.pair_decode
                    with concurrent.futures.ThreadPoolExecutor(2) as pool:
                        pre = pool.submit(post, target + path, payload, a.timeout)
                        dec = pool.submit(post, a.pair_decode + path, payload, a.timeout)
                        (pstatus, _), (status, body) = pre.result(), dec.result()
                    receipt.update(prefill_http_status=pstatus)
                    status = status if pstatus == 200 else pstatus
                else:
                    status, body = post(target + path, payload, a.timeout)
                receipt.update(http_status=status, completed=status == 200, usage=body.get("usage"))
            except (OSError, ValueError, urllib.error.HTTPError) as e:
                failures += 1
                receipt.update(completed=False, error=f"{type(e).__name__}: {e}")
            receipt["ended_at_unix"] = time.time()
            out.write(json.dumps(receipt, sort_keys=True) + "\n")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
