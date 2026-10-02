#!/usr/bin/env python3
"""Checks of the A/B tooling that need no GPU and no gateway.

The analyzer decides whether a point is banked and whether a difference is claimed, and the load generator
decides whether a request counts; both are exercised here on synthetic rows and against a local SSE stand-in.
Every case states the verdict it expects, including the ones where the tool must refuse.
"""
import http.server
import json
import pathlib
import subprocess
import sys
import tempfile
import threading

HERE = pathlib.Path(__file__).resolve().parent
failed = 0


def check(label, ok, detail=""):
    global failed
    failed += not ok
    print(f"  {'ok  ' if ok else 'FAIL'} {label}{'' if ok else ' -- ' + str(detail)}")


def rows(exact_ms, base_ms, families=20):
    """One request row per (repetition, arm, family); *_ms = the TTFT of each repetition."""
    out = []
    for arm, per_rep in (("exact", exact_ms), ("baseline", base_ms)):
        for rep, ttft in enumerate(per_rep, 1):
            for n in range(families):
                t0 = 1000.0 * rep + n
                out.append({"repetition": rep, "arm": arm, "prompt_id": f"family-{n:03d}", "completed": True,
                            "http_status": 200, "sse_done": True, "ttft_ms": ttft + n, "tpot_ms": 10.0,
                            "e2e_ms": ttft + n + 320, "started_at_unix": t0, "ended_at_unix": t0 + 1,
                            "completion_tokens": 32, "prompt_tokens": 3400, "schedule_delay_ms": 0.5})
    return out


def analyze(tmp, name, data):
    """Lay the rows out as point.sh does, run the analyzer, return (exit code, summary or None)."""
    d = pathlib.Path(tmp) / name
    for r in data:
        f = d / f"repetition-{r['repetition']}" / r["arm"] / "requests.jsonl"
        f.parent.mkdir(parents=True, exist_ok=True)
        with f.open("a") as s:
            s.write(json.dumps(r) + "\n")
    p = subprocess.run([sys.executable, str(HERE / "analyze.py"), "--input-dir", str(d), "--summary", str(d / "s.json"),
                        "--self-test"], capture_output=True, text=True)
    return p.returncode, json.loads((d / "s.json").read_text()) if (d / "s.json").exists() else None


class Stub(http.server.BaseHTTPRequestHandler):
    seen, fail_on = [], None

    def log_message(self, *a):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        text = body["messages"][0]["content"]
        Stub.seen.append(text)
        if text == Stub.fail_on:
            self.send_response(503); self.end_headers(); return
        self.send_response(200); self.send_header("Content-Type", "text/event-stream"); self.end_headers()
        for ev in ({"choices": [{"delta": {"content": "a"}}]}, {"choices": [{"delta": {"content": "b"}}]},
                   {"choices": [], "usage": {"prompt_tokens": 7, "completion_tokens": 2}}):
            self.wfile.write(f"data: {json.dumps(ev)}\n\n".encode())
        if text != "no-done":
            self.wfile.write(b"data: [DONE]\n\n")


def bench(tmp, url, corpus, *extra):
    Stub.seen = []
    out = pathlib.Path(tmp) / "bench.jsonl"
    p = subprocess.run([sys.executable, str(HERE / "bench.py"), "--corpus", str(corpus), "--output", str(out), "--url", url,
                        "--model", "m", "--arm", "exact", "--repetition", "1", "--concurrency", "1", *extra])
    return p.returncode, [json.loads(x) for x in out.read_text().splitlines()], list(Stub.seen)


def main():
    with tempfile.TemporaryDirectory() as tmp:
        print("analyzer verdicts")
        rc, s = analyze(tmp, "a1", rows([100, 110, 105], [300, 320, 310]))
        check("A1 every exact repetition under every baseline one -> exact_lower", rc == 0 and s and
              s["effects"]["ttft_p95_separation"] == "exact_lower" and s["effects"]["ttft_p95_delta_percent"] < 0, (rc, s))
        rc, s = analyze(tmp, "a2", rows([100, 330, 105], [300, 320, 310]))
        check("A2 one exact repetition above a baseline one -> overlap, no claim", rc == 0 and s and
              s["effects"]["ttft_p95_separation"] == "overlap", (rc, s))
        rc, s = analyze(tmp, "a3", rows([300, 320, 310], [300, 320, 310]))
        check("A3 identical arms -> overlap, delta 0", rc == 0 and s and s["effects"]["ttft_p95_separation"] == "overlap"
              and s["effects"]["ttft_p95_delta_percent"] == 0, (rc, s))
        rc, s = analyze(tmp, "a4", rows([300, 320, 310], [100, 110, 105]))
        check("A4 exact slower in every repetition -> baseline_lower", rc == 0 and s and
              s["effects"]["ttft_p95_separation"] == "baseline_lower", (rc, s))
        bad = rows([100, 110, 105], [300, 320, 310]); bad[7]["sse_done"] = False
        rc, s = analyze(tmp, "a5", bad)
        check("A5 one stream without [DONE] -> void, no summary", rc == 1 and s is None, (rc, s))
        bad = rows([100, 110, 105], [300, 320, 310]); bad[7]["http_status"] = 503
        rc, s = analyze(tmp, "a6", bad)
        check("A6 one non-200 answer -> void", rc == 1 and s is None, (rc, s))
        rc, s = analyze(tmp, "a7", rows([100, 110, 105], [300, 320, 310])[1:])
        check("A7 a request present in one arm only -> void", rc == 1 and s is None, (rc, s))
        rc, s = analyze(tmp, "a8", rows([100, 110], [300, 320]))
        check("A8 two repetitions -> void", rc == 1 and s is None, (rc, s))
        bad = rows([100, 110, 105], [300, 320, 310]); bad.append(dict(bad[0]))
        rc, s = analyze(tmp, "a9", bad)
        check("A9 a duplicated request row -> void", rc == 1 and s is None, (rc, s))
        bad = rows([100, 110, 105], [300, 320, 310]); bad[3]["tpot_ms"] = None
        rc, s = analyze(tmp, "a10", bad)
        check("A10 a row without a per-token time -> void", rc == 1 and s is None, (rc, s))

        print("first-round warmth")

        def round1(name, first_ms, later_ms, suffix=True):
            f = pathlib.Path(tmp) / f"{name}.jsonl"
            data = [{"prompt_id": f"family-{n:03d}" + (f"-repeat-{k:03d}" if suffix else ""), "ttft_ms": ms + n}
                    for k, ms in ((1, first_ms), (2, later_ms), (3, later_ms)) for n in range(20)]
            f.write_text("".join(json.dumps(r) + "\n" for r in data))
            return subprocess.run([sys.executable, str(HERE / "round1.py"), str(f)], capture_output=True, text=True).returncode
        check("R1 first round as fast as the later ones -> warm", round1("r1", 55, 50) == 0)
        check("R2 first round 3.6x the later ones -> cold, refused", round1("r2", 180, 50) == 1)
        check("R3 first round 1.4x (a decode pull) -> still warm", round1("r3", 350, 250) == 0)
        check("R4 rows without a round number -> cannot judge, refused", round1("r4", 55, 50, suffix=False) == 2)

        print("load generator")
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Stub)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        url = f"http://127.0.0.1:{srv.server_address[1]}"
        corpus = pathlib.Path(tmp) / "corpus.jsonl"
        subprocess.run([sys.executable, str(HERE / "gen_corpus.py"), "--output", str(corpus), "--families", "12",
                        "--owners", "2", "--shape", "short"], check=True)
        src = [json.loads(x)["timed_prompt"] for x in corpus.read_text().splitlines()]
        rc, res, plain = bench(tmp, url, corpus)
        check("B1 every stream with tokens, usage and [DONE] is complete", rc == 0 and len(res) == 12 and
              all(r["completed"] and r["completion_tokens"] == 2 and r["ttft_ms"] is not None for r in res), rc)
        check("B2 without a seed the corpus order is kept", plain == src, plain[:2])
        rc, res, one = bench(tmp, url, corpus, "--order-seed", "1", "--repeat-count", "2")
        _, _, again = bench(tmp, url, corpus, "--order-seed", "1", "--repeat-count", "2")
        _, _, other = bench(tmp, url, corpus, "--order-seed", "2", "--repeat-count", "2")
        check("B3 a seed reorders, the same seed gives the same order, another seed another", rc == 0 and
              one == again and one != other and one[:12] != src, one[:2])
        check("B4 every round still offers every family once, under distinct request ids",
              sorted(one[:12]) == sorted(src) and sorted(one[12:]) == sorted(src) and len({r["prompt_id"] for r in res}) == 24)
        Stub.fail_on = src[5]
        rc, res, _ = bench(tmp, url, corpus)
        check("B5 one refused request -> exit 1 and that row is not complete", rc == 1 and
              [r["completed"] for r in res].count(False) == 1, rc)
        Stub.fail_on = None
        rows_ = [json.loads(x) for x in corpus.read_text().splitlines()]
        rows_[0]["timed_messages"][0]["content"] = "no-done"
        corpus.write_text("".join(json.dumps(r) + "\n" for r in rows_))
        rc, res, _ = bench(tmp, url, corpus)
        check("B6 a stream that ends without [DONE] -> exit 1", rc == 1 and not res[0]["completed"] and res[0]["sse_done"] is False, rc)
        rc, res, _ = bench(tmp, url, corpus, "--request-rate", "200")
        check("B7 open loop: every request carries its schedule and its start delay", rc == 1 and
              all(r["scheduled_at_unix"] and r["schedule_delay_ms"] is not None for r in res), rc)
        srv.shutdown()
    print(f"SELFTEST kv-model-ab-perf: {'PASS' if not failed else f'FAIL ({failed})'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
