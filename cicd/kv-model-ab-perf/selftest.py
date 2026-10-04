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


def analyze(tmp, name, data, scrapes=None):
    """Lay the rows out as point.sh does, run the analyzer, return (exit code, summary or None).
    scrapes: {arm: (before text, after text)} written as one engine's scrape pair into every repetition."""
    d = pathlib.Path(tmp) / name
    for r in data:
        f = d / f"repetition-{r['repetition']}" / r["arm"] / "requests.jsonl"
        f.parent.mkdir(parents=True, exist_ok=True)
        with f.open("a") as s:
            s.write(json.dumps(r) + "\n")
    for arm, (before, after) in (scrapes or {}).items():
        for rep in {r["repetition"] for r in data}:
            if before is not None:
                (d / f"repetition-{rep}" / arm / "before-engine-10.0.0.7.prom").write_text(before)
            (d / f"repetition-{rep}" / arm / "after-engine-10.0.0.7.prom").write_text(after)
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
        check("A1 slow share: every baseline request is at least twice the exact median, no exact one is; no scrapes -> no computed share",
              rc == 0 and s and s["arms"]["baseline"]["slow_request_percent"] == 100.0 and
              s["arms"]["exact"]["slow_request_percent"] == 0.0 and
              s["arms"]["exact"]["computed_prompt_token_percent"] is None, (rc, s and s["arms"]["exact"]))
        # The computed-token share comes from the engines' own counters: 20 requests of 3400 prompt tokens per
        # repetition and arm = 68000 prompt tokens.
        # The other source and a metric whose name only starts the same move by the same amount: counting either
        # doubles the share.
        vl = ('vllm:prompt_tokens_by_source_total{{source="local_compute"}} {0}\n'
              'vllm:prompt_tokens_by_source_total{{source="local_cache_hit"}} {0}\n'
              'vllm:prompt_tokens_by_source_total_created{{source="local_compute"}} {0}\n')
        sg = ('sglang:uncached_prompt_tokens_histogram_sum{{model_name="m"}} {0}\n'
              'sglang:uncached_prompt_tokens_histogram_sum_other{{model_name="m"}} {0}\n'
              'sglang:uncached_prompt_tokens_histogram_bucket{{le="100.0",model_name="m"}} 777\n')
        for label, text in (("C1 vLLM", vl), ("C2 SGLang", sg)):
            rc, s = analyze(tmp, label[:2].lower(), rows([100, 110, 105], [300, 320, 310]),
                            {"exact": (text.format(1000), text.format(7800)), "baseline": (text.format(0), text.format(34000))})
            check(f"{label} scrapes: 6800 of 68000 prompt tokens computed in the exact arm -> 10.0 %, 34000 in the baseline -> 50.0 %",
                  rc == 0 and s and s["arms"]["exact"]["computed_prompt_token_percent"] == 10.0 and
                  s["arms"]["baseline"]["computed_prompt_token_percent"] == 50.0, (rc, s and s["arms"]["exact"]))
        rc, s = analyze(tmp, "c3", rows([100, 110, 105], [300, 320, 310]), {"exact": (None, sg.format(7800))})
        check("C3 an after scrape without its before scrape -> no computed share", rc == 0 and s and
              s["arms"]["exact"]["computed_prompt_token_percent"] is None, (rc, s and s["arms"]["exact"]))
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
    # The endpoint index of the share gate comes from the gateway's listing of the rule, which orders endpoints by
    # address: prefill engines with the higher addresses are NOT endpoints 0 and 1.
    import calib
    import epidx
    listing = {"lbAttr": [
        {"serviceArguments": {"externalIP": "10.0.0.12", "port": 8080, "model_name": "other/model"},
         "endpoints": [{"endpointIP": "10.0.0.10"}, {"endpointIP": "10.0.0.11"}]},
        {"serviceArguments": {"externalIP": "10.0.0.12", "port": 8080, "model_name": "org/model"},
         "endpoints": [{"endpointIP": x} for x in ("10.0.0.7", "10.0.0.8", "10.0.0.10", "10.0.0.11")]}]}
    args = ("10.0.0.12", 8080, "org/model")
    check("E1 prefill engines with the higher addresses are endpoints 2 and 3",
          [epidx.endpoint_index(listing, *args, a) for a in ("10.0.0.10", "10.0.0.11")] == [2, 3])
    check("E2 prefill engines with the lower addresses are endpoints 0 and 1",
          [epidx.endpoint_index(listing, *args, a) for a in ("10.0.0.7", "10.0.0.8")] == [0, 1])
    for label, call in (("E3 an address outside the rule is refused", (listing, *args, "10.0.0.9")),
                        ("E4 a listing without the rule is refused", (listing, "10.0.0.12", 8081, "org/model", "10.0.0.7")),
                        ("E5 an empty listing is refused", ({}, *args, "10.0.0.7"))):
        try:
            got = epidx.endpoint_index(*call)
        except LookupError:
            got = None
        check(label, got is None, got)
    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp)
        (tmp / "rules.json").write_text(json.dumps(listing))
        run = subprocess.run([sys.executable, str(HERE / "epidx.py"), str(tmp / "rules.json"), "10.0.0.12", "8080",
                              "org/model", "10.0.0.9"], capture_output=True, text=True)
        check("E6 the command exits 1 and names the address", run.returncode == 1 and "10.0.0.9" in run.stdout, run)

        # Calibration: a floored point rate above the measured capacity is refused and nothing is banked.
        def cal_run(n, seconds):
            rows_ = [{"started_at_unix": 1000.0 + i * seconds / n, "ended_at_unix": 1000.0 + (i + 1) * seconds / n,
                      "ttft_ms": 100.0, "prompt_tokens": 3400} for i in range(n)]
            (tmp / "cal.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows_))
            (tmp / "conc.txt").write_text("4\n")
            for f in ("calibration.json", "calibration-refused.json"):
                (tmp / f).unlink(missing_ok=True)
            r = subprocess.run([sys.executable, str(HERE / "calib.py"), str(tmp / "cal.jsonl"),
                                str(tmp / "calibration.json"), str(tmp / "conc.txt")], capture_output=True, text=True)
            return r, (tmp / "calibration.json").exists(), (tmp / "calibration-refused.json").exists()
        r, banked, kept = cal_run(24, 110.77)            # 0.22 req/s: both floors are above the capacity
        check("K1 capacity 0.22 req/s -> CAPACITY_BELOW_RATE_FLOOR, exit 3, no calibration banked, measurement kept",
              r.returncode == 3 and r.stdout.startswith("CAPACITY_BELOW_RATE_FLOOR") and not banked and kept, r)
        r, banked, kept = cal_run(120, 113.71)           # 1.06 req/s: rates 0.5 / 1.0, the high one below capacity
        out = json.loads((tmp / "calibration.json").read_text()) if banked else {}
        check("K2 capacity 1.06 req/s -> banked with rates 0.5 / 1.0",
              r.returncode == 0 and (out.get("rate_low"), out.get("rate_high")) == (0.5, 1.0) and not kept, r)
        r, banked, kept = cal_run(120, 126.4)            # 0.95 req/s: the 1.0 floor is above the capacity
        check("K3 capacity 0.95 req/s -> refused (the floored 1.0 req/s is above it)", r.returncode == 3 and not banked, r)
        r, banked, kept = cal_run(120, 25.2)             # 4.76 req/s: no floor in play
        out = json.loads((tmp / "calibration.json").read_text()) if banked else {}
        check("K4 capacity 4.76 req/s -> rates 2.0 / 4.0", (out.get("rate_low"), out.get("rate_high")) == (2.0, 4.0), out)
        check("K5 the refusal is the comparison, not the floor: 1.06 is not refused, 0.95 is",
              not calib.refused({"rate_high": 1.0, "cold_closed_loop_rps": 1.06})
              and calib.refused({"rate_high": 1.0, "cold_closed_loop_rps": 0.95}))
    print(f"SELFTEST kv-model-ab-perf: {'PASS' if not failed else f'FAIL ({failed})'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
