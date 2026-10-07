#!/usr/bin/env python3
"""Checks of the A/B tooling that need no GPU and no gateway.

The analyzer decides whether a point is banked and whether a difference is claimed, and the load generator
decides whether a request counts; both are exercised here on synthetic rows and against a local SSE stand-in.
Every case states the verdict it expects, including the ones where the tool must refuse.
"""
import hashlib
import http.server
import json
import os
import pathlib
import shutil
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
        # A prefill/decode fleet: the decode engine's series moves by the same tokens as its prefill engine's.
        pd = ('sglang:uncached_prompt_tokens_histogram_sum{{engine_type="prefill",model_name="m"}} {0}\n'
              'sglang:uncached_prompt_tokens_histogram_sum{{engine_type="decode",model_name="m"}} {0}\n')
        rc, s = analyze(tmp, "c4", rows([100, 110, 105], [300, 320, 310]),
                        {"exact": (pd.format(1000), pd.format(7800)), "baseline": (pd.format(0), pd.format(34000))})
        check("C4 SGLang prefill/decode scrapes: the decode engine repeats the prefill engine's tokens -> still 10.0 % and 50.0 %",
              rc == 0 and s and s["arms"]["exact"]["computed_prompt_token_percent"] == 10.0 and
              s["arms"]["baseline"]["computed_prompt_token_percent"] == 50.0, (rc, s and s["arms"]["exact"]))
        dec = 'sglang:uncached_prompt_tokens_histogram_sum{{engine_type="decode",model_name="m"}} {0}\n'
        rc, s = analyze(tmp, "c5", rows([100, 110, 105], [300, 320, 310]), {"exact": (dec.format(1000), dec.format(7800))})
        check("C5 a decode engine's scrape alone counts as scraped, with no computed tokens -> 0.0 %", rc == 0 and s and
              s["arms"]["exact"]["computed_prompt_token_percent"] == 0.0, (rc, s and s["arms"]["exact"]))
        rc, s = analyze(tmp, "c3", rows([100, 110, 105], [300, 320, 310]), {"exact": (None, sg.format(7800))})
        check("C3 an after scrape without its before scrape -> no computed share", rc == 0 and s and
              s["arms"]["exact"]["computed_prompt_token_percent"] is None, (rc, s and s["arms"]["exact"]))
        # TensorRT-LLM counts missed KV blocks; the block size is a gauge of the same scrape. 200 blocks of 32
        # tokens = 6400 of 68000 prompt tokens, 1000 blocks = 32000. A series whose name only starts the same
        # must not be counted, and a block count with no block size is not a token count.
        tb = ('trtllm_kv_cache_missed_blocks_total{{engine_type="pytorch",model_name="m"}} {0}\n'
              'trtllm_kv_cache_missed_blocks_total_other{{model_name="m"}} {0}\n')
        tr = tb + 'trtllm_kv_cache_tokens_per_block{{engine_type="pytorch",model_name="m",pid="1"}} 32.0\n'
        rc, s = analyze(tmp, "c6", rows([100, 110, 105], [300, 320, 310]),
                        {"exact": (tr.format(50), tr.format(250)), "baseline": (tr.format(0), tr.format(1000))})
        check("C6 TensorRT-LLM scrapes: 200 missed blocks of 32 tokens in the exact arm -> 9.4 %, 1000 in the baseline -> 47.1 %",
              rc == 0 and s and s["arms"]["exact"]["computed_prompt_token_percent"] == 9.4 and
              s["arms"]["baseline"]["computed_prompt_token_percent"] == 47.1, (rc, s and s["arms"]["exact"]))
        rc, s = analyze(tmp, "c7", rows([100, 110, 105], [300, 320, 310]), {"exact": (tb.format(50), tb.format(250))})
        check("C7 TensorRT-LLM missed blocks with no block size in the scrape -> no computed share", rc == 0 and s and
              s["arms"]["exact"]["computed_prompt_token_percent"] is None, (rc, s and s["arms"]["exact"]))
        # KV transfers of a prefill/decode fleet, from the same scrapes. The helper writes one engine's pair into
        # each of the three repetitions, so an arm's totals are three times one pair's difference. A series whose
        # name only starts the same moves too: counting it doubles the count.
        nx = ('vllm:nixl_bytes_transferred_count{{engine="0"}} {0}\n'
              'vllm:nixl_bytes_transferred_count_other{{engine="0"}} {0}\n'
              'vllm:nixl_bytes_transferred_sum{{engine="0"}} {1}\n'
              'vllm:nixl_xfer_time_seconds_sum{{engine="0"}} {2}\n'
              'vllm:nixl_num_failed_transfers_total{{engine="0"}} {3}\n')
        mk = ('sglang:kv_transfer_total_mb_count{{engine_type="prefill"}} {0}\n'
              'sglang:kv_transfer_total_mb_count_other{{engine_type="prefill"}} {0}\n'
              'sglang:kv_transfer_total_mb_sum{{engine_type="prefill"}} {1}\n'
              'sglang:kv_transfer_latency_ms_sum{{engine_type="prefill"}} {2}\n'
              'sglang:num_transfer_failed_reqs_total{{engine_type="prefill"}} {3}\n')
        mib = 2 ** 20
        for label, before, after in (("T1 vLLM", nx.format(10, 930 * mib, 1.0, 1), nx.format(30, 2790 * mib, 3.0, 2)),
                                     ("T2 SGLang", mk.format(10, 930, 1000, 1), mk.format(30, 2790, 3000, 2))):
            rc, s = analyze(tmp, label[:2].lower(), rows([100, 110, 105], [300, 320, 310]),
                            {"exact": (before, after), "baseline": (before, before)})
            e, b = (s["arms"][x] for x in ("exact", "baseline")) if s else ({}, {})
            check(f"{label} transfer counters: 20 transfers a repetition of 93.0 MB and 100.0 ms each, 1 failed -> 60, 5580.0 MB, 3 failed",
                  rc == 0 and (e.get("kv_transfers"), e.get("kv_transfer_mb"), e.get("kv_transfer_mb_each"),
                               e.get("kv_transfer_ms_each"), e.get("kv_transfer_failed")) == (60, 5580.0, 93.0, 100.0, 3) and
                  e["per_run"][0]["kv_transfers"] == 20, (rc, e))
            check(f"{label} counters that did not move -> 0 transfers, no size or time each (not 0.0)",
                  rc == 0 and (b.get("kv_transfers"), b.get("kv_transfer_mb_each"), b.get("kv_transfer_ms_each")) == (0, None, None), (rc, b))
        rc, s = analyze(tmp, "t3", rows([100, 110, 105], [300, 320, 310]), {"exact": (None, mk.format(30, 2790, 3000, 2))})
        check("T3 transfer counters in an after scrape without its before scrape -> no transfer reading", rc == 0 and s and
              s["arms"]["exact"]["kv_transfers"] is None and s["arms"]["exact"]["kv_transfer_mb"] is None, (rc, s and s["arms"]["exact"]))
        rc, s = analyze(tmp, "t4", rows([100, 110, 105], [300, 320, 310]), {"exact": (sg.format(1000), sg.format(7800))})
        check("T4 engine scrapes with no transfer counter (one pool of engines) -> no transfer reading", rc == 0 and s and
              s["arms"]["exact"]["kv_transfers"] is None and s["arms"]["baseline"]["kv_transfers"] is None, (rc, s and s["arms"]["exact"]))
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
    # The rule of an arm. A baseline or calibration rule routes without the cache, but on a prefill/decode fleet
    # the gateway still needs the engine type to speak that engine's prefill/decode dialect.
    import rule
    print("gateway rules")
    fleet = ("10.0.0.12", "8080", None, "org/model", "prof-v1", "8000", "10.0.0.7 10.0.0.8", "10.0.0.10 10.0.0.11")
    def sa(arm, eng, topo):
        return rule.build(arm, *fleet[:2], eng, *fleet[3:], topo)["serviceArguments"]
    check("G1 SGLang prefill/decode: the baseline and the calibration rule name the engine type, exact routing off",
          all(sa(a, "sglang", "pd").get("kvEngineType") == "sglang" and sa(a, "sglang", "pd")["kvExactMode"] == 0
              for a in ("baseline", "calibration")), sa("baseline", "sglang", "pd"))
    check("G2 vLLM prefill/decode: the baseline and the calibration rule carry no engine type",
          all("kvEngineType" not in sa(a, "vllm", "pd") and sa(a, "vllm", "pd")["pd_disagg_mode"] is True
              for a in ("baseline", "calibration")), sa("baseline", "vllm", "pd"))
    check("G3 converged: no engine type and no prefill/decode mode on the baseline rule, either engine",
          all("kvEngineType" not in sa("baseline", e, "converged") and "pd_disagg_mode" not in sa("baseline", e, "converged")
              for e in ("sglang", "vllm")), sa("baseline", "sglang", "converged"))
    check("G4 exact rule: mode 1 on prefill/decode, 3 converged, engine type and profile on both",
          [(sa("exact", "sglang", t)["kvExactMode"], sa("exact", "sglang", t)["kvEngineType"], sa("exact", "sglang", t)["kvModelProfile"])
           for t in ("pd", "converged")] == [(1, "sglang", "prof-v1"), (3, "sglang", "prof-v1")])
    eps = rule.build("baseline", *fleet[:2], "sglang", *fleet[3:], "pd")["endpoints"]
    check("G5 prefill/decode endpoints: prefill engines role 1, decode engines role 2",
          [(e["endpointIP"], e["ep_role"]) for e in eps] == [("10.0.0.7", 1), ("10.0.0.8", 1), ("10.0.0.10", 2), ("10.0.0.11", 2)], eps)

    trt, sgl = sa("exact", "trtllm", "converged"), sa("exact", "sglang", "converged")
    check("G6 TensorRT-LLM converged: the exact rule names the engine, mode 3 and its 32-token blocks (16 on the others); "
          "the baseline rule names no engine",
          (trt["kvEngineType"], trt["kvExactMode"], trt["kvBlockSize"], sgl["kvBlockSize"], sa("exact", "vllm", "pd")["kvBlockSize"])
          == ("trtllm", 3, 32, 16, 16) and "kvEngineType" not in sa("baseline", "trtllm", "converged"), trt)

    # Seeding. An SGLang prefill engine keeps a prefix only for a request it serves together with a decode
    # engine: the same body, with the prefill engine as bootstrap host and one room, goes to both.
    print("seeding")
    class Engine(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            self.server.bodies.append(body)
            self.send_response(self.server.status); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(json.dumps({"usage": {"prompt_tokens": 9}}).encode())
    def engine(status=200):
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Engine)
        srv.bodies, srv.status = [], status
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv, f"http://127.0.0.1:{srv.server_address[1]}"
    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp)
        (tmp / "c.jsonl").write_text("".join(json.dumps(
            {"prompt_id": f"family-{n:03d}", "owner": n % 2, "seed_messages": [{"role": "user", "content": f"p{n}"}],
             "seed2_messages": [{"role": "user", "content": f"q{n}"}]}) + "\n"
            for n in range(4)))
        def seed(*extra):
            r = subprocess.run([sys.executable, str(HERE / "seed.py"), "--corpus", str(tmp / "c.jsonl"), "--output",
                                str(tmp / "r.jsonl"), "--model", "m", *extra], capture_output=True, text=True)
            return r.returncode, [json.loads(x) for x in (tmp / "r.jsonl").read_text().splitlines()]
        (p0, u0), (p1, u1), (d, ud) = engine(), engine(), engine()
        rc, rec = seed("--target", u0, "--target", u1)
        check("S1 plain seeding: each family once on its owner engine, no bootstrap field, nothing to the decode engine",
              rc == 0 and len(p0.bodies) == len(p1.bodies) == 2 and not d.bodies and all(r["completed"] for r in rec)
              and not any(k.startswith("bootstrap") for b in p0.bodies + p1.bodies for k in b), (rc, rec[:1]))
        for srv in (p0, p1, d):
            srv.bodies.clear()
        rc, rec = seed("--target", u0, "--target", u1, "--pair-decode", ud)
        rooms = [b.get("bootstrap_room") for b in d.bodies]
        check("S2 paired seeding: every family goes to its owner and to the decode engine with the same body",
              rc == 0 and len(d.bodies) == 4 and len(p0.bodies) == len(p1.bodies) == 2
              and sorted(json.dumps(b, sort_keys=True) for b in p0.bodies + p1.bodies) == sorted(json.dumps(b, sort_keys=True) for b in d.bodies),
              (rc, len(d.bodies)))
        check("S3 paired seeding: bootstrap host = the prefill engine's host, port 8998, one room per family",
              all(b.get("bootstrap_host") == "127.0.0.1" and b.get("bootstrap_port") == 8998 for b in d.bodies)
              and len(set(rooms)) == 4 and None not in rooms, d.bodies[:1])
        check("S4 paired seeding: the receipt names the decode engine and both answers",
              all(r["completed"] and r["pair_decode"] == ud and r["prefill_http_status"] == 200 for r in rec), rec[:1])
        bad, ub = engine(400)
        rc, rec = seed("--target", ub, "--target", u1, "--pair-decode", ud)
        check("S5 a prefill engine that refuses its half -> exit 1, those families not seeded",
              rc == 1 and [r["completed"] for r in rec].count(False) == 2, (rc, rec))
        for srv in (p0, p1, d):
            srv.bodies.clear()
        rc, rec = seed("--target", u0, "--target", u1, "--second-touch")
        sent = sorted(b["messages"][0]["content"] for b in p0.bodies + p1.bodies)
        check("S6 second touch: each family once on its owner engine with its second seed request, receipts say touch 2",
              rc == 0 and sent == ["q0", "q1", "q2", "q3"] and [b["messages"][0]["content"] for b in p0.bodies] == ["q0", "q2"]
              and all(r["completed"] and r.get("touch") == 2 for r in rec) and all(b["max_tokens"] == 1 for b in p0.bodies), (rc, sent, rec[:1]))
        for srv in (p0, p1, d, bad):
            srv.shutdown()
        # The three requests of a family share the prefix and nothing after it: each ending starts with another
        # character, so a request branches from the other two exactly at the end of the prefix.
        subprocess.run([sys.executable, str(HERE / "gen_corpus.py"), "--output", str(tmp / "long.jsonl"), "--families", "4",
                        "--owners", "2", "--prefix-repetitions", "3"], check=True)
        subprocess.run([sys.executable, str(HERE / "gen_corpus.py"), "--output", str(tmp / "short.jsonl"), "--families", "4",
                        "--owners", "2", "--shape", "short"], check=True)
        def shared(x, y):
            return next((i for i, (p, q) in enumerate(zip(x, y)) if p != q), min(len(x), len(y)))
        long_ = [json.loads(x) for x in (tmp / "long.jsonl").read_text().splitlines()]
        cuts = [{shared(r[a], r[b]) for a, b in (("seed_prompt", "seed2_prompt"), ("seed_prompt", "timed_prompt"), ("seed2_prompt", "timed_prompt"))}
                for r in long_]
        check("S7 long corpus: seed, second seed and timed request of a family branch at one place, the end of the prefix",
              all(len(c) == 1 for c in cuts) and all(
                  hashlib.sha256(r["seed2_prompt"][:next(iter(c)) - 1].encode()).hexdigest() == r["prefix_sha256"]
                  and r["seed2_messages"] == [{"role": "user", "content": r["seed2_prompt"]}] for r, c in zip(long_, cuts)), cuts)
        short = [json.loads(x) for x in (tmp / "short.jsonl").read_text().splitlines()]
        check("S8 short corpus: the second seed is the prompt itself, as the first",
              all(r["seed2_prompt"] == r["seed_prompt"] == r["timed_prompt"] for r in short), short[:1])

    # The decode engines' launch arguments. validation.sh itself is run, beside a stand-in for the engine
    # launcher that records what each engine would have been started with.
    print("decode-side prefix cache")
    arg = "--disaggregation-decode-enable-radix-cache"
    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp)
        ab, compat, prof = tmp / "cicd/kv-model-ab-perf", tmp / "cicd/kv-model-compat-pd", tmp / "cicd/common/kv_hash/fixtures/profiles"
        for d in (ab, compat, prof):
            d.mkdir(parents=True)
        for f in ("validation.sh", "env.sh"):
            shutil.copy(HERE / f, ab / f)
        shutil.copy(HERE.parent / "kv-model-compat-pd/env.sh", compat / "env.sh")
        (compat / "engine.sh").write_text('#!/bin/bash\necho "$3 $4 [${SGL_EXTRA:-}]" >> "$STARTS"\n')
        (compat / "engine.sh").chmod(0o755)
        for name in ("r1-distill-qwen-15b-v1", "gemma4-e2b-it-v1", "qwen38-27b-fp8-v1", "never-started-v1"):
            (prof / f"{name}.yaml").write_text(f"profileId: {name}\nbaseModel: org/{name}\n")
        def fleet(eng, name, topology="pd", **env):
            starts = tmp / "starts.txt"
            starts.unlink(missing_ok=True)
            e = {"PATH": os.environ["PATH"], "TOPOLOGY": topology, "VIP": "10.0.0.12", "LOGD": str(tmp), "ABROOT": str(tmp / "ev"),
                 "STARTS": str(starts), **env}
            e.update({"PREFILLS": "10.0.0.7 10.0.0.8", "DECODES": "10.0.0.10 10.0.0.11"} if topology == "pd" else {"ENGINES": "10.0.0.7 10.0.0.8"})
            r = subprocess.run(["bash", str(ab / "validation.sh"), "fleet-up", eng, name], capture_output=True, text=True, env=e)
            lines = starts.read_text().splitlines() if starts.exists() else []
            return r.returncode, r.stdout, [x for x in lines if x.startswith("decode ")], [x for x in lines if not x.startswith("decode ")]
        def state(n):
            f = tmp / "ev" / f"sglang-{n}" / "decode-cache.txt"
            return f.read_text().strip() if f.exists() else "(no file)"
        rc, out, dec, pre = fleet("sglang", "r1-distill-qwen-15b-v1")
        check("D1 SGLang prefill/decode, a measured model: both decode engines get the argument, no prefill engine does",
              rc == 0 and len(dec) == 2 and all(arg in x for x in dec) and len(pre) == 2 and not any(arg in x for x in pre)
              and "DECODE_CACHE_" not in out, (rc, out, dec, pre))
        for name, why in (("gemma4-e2b-it-v1", "refused"), ("qwen38-27b-fp8-v1", "refused"), ("never-started-v1", "unmeasured")):
            rc, out, dec, pre = fleet("sglang", name)
            check(f"D2 {name}: no decode engine gets the argument, and the run says DECODE_CACHE_SKIPPED {why}",
                  rc == 0 and len(dec) == 2 and not any(arg in x for x in dec + pre) and f"DECODE_CACHE_SKIPPED {why}" in out, (rc, out, dec))
        rc, out, dec, pre = fleet("sglang", "r1-distill-qwen-15b-v1", SGL_DECODE_CACHE="0")
        check("D3 SGL_DECODE_CACHE=0: off for a measured model too, and the run says DECODE_CACHE_OFF",
              rc == 0 and len(dec) == 2 and not any(arg in x for x in dec) and "DECODE_CACHE_OFF" in out, (rc, out, dec))
        rc, out, dec, pre = fleet("sglang", "never-started-v1", SGL_EXTRA_DECODE=arg)
        check("D4 SGL_EXTRA_DECODE still reaches the decode engines only; the argument in it is recorded as forced",
              len(dec) == 2 and all(arg in x for x in dec) and not any(arg in x for x in pre)
              and state("never-started-v1") == "forced" and "DECODE_CACHE_" not in out, (out, dec, pre))
        fleet("sglang", "never-started-v1")
        rc, out, dec, pre = fleet("vllm", "r1-distill-qwen-15b-v1")
        rc2, out2, dec2, pre2 = fleet("sglang", "r1-distill-qwen-15b-v1", topology="converged")
        check("D5 vLLM, and SGLang converged: no engine gets the argument and no line is printed",
              rc == rc2 == 0 and len(dec) == 2 and not dec2 and len(pre2) == 2 and not any(arg in x for x in dec + pre + pre2)
              and "DECODE_CACHE_" not in out + out2 and "decode-side" not in out + out2, (out, out2, dec, pre2))
        rc, out, dec, pre = fleet("sglang", "r1-distill-qwen-15b-v1", SGL_DECODE_CACHE="yes")
        check("D6 SGL_DECODE_CACHE other than 0 or 1 is refused before any engine starts", rc == 64 and not dec and not pre, (rc, dec, pre))
        check("D7 the state is kept with the evidence",
              (state("gemma4-e2b-it-v1"), state("never-started-v1")) == ("refused", "unmeasured"), state("gemma4-e2b-it-v1"))
        # TensorRT-LLM is driven as one pool of converged engines on the chat surface; every other shape is
        # refused before an engine starts.
        print("TensorRT-LLM")
        rc, out, dec, pre = fleet("trtllm", "r1-distill-qwen-15b-v1", topology="converged")
        check("E1 TensorRT-LLM converged: one converged engine per node, no decode engine, no decode-cache line",
              rc == 0 and not dec and len(pre) == 2 and all(x.startswith("converged ") for x in pre) and "DECODE_CACHE_" not in out, (rc, out, pre))
        r = subprocess.run(["bash", str(ab / "validation.sh"), "fleet-up", "trtllm", "r1-distill-qwen-15b-v1"], capture_output=True, text=True,
                           env={"PATH": os.environ["PATH"], "TOPOLOGY": "pd", "VIP": "10.0.0.12", "LOGD": str(tmp), "ABROOT": str(tmp / "ev"),
                                "STARTS": str(tmp / "starts-pd.txt"), "PREFILLS": "10.0.0.7 10.0.0.8", "DECODES": "10.0.0.10 10.0.0.11"})
        check("E2 TensorRT-LLM on a prefill/decode fleet is refused before any engine starts",
              r.returncode == 64 and "TRTLLM_TOPOLOGY_UNSUPPORTED pd" in r.stderr and not (tmp / "starts-pd.txt").exists(), (r.returncode, r.stderr))
        rc, out, dec, pre = fleet("tgi", "r1-distill-qwen-15b-v1", topology="converged")
        check("E3 an engine the scenario does not drive is refused before any engine starts", rc == 64 and not dec and not pre, (rc, dec, pre))
        shutil.copy(HERE / "point.sh", ab / "point.sh")
        # The gateway address and the registry are stand-ins: a point that got past the refusal would otherwise
        # reach for the ones of the machine this runs on.
        conv = {"PATH": os.environ["PATH"], "TOPOLOGY": "converged", "ENGINES": "10.0.0.7 10.0.0.8", "VIP": "10.0.0.12", "LOGD": str(tmp),
                "ABROOT": str(tmp / "ev"), "GW_API": "http://127.0.0.1:9/none", "REG": str(tmp / "registry"), "GW_CTR": "none"}
        r = subprocess.run(["bash", str(ab / "point.sh"), "trtllm", "r1-distill-qwen-15b-v1", "p1", str(tmp / "none.jsonl"), "1.0", "3", "completions"],
                           capture_output=True, text=True, env=conv)
        check("E4 a completions point on TensorRT-LLM is refused before the point directory is made",
              r.returncode == 64 and "TRTLLM_SURFACE_UNSUPPORTED completions" in r.stderr and not (tmp / "ev" / "trtllm-r1-distill-qwen-15b-v1-converged" / "p1").exists(),
              (r.returncode, r.stderr))
        # The launcher itself (../kv-model-compat-pd/engine.sh), with a stand-in for ssh that answers the image
        # question and records every other command: a refusal must come before anything is started on a node.
        real = HERE.parent / "kv-model-compat-pd"
        for f in ("engine.sh", "env.sh"):
            shutil.copy(real / f, compat / f)
        (compat / "trtllm").mkdir()
        shutil.copy(real / "trtllm/converged.yaml", compat / "trtllm/converged.yaml")
        (prof / "olmo2-0425-1b-v1.yaml").write_text("profileId: olmo2-0425-1b-v1\nbaseModel: org/olmo\ntokenizerRevision: abc\n")
        (prof / "r1-distill-qwen-15b-v1.yaml").write_text("profileId: r1-distill-qwen-15b-v1\nbaseModel: org/r1\ntokenizerRevision: abc\n")
        ssh = tmp / "ssh-stub"
        ssh.write_text('#!/bin/bash\ncase "$*" in *"docker image inspect"*) echo "$IMAGE_ID" ;; *) echo "$*" >> "$SSH_LOG"; exit 1 ;; esac\n')
        ssh.chmod(0o755)
        def launch(role, name, image_id):
            log = tmp / "ssh.log"
            log.unlink(missing_ok=True)
            r = subprocess.run(["bash", str(compat / "engine.sh"), "start", "trtllm", role, name], capture_output=True, text=True,
                               env={"PATH": os.environ["PATH"], "PREFILL": "10.0.0.7", "DECODE": "10.0.0.8", "CONVERGED": "10.0.0.7",
                                    "VIP": "10.0.0.12", "LOGD": str(tmp), "SSH": str(ssh), "SSH_LOG": str(log), "IMAGE_ID": image_id,
                                    "EVROOT": str(tmp / "ev-engine")})
            return r.returncode, r.stdout, log.read_text() if log.exists() else ""
        pinned = [x.split("=", 1)[1] for x in (real / "env.sh").read_text().splitlines() if x.startswith("TRT_IMAGE_ID=")][0]
        rc, out, cmds = launch("converged", "olmo2-0425-1b-v1", pinned)
        check("E5 a model TensorRT-LLM cannot serve: ENGINE_MODEL_BLOCKED, nothing run on the node",
              rc == 1 and "ENGINE_MODEL_BLOCKED trtllm" in out and "architecture_unsupported" in out and not cmds, (rc, out, cmds))
        rc, out, cmds = launch("prefill", "r1-distill-qwen-15b-v1", pinned)
        check("E6 a TensorRT-LLM prefill engine: ENGINE_ROLE_UNSUPPORTED, nothing run on the node",
              rc == 64 and "ENGINE_ROLE_UNSUPPORTED trtllm prefill" in out and not cmds, (rc, out, cmds))
        rc, out, cmds = launch("converged", "r1-distill-qwen-15b-v1", "sha256:" + "0" * 64)
        check("E7 the node's image is not the pinned one: ENGINE_IMAGE_MISMATCH, nothing run on the node",
              rc == 1 and "ENGINE_IMAGE_MISMATCH 10.0.0.7" in out and not cmds, (rc, out, cmds))
        rc, out, cmds = launch("converged", "r1-distill-qwen-15b-v1", pinned)
        check("E8 the pinned image: the launch goes on to the node (the weights check is its first command there)",
              rc == 1 and "WEIGHTS_MISSING 10.0.0.7" in out and "config.json" in cmds and "ENGINE_" not in out, (rc, out, cmds))
        # The per-profile plans of a state-space model on SGLang, asked of env.sh itself.
        print("second seed and static memory")
        def ask(call, topology="converged"):
            e = {"PATH": os.environ["PATH"], "TOPOLOGY": topology, "VIP": "10.0.0.12", "LOGD": str(tmp)}
            e.update({"PREFILLS": "10.0.0.7 10.0.0.8", "DECODES": "10.0.0.10 10.0.0.11"} if topology == "pd" else {"ENGINES": "10.0.0.7 10.0.0.8"})
            r = subprocess.run(["bash", "-c", f'source "{ab}/env.sh" && {call}'], capture_output=True, text=True, env=e)
            return r.stdout.strip() if r.returncode == 0 else f"rc {r.returncode} {r.stderr.strip()}"
        got = [ask(f"sgl_second_seed_plan {x}", t) for x, t in (
            ("sglang converged qwen38-27b-fp8-v1", "converged"), ("sglang converged r1-distill-qwen-15b-v1", "converged"),
            ("vllm converged qwen38-27b-fp8-v1", "converged"), ("trtllm converged qwen38-27b-fp8-v1", "converged"),
            ("sglang pd qwen38-27b-fp8-v1", "pd"))]
        check("H1 second seed: only the measured state-space model on one pool of SGLang engines; no other model, engine or fleet shape",
              got == ["second", "none", "none", "none", "none"], got)
        got = [ask(f"sgl_static_mem {x}") for x in ("converged qwen38-27b-fp8-v1", "prefill qwen38-27b-fp8-v1", "decode qwen38-27b-fp8-v1",
                                                    "converged r1-distill-qwen-15b-v1")]
        check("H2 static memory: 0.85 for that model's converged engine, 0.70 for its prefill and decode engines and for every other model",
              got == ["0.85", "0.70", "0.70", "0.70"], got)
        text = (real / "engine.sh").read_text()
        check("H3 the launcher takes the share from that plan, SGL_MEM still overrides it, and no launch line names a number",
              'SGL_STATIC_MEM=${SGL_MEM:-$(sgl_static_mem "$ROLE" "$PROF")}\n' in text
              and [x.split("--mem-fraction-static ")[1].split()[0] for x in text.splitlines() if "--mem-fraction-static " in x] == ["$SGL_STATIC_MEM"], text.count("mem-fraction"))
    print(f"SELFTEST kv-model-ab-perf: {'PASS' if not failed else f'FAIL ({failed})'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
