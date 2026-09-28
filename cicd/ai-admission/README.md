# ai-admission — the capacity admission gate

A gateway booted with the capacity gate enforcing (service ceiling 8,
endpoint ceiling 5), six AI-gateway services over one backend process
whose receipts, peak-concurrency counters and arrival order say what
actually executed, and drivers that push each service past its ceilings
over HTTP/1.1, HTTP/2 and TLS, into and out of the bounded queue, through
a rule delete and a maintenance drain. The last arm reboots the gateway in
observe mode and drives the same load again.

The mode and the ceilings come from the process environment
(`LLB_FC_MODE`, `LLB_FC_MAX_OUTSTANDING`, `LLB_FC_EP_MAX_INFLIGHT`); the
queue is configured per rule (`fc_max_queue_depth`, `fc_max_queue_wait_ms`)
and read back through `fc_effective`.

## Topology

```
l3h1 (10.10.10.1) ---- llb1 (VIP 10.10.10.254) ---- l3ep1 (31.31.31.1)

:2021  HTTP/1.1   -> l3ep1:8080, :8081   mock_backend.py (one process, both ports)
:2022  HTTP/2     -> l3ep1:8090, :8091   h2c_backend.py x2
:2023  TLS        -> l3ep1:8080, :8081   with max_stream_duration_sec = 3
:2024  HTTP/1.1   -> l3ep1:8080          one endpoint, so its ceiling (5) binds
:2025  HTTP/1.1   -> l3ep1:8080, :8081   fc_max_queue_depth 4, fc_max_queue_wait_ms 30000
:2026  HTTP/1.1   -> l3ep1:8080          fc_max_queue_depth 65536: the memory warning at apply
```

The gateway runs with `--audit-dir --audit-required`, so every refusal the
gate makes must also be a `sec.ai.deny` record with stage `capacity`.

## Rows

| Row | Drive | What must hold |
|---|---|---|
| P | scrape | mode 2, ceilings 8 / 5 exported, gauge 0, no anomaly |
| A | 4 sequential requests | 4 x 200, 4 receipts, admitted +4, gauge back to 0 |
| B | 12 held requests | exactly 8 receipts, 4 x 429 with `X-Loxilb-Admission-Inflight/-Queued/-Limit`, `Retry-After`, `jitter_hint_ms`; gauge 8 while held; 8 x 200 after release; capacity_shed +4 |
| N | 12 held requests on the one-endpoint pool | exactly 5 receipts, 7 x 429 carrying `X-Loxilb-Admission-Limit: 5`, endpoint gauge 5, 5 x 200 after release |
| C | 64 simultaneous 2 s requests | peak concurrency at the backend == 8, each endpoint <= 5, receipts == admitted |
| D | 5 requests on one keep-alive socket | one connection, 5 receipts, gauge back to 0 |
| E | 12 HTTP/2 streams on one connection, 3 cancelled | gauge 8 (streams, not connections), 4 refused on their own stream with the headers, gauge 5 after the cancels, 5 x 200, 8 receipts |
| F | 4 executing clients reset | 4 receipts, gauge back to 0 with the backend still holding |
| G | second request on a kept connection while the pool is full | 429 on the same socket, 0 receipts |
| I | `GET /v1/models` while the pool is full | 200, reached the backend, counted as `bypass_non_inference` |
| K | the trail | 4 `sec.ai.deny` records for B's 429s: stage capacity, status 429, reason admission, decision admission_capacity, service, model |
| L | TLS listener | the ninth request reads a 429 through TLS (curl exit 0); an SSE stream past the cap reads the reaper's error event through TLS, chunk-framed like the stream it ends, and the gateway log shows the socket's owner worker wrote it |
| J | scrape | no anomaly, no no_healthy_capacity, four pools exported |
| Q | 8 held on the queue pool (depth 4, wait 30 s), 4 more sent 300 ms apart, then 2 more | queued gauge 4, `role="queue"` limit 4, 0 receipts for the waiters, queued +4; the 2 extra get 429 with `X-Loxilb-Admission-Queued: 4` and `admission_capacity`, queue_full +2; one held request released ⇒ the 4 waiters reach the backend in arrival order (`__order`), 4 × 200, wait histogram count +4, admitted +12, gauges back to 0 |
| T | the wait shortened to 4000 ms by a replace POST and read back, 8 held, 2 waiters past the window | both 504 `admission_queue_timeout` with `queued_ms` ≥ 4000 and `Retry-After`, queue_timeout +2, queued gauge 0, 0 receipts then or later, the 30 s wait restored and read back |
| X | 8 held, 2 waiters reset their connections after 3 s | cancelled +2, queued gauge 0, 0 receipts then or later, gauge back to 0 |
| W | the `:2026` rule with depth 65536 | the gateway log (read through the `loxilb*.log` glob, asserted non-empty) carries the memory warning naming that rule and both guards; no warning for the `:2025` rule; the pool is gated with queue limit 65536 |
| R | GET and a replace POST on the `:2025` rule | `fc_max_queue_depth`/`fc_max_queue_wait_ms` read back; `fc_effective` reports mode, ceiling, depth, wait, `queue_memory_bound_mib` = depth, live `queued`; a replace POST with depth 2 is read back, held by the data plane and exported, then restored; a depth without a wait window is refused 400; a replace carrying only a depth is accepted and keeps the stored wait, one carrying only a zero wait is refused 400 with the stored rule untouched (the pair is judged on the merged rule) |
| KA | pool full, one connection sends a buffered request, then another on the same socket after the pool empties | 429 with `Connection: keep-alive`, socket open; the second request on the SAME socket is 200; receipts 0 then 1 |
| DL | 8 held on `:2025`, 2 waiting, the rule is deleted by its full key (host, path prefix, match mode, model name) and the GET no longer lists it | both 503 `admission_drained`, 0 receipts then or later, 2 `sec.ai.deny` records with decision `admission_drained`; the rule re-created reports enforce with nothing in flight |
| M | 8 held on `:2025`, 2 waiting, `PUT /maintenance {enabled:true}` | GET maintenance says `refusing_new_inference: true` and `in_flight_requests: 8`; the 2 waiters get 503 `admission_drained` (drained +2); a new request gets 503 `gateway_draining` with `Connection: close` and `Retry-After: 5` and 0 receipts (draining +1); the 8 executing finish 200; `enabled:false` ⇒ `refusing_new_inference: false` and the next request is admitted |
| H | reboot in observe mode, 12 held | 12 receipts, gauge 12, nothing refused, observe_would_shed 6 (4 over the service ceiling, 1 over each endpoint's), admitted 12 |

## Files

- `config.sh` / `validation.sh` / `rmconfig.sh` — the scenario
- `gw.sh` — the gateway boot, rules and observe-mode restart, shared by config and validation
- `mock_backend.py` — HTTP/1.1 backend: receipts, hold/release, delay, peak concurrency across both ports
- `h2c_backend.py` — the h2c echo backend the HTTP/2 legs of `ai-jwtauth` use (receipts, per-request delay)
- `h2_admit.py` — HTTP/2 driver: k streams on one connection, refusals reported per stream, RST_STREAM on live streams
- `h1_client.py` — the HTTP/1.1 shapes curl cannot drive: clients that vanish while executing, a second request on a kept connection
