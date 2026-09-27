# ai-admission — the capacity admission gate

A gateway booted with the capacity gate enforcing (service ceiling 8,
endpoint ceiling 5), three AI-gateway services over one backend process
whose receipts and peak-concurrency counters say what actually executed,
and drivers that push each service past its ceilings over HTTP/1.1, HTTP/2
and TLS. The last arm reboots the gateway in observe mode and drives the
same load again.

The gate is configured from the process environment for now
(`LLB_FC_MODE`, `LLB_FC_MAX_OUTSTANDING`, `LLB_FC_EP_MAX_INFLIGHT`); the
rule fields arrive with the configuration change that follows this one.

## Topology

```
l3h1 (10.10.10.1) ---- llb1 (VIP 10.10.10.254) ---- l3ep1 (31.31.31.1)

:2021  HTTP/1.1   -> l3ep1:8080, :8081   mock_backend.py (one process, both ports)
:2022  HTTP/2     -> l3ep1:8090, :8091   h2c_backend.py x2
:2023  TLS        -> l3ep1:8080, :8081   with max_stream_duration_sec = 3
:2024  HTTP/1.1   -> l3ep1:8080          one endpoint, so its ceiling (5) binds
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
| H | reboot in observe mode, 12 held | 12 receipts, gauge 12, nothing refused, observe_would_shed 6 (4 over the service ceiling, 1 over each endpoint's), admitted 12 |

## Files

- `config.sh` / `validation.sh` / `rmconfig.sh` — the scenario
- `gw.sh` — the gateway boot, rules and observe-mode restart, shared by config and validation
- `mock_backend.py` — HTTP/1.1 backend: receipts, hold/release, delay, peak concurrency across both ports
- `h2c_backend.py` — the h2c echo backend the HTTP/2 legs of `ai-jwtauth` use (receipts, per-request delay)
- `h2_admit.py` — HTTP/2 driver: k streams on one connection, refusals reported per stream, RST_STREAM on live streams
- `h1_client.py` — the HTTP/1.1 shapes curl cannot drive: clients that vanish while executing, a second request on a kept connection
