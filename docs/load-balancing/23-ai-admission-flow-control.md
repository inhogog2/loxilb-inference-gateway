# AI admission flow control: the capacity gate and its queue

The capacity admission gate bounds how many inference requests execute on a
model pool at once, and how many may wait for a turn. It runs on every
AI-gateway service (a rule with `sse_mode`, `pd_disagg_mode` or an API-key
policy) after the policy checks (credential, quota, rate limit) and before
any byte reaches a backend. A refused request never opens a backend
connection; a queued request holds no backend resource while it waits.

This page covers the gate's modes and ceilings, the bounded queue and the
two rule fields that configure it, what the client sees, the maintenance
drain, and the metrics. The REST fields are also listed in the
[REST reference](05-rest-api-reference.md).

## Modes

The gate reads its mode from the process environment when a pool is
created:

| `LLB_FC_MODE` | Behaviour |
|---|---|
| unset / `off` | The dispatch path is unchanged. Every pool still exports its state with mode `0`, so a scrape can tell an ungated AI pool from a non-AI service. |
| `observe` | Every decision is computed and counted; everything is admitted. The `observe_would_shed` and `observe_would_queue` counters say what `enforce` would have done, at each ceiling that would have refused the request. |
| `enforce` | Over a ceiling, a request is queued when the pool has a queue depth and the request may wait, else refused. |

## Ceilings

A ceiling of `0` means unlimited at that level. The process defaults come
from the environment; the rule fields below override the queue's two.

| Level | Environment default | Counts |
|---|---|---|
| service (pool-wide) | `LLB_FC_MAX_OUTSTANDING` | one unit per executing inference request, however many backend legs it opens |
| endpoint, normal role | `LLB_FC_EP_MAX_INFLIGHT` | one unit per executing request on that endpoint |
| endpoint, prefill role | `LLB_FC_PREFILL_MAX_INFLIGHT` (falls back to `LLB_PD_MAX_INFLIGHT_PER_EP`) | one unit per prefill leg |
| endpoint, decode role | `LLB_FC_DECODE_MAX_INFLIGHT` | one unit per decode leg |

A unit is taken once per request: an HTTP/1.1 request (each request on a
keep-alive connection is gated again), or an HTTP/2 stream. It is released
when the request completes, when the client goes away, or when the backend
leg fails, whichever comes first. Requests that are not inference calls
(`GET /v1/models`, health probes) bypass the ceilings and are counted under
`bypass_non_inference`.

## The bounded queue

When the pool is over a ceiling and has a queue depth, an HTTP/1.1 request
whose body has arrived is parked instead of refused: its connection stays
open with reads paused, and it holds no capacity unit and no backend
connection. Each release of an executing unit on the pool wakes exactly one
waiter, oldest first; a newcomer never jumps a non-empty queue. A woken
request that loses the race for the unit goes back to the head.

| Field (`serviceArguments`) | Process default | Meaning |
|---|---|---|
| `fc_max_queue_depth` | `LLB_FC_MAX_QUEUE_DEPTH` | requests that may wait on the pool; `0` means over a ceiling is refused at once. Ceiling 65536. |
| `fc_max_queue_wait_ms` | `LLB_FC_MAX_QUEUE_WAIT_MS` (5000 when a depth is set and the window is not) | the longest a request may wait before it is ended with `504 admission_queue_timeout`. Required, greater than `0`, whenever a depth is set. |

Rules of the two fields:

- A rule value wins over the environment; the environment is the process
  default for rules that declare nothing.
- Both are runtime settings: a replace `POST` with the same key applies the
  new values to the live pool without touching the executing requests.
  Waiters already in the queue keep their place; a smaller depth applies to
  newcomers. `PATCH` does not reach FullProxy (mode 4) rules, which every
  AI-gateway service is, so the replace `POST` is the way to change them.
- Omitting a field on a replace keeps the stored value; an explicit `0`
  resets it to the process default; JSON `null` is rejected.
- `GET` reads back the posted values and, for AI-gateway services, the
  `fc_effective` object with what the data plane holds: `mode`,
  `max_outstanding`, `ep_max_inflight`, `prefill_max_inflight`,
  `decode_max_inflight`, `queue_depth`, `queue_wait_ms`, the live
  `inflight` and `queued`, and `queue_memory_bound_mib`.

### What a queue costs

A waiting request keeps its client connection, and a parked connection
holds about 1 MiB of receive buffer with the request in it. A depth is
therefore a memory bound as much as a queue bound:

```
memory the full queue may park ≈ fc_max_queue_depth × 1 MiB
```

65536 is about 64 GiB. The gateway applies any depth up to the ceiling and
logs one WARNING at rule apply when the bound exceeds half of the node's
memory:

```
[AIGateway] 10.10.10.254:2026 (…) fc_max_queue_depth=65536 may park up to 65536 MiB of client receive buffers (about 1 MiB per waiting request), more than half of this node's 63976 MiB; bound the connections with connectionLimit or LLB_PD_MAX_TOTAL_INFLIGHT
```

The two guards it names bound the connections themselves rather than the
queue: the per-rule `connectionLimit` (SYN-time, DNAT rules) and the
process valve `LLB_PD_MAX_TOTAL_INFLIGHT` (accept-time, every proxied
connection). Size the depth from the memory you can spend, and read
`fc_effective.queue_memory_bound_mib` back to see the bound in force.

### Who waits

| Request | Over a ceiling |
|---|---|
| HTTP/1.1, body fully buffered | queued when the pool has a depth |
| HTTP/1.1, streamed body (large or chunked) | queued when the pool has a depth; the connection closes after the answer either way |
| HTTP/2 stream | refused on its own stream with `429`; streams never wait |
| the prefill or decode leg of a P/D request | refused; role legs never wait, the request is answered once |

## What the client sees

Every refusal carries `Retry-After` in seconds (`1` for a ceiling refusal;
the mean queue wait, between `1` and `30`, when the queue was full or a wait
timed out; `5` for a drain) and the three admission headers `X-Loxilb-Admission-Inflight`,
`X-Loxilb-Admission-Queued` and `X-Loxilb-Admission-Limit`, the live counts
and the ceiling that refused. The body is JSON.

| Status | `error` | When | Connection |
|---|---|---|---|
| `429` | `admission_capacity` | over a ceiling with no queue, or the queue at its depth (`X-Loxilb-Admission-Queued` then equals the depth); body carries `retry_after` and `jitter_hint_ms` | kept open when the request body was fully buffered, else closed |
| `503` | `admission_no_capacity` | no healthy endpoint of the pool has capacity | closed |
| `503` | `gateway_draining` | the gateway is in maintenance (see below) | closed |
| `504` | `admission_queue_timeout` | the request waited the whole `fc_max_queue_wait_ms`; body carries `queued_ms`, the wait it spent | closed |
| `503` | `admission_drained` | the request was waiting when its pool was deleted or the gateway entered maintenance | closed |

A client that keeps a `429` connection open may send its next request on the
same socket; it is gated again. Clients should honour `Retry-After` and add
the jitter the body hints, so a burst of refusals does not return as one
burst of retries. Every non-admit decision is also a `sec.ai.deny` record on
the audit trail with the service, the model and the decision.

## Maintenance drain

`PUT /netlox/v1/maintenance {"enabled": true}` now reaches the data path:
new inference requests on every gated pool are answered `503
gateway_draining`, every request waiting in a queue is ended with `503
admission_drained`, and executing requests finish on their own. `GET
/netlox/v1/maintenance` reports `refusing_new_inference: true` while this is
in effect and `in_flight_requests`, the executing count summed over the
gated pools; `enabled: false` restores admission. On a management plane
with no data path attached `refusing_new_inference` stays `false`, so the
read-back never claims a drain that is not happening.

## Metrics

All families are per service and pool (`service="VIP:port"`, `pool` = the
pool key) and are emitted for every AI-gateway pool in every mode.

| Family | Type | Meaning |
|---|---|---|
| `loxilb_ai_admission_mode` | gauge | `0` off, `1` observe, `2` enforce |
| `loxilb_ai_admission_inflight{role}` | gauge | units held: `service` pool-wide, `normal`/`prefill`/`decode` summed over the endpoints |
| `loxilb_ai_admission_limit{role}` | gauge | the ceiling in force per role; `role="queue"` is the depth |
| `loxilb_ai_admission_queued` | gauge | requests waiting right now |
| `loxilb_ai_admission_queue_wait_seconds` | histogram | how long resumed requests waited (buckets 10 ms to 5 s) |
| `loxilb_ai_admission_decisions_total{reason}` | counter | `admitted`, `capacity_shed`, `no_healthy_capacity`, `observe_would_shed`, `bypass_non_inference`, `queued`, `queue_full`, `queue_timeout`, `cancelled`, `drained`, `observe_would_queue`, `draining` |
| `loxilb_ai_admission_anomalies_total{kind}` | counter | process-wide bookkeeping faults (`underflow`, `unknown_permit`); any increase is a defect, not load |

The AI dashboard's "AI admission gate" row plots in flight against the
ceiling, queued against the depth, the queue wait p50/p95 and the decisions
by reason.

## Limits

- The queue is per gateway process; nothing is shared across instances.
- HTTP/2 streams and P/D role legs never wait (they are refused at the
  ceiling); only HTTP/1.1 requests queue.
- A `429` keeps the connection only when the request body was fully
  buffered before the decision; a streamed body closes it.
- Adaptive tightening from backend telemetry, warm-up ramps and tenant fair
  share are not part of this release; the queue is strictly FIFO.
