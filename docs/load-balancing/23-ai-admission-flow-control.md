# AI admission flow control: the capacity gate and its queue

The capacity admission gate bounds how many inference requests execute on a
model pool at once, and how many may wait for a turn. It runs on every
AI-gateway service (a rule with `sse_mode`, `pd_disagg_mode` or an API-key
policy) after the policy checks (credential, quota, rate limit) and before
any byte reaches a backend. A refused request never opens a backend
connection; a queued request holds no backend resource while it waits.

This page covers the gate's modes and ceilings, the bounded queue, the rule
fields that configure each of them over the process defaults, what the
client sees, the maintenance drain, and the metrics. The REST fields are also listed in the
[REST reference](05-rest-api-reference.md).

## Modes

A rule sets its mode with `fc_mode` (`off`, `observe`, `enforce`); a rule
that declares none, or declares `inherit`, runs on the process default
`LLB_FC_MODE`. A rule may switch the gate off under an enforcing
environment.

| Mode | Behaviour |
|---|---|
| unset / `off` | The dispatch path is unchanged. Every pool still exports its state with mode `0`, so a scrape can tell an ungated AI pool from a non-AI service. |
| `observe` | Every decision is computed and counted; everything is admitted. The `observe_would_shed` and `observe_would_queue` counters say what `enforce` would have done, at each ceiling that would have refused the request. |
| `enforce` | Over a ceiling, a request is queued when the pool has a queue depth and the request may wait, else refused. |

## Ceilings

A ceiling of `0` in force means unlimited at that level.

| Level | Field (`serviceArguments`) | Environment default | Counts |
|---|---|---|---|
| service (pool-wide) | `fc_max_outstanding` | `LLB_FC_MAX_OUTSTANDING` | one unit per executing inference request, however many backend legs it opens |
| endpoint, normal role | `fc_ep_max_inflight` | `LLB_FC_EP_MAX_INFLIGHT` | one unit per executing request on that endpoint |
| endpoint, prefill role | `fc_prefill_max_inflight` | `LLB_FC_PREFILL_MAX_INFLIGHT` (falls back to `LLB_PD_MAX_INFLIGHT_PER_EP`) | one unit per prefill leg |
| endpoint, decode role | `fc_decode_max_inflight` | `LLB_FC_DECODE_MAX_INFLIGHT` | one unit per decode leg |

Each field is at most 100000.

### Where a value comes from

Every setting on this page resolves the same way, per rule: the rule's own
value when it declares one, else the process environment, else the product
default. A rule field of `0` (or `fc_mode` `inherit`) declares nothing: it
inherits, so a rule cannot ask for "unlimited" under an environment that
sets a ceiling. GET on the rule returns what was declared, and
`fc_effective` returns what is in force on the pool together with
`fc_effective.source`, which names for each value whether it came from the
`rule`, the `env` or the `default`.

All the fields are runtime settings. A replace `POST` with the same key
applies the new values to the live pool without touching executing
requests: an omitted field keeps its stored value, an explicit `0` (or
`inherit`) returns it to the environment or default, and JSON `null` is
refused. When a change lets waiting requests through (a higher ceiling, or
a mode that no longer enforces), they are woken at once, oldest first, one
per free unit, or all of them when the pool no longer enforces, instead of
one per second. PATCH does not reach FullProxy rules; on an AI service the
runtime change is a replace `POST`.

A replace that changes only these fields (and the queue's two) is applied
in place. A replace that also changes anything else re-creates the
service's data-plane entry: requests waiting in its queue are then ended
with `503 admission_drained`, as on a rule delete, and the pool's counts
start again. Change the gate on its own when requests may be waiting.

These are rule configuration, like every other `serviceArguments` field:
nothing replicates them between gateway instances. Each instance holds the
rules its controller (or its snapshot) gave it, so two instances given the
same rule resolve the same values, and an instance given a rule without
them runs on its own environment.

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
request that loses the race for the unit goes back to the head, even when
newcomers filled the queue to its depth meanwhile; one that fails an
endpoint ceiling goes back without waking anyone, since the next waiter
would meet the same ceiling. Going back does not restart the clock: the
request keeps the deadline it was first parked with, so
`fc_max_queue_wait_ms` bounds its whole wait however often it is woken, and
several woken requests that go back keep the order they arrived in. A turn
is never lost: when a woken client has
gone before it resumed, or its wake could not be delivered, the turn passes
to the next waiter, and a once-a-second pass wakes the head of any pool that
has a free unit and requests still waiting.

| Field (`serviceArguments`) | Process default | Meaning |
|---|---|---|
| `fc_max_queue_depth` | `LLB_FC_MAX_QUEUE_DEPTH` | requests that may wait on the pool; `0` means over a ceiling is refused at once. Ceiling 65536. |
| `fc_max_queue_wait_ms` | `LLB_FC_MAX_QUEUE_WAIT_MS` (5000 when a depth is set and the window is not; at most 3600000) | the longest a request may wait before it is ended with `504 admission_queue_timeout`. Required, greater than `0`, whenever a depth is set. Ceiling 3600000 (an hour). |

Rules of the two fields:

- A rule value wins over the environment; the environment is the process
  default for rules that declare nothing.
- Both are runtime settings: a replace `POST` with the same key that
  changes only the admission fields applies the new values to the live pool
  without touching the executing requests. Waiters already in the queue keep
  their place; a smaller depth applies to newcomers (see "Where a value
  comes from" for a replace that changes other fields too). `PATCH` does not reach FullProxy (mode 4) rules, which every
  AI-gateway service is, so the replace `POST` is the way to change them.
- Omitting a field on a replace keeps the stored value; an explicit `0`
  resets it to the process default; JSON `null` is rejected.
- The rule that a depth needs a wait window is judged on the rule a request
  leaves behind: a replace carrying only a new depth keeps the stored wait
  and is accepted; one carrying only `fc_max_queue_wait_ms: 0` on a rule with
  a stored depth is refused `400`, and the stored rule is unchanged.
- `GET` reads back the posted values and, for AI-gateway services, the
  `fc_effective` object with what the data plane holds: `mode`,
  `max_outstanding`, `ep_max_inflight`, `prefill_max_inflight`,
  `decode_max_inflight`, `queue_depth`, `queue_wait_ms`, the live
  `inflight` and `queued`, `queue_memory_bound_mib`, `telemetry_stale_ms`,
  and `source` (where each value came from: `rule`, `env` or `default`).

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

## Scraped queue depth: how long it is trusted

The P/D scorers weigh each endpoint by its scraped queue depth. A depth that
has not been refreshed for longer than the pool's telemetry window is no
longer trusted: the scorer uses the candidates' average in its place, so a
dead endpoint whose last report was an empty queue is not favoured forever.
The window is `fc_telemetry_stale_ms` on the rule, else
`LLB_FC_TELEMETRY_STALE_MS`, else 30000 (three default scrape intervals);
at most 3600000. The scraper stamps whole seconds, so the window is
effectively rounded to them. The window in force is
`fc_effective.telemetry_stale_ms`.

The same window decides what the adaptive ceiling below may act on.

## The adaptive service ceiling

With `fc_adaptive` `on` (or `LLB_FC_ADAPTIVE=on` and the rule declaring
nothing), the pool-wide ceiling in force follows what the pool's engines
report, between a quarter of the configured `fc_max_outstanding` (at least
one) and all of it. Once a second, per pool:

| The pool's endpoints, within the telemetry window | The ceiling in force |
|---|---|
| an endpoint reports requests waiting in its engine (`vllm:num_requests_waiting` above 0) | four fifths of what it was, never below the quarter (reason `queued`) |
| an endpoint's time to first token is above `fc_ttft_target_ms` | the same (reason `ttft`) |
| fresh reports, no backpressure | one unit more, up to the configured ceiling; the request waiting longest is woken for it (reason `clear`) |
| nothing fresh (the scrapes fail, or stopped) | unchanged: it is held, never widened (state `frozen`, reason `stale`) |

Only fresh evidence moves it, and only fresh evidence without backpressure
widens it: a gateway that has lost sight of its engines keeps the tighter
bound it last had reason for. The configured ceiling stays the hard bound;
the adaptive one is never above it, and a pool without a service ceiling
(`fc_max_outstanding` `0` in force) has nothing to adapt.

The waiting requests come from the engine's own `/metrics`, which the
gateway scrapes every 10 s for every rule that adapts (and for P/D rules,
whose scorers read the same values). A service with several model pools on
one VIP and port gets the depth on its first pool only; the others adapt on
the time to first token alone.

The time to first token is measured on streamed responses: from the moment
a request is admitted (a wait at the gate is not the engine's) to its first
data event, and credited to the endpoint that holds its unit (the decode
endpoint of a disaggregated request). Each endpoint keeps an average that
weights a new sample one eighth, so an endpoint that was twice over the
target needs about eight fast samples to come back under it. One endpoint
over the target is enough to tighten the pool, and the ceiling climbs again
only while no endpoint is. An average older than the telemetry window is
not used: with nothing fresh the ceiling freezes where it is, and the next
sample starts that endpoint's average over. A buffered response is not measured: its
headers come when the whole completion is done, so its first byte says how
long the answer was, not how soon the engine started. `fc_ttft_target_ms`
`0` in force leaves the time to first token out.

`fc_effective` reads back `adaptive`, `effective_max_outstanding` (the
ceiling in force now), `adapt_state` (`off`, `open` at the ceiling,
`tightened`, `frozen`) and `adapt_reason`. Turning `fc_adaptive` off by a
replace gives the configured ceiling back at once; a replace that lowers
the ceiling takes the adaptive one down with it, and one that raises it
lets a tightened pool climb on, one unit a second.

## Warm-up after a return to service

An endpoint that comes back (its circuit breaker closes, its health probe
or host state turns it active again, or a replace adds it) takes a full
share of a burst at once; a cold engine then answers slowly or fails. With
`fc_warmup_ms` on the rule (or `LLB_FC_WARMUP_MS`), its per-endpoint
ceilings ramp instead: a quarter of each (at least one) at the moment it
returns, rising in a straight line to all of it at the end of the window.
An unlimited role stays unlimited. The service ceiling is not ramped.
`fc_effective.warming_endpoints` counts the endpoints inside their window.

## Tenant fair share

Without a share the queue is strictly first come, first served, so one
tenant sending a burst fills the ceiling and the queue and everyone else
waits behind it. With `fc_tenant_max_share_pct` on the rule (or
`LLB_FC_TENANT_MAX_SHARE_PCT`), a tenant holds at most that percentage of
the service ceiling in force (the adaptive one while the pool adapts) and of
the queue depth, rounded up and at least one each:

| `fc_max_outstanding` | `fc_max_queue_depth` | share | a tenant may execute | and wait |
|---|---|---|---|---|
| 8 | 16 | 25 | 2 | 4 |
| 10 | 0 | 30 | 3 | refused at once |
| 3 | 1 | 10 | 1 | 1 |

A tenant is the tenant id the request's credential resolved to (API key or
JWT, on a service that enforces one); every request without a tenant id,
keyless traffic included, is one tenant. A tenant at its share of the
ceiling waits for one of its own units when the pool queues and it still has
room in its share of the queue; otherwise it is refused `429
admission_tenant_share` while every other tenant still admits. A waiting
tenant that cannot run holds nobody up: a newcomer waits behind the queue
only when someone in it could take the unit, and a released unit wakes the
oldest waiter whose tenant is under its share, the others keeping their
place. The share is a hard cap: it binds even when the service is otherwise
idle. It needs a service ceiling (`fc_max_outstanding`); a share of `100`
is no share.

A pool tracks up to 64 tenants at a time. Tenants past that share one last
slot and are held together to one share; each request placed there counts
`loxilb_ai_admission_anomalies_total{kind="tenant_table_full"}`. A tenant's
slot is freed as soon as it holds nothing, so the table bounds the tenants
active at once, not the tenants known. `fc_effective.tenants_active`
counts them.

## What the client sees

Every refusal carries `Retry-After` in seconds (`1` for a ceiling refusal;
the mean queue wait, between `1` and `30`, when the queue was full or a wait
timed out; `5` for a drain, on HTTP/1.1 and HTTP/2 alike) and the three admission headers `X-Loxilb-Admission-Inflight`,
`X-Loxilb-Admission-Queued` and `X-Loxilb-Admission-Limit`, the live counts
and the ceiling that refused. The body is JSON.

| Status | `error` | When | Connection |
|---|---|---|---|
| `429` | `admission_capacity` | over a ceiling with no queue, or the queue at its depth (`X-Loxilb-Admission-Queued` then equals the depth); body carries `retry_after` and `jitter_hint_ms` | kept open when the request body was fully buffered, else closed |
| `429` | `admission_tenant_share` | the request's tenant holds its share of the ceiling (and may not wait) or of the queue; the admission headers carry the pool's counts, not the tenant's | as `admission_capacity` |
| `503` | `admission_no_capacity` | no healthy endpoint of the pool has capacity | closed |
| `503` | `gateway_draining` | the gateway is in maintenance (see below) | closed |
| `504` | `admission_queue_timeout` | the request waited the whole `fc_max_queue_wait_ms`; body carries `queued_ms`, the wait it spent | closed |
| `503` | `admission_drained` | the request was waiting when its pool was deleted or the gateway entered maintenance | closed |

A client that keeps a `429` connection open may send its next request on the
same socket; it is gated again. Clients should honour `Retry-After` and add
the jitter the body hints, so a burst of refusals does not return as one
burst of retries. Every non-admit decision is also a `sec.ai.deny` record on
the audit trail with the service, the model and the decision.

### The same headers on admitted responses

With `fc_expose_headers` `on` (or `LLB_FC_EXPOSE_HEADERS=on` and the rule
declaring nothing), every admitted inference response carries the three
admission headers too, so a client can slow down before it is refused:
`X-Loxilb-Admission-Inflight` and `X-Loxilb-Admission-Queued` are the pool's
executing and waiting requests as the response head goes out (the request
itself counted), and `X-Loxilb-Admission-Limit` the service ceiling in force
(the adaptive one while the pool adapts; `0` when the pool has none). They
go on the response head on HTTP/1.1 and HTTP/2, streamed (`text/event-stream`,
chunked) responses included; the body is never touched. Fields of those
names sent by the backend are replaced. A pool in `observe` mode reports
them too, since it counts its requests; requests the gate does not count
(non-inference paths, a pool in `off` mode) carry none. On HTTP/1.1 a
response head the backend split across several reads is sent without them.

A rule refuses `fc_expose_headers` `on` with a `sockMapMode` of `both` or
`response` (`400`): those responses go from the backend to the client in the
kernel and the gateway never sees them. Set process-wide with
`LLB_FC_EXPOSE_HEADERS=on`, the headers appear only on the responses the
gateway relays.

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
| `loxilb_ai_admission_decisions_total{reason}` | counter | `admitted`, `capacity_shed`, `no_healthy_capacity`, `observe_would_shed`, `bypass_non_inference`, `queued`, `queue_full`, `queue_timeout`, `cancelled`, `drained`, `observe_would_queue`, `draining`, `tenant_share` |
| `loxilb_ai_admission_effective_limit` | gauge | the service ceiling in force now: the adaptive one while the pool adapts, else the configured one |
| `loxilb_ai_admission_adapt_state{state}` | gauge | state set, `1` for the current one: `off`, `open`, `tightened`, `frozen` |
| `loxilb_ai_admission_adapt_reason{reason}` | gauge | state set: `none`, `queued`, `ttft`, `clear`, `stale` |
| `loxilb_ai_admission_adapt_moves_total{direction}` | counter | steps of the adaptive ceiling, `down` and `up` |
| `loxilb_ai_admission_warming_endpoints` | gauge | endpoints inside their warm-up window |
| `loxilb_ai_admission_tenants_active` | gauge | tenants holding a unit or waiting, while the pool has a tenant share |
| `loxilb_ai_admission_anomalies_total{kind}` | counter | process-wide: `underflow` and `unknown_permit` are bookkeeping faults (any increase is a defect, not load); `tenant_table_full` counts requests whose tenant shared the overflow slot |

The process accept valve (`LLB_PD_MAX_TOTAL_INFLIGHT`) bounds connection
contexts, not requests, before any pool sees them:

| Family | Type | Meaning |
|---|---|---|
| `loxilb_proxy_context_inflight` | gauge | connection contexts held, client and backend legs alike; counted only while the valve is on, so `0` when unbounded |
| `loxilb_proxy_accept_bound` | gauge | the bound; `0` when unbounded |
| `loxilb_proxy_accept_blocked_total` | counter | times the valve paused accepting at the bound: connections wait in the listen backlog until a context is released, which re-arms the listener; one per pause, not per connection, so a steady rate is the node reaching its bound again and again |

At the bound the valve pauses the listeners: poll stops reporting them, so
connections waiting in the backlog cost no CPU. The release of a connection
context re-arms them, and the once-a-second health pass re-arms any that a
release missed. Measured on a test bed with ten streams held at a bound of
12: 8.5 % of one core, against 8.2 % with no bound.
Size the bound so that it is reached only in overload, and treat contexts
held at the bound as a capacity alarm.

The AI dashboard's "AI admission gate" row plots in flight against the
ceiling, queued against the depth, the queue wait p50/p95 and the decisions
by reason.

## Runbook

| What you see | What it means | What to do |
|---|---|---|
| `decisions_total{reason="capacity_shed"}` rising while `effective_limit` equals `limit{role="service"}` | the pool is at its configured ceiling | raise `fc_max_outstanding` if the engines have headroom (their own `num_requests_waiting` stays at 0), else add endpoints |
| the same while `effective_limit` is below the configured one, `adapt_reason` `queued` or `ttft` | the engines report backpressure and the gateway is shedding in front of them, as intended | add capacity; a target (`fc_ttft_target_ms`) far below what the model can do keeps the ceiling at its floor |
| `adapt_state{state="frozen"}` | the scrapes stopped (engine `/metrics` down or blocked) while the ceiling was tightened: it holds | check the engines' `/metrics` and `loxilb_ai_worker_scrape_total`; turn `fc_adaptive` off by a replace to return to the configured ceiling at once |
| `decisions_total{reason="queue_timeout"}` rising | requests wait a whole `fc_max_queue_wait_ms` | the queue only delays refusals at this load: shorten the wait or add capacity |
| `queued` near `limit{role="queue"}` for minutes | the queue absorbs a sustained, not a burst, overload | add capacity; a deeper queue parks more client memory (depth × 1 MiB) |
| `warming_endpoints` above 0 after every health flap | an endpoint flaps between down and up | fix the endpoint; its ramp restarts on every return |
| `proxy_context_inflight` at `proxy_accept_bound`, or `proxy_accept_blocked_total` rising | the node is at its connection-context bound; new connections wait in the listen backlog | raise `LLB_PD_MAX_TOTAL_INFLIGHT` if memory allows, else add gateway instances |
| `anomalies_total` above 0 | a bookkeeping defect | report it with the gateway log |
| `decisions_total{reason="tenant_share"}` rising while `inflight` is below the limit | one tenant is at its share; the rest of the ceiling is left for others, as intended | raise `fc_tenant_max_share_pct` if one tenant should be allowed more of an idle pool |
| `anomalies_total{kind="tenant_table_full"}` rising | more than 64 tenants active on one pool at once; the ones past the table share one budget | expected under a very wide tenant fan-out; split the pool if they need separate budgets |

The shipped alert rules (`deploy/monitoring/prometheus/rules/loxilb-alerts.yml`,
group `loxilb-ai-admission`) fire on sustained shedding, queue timeouts, a
queue held near its depth, a frozen adaptive ceiling, the accept valve
holding connections back, and any anomaly.

## Limits

- The queue is per gateway process; nothing is shared across instances.
- HTTP/2 streams and P/D role legs never wait (they are refused at the
  ceiling); only HTTP/1.1 requests queue.
- A `429` keeps the connection only when the request body was fully
  buffered before the decision; a streamed body closes it.
- The queue is first come, first served within the tenant share; without a
  share it is strictly FIFO. There are no priorities between tenants beyond
  the share.
