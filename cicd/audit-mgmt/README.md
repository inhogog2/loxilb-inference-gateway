# audit-mgmt

The management-plane audit trail, end to end, on a self-contained bed: one
gateway, one PostgreSQL holding both stores, no GPU, no external identity
provider. This is the scenario the coverage manifest points at when it says
an event type is covered.

## What it proves

| id | claim | how |
|---|---|---|
| T-GW-1 | `/audit/status` reports the writer and never the trail's content | field checks; the first record of a boot is `sys.writer.start` |
| T-GW-3 | the log-archive API refuses an audit segment by name | `GET /log-archives/audit.jsonl` is not 200 and leaks no record |
| T25 | the delegated originator is recorded on every record of a request, trusted only for an account marked `delegation_allowed`, never promoted to `actor.user`; a malformed value is dropped and counted | an admin account, a delegating account, a viewer's 403, a malformed header; `/metrics` and `/audit/status` counters |
| TM | the named routes each leave an intent+result pair of their own type with the detail the plan lists | persist, export, maintenance on/off, token upgrade, logout, user create/delete, API-key create, two listing reads |
| T22 | the side-effecting OAuth GETs are gated | healthy: start answers 307 with a fingerprinted state, unknown-state callback 400, refresh with both tokens in the query string recorded without the query; wedged: all three 503 before any exchange |
| T15 | canary secrets reach no segment (active, sealed, compressed) and no error body | nine canaries the harness sends (proved from its own request log) plus the raw API keys and the OAuth state the gateway minted |
| T11 | actor conformance | with `--userservice` every successful result names a principal with `auth=session`; without it every record says `auth=none` and names nobody |
| T20 | a crash between a durable intent and its result is reported at the next boot, never guessed | the store is paused, a user create blocks after its intent, the process is SIGKILLed; boot 2 writes exactly one `sys.intent.orphaned` naming that `event_id`, the counter reads 1, no result exists |
| T3 | the gate fails closed with the authoritative state unchanged | the audit directory sits on a 1 MiB tmpfs that is filled to the last byte, then written into with an audited probe that changes nothing until the gate refuses one (fatal if it never does); the probe's intent is the shortest line anything written while wedged can be, which a row checks; a generated route, a raw route and a named route answer 503 `audit_unavailable` and the rule table, the key and the account list are unchanged; freed, the same calls leave a pair sharing one `event_id`, intent before result by `seq` |
| T-GW-2 | the audit policy, the remote sink and sealing on demand are management changes like any other | a policy replace and an unsatisfiable one; a sink refused for a missing, out-of-range or unreadable argument and one accepted; `POST /audit/rotate` seals the segment the status named and the next record lands in the new one |
| T-GW-5 | `loxicmd` drives the three audit paths against a live gateway, and its refusals stay local | `get audit-status` on a running writer and on a boot whose audit directory is unusable; `get audit-sink` unconfigured and configured; a set, a replace that proves the endpoint replaces rather than patches, and `--disable`; five locally refused invocations that leave the audited `mgmt.audit.sink` count untouched, against one the gateway refuses that does not; `-o json` compared key for key with the gateway's own body |
| T-GW-6 | no admitted management call is left without an answer or a result | every boot's settle probe (`POST /config/loadbalancer` with an empty body) gets an HTTP answer, including on the boots where it reaches the handler because management authentication is off; every probe intent in the trail has its result, with a floor on how many there are; and, once boot 6 has scanned boot 4, the only `sys.intent.orphaned` in the trail is the one T20 makes on purpose |
| T19 | the writer is not the only witness to its own failure | `loxilb_audit_write_failures_total` rises, `loxilb_audit_last_write_timestamp_seconds` stands still across a heartbeat interval, the operational log carries the fallback line; after recovery one `sys.writer.write_failed` names the interval and count, and every line of the segment still parses |

## Layout

| file | role |
|---|---|
| `config.sh` | PostgreSQL (both roles from `scripts/aigw-db-bootstrap.sql`), the topology, the gateway with `--userservice`, the OAuth routes on a placeholder provider, the API-key store and `--audit-dir … --audit-required`; the administrator; `.state` with the flag sets |
| `validation.sh` | the matrix above, across six boots of the gateway process |
| `rmconfig.sh` | teardown (unpauses the store first, in case T20 was interrupted) |
| `gen-coverage-manifest.py` | the event matrix: one entry per event type, stage-scoped requirements naming the assertions above; `--check` is the drift gate CI runs |
| `audit-coverage-manifest.json` | generated; its SHA-256 over the entries is the `matrix_digest` |

## The six boots

The gateway process is restarted inside its container (the `tiers.sh`
pattern) because the flag set and the audit directory have to change, and
because T20 needs a crash. Every boot's records stay readable: the previous
boot's segment is sealed at recovery and compressed, never removed.

1. `--userservice`, OAuth, audit at `/var/log/loxilb/audit` — T-GW-1, T-GW-3,
   T25, TM, T22 healthy arms, the canary sends, T11 arm 1. Ends with the
   T20 crash.
2. same flags — the orphan report, then an orderly stop.
3. audit at `/var/log/loxilb/audit-wedge`, a 1 MiB tmpfs — the key for the
   raw arm is created, the filesystem is filled and the first refusal is
   observed, T3 / T22 wedged / T19,
   the filesystem is freed, the positive arms and the retroactive record.
4. no `--userservice` — T11 arm 2, the canary sweep over both directories
   (so it covers the compressed segments of boots 1 and 2), then T-GW-2.
5. `--audit-dir` pointed below a regular file — no writer at all. Only the
   `available:false` arm of T-GW-5 runs here.
6. audit at `/var/log/loxilb/audit` again, still no `--userservice` — the
   rest of T-GW-5, against a healthy writer and a sink that has never been
   configured.

## Design decisions worth knowing

- **The wedge is a full filesystem, not a fault build.** Mounting over the
  audit directory or changing its mode does nothing to a file the writer
  already holds open; only the filesystem itself can refuse an append. A
  tmpfs of one MiB filled with `dd` (page-sized, then byte-sized to close
  the last page) takes every free page, and `rm` undoes it. The fill alone
  does not refuse the next append (see *T3's wedge is not airtight* below),
  so the scenario then drives an audited probe (a PATCH of a key that
  names no field, which the gate records and the handler then refuses with
  400) until the gate answers 503 `audit_unavailable`, and fails outright
  if it never does; only then do T3's refusals run. That is also
  the "fill the filesystem" arm of T19. The
  permission-loss arm of T19 is not driven here: a `chmod` of the directory
  cannot reach an open descriptor either; the writer's reaction to EACCES
  is covered by the unit suite through the fault hook.
- **T20 needs no fault point.** `docker pause` freezes the store's
  processes but the kernel keeps acknowledging TCP, so a handler that
  already holds a pooled connection waits for an answer that never comes.
  A fresh login just before the pause makes sure such a connection exists
  (the pool recycles connections after five minutes). The intent is durable
  before the handler runs; SIGKILL then leaves it without a result.
  Whether the paused store commits the insert once it resumes is printed,
  not asserted: the trail does not guess either way and neither does the
  scenario.
- **T11 exempts two shapes, counted separately.** The loopback bootstrap of
  the first account (`actor.bootstrap`) and the unauthenticated OAuth start
  whose result inherits the provisional view (`actor.provisional`) have no
  principal by design; the scenario counts them so the exemption cannot
  swallow the rule.
- **T15 proves the canaries were sent before proving they are absent.**
  The harness keeps its own request log and greps it first; the raw API
  keys and the OAuth state are received rather than sent and join only the
  absence sweep. The operational log runs at debug on this bed, which the
  product does not ship; a canary there is printed as a note, not scored.
- **The writer-less boot is made with a path, not a permission.**
  `--audit-dir` defaults to the healthy directory, so leaving the flag out
  does not produce a gateway without a trail. Boot 5 points it below a
  regular file instead, where the create fails with `ENOTDIR`, and it
  deliberately omits `--audit-required`: with that flag the process refuses
  to boot, and what T-GW-5 needs is a *booted* gateway answering about an
  audit trail it does not have.
- **T-GW-5 selects its records by value, never by position.** It runs after
  the seal in T-GW-2, so the trail is no longer in positional order. Every
  one of its trail assertions picks its record out by a receiver address
  only that arm configured (`127.0.0.1:7514`, `127.0.0.1:7515`) or by the
  removal being the one successful sink record naming no endpoint — none of
  which any ordering can disturb. It also configures a sink, which is why it
  cannot run before T-GW-2's "no sink is configured yet".
- **Restarts pass `-p --loglevel debug` explicitly.** `spawn_docker_host`
  adds them to the first boot; a restart that forgot them would lose
  `/metrics` (503 "Prometheus option is disabled") and read as a product
  failure.

## What this bed cannot do

- The OAuth callback that completes a login needs a real identity provider;
  only the unknown-state refusal and the wedged refusal run here.
- T17 (writer panic, supervised restart) needs the `audit_faults` build tag
  and `LOXILB_AUDIT_FAULT=writer.panic`; the CI image is built by `make`
  without tags. It runs in the unit suite in every build (the package's
  internal hook) and once more with the tag in the `unit-gates` job.
- The disk reserve (`sys.disk.reserve_breached`) is zero in the shipped
  configuration; its crossing is driven in the unit suite.
- A restore (`mgmt.snapshot.restore`) rolls the whole configuration back on
  failure and is exercised behind the real gate in the unit suite, not on
  the shared bed.

## Observed, not scored

- After `POST /auth/logout`, a `GET /auth/users` with the logged-out token
  still answers 200 on this bed. Whether an issued token dies with the
  logout is the authentication plane's contract, not the trail's; the
  scenario prints the answer as a note for that plane's owner and scores
  only the logout's own record.
- The operational log runs at debug here. A canary found there is printed,
  not scored; none was found in the reference run.
- **T3's wedge is not airtight.** Filling the 1 MiB tmpfs uses up its free
  pages, but the active segment's last page keeps whatever it had not yet
  filled, and appends that fit there still succeed on a filesystem `df`
  reports as 100% full. How much room that is depends on the segment's
  length when the fill runs, which varies from run to run, so the first
  calls T3 expects to be refused can be accepted and recorded instead.
  Seen once, in the `noguard` twin below: T3-1a–1d and T3-2a–2c went red
  with `write_failures_total` already at 5, and T3-4a answered 409 because
  the "refused" rule had in fact been created. The same `dd` fill followed
  by 600-byte appends to a file with 3,192 bytes of last-page room took five
  appends before `ENOSPC`, exactly at the page boundary. The gate was right
  each time -- the intent it answered for had been written; it is the
  scenario's assumption that a full filesystem takes no append that does
  not hold. The scenario now observes the wedge instead of assuming it: the
  probes described under *The wedge is a full filesystem* run until the
  first refusal, and the line `wedged after N probe(s); M landed` reports
  how much slack there was.
- **Which probe observes the wedge matters.** A refused append is cut back
  to the last complete line, so the room in the last page is still there
  after the refusal, and any shorter line still fits into it. A probe that
  re-enabled an enabled key wrote a 638-byte intent in this scenario; the
  OAuth start's is 618 bytes. With room for a line between those two
  lengths the gate refused that probe and then admitted the OAuth start, on
  a filesystem the scenario had just declared wedged (reproduced on a 1 MiB
  tmpfs through the gate, with the segment padded to leave exactly that
  much). The probe therefore names no field: its intent is 609 bytes,
  shorter than the intent of every call made while wedged (OAuth start 618,
  OAuth callback 630, user create 633, OAuth refresh 634, load balancer
  create 657; the PATCH that disables the key is the probe with a field
  named, so longer by construction), than a listing read's result (629) and
  than the heartbeat (677), so its refusal covers them all. The lengths
  move with the remote address and the account name, which is why `T3-0b`
  measures the shortest line of each of those seven kinds in the trail
  instead of trusting these numbers, and fails if any is shorter than the
  probe's or if the probe's own line is missing. No boot before the wedged
  one stays up for a heartbeat interval, so the scenario waits for that
  boot's first heartbeat before it measures. `T19-3c` counts from the first
  refusal, so a record that did land while wedged is a named failure.

## Red twins

A test counts only once its red twin has been run: the named mutation that
makes the assertion fail for the right reason (plan §6.1). Twins are code
mutations followed by a rebuild, which CI cannot do to itself, so they are
run by hand on the bed and recorded here; `gen-coverage-manifest.py` marks
a requirement *covered and tested* only when its `red_twin_run_id` names a
row of this table, and nothing else may set one.

Each run: the mutation applied to a synced copy of this tree (the diff is
in the run log), the image rebuilt with the overlay recipe, the whole
scenario run against it, the file restored. The baseline run on the same
tree and bed was green (165 assertions, 0 failed).

| run id | twin (plan §6.1) | mutation | assertions that went red, and nothing else |
|---|---|---|---|
| `llbigw-2-twin-T3-r1` | middleware moved back to post-handler | in `AuditGateMiddleware`, the handler runs against a discarded recorder before the 503 is answered | T3-1d (rule created), T3-2c (key disabled), T3-3b (account created); T3-4a followed with 409 because the rule already existed |
| `llbigw-2-twin-T20-r1` | recovery scan skipped | `scanOrphans` returns at entry | T20-1a, T20-1b, T20-2a, T20-2b, T20-2c |
| `llbigw-2-twin-T19-r1` | fallback counters removed | `noteWriteFailure` no longer counts | T19-1a, T19-1b, T19-3b, T19-5 |
| `llbigw-2-twin-T15-r1` | a secret enters a recorded field | the login body reader returns the password with the claimed name | T15-s1e and T15-2.1, T15-2.2, T15-2.8, T15-2.9 (every login password canary found in a segment) |
| `llbigw-2-twin-2-sinkrange-r1` | the sink stops checking the range of its two numeric knobs | the four range refusals in `AuditPostSink` and `syslog.New` are neutralised, as the endpoint was before they were added | T-GW-2-6a, T-GW-2-6b, T-GW-2-6c |
| `llbigw-2-twin-2-polfields-r1` | a policy change stops naming what it changed | `audit.ChangedFields` returns nothing | T-GW-2-2b and, because `SetPolicy` then treats the change as a no-op and never applies it, T-GW-2-2c and T-GW-2-3b |
| `llbigw-2-twin-2-rotate-r1` | sealing becomes a label rather than a boundary | `RotateNow` reports the active segment as both sealed and opened without rotating | T-GW-2-8c, T-GW-2-8e |

T11, T22 and T25 have no twin in the plan's table; their assertions are
scored but the manifest does not claim them as tested.
The mutations they need, with the rows each one must redden and nothing else:

| run id | twin (this section) | mutation | assertions that went red, and nothing else |
|---|---|---|---|
| `llbigw-2-twin-2-cli-nocheck-r1` | the CLI stops refusing anything itself | the five `return invalid(...)` guards removed from loxicmd's `auditSinkRequest` | the whole local-refusal block: `T-GW-5-5a`–`T-GW-5-5k`. The exit-code rows go first (the gateway's answer, not a local 2), the "names its flag" rows follow because there is no local refusal left to name one, and `5k` — the point of the block — sees the audited `mgmt.audit.sink` count move |
| `llbigw-2-twin-2-sink-patch-r1` | the sink endpoint patches rather than replaces | `AuditPostSink` builds its config from `auditSink.cfg` and lets only non-zero incoming fields overwrite it | `T-GW-5-8c`, `T-GW-5-8d` — the omitted server name and frame cap survive the replace |
| `llbigw-2-twin-2-sink-noendpoint-r1` | the sink record stops naming the receiver | `d.Endpoint` no longer set in the sink path's `AuditDetail` | `T-GW-5-7k`, `T-GW-5-7l`, `T-GW-5-8f`, `T-GW-5-8g`, `T-GW-5-9f`, and `T-GW-2-7d`, which selects its record the same way and breaks for the same reason |
| `llbigw-2-twin-6-main-r1` | neither fix: the image of main's tree | none; the image built for T-GW-5 from main, run with this `validation.sh` | `T-GW-6-1` (two probes, boots 4 and 6, got no answer), `T-GW-6-3` (their two intents have no result), `T-GW-6-4` (two orphans in the trail), `T-GW-6-5` (the second names boot 4's probe; boot 6's is never scanned). `6-2`'s floor stays green |
| `llbigw-2-twin-6-noguard-r1` | the create handler reads through a missing `serviceArguments` again | the nil check removed from `ConfigPostLoadbalancer`; the gate's fix kept | `T-GW-6-1` only among T-GW-6: the probes panic again and go unanswered, but their results are recorded with status 500, so `6-3`, `6-4` and `6-5` stay green -- the gate's panic path proving itself on a live gateway. `T3-1a`–`1d`, `2a`–`2c` and `4a` also went red for an unrelated reason: see *T3's wedge is not airtight* above |
| `llbigw-2-twin-3-oldprobe-r1` | the wedge probe names a field again | in `validation.sh`, the probe's body is `{"enabled":true}` and its expected answer a 2xx; no rebuild, the gateway is the reference image | `T3-0b` only: seven kinds measured, five of them shorter than the probe's 638-byte intent |
| `llbigw-2-twin-3-nofill-r1` | the filesystem is never filled | the two `dd` fills removed from `validation.sh`; same image | none: the scenario stops at `FATAL: the gate never refused within 32 probes; the filesystem is not wedged`, with the 85 assertions before it green |

The two wedge twins were run against a reference of **265 OK / 0 FAILED**
-- the 264 unchanged plus `T3-0b` -- which wedged after three probes, two of
them landed. They mutate the scenario and not the gateway, because what
they prove is the scenario's own claim that it observed a wedge.

T-GW-6 was run against a reference of **264 OK / 0 FAILED** -- the
259-assertion baseline unchanged plus its five rows -- where the probe
results were two 400s (the boots with management authentication off), three
401s and seven 503s from the freeze. A twin that removes only the gate's
fix leaves T-GW-6 green: once the handler no longer panics, nothing on a
live gateway reaches that path, so it is proven by the unit tests' own twins
instead.

Run 2026-09-27 against a reference of **259 OK / 0 FAILED** — the
193-assertion baseline unchanged plus 66 `T-GW-5` rows. All three images are
full `Dockerfile.u24` builds of the mutated tree (an overlay could not be
used: what changes is loxicmd, which an overlay does not replace), so each
twin differs from the reference by its mutation alone. `9f` counts **exactly
one** successful sink record naming no receiver rather than at least one,
which is what lets `sink-noendpoint` reach it; at "at least one" it stayed
green and proved nothing.

The three `T-GW-2` twins were run on 2026-09-27 against a reference run of
**193 assertions, 0 failed** — the 165-assertion baseline unchanged plus the
28 new ones. Two things about that section are worth knowing before it is
moved or extended. It **must run last**: it is the only part of the scenario
that seals a segment, and `trail_raw` concatenates `*.jsonl` before
`*.jsonl.gz`, so a sealed-and-compressed segment lands after the active one
and every helper that takes the newest record by position stops being right
(placing it mid-scenario reddened `TM-7`, `TM-10` and four `T15-s1*`
assertions that have nothing to do with these endpoints). And the sink's
trust anchor is generated **on the host** and copied in, because the image's
`openssl` is built against a config prefix that does not exist inside it.

## Running

```
cd cicd/audit-mgmt
LOXILB_DOCKER_IMAGE=<tag> ./config.sh && ./validation.sh; ./rmconfig.sh
python3 gen-coverage-manifest.py --check
```

`jq` and `openssl` must be on the host: the requests go through `docker
exec`, the extraction does not, and the sink's trust anchor cannot be
generated inside the image. One gateway at a time on a shared host; teardown
removes `pg-audit`, which runs with `--rm`. The whole run takes about eight
minutes, most of it the six boots, the wait for the wedged boot's first heartbeat
and the 35 s staleness window.
