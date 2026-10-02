# audit-sink

The audit trail leaving the gateway, end to end, against a strict RFC 5425
(syslog over TLS) receiver that stands in for the SIEM. No GPU, no cloud
service, no user service, no database: a gateway with the trail under
`--audit-dir` and `--audit-required`, and three receivers.

This is the third audit scenario. `cicd/audit-mgmt` covers what the
management plane writes to the trail and `cicd/audit-data` what the
inference path writes; this one covers what follows the trail out.

## Why a receiver, and why a strict one

The gateway's status can only say what the sender believes: a write that
returned. Whether a record was delivered, in what order, under which
number and with which bytes are facts about what arrived, and only the
receiving side can state them. Every row below that is about delivery is
read from the receiver; the status is used to wait, and for the rows that
are about the status itself.

A permissive collector would hide the defects this scenario looks for, so
`syslog_receiver.py` is strict where a collector is lenient: a frame that is
not `MSG-LEN SP SYSLOG-MSG` closes the connection, every message must be a
well-formed RFC 5424 header with the audit envelope as MSG, and an element
of STRUCTURED-DATA under another enterprise number is an error. It keeps,
for each record, its `(instance_id, boot_id, seq)`, its export sequence,
the SHA-256 of the MSG bytes and its arrival order, and it has the levers
the outage and ordering arms need (`/__slow`, `/__records`, `/__stats`) on a
control port only the harness reaches. It is the standard library only.

## What it proves

| | claim | how |
|---|---|---|
| TR | a session is made only to a receiver the configured CA vouches for | a decoy on the same host, running the same program, with a certificate from another CA: the gateway attempts it and no session, and no frame, ever arrives; the sink says why |
| TR | the frames are what a strict receiver accepts, and MSG is the local record | zero framing, header, envelope and STRUCTURED-DATA errors over each receiver's life; the SHA-256 of every MSG that arrived equals that of the line in the segment |
| ST | the status reports the sinks, and what cannot be a secondary sink is refused | `compliance_sink`, `sinks[]` with the cursor in the segment being written; the reserved name, a name that is not a file name, a missing enterprise number, a missing trust anchor and an unknown stream each answer 400 and install nothing |
| T23 | a filtered sink numbers what it sends, contiguously, and never uses a number twice | arm 1: only the management stream arrives, `xseq` runs from 1 with no hole, while the unfiltered sink received the records the filter withholds. arm 2: after a clean stop the next number is the very next one; after a kill it is above every number sent, by at most one reserved block. arm 3: a cursor file cut short, or missing beside a readable reservation, is reported as `sys.sink.cursor_reset` and continues in the same epoch. arm 4: with both state files gone the epoch is a greater one and the sequence starts at 1. arm 5: the gateway is ended between a submission and the cursor write, and between the rename of a state file and the flush of its directory |
| T5 | a receiver outage loses nothing | (a) the receiver is killed, twenty records are written, it comes back with no memory: every record of the outage arrives, and the trail holds a disconnect and a connect. (b) the gateway is restarted in the middle of the outage: every record the previous boot wrote during it arrives under that boot's id |
| T6 | sealing the segment while the sink is behind keeps the order | the receiver is throttled, the segment is sealed twice: nothing is missing across three segments and the records arrive in `seq` order |
| T16 | a segment pruned before a sink had it is put on record first | the secondary's receiver is taken away and the trail is given a quota of one small segment: `sys.segment.lost_to_retention` names the range and the sink that was behind, ahead of the `sys.segment.prune` that names the sink that had it; the receiver that prune names does hold every record of the range; no loss is recorded against the sink that kept up; the sink that was behind reports the removal and catches up |
| MT | the scrape says where each sink is | one series per sink: `loxilb_audit_sink_connected` follows the receiver being there and away, for that sink alone; with the receiver away the failed submissions are counted, bytes of the trail are behind the sink and the oldest record it could not send has an age, and both lags return to zero once it has caught up; the exported count covers what the receiver holds; `loxilb_audit_records_lost_to_retention_total` covers the range T16 lost and `loxilb_audit_sink_lag_drops_total` agrees with the sink's own report |

## Topology

```
llb1 ---- siem1 (33.33.33.1)  compliance receiver :6514, control :6515
     |                        decoy receiver      :6516, control :6517
     ---- siem2 (34.34.34.1)  secondary receiver  :6514, control :6515
```

Two receivers because T23 is about the difference between them: the
compliance sink takes no filter and is checked on `seq`, the secondary is
filtered to the management stream and is checked on `xseq`. One receiver in
both roles could not tell a filter on the wrong sink from a correct one.

`config.sh` mints two authorities with `openssl`. The gateway is given the
first only. The decoy's certificate is from the second, and `config.sh`
refuses to continue if it verifies under the first.

## What drives it

The management stream alone. Each driven change is an audited change to
the audit policy (how many segments one prune pass may remove, flipped
between two values), which writes an intent and a result. The records the
filter has to keep from the secondary sink are the writer's own
`audit_system` records, and the row that says none arrived is paired with
one that says the unfiltered sink received them.

## Sink configuration is not kept across a restart

Every boot of the gateway configures its sinks again (`sinks_up`). A sink's
place in the trail and its export sequence are kept on disk under
`<audit dir>/sink/`, so a sink configured again under its name continues
both; that is what the restart arms measure.

## The crash arms need a fault-enabled image

T23 arm 5 ends the gateway at a named step of the cursor protocol, which
only a build carrying the `audit_faults` tag can do:

```
make HAVE_AUDIT_FAULTS=1
```

The points are `sink.cursor.before_write` and `sink.cursor.after_rename`,
selected with `LOXILB_AUDIT_FAULT`. An armed point ends the process with a
line on standard error naming it, and the arm counts that line before it
scores anything after the crash. `validation.sh` reads the tag off
`--version` and fails, rather than skips, on an image without it.

For the first point the secondary sink is removed and records are written
while it is gone, so the boot that carries the fault has records to send
the moment the sink is configured: the crash then falls after a submission
and before the cursor write, and the row beside it states that frames did
go out in that boot. Removing a sink keeps its state.

## Bounds the scenario states rather than hides

- After a kill the export sequence continues above the reserved block, so
  the numbers given up are at most 1024. The row asserts that bound, not a
  hole of zero.
- An epoch is taken from the clock in seconds. Arm 4 waits two seconds
  before it deletes the state, so that the new epoch is not asked for
  inside the second the old one was made in.
- A segment sealed before the quota was lowered keeps the terms it was
  written under, so T16 prunes only what was sealed after.
- Prune passes run with the writer's heartbeat, every 30 seconds; T16
  waits for one and captures the records as they appear, because under that
  quota the segment holding them is pruned a few passes later.

## Red twins

A test counts only once its red twin has been run: the named mutation that
makes the assertion fail for the right reason. Twins are code mutations
followed by a rebuild, which CI cannot do to itself, so they are run by
hand on the bed and recorded here; `gen-coverage-manifest.py` marks a
requirement *covered and tested* only when its `red_twin_run_id` names a
row of this table.

Each run: one mutation applied to a synced copy of the tree, the
fault-enabled binary rebuilt and laid over the image, the whole scenario
run against it, the file restored. The baseline on the same tree and bed
was green (146 assertions, 0 failed). The last three revert a defect this
scenario found.

| run id | mutation | assertions that went red, and nothing else |
|---|---|---|
| `llbigw-2-twin-2-sink-nopersist-r1` | a sink's saved state is never read back: `fileSinkStore` answers every read with "no such file" | every boot begins a new epoch at 1 and has no cursor to find damaged. `T23-2b`, `T23-2d`, `T23-2e`, `T23-2f` (the sequence does not continue), `T23-3b`–`T23-3f` and `T23-3h`–`T23-3j` (no `sys.sink.cursor_reset`, a new epoch instead), `T23-5w-f`, `T23-5w-h`, `T23-5r-f`, `T23-5r-h`. The rows that count a number arriving twice stay green: a new epoch reuses nothing |
| `llbigw-2-twin-2-sink-noreserve-r1` | numbers are handed out without a block being reserved first | after a kill the sequence resumes at the saved cursor and sends ten numbers a second time: `T23-2e`, `T23-2f`, `T23-2g`, and with them every later row that reads the receiver's running count of repeats (`T23-3g`, `T23-3k`, `T23-4d`, `T23-5w-i`, `T23-5r-i`, `T23-6`). `T23-5r-e`: with no reservation to write, the first state file renamed is the cursor behind twelve records already sent, so the crash no longer falls before the first submission |
| `llbigw-2-twin-2-sink-nolost-r1` | retention removes a segment a sink was not sent without recording it | `T16-2a`–`T16-2h`: no loss record, and the rows that follow from it |
| `llbigw-2-twin-2-sink-nowindow-r1` | a failed session saves the cursor where it stood, not at the start of the window it will send again | `T5-2d`: one record of the previous boot, written into the dead session, never arrives |
| `llbigw-2-twin-2-sink-noresendend-r1` | a resend does not ask whether the segment it is waiting to reach is still there | `T16-3a`, `T16-3b`: the sink that was behind never catches up and reports no removal |
| `llbigw-2-twin-2-sink-nosealed-r1` | a sink standing in a segment sealed during the prune pass is taken for one that lost its place | `T16-2j`: a loss recorded against the compliance sink, whose receiver holds the range |

## Layout

| file | what it does |
|---|---|
| `config.sh` | two authorities and three certificates, the topology, three receivers |
| `validation.sh` | the assertions; restarts the gateway and the receivers itself |
| `syslog_receiver.py` | the receiver |
| `rmconfig.sh` | teardown, including receivers a killed run left behind |

## Running

```
cd cicd/audit-sink
LOXILB_DOCKER_IMAGE=<image built with HAVE_AUDIT_FAULTS=1> ./config.sh && ./validation.sh; ./rmconfig.sh
```

Needs `jq`, `openssl` and `python3` on the host. About ten minutes: it
restarts the gateway a dozen times and waits on a prune pass.
