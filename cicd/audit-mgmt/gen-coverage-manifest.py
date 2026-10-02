#!/usr/bin/env python3
"""Generate and check audit-coverage-manifest.json, the release evidence for
the audit trail's event matrix.

One entry per canonical event type. Each entry lists the same-class rows of
the type as ``variants``, names the intent type when the entry is a
cross-class result (``result_of``), and carries stage-scoped
``requirements``: what the type must record at that stage, which scenario
assertions prove it, and the red-twin run that showed those assertions go
red under the fault they name. A stage's exit checks only the requirements
scoped to it.

Coverage states, computed here and never at runtime:

  covered and tested      assertions exist in a committed validation.sh AND
                          a red-twin run is recorded for them
  covered but untested    assertions (or a unit test) exist, no red-twin run
  uncovered               nothing proves the requirement yet
  intentionally excluded  a surface the release claim deliberately leaves out

The manifest's SHA-256 over its entries is the matrix digest a reviewer
compares against the build. ``--check`` regenerates the manifest and fails
on drift: a committed manifest that no longer matches this table, an event
type emitted by the Go tree that has no entry, a stage-claimed type with no
emitter, an assertion id that no validation.sh contains, a unit test that
no longer exists, or an uncovered requirement inside the claimed stage.

Usage:
  gen-coverage-manifest.py            write the manifest next to this script
  gen-coverage-manifest.py --check    verify the committed manifest and the tree
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
MANIFEST = os.path.join(HERE, "audit-coverage-manifest.json")

# More than one scenario feeds this matrix, so a requirement names the one
# that proves it rather than inheriting a single global. audit-mgmt covers the
# management plane; audit-data covers the inference path's own trail;
# audit-sink covers what leaves the gateway for a receiver.
SCENARIOS = {
    "audit-mgmt": os.path.join(REPO, "cicd", "audit-mgmt", "validation.sh"),
    "audit-data": os.path.join(REPO, "cicd", "audit-data", "validation.sh"),
    "audit-sink": os.path.join(REPO, "cicd", "audit-sink", "validation.sh"),
}
DEFAULT_SCENARIO = "audit-mgmt"
CLAIMED_STAGE = "1b"

# Directories whose Go files may emit records. Every string literal shaped
# like an event type found here must have an entry below.
# pkg/loxinet joined the list at stage 1b: the inference path's records are
# emitted from the datapath's cgo exports, not from the management plane.
EMITTER_DIRS = ["pkg/audit", "api/restapi/handler", "pkg/loxinet"]
EVENT_LITERAL = re.compile(r'"((?:mgmt|sec|read|data|sys)\.[a-z_]+(?:\.[a-z_]+)*)"')

# Red-twin runs are recorded by hand from a bed run: the mutation applied,
# the assertions that went red, the run's identifier. An id here must be
# described in README.md under "Red twins"; nothing else may set one.
RED_TWINS = {
    "T3": "llbigw-2-twin-T3-r1",
    "T15": "llbigw-2-twin-T15-r1",
    "T19": "llbigw-2-twin-T19-r1",
    "T20": "llbigw-2-twin-T20-r1",
    # Stage 1b, run against cicd/audit-data. Each reverts one defect the
    # scenario found, except the gap twin, whose row had no defect to revert.
    "1b-reqid": "llbigw-2-twin-1b-reqid-r1",
    "1b-complete": "llbigw-2-twin-1b-complete-r1",
    "1b-deny": "llbigw-2-twin-1b-deny-r1",
    "1b-gap": "llbigw-2-twin-1b-gap-r1",
    "2-exact": "llbigw-2-twin-2-exact-r1",
    # Stage 2, run against cicd/audit-mgmt. One mutation each, so a row claims
    # the twin that actually exercises its own assertions.
    # sinkrange: the sink accepts the two numeric knobs without checking their
    #   range, as it did before they were bounded.
    # polfields: a policy change no longer names the fields it changed.
    # rotate: sealing reports the active segment as both sealed and opened,
    #   making the seal a label rather than a boundary.
    "2-sinkrange": "llbigw-2-twin-2-sinkrange-r1",
    "2-polfields": "llbigw-2-twin-2-polfields-r1",
    "2-rotate": "llbigw-2-twin-2-rotate-r1",
    # Stage 2, run against cicd/audit-sink; described in that scenario's
    # README.
    # sink-nopersist: a sink's saved state is never read back at start.
    # sink-nolost: retention removes a segment a sink was not sent without
    #   recording the loss.
    # sink-nowindow: a failed session saves the cursor where it stood, not
    #   at the start of the window it will send again.
    # sink-nosealed: a sink standing in a segment sealed during the prune
    #   pass is taken for one that lost its place.
    "2-sink-nopersist": "llbigw-2-twin-2-sink-nopersist-r1",
    "2-sink-nolost": "llbigw-2-twin-2-sink-nolost-r1",
    "2-sink-nowindow": "llbigw-2-twin-2-sink-nowindow-r1",
    "2-sink-nosealed": "llbigw-2-twin-2-sink-nosealed-r1",
}


def req(stage, fields, behaviour, assertions=(), unit=(), twin=None, note=None,
        scenario=None):
    if assertions and scenario is None:
        scenario = DEFAULT_SCENARIO
    if assertions and scenario not in SCENARIOS:
        raise SystemExit(f"req(): unknown scenario {scenario!r}")
    r = {
        "stage": stage,
        "fields": list(fields),
        "behaviour": behaviour,
        "scenario": scenario if assertions else ("unit" if unit else None),
        "assertion_ids": list(assertions),
        "unit_tests": list(unit),
        "red_twin_run_id": RED_TWINS.get(twin) if twin else None,
    }
    if note:
        r["note"] = note
    return r


def entry(event_type, cls, requirements, variants=(), result_of=None, excluded=None):
    e = {"event_type": event_type, "class": cls, "variants": list(variants)}
    if result_of:
        e["result_of"] = result_of
    if excluded:
        e["excluded"] = excluded
    e["requirements"] = requirements
    return e


def later(stage, fields, behaviour):
    """A requirement of a stage this tree does not claim yet."""
    return req(stage, fields, behaviour)


MATRIX = [
    # ── class M: management ─────────────────────────────────────────────────
    entry("mgmt.config.mutate", "M", [
        req("1a", ["method", "path", "route_class", "raw", "changed_fields", "config_generation"],
            "two-phase: durable intent before the handler, result after; fail-closed with 503 audit_unavailable and the state unchanged",
            assertions=["T3-1a", "T3-1b", "T3-1c", "T3-1d", "T3-2a", "T3-2b", "T3-2c",
                        "T3-4a", "T3-4b", "T3-4c", "T3-4d", "T3-5a", "T3-5b", "T3-5c", "T3-5d",
                        "T25-1a", "T25-2a", "T25-4a", "TM-7"],
            unit=["TestAuditGateWritesIntentAndResultPair", "TestAuditGateRawRoutesAreMarkedRaw",
                  "TestAuditGatedPredicate"],
            twin="T3"),
    ], variants=["generated", "extras", "raw"]),
    entry("mgmt.snapshot.persist", "M", [
        req("1a", ["filename", "bytes", "checksum", "config_generation"],
            "pair; the result names the file written",
            assertions=["TM-1"]),
    ]),
    entry("mgmt.snapshot.restore", "M", [
        req("1a", ["restore_phase", "entries_applied", "entries_failed"],
            "intent carries begin; result names plan/commit/rollback/rollback_failed/rejected",
            unit=["TestAuditEmitRestorePhases"],
            note="a restore rolls the whole configuration back on failure and is not driven on the shared bed; the handler is exercised behind the real gate in the unit suite"),
    ]),
    entry("mgmt.cert.reload", "M", [later("2", ["cert_id", "subject", "not_after", "fingerprint_sha256"], "pin in stage 2")]),
    entry("mgmt.auth.login", "M", [
        req("1a", ["username_claimed", "username"],
            "intent carries the claimed name and never the password; result carries the authenticated user; a refusal is re-typed sec.mgmt.authn_failed",
            assertions=["T15-s1", "T15-s1e", "T11-1a", "T11-1b", "T11-1d"],
            unit=["TestAuditGateLoginCarriesClaimedNameNeverPassword", "TestAuditGateLoginSuccessCarriesTheActorTheHandlerSet",
                  "TestAuditGateWithRealLoginHandler"],
            twin="T15"),
    ]),
    entry("mgmt.auth.logout", "M", [
        req("1a", [], "pair; the session owner is the actor; the token no longer authenticates afterwards",
            assertions=["TM-5", "TM-5b"], unit=["TestAuditGateNamedRoutes"]),
    ]),
    entry("mgmt.auth.token_upgrade", "M", [
        req("1a", ["token_fingerprint_sha256"], "pair; the new token is fingerprinted, never carried",
            assertions=["TM-4"], unit=["TestAuditEmitManualTokenFingerprint"]),
    ]),
    entry("mgmt.user.create", "M", [
        req("1a", ["username", "role", "bootstrap"],
            "pair; the account is the subject and the password never leaves the request; the loopback bootstrap is marked on actor and detail; fail-closed",
            assertions=["TM-10", "T3-3a", "T3-3b", "T11-1c", "T20-0a", "T20-1a", "T20-1b"],
            unit=["TestAuditEmitUserCreateBootstrap", "TestAuditEmitUserCreateWithCredential"], twin="T3"),
    ]),
    entry("mgmt.user.update", "M", [
        req("1a", ["username", "changed_fields", "role_from", "role_to"],
            "pair; changed field names only; delegation_allowed is a changed field",
            assertions=["T25-0d", "T25-0e", "T25-0f"],
            unit=["TestAuditEmitUserUpdateNamesTheAccount", "TestAuditEmitUserUpdateDelegationFlag"]),
    ]),
    entry("mgmt.user.delete", "M", [
        req("1a", [], "pair", assertions=["TM-9"], unit=["TestAuditGateNamedRoutes"]),
    ]),
    entry("mgmt.auth.oauth_start", "M", [
        req("1a", ["provider", "action", "state_token_fingerprint"],
            "side-effecting GET is gated: pair with a provisional actor, the state token fingerprinted; 503 while wedged",
            assertions=["T22-1a", "T22-1c", "T22-1d", "T22-1e", "T22-1f", "T22-1g", "T22-4a", "T22-4b"],
            unit=["TestAuditGateSideEffectingGETsAreGated", "TestAuditEmitOAuthStartFingerprint"]),
    ]),
    entry("mgmt.auth.oauth_callback", "M", [
        req("1a", ["provider", "action", "state_token_fingerprint"],
            "gated GET; the subject is known only once a token was issued; 503 while wedged before any exchange",
            assertions=["T22-2a", "T22-2b", "T22-2c", "T22-5"],
            unit=["TestAuditEmitOAuthActionsNameTheStep"],
            note="the completing callback needs a real identity provider; only the unknown-state refusal runs on this bed"),
    ]),
    entry("mgmt.auth.oauth_token_refresh", "M", [
        req("1a", ["provider", "action", "username"],
            "gated GET; the query string (both tokens) is never recorded; 503 while wedged before any exchange",
            assertions=["T22-3a", "T22-3b", "T22-6", "T15-6"],
            unit=["TestAuditEmitOAuthActionsNameTheStep", "TestPathIsSanitized"]),
    ]),
    entry("mgmt.maintenance", "M", [
        req("1a", ["active_from", "active_to"], "pair carrying both values",
            assertions=["TM-3"], unit=["TestAuditEmitMaintenanceTransition"]),
    ]),
    entry("mgmt.audit.policy", "M", [
        req("2", ["changed_fields", "floor_rejected"],
            "the runtime-changeable policy is replaced through the gate like any other mutation: the "
            "result names the fields that changed and states whether the deployment profile's floor "
            "refused them, and a refused change leaves the policy untouched",
            assertions=["T-GW-2-1a", "T-GW-2-1b", "T-GW-2-2a", "T-GW-2-2b", "T-GW-2-2c",
                        "T-GW-2-3a", "T-GW-2-3b"],
            unit=["TestAuditPolicyChangeIsAuditedWithWhatChanged",
                  "TestAuditPolicyBelowTheFloorIsRefusedAndRecorded",
                  "TestSetPolicyRefusesBelowTheFloorForEveryCaller",
                  "TestLoweringRetentionDoesNotDeleteWhatIsAlreadySealed"],
            twin="2-polfields",
            note="a floor refusal answers 400 rather than 403 on purpose: the gate re-types every 403 "
                 "into sec.mgmt.authz_denied, which would file a refused policy change as an "
                 "authorization failure and lose the record that names the refused field. The bed "
                 "drives an accepted change and an unsatisfiable one; the FLOOR refusal itself stays "
                 "unit-owned, because the floor comes from a deployment profile and this bed runs "
                 "with the zero floor, which refuses nothing. The endpoint REPLACES the policy rather "
                 "than patching it, so the scenario reads it and writes the whole thing back"),
    ]),
    entry("mgmt.audit.sink", "M", [
        req("2", ["changed_fields", "endpoint", "tls_ca_id"],
            "a sink change is recorded with where the trail is being sent and what vouches for the "
            "receiver, both named and never their contents; a configuration whose receiver could not "
            "be verified is refused when it is configured, not when it first connects",
            assertions=["T-GW-2-4a", "T-GW-2-4b", "T-GW-2-5a", "T-GW-2-5b", "T-GW-2-6a",
                        "T-GW-2-6b", "T-GW-2-6c", "T-GW-2-7a", "T-GW-2-7b", "T-GW-2-7c",
                        "T-GW-2-7d", "T-GW-2-7e", "T-GW-2-7f"],
            unit=["TestAuditSinkChangeRecordsTheEndpointAndItsTrustAnchor",
                  "TestAuditSinkWithoutATrustAnchorIsRefused",
                  "TestAuditSinkNumbersOutsideTheirRangeAreRefused"],
            twin="2-sinkrange",
            note="the transport itself is covered in pkg/audit/syslog, including a receiver signed by "
                 "an untrusted authority being refused. On the bed the anchor is generated per run "
                 "inside the container, and both the record and the read-back are checked for "
                 "certificate material: the anchor is named, never served"),
    ]),
    entry("mgmt.audit.rotate_now", "M", [
        req("2", ["sealed_segment_uuid", "new_segment_uuid"],
            "the operator seals the active segment and the record names both the segment sealed and "
            "the one now active",
            assertions=["T-GW-2-8a", "T-GW-2-8b", "T-GW-2-8c", "T-GW-2-8d", "T-GW-2-8e",
                        "T-GW-2-8f", "T-GW-2-8g"],
            unit=["TestRotateNowSealsAndOpens"],
            twin="2-rotate",
            note="the bed checks the seal is a boundary and not a label: the sealed uuid is the one "
                 "the status named, the new one differs, the status moves to it, and the next record "
                 "written lands in the new segment"),
    ]),
    entry("mgmt.opa.policy", "M", [later("2", ["policy_version", "digest"], "pin in stage 2")]),
    entry("mgmt.audit.replay", "M", [later("2", ["sink", "seq_from", "seq_to"], "re-submission of a range to a sink")]),
    entry("mgmt.audit.hold", "M", [later("3", ["hold_id", "segments", "reason_code"], "legal hold applied")]),
    entry("mgmt.audit.hold_release", "M", [later("3", ["hold_id", "segments"], "legal hold released")]),
    entry("mcp.tool_call", "M-legacy", [], excluded="the bridge-local tool_call trail; every mutation it performs reaches the gateway REST API where the class-M gate records it with the originator"),

    # ── class S: security decisions ─────────────────────────────────────────
    entry("sec.mgmt.authn_failed", "S", [
        req("1a", ["mechanism", "username_claimed", "delegated"],
            "a 401 result is re-typed with result_of naming the intent's type; reason auth for a token, login_failed for a password",
            assertions=["T15-s1b", "T15-s1c", "T15-s1d", "T15-s2", "T15-s2b", "T15-s2c"],
            unit=["TestAuditGateLoginCarriesClaimedNameNeverPassword", "TestAuditOriginatorOnAnUnauthenticatedRefusal"]),
    ], variants=["token", "login"], result_of="mgmt.auth.login"),
    entry("sec.mgmt.authz_denied", "S", [
        req("1a", ["role", "delegated"],
            "a 403 result is re-typed; the principal and its role are named; the originator claim rides along untrusted",
            assertions=["T25-3a", "T25-3b", "T25-3c", "T25-3d", "T25-3e", "T25-3f", "T25-3g"],
            unit=["TestAuditGateAuthzDenialIsASecurityRecord", "TestAuditOriginatorOnARefusal"]),
    ]),
    entry("sec.ai.deny", "S", [
        req("1b", ["request_id", "service", "model", "stage", "decision", "reason", "outcome.status"],
            "one record per refusal, from the gate's single verdict frame: class security on the data "
            "stream, the correlation key the gate decided on, the stage and error code that refused it, "
            "and the identity that arm resolved — empty only when it refused before resolving one",
            assertions=["T14-2b", "T14-2c", "T14-2d", "T14-2e", "T14-2f", "T14-2g", "T14-2h", "T14-2i",
                        "T4-3c", "T4-3f", "T4-3g", "T4-3h"],
            scenario="audit-data",
            twin="1b-deny",
            unit=["TestEmitAIDenyIsASecurityRecord", "TestEmitAIDenyCarriesNoCredential",
                  "TestAIDenyReasonPerStage"],
            note="a spent token budget arrives at the rate-limit stage and reads as quota, not "
                 "ratelimit: a budget that ran out is a different resource from a client that is "
                 "too fast, and a different remedy"),
    ]),
    entry("sec.mtls.client_verify_failed", "S", [later("2", ["subject", "x509_error"], "frontend client certificate rejected")]),
    entry("sec.backend_tls_verify_failed", "S", [later("2", ["endpoint", "x509_error"], "backend certificate rejected")]),
    entry("sec.llamafw.block", "S", [later("2", ["request_id", "scanner", "decision"], "scanner block")]),
    entry("sec.pii.detected", "S", [later("3", ["request_id", "entity_types", "count", "action"], "PII found")]),
    entry("sec.opa.l4_deny", "S", [later("2", ["policy_version"], "pin in stage 2")]),

    # ── class R: sensitive reads ────────────────────────────────────────────
    entry("read.config.export", "R", [
        req("1a", ["format", "bytes", "checksum", "secrets_included", "content_disposition"],
            "R-export: two-phase like a mutation; reports what was served, never the content",
            assertions=["TM-2"], unit=["TestAuditGateExportReadsAreTwoPhase", "TestAuditEmitExportDetail"]),
    ]),
    entry("read.credential.list", "R", [
        req("1a", ["resource", "count", "tenant"],
            "R-list: served whatever the writer's state, one result-only record after the handler",
            assertions=["TM-6", "TM-8", "T3-3c"],
            unit=["TestAuditEmitListReadIsResultOnly", "TestAuditEmitListReadServedWithoutWriter"]),
    ], variants=["user", "apikey"]),
    entry("read.log_archive.download", "R", [
        req("1a", ["filename", "bytes"],
            "R-export; an audit-named file is refused by the log-archive API",
            assertions=["T-GW-3-1", "T-GW-3-2"],
            unit=["TestLogArchivesNeverServeAuditFiles", "TestAuditEmitArchiveDownloadBytes"]),
    ]),
    entry("read.audit.status", "R", [later("2", [], "not audited by decision: polled by monitoring")]),
    entry("read.audit.policy", "R", [later("2", [], "not audited by decision")]),
    entry("read.audit.segment_metadata", "R", [later("2", ["count"], "R-list")]),
    entry("read.audit.content", "R", [], excluded="impossible by design over the management API; the readers are the SIEM and the on-host verifier"),

    # ── class D: data path ──────────────────────────────────────────────────
    entry("data.ai.complete", "D", [
        req("1b", ["request_id", "service", "model", "tokens_in", "tokens_out", "latency_ms", "stream",
                   "outcome.status"],
            "one record per admitted request, carrying the correlation key the gate decided on so it "
            "joins its settle and any refusal, and written once the tokens are known rather than when "
            "the response headers land — a body split across segments would otherwise report nothing "
            "spent beside a settle charging the real amount",
            assertions=["T14-3a", "T14-3b", "T14-3d", "T14-4a", "T14-4b", "T14-4c", "T14-4d", "T14-4e",
                        "T14-5b", "T14-5e", "T14-5h", "T4-1d", "T4-1e"],
            scenario="audit-data",
            twin="1b-complete",
            unit=["TestEmitAICompleteRecordsTheRequest", "TestEmitAICompleteCarriesNoBody",
                  "TestEmitAICompleteReasonFollowsTheDatapath"]),
    ]),
    entry("data.ai.settle", "D", [
        req("1b", ["request_id", "service", "model", "tokens_in", "tokens_out", "reserved", "res_epoch"],
            "the tokens recorded are the tokens charged, joined to the completion by the request id; "
            "emitted even for a pure release, and reading quota rather than ok when the budget was spent",
            assertions=["T14-3e", "T14-3g", "T4-1b", "T4-1c", "T4-1f", "T4-2b", "T4-2c", "T4-2d", "T4-2e"],
            scenario="audit-data",
            twin="1b-reqid",
            unit=["TestEmitAISettleRecordsTheCharge", "TestEmitAISettleRecordsAPureRelease",
                  "TestEmitAISettleOverQuotaSaysSo"]),
    ]),

    # ── class A: the audit system ───────────────────────────────────────────
    entry("sys.writer.start", "A", [
        req("1a", ["boot_id"], "first record of every boot",
            assertions=["T-GW-1-8"], unit=["TestWriteDurableRoundTrip"]),
    ]),
    entry("sys.writer.restart", "A", [
        req("1a", ["last_seq_before", "restart_count"], "supervised restart after a panic; mutating calls got 503 for the gap",
            unit=["TestSupervisorRestartsAfterPanic"],
            note="needs the audit_faults build tag; the CI image is built without it, so the panic arm runs in the unit suite (every build, internal hook) and on the bed"),
    ]),
    entry("sys.writer.panic", "A", [
        req("1a", ["panic_msg", "last_seq_before"], "the panic counter moves even if the record cannot be written",
            unit=["TestSupervisorRestartsAfterPanic"]),
    ]),
    entry("sys.writer.write_failed", "A", [
        req("1a", ["errno_class", "first_ts", "last_ts", "count"],
            "written retroactively once writing resumes; the metric and the operational log carry the failure meanwhile",
            assertions=["T19-1a", "T19-1b", "T19-2", "T19-3a", "T19-3b", "T19-3c", "T19-4a", "T19-4b", "T19-4c", "T19-4d", "T19-4e", "T19-5", "T19-6"],
            unit=["TestWriteFailureIsRecordedRetroactively"], twin="T19"),
    ]),
    entry("sys.disk.reserve_breached", "A", [
        req("1a", ["free_bytes", "reserved_bytes"], "crossing the reserve produces one record and durable writes are refused",
            unit=["TestRetentionPrunesOneAnnouncedSegmentPerPass"],
            note="the shipped configuration sets no reserve; the crossing is driven in the unit suite"),
    ]),
    entry("sys.heartbeat", "A", [
        req("1a", ["seq_high", "accepted", "dropped_by_reason", "queue_depth", "queue_hwm", "write_failures_total"],
            "fixed-interval liveness record with counters since boot",
            assertions=["T11-2e", "T11-2f", "T19-3b"], unit=["TestHeartbeatWhenIdle"]),
    ]),
    entry("sys.producer.gap", "A", [
        req("1b", ["producer_id", "stream", "pseq_from", "pseq_to", "reason", "exact"],
            "what a saturated writer lost, named per producer: every gap names its producer and stream "
            "and states whether its range is exact, no range runs backwards, and a range too large for "
            "the drop ring is conservative rather than a guess",
            assertions=["T18-1a", "T18-1b", "T18-1c", "T18-1d", "T18-1e", "T18-1f",
                        "T18-2a", "T18-2b", "T18-2c", "T18-3a", "T21-1a", "T21-1b"],
            scenario="audit-data",
            twin="1b-gap",
            unit=["TestProducerDropAccounting"],
            note="this row is the per-producer claim: that a gap names whose records were lost, on "
                 "which stream, over which range. Whether the range is honest about being exact is a "
                 "separate claim and is scoped to the row below"),
        req("2", ["ring_overflows", "dropped_total"],
            "the exactness claim is falsifiable: a gap may call its range exact only when the "
            "producer's drop ring discarded nothing since that producer's previous gap, and the "
            "ranges plus the entries the ring admits it discarded reconcile to the producer's own "
            "counted total",
            assertions=["T18-1e", "T18-1g", "T18-2b", "T18-2e"],
            scenario="audit-data",
            twin="2-exact",
            unit=["TestProducerDropAccounting", "TestProducerGapRingOverflow"],
            note="before these two fields the trail carried nothing a reader could hold the claim "
                 "against: exact was checked only against a width the emitter derived from the range "
                 "it was asserting, so a gap that always claimed exactness went undetected. Both "
                 "inexact branch is asserted on the bed, where a producer refused at all has been "
                 "refused far more often than its ring can name; the exact branch is opportunistic "
                 "there and varies run to run, so it is driven in the unit suite instead"),
    ]),
    entry("sys.intent.orphaned", "A", [
        req("1a", ["intent_event_id", "config_generation_at_boot"],
            "boot-time scan of the previous boot: one record per intent without a result, nothing synthesised",
            assertions=["T20-1a", "T20-1b", "T20-2a", "T20-2b", "T20-2c", "T20-3"],
            unit=["TestOrphanedIntentIsReportedAtNextStart", "TestOrphanScanIgnoresOwnBootAndEmptyDir"], twin="T20"),
    ]),
    entry("sys.segment.open", "A", [
        req("1a", ["prev_segment_uuid", "first_seq"], "new segment started",
            unit=["TestRotationFramesAndPermissions"]),
    ]),
    entry("sys.segment.seal", "A", [
        req("1a", ["record_count", "last_seq"], "close footer, unkeyed", unit=["TestRotationFramesAndPermissions"]),
        later("3", ["key_id", "seal"], "HMAC footer"),
    ]),
    entry("sys.segment.recovered", "A", [
        req("1a", ["records_recovered", "truncated_tail_bytes"], "unclosed segment of the previous boot closed at start",
            assertions=["T20-4"], unit=["TestRecoveryOfUnsealedSegment"]),
        later("3", [], "seal on recovery"),
    ]),
    entry("sys.segment.rotation_failed", "A", [
        req("1a", ["errno_class"], "writing continues on the old handle", unit=["TestRotationFramesAndPermissions"],
            note="fault point; unit suite arms it through the internal hook"),
    ]),
    entry("sys.segment.compress_failed", "A", [
        req("1a", ["errno_class"], "the plain segment is kept", unit=["TestRotationFramesAndPermissions"],
            note="fault point; unit suite arms it through the internal hook"),
    ]),
    entry("sys.segment.seal_failed", "A", [later("3", ["key_id", "errno_class"], "HMAC footer could not be written")]),
    entry("sys.segment.prune", "A", [
        req("1a", ["age_days", "bytes", "hold"], "announced durably before the delete", unit=["TestRetentionPrunesOneAnnouncedSegmentPerPass"]),
        req("2", ["exported_to"],
            "retention is not held back by a sink: the segment is removed whether or not every sink "
            "was sent it, and the record names the sinks that were",
            assertions=["T16-2e", "T16-2f", "T16-2g", "T16-2i"],
            scenario="audit-sink",
            unit=["TestPruneOfAnExportedSegmentLosesNothing", "TestPruneWithoutSinksSaysNothingAboutSinks"]),
    ]),
    entry("sys.segment.lost_to_retention", "A", [
        req("2", ["seq_from", "seq_to", "sinks_pending"],
            "written durably before the prune of a segment some sink was not sent: the range a "
            "receiver will find missing and the sinks it is missing from",
            assertions=["T16-2a", "T16-2b", "T16-2c", "T16-2d", "T16-2f", "T16-2h"],
            scenario="audit-sink",
            twin="2-sink-nolost",
            unit=["TestPruneRecordsWhatASinkWasNeverSent", "TestPruneWaitsForTheRangeOfASegmentItDidNotSeal",
                  "TestPruneDoesNotReadASegmentNoSinkIsBehind"]),
        req("2", ["sinks_pending"],
            "a sink that was sent the segment is not named: the pass's own records can seal the "
            "active segment under it, and a sink standing in a segment sealed since the pass listed "
            "the directory is ahead, not lost",
            assertions=["T16-2j"],
            scenario="audit-sink",
            twin="2-sink-nosealed",
            unit=["TestPruneDoesNotCallASinkBehindForASegmentSealedDuringThePass"]),
    ]),
    entry("sys.hold.applied", "A", [later("3", ["hold_id"], "legal hold")]),
    entry("sys.hold.released", "A", [later("3", ["hold_id"], "legal hold")]),
    entry("sys.sink.connect", "A", [
        req("2", ["peer_subject", "cert_not_after", "cursor"],
            "one record per session, naming the certificate the receiver presented; a receiver "
            "whose certificate does not verify never gets a session",
            assertions=["TR-5a", "TR-5b", "TR-5c", "TR-6c", "TR-6d", "T5-1g"],
            scenario="audit-sink",
            unit=["TestSinkTailerComplianceSinkReceivesEveryRecordUnchanged",
                  "TestSinkTailerOutageIsACursorThatDoesNotMove"]),
    ]),
    entry("sys.sink.disconnect", "A", [
        req("2", ["reason", "cursor", "reconnect_window_records"],
            "one record per lost session, with how far back the sink will send again; the records "
            "written during the outage all arrive after it",
            assertions=["TR-6g", "T5-1a", "T5-1b", "T5-1c", "T5-1e", "T5-1f", "T5-1g"],
            scenario="audit-sink",
            unit=["TestSinkTailerOutageIsACursorThatDoesNotMove",
                  "TestSinkTailerFailedWriteBurnsItsNumberAndResendsTheWindow"]),
        req("2", ["cursor"],
            "the window outlives the process: a gateway restarted during the outage still sends "
            "the previous boot's records the dead session swallowed",
            assertions=["T5-2c", "T5-2d"],
            scenario="audit-sink",
            twin="2-sink-nowindow",
            unit=["TestSinkTailerWindowSurvivesARestartDuringTheOutage"]),
    ]),
    entry("sys.sink.poison", "A", [
        req("2", ["poison_seq", "reason"],
            "a record the receiver rejects is skipped and named; a sink record is never the "
            "subject of one",
            unit=["TestSinkTailerPoisonRecordIsSkippedAndNamed",
                  "TestSinkTailerRejectingEverythingDoesNotFeedOnItself"],
            note="no bed row: the scenario's receiver accepts every well-formed frame"),
    ]),
    entry("sys.sink.cursor_reset", "A", [
        req("2", ["old_cursor", "new_cursor", "method"],
            "a cursor that cannot be read is rebuilt from the reservation, in the same epoch and "
            "above every number already sent, and the record is durable before the sink acts on it",
            assertions=["T23-3b", "T23-3c", "T23-3d", "T23-3e", "T23-3f", "T23-3h", "T23-3i", "T23-3j"],
            scenario="audit-sink",
            twin="2-sink-nopersist",
            unit=["TestSinkTailerReportsACursorResetBeforeActingOnIt"]),
    ]),
    entry("sys.sink.cursor_recovery_failed", "A", [
        req("2", ["errno_class", "cursor"],
            "a segment that is listed and cannot be read out stalls the sink at its place: one "
            "record per stall, nothing behind the segment is sent until it is gone",
            unit=["TestSinkTailerReportsASegmentItCannotRead"],
            note="no bed row"),
    ]),
    entry("sys.replay.completed", "A", [later("2", ["replay_event_id", "sink", "seq_from", "seq_to"], "replay finished")]),
    entry("sys.key.rotated", "A", [later("3", ["old_key_id", "new_key_id"], "signing key rotated")]),
    entry("sys.ha.role_change", "A", [later("2", ["instance_id", "role_from", "role_to"], "HA transition")]),
]


def state_of(r):
    if r["assertion_ids"] and r["red_twin_run_id"]:
        return "covered and tested"
    if r["assertion_ids"] or r["unit_tests"]:
        return "covered but untested"
    return "uncovered"


def build():
    entries = []
    for e in MATRIX:
        e = json.loads(json.dumps(e))  # deep copy
        if e.get("excluded"):
            e["state"] = "intentionally excluded"
        else:
            for r in e["requirements"]:
                r["state"] = state_of(r)
            claimed = [r for r in e["requirements"] if r["stage"] == CLAIMED_STAGE]
            if claimed:
                e["state"] = "covered and tested" if all(r["state"] == "covered and tested" for r in claimed) else \
                    ("uncovered" if any(r["state"] == "uncovered" for r in claimed) else "covered but untested")
            else:
                e["state"] = "uncovered"
        entries.append(e)
    entries.sort(key=lambda e: e["event_type"])
    canonical = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
    digest = hashlib.sha256(canonical).hexdigest()
    summary = {}
    for e in entries:
        for r in e.get("requirements", []):
            key = r["stage"]
            summary.setdefault(key, {})
            summary[key][r["state"]] = summary[key].get(r["state"], 0) + 1
    return {
        "schema": 1,
        "generated_by": "cicd/audit-mgmt/gen-coverage-manifest.py",
        "stage_claimed": CLAIMED_STAGE,
        "event_types": len(entries),
        "matrix_digest": digest,
        "requirements_by_stage": summary,
        "entries": entries,
    }


def emitted_literals():
    found = set()
    for d in EMITTER_DIRS:
        for root, _, files in os.walk(os.path.join(REPO, d)):
            for f in files:
                if not f.endswith(".go") or f.endswith("_test.go"):
                    continue
                with open(os.path.join(root, f), encoding="utf-8", errors="replace") as fh:
                    found.update(EVENT_LITERAL.findall(fh.read()))
    return found


def unit_test_exists(name):
    try:
        out = subprocess.run(["grep", "-rl", "--include=*_test.go", f"func {name}(", REPO],
                             capture_output=True, text=True, check=False)
        return out.returncode == 0 and out.stdout.strip() != ""
    except OSError:
        return False


def check(manifest):
    errors = []
    if os.path.exists(MANIFEST):
        with open(MANIFEST, encoding="utf-8") as fh:
            committed = json.load(fh)
        if committed != manifest:
            errors.append("audit-coverage-manifest.json is out of date; regenerate it with this script")
    else:
        errors.append("audit-coverage-manifest.json is missing")

    types = {e["event_type"] for e in manifest["entries"]}
    literals = emitted_literals()
    for lit in sorted(literals - types):
        errors.append(f"the Go tree emits {lit!r} but the matrix has no entry for it")
    for e in manifest["entries"]:
        if e.get("excluded"):
            continue
        if any(r["stage"] == CLAIMED_STAGE for r in e["requirements"]) and e["event_type"] not in literals:
            errors.append(f"{e['event_type']} is claimed at stage {CLAIMED_STAGE} but nothing in the Go tree emits it")

    validations = {}
    for name, path in SCENARIOS.items():
        try:
            with open(path, encoding="utf-8") as fh:
                validations[name] = fh.read()
        except OSError as exc:
            errors.append(f"scenario {name}: {exc}")
            validations[name] = ""
    seen_units = {}
    for e in manifest["entries"]:
        for r in e.get("requirements", []):
            body = validations.get(r["scenario"], "")
            for a in r["assertion_ids"]:
                if not re.search(r"\b" + re.escape(a) + r"\b", body):
                    errors.append(f"{e['event_type']}: assertion {a} is not in "
                                  f"{r['scenario']}/validation.sh")
            for u in r["unit_tests"]:
                if u not in seen_units:
                    seen_units[u] = unit_test_exists(u)
                if not seen_units[u]:
                    errors.append(f"{e['event_type']}: unit test {u} does not exist")
            if r["red_twin_run_id"] and not r["assertion_ids"]:
                errors.append(f"{e['event_type']}: a red-twin run without scenario assertions")
            if r["stage"] == CLAIMED_STAGE and r["state"] == "uncovered":
                errors.append(f"{e['event_type']}: uncovered at the claimed stage {CLAIMED_STAGE}")
    return errors


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="verify the committed manifest against this table and the tree")
    args = ap.parse_args()
    manifest = build()
    if args.check:
        errors = check(manifest)
        for err in errors:
            print(f"FAIL: {err}")
        print(f"{'FAIL' if errors else 'ok'}: {manifest['event_types']} event types, digest {manifest['matrix_digest'][:16]}..., "
              f"stage {CLAIMED_STAGE}: {manifest['requirements_by_stage'].get(CLAIMED_STAGE, {})}")
        sys.exit(1 if errors else 0)
    with open(MANIFEST, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=False)
        fh.write("\n")
    print(f"wrote {os.path.relpath(MANIFEST, REPO)}: {manifest['event_types']} event types, digest {manifest['matrix_digest']}")
    print(f"stage {CLAIMED_STAGE}: {manifest['requirements_by_stage'].get(CLAIMED_STAGE, {})}")


if __name__ == "__main__":
    main()
