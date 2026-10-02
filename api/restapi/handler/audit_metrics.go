/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package handler

import (
	"time"

	"github.com/loxilb-io/loxilb/pkg/audit"
	"github.com/prometheus/client_golang/prometheus"
)

// The audit trail's own metrics. They are the independent witness to the
// writer's failure: when the writer cannot write, the record of that
// fact cannot be in the trail, so it is here and in the ordinary log. The
// families are read from the writer's counters at scrape time — nothing on
// the write path touches a metric — and every counter is emitted from
// start, at zero, so an absent series is never mistaken for a quiet one.
var (
	auditWriterUpDesc = prometheus.NewDesc(
		"loxilb_audit_writer_up",
		"1 while the audit writer goroutine is running; 0 while it restarts after a failure, and 0 when no writer was configured because the audit directory was unusable at start. Every audited management call is refused while this is 0.",
		nil, nil)
	auditRecordsWrittenDesc = prometheus.NewDesc(
		"loxilb_audit_records_written_total",
		"Audit records appended to the trail, by stream (mgmt, data, audit_system).",
		[]string{"stream"}, nil)
	auditRecordsDroppedDesc = prometheus.NewDesc(
		"loxilb_audit_records_dropped_total",
		"Audit records the writer could not accept, by stream and reason (queue_full, writer_down, invalid, disk_reserve). A management drop refused the call; a data or system drop is a record that does not exist.",
		[]string{"stream", "reason"}, nil)
	auditResultWriteFailuresDesc = prometheus.NewDesc(
		"loxilb_audit_result_write_failures_total",
		"Management result records lost after the change had been applied; the durable intent stays in the trail without its outcome.",
		nil, nil)
	auditWriteFailuresDesc = prometheus.NewDesc(
		"loxilb_audit_write_failures_total",
		"Appends to the active segment that failed. The writer records the failure interval in the trail once writing resumes; until then this counter and the log are the only evidence.",
		nil, nil)
	auditSyncFailuresDesc = prometheus.NewDesc(
		"loxilb_audit_sync_failures_total",
		"fsyncs of the active segment that failed; a durable management write that hit one was refused.",
		nil, nil)
	auditMgmtTimeoutsDesc = prometheus.NewDesc(
		"loxilb_audit_mgmt_timeouts_total",
		"Durable management writes that missed the request's deadline; each one refused a management call.",
		nil, nil)
	auditWriterPanicsDesc = prometheus.NewDesc(
		"loxilb_audit_writer_panics_total",
		"Writer goroutine panics caught by the supervisor.",
		nil, nil)
	auditWriterRestartsDesc = prometheus.NewDesc(
		"loxilb_audit_writer_restarts_total",
		"Writer goroutine restarts by the supervisor; each one is a gap during which audited management calls were refused.",
		nil, nil)
	auditLastWriteDesc = prometheus.NewDesc(
		"loxilb_audit_last_write_timestamp_seconds",
		"Unix time of the last durable audit write; 0 until the first.",
		nil, nil)
	auditLastHeartbeatDesc = prometheus.NewDesc(
		"loxilb_audit_last_heartbeat_timestamp_seconds",
		"Unix time of the writer's last liveness record; a value that stops advancing is a writer that is not running, whatever the counters say.",
		nil, nil)
	auditUnattributedDesc = prometheus.NewDesc(
		"loxilb_audit_records_unattributed_total",
		"Records that reached the writer without a producer identity; a producer-side loss of such a record cannot be reconciled.",
		nil, nil)
	auditOrphanedIntentsDesc = prometheus.NewDesc(
		"loxilb_audit_orphaned_intents_total",
		"Management intents of the previous boot found without a result at this writer's start: changes whose outcome is unknown, each reported in the trail as an orphaned intent.",
		nil, nil)
	auditSealFailuresDesc = prometheus.NewDesc(
		"loxilb_audit_segment_seal_failures_total",
		"Segment rotations that failed to seal the active segment; the writer keeps appending to it and retries at the next rotation.",
		nil, nil)
	auditSegmentsPrunedDesc = prometheus.NewDesc(
		"loxilb_audit_segments_pruned_total",
		"Sealed segments deleted by the retention policy, each announced in the trail before deletion.",
		nil, nil)
	auditReserveBreachedDesc = prometheus.NewDesc(
		"loxilb_audit_reserve_breached",
		"1 while the audit filesystem is below its configured free-space reserve; durable management writes are refused until space is recovered.",
		nil, nil)
	auditOriginatorDroppedDesc = prometheus.NewDesc(
		"loxilb_audit_originator_dropped_total",
		"X-Loxilb-Originator headers that did not parse and were dropped rather than recorded in part.",
		nil, nil)
	auditDelegationLookupsDesc = prometheus.NewDesc(
		"loxilb_audit_delegation_lookups_total",
		"Account lookups made to decide whether a named originator is trusted; a request without the header makes none.",
		nil, nil)
	auditLostToRetentionDesc = prometheus.NewDesc(
		"loxilb_audit_records_lost_to_retention_total",
		"Records in segments the retention policy deleted before every configured sink had been sent them; each such segment is named in the trail with its range before the deletion.",
		nil, nil)
)

// The per-sink families exist for a sink while it is configured. A sink
// configured again starts its counters again.
var (
	auditSinkLabels        = []string{"sink"}
	auditSinkConnectedDesc = prometheus.NewDesc(
		"loxilb_audit_sink_connected",
		"1 while the sink's receiver took the last record it was offered; 0 before the first record of a session, while the receiver is away and while the sink is stalled.",
		auditSinkLabels, nil)
	auditSinkExportedDesc = prometheus.NewDesc(
		"loxilb_audit_sink_records_exported_total",
		"Records the sink's receiver accepted, records sent again after a lost session included.",
		auditSinkLabels, nil)
	auditSinkExportFailuresDesc = prometheus.NewDesc(
		"loxilb_audit_sink_export_failures_total",
		"Submissions to the sink's receiver that failed; the record stays in hand and is sent again.",
		auditSinkLabels, nil)
	auditSinkPoisonDesc = prometheus.NewDesc(
		"loxilb_audit_sink_poison_total",
		"Records passed over because the sink cannot carry them; each is named in the trail.",
		auditSinkLabels, nil)
	auditSinkLagDropsDesc = prometheus.NewDesc(
		"loxilb_audit_sink_lag_drops_total",
		"Times the segment the sink stood in was deleted by retention before it had been read out.",
		auditSinkLabels, nil)
	auditSinkLagBytesDesc = prometheus.NewDesc(
		"loxilb_audit_sink_cursor_lag_bytes",
		"Bytes of the trail's files behind the sink: the rest of the segment it stands in and every later one. 0 once the sink has been through every record; an upper bound while its place inside a compressed segment, or before the first record of a run, is not known.",
		auditSinkLabels, nil)
	auditSinkLagSecondsDesc = prometheus.NewDesc(
		"loxilb_audit_sink_cursor_lag_seconds",
		"Age of the oldest record the sink has read and not been able to send; 0 when it holds none.",
		auditSinkLabels, nil)
)

// auditCollector emits the audit families from the writer's snapshot on
// every scrape. It is registered at package init, before any writer exists,
// so the up gauge is 0 and the gate's own counters are visible from the
// first scrape of a gateway whose audit directory was unusable.
type auditCollector struct{}

// Describe implements prometheus.Collector.
func (auditCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{
		auditWriterUpDesc, auditRecordsWrittenDesc, auditRecordsDroppedDesc,
		auditResultWriteFailuresDesc, auditWriteFailuresDesc, auditSyncFailuresDesc,
		auditMgmtTimeoutsDesc, auditWriterPanicsDesc, auditWriterRestartsDesc,
		auditLastWriteDesc, auditLastHeartbeatDesc, auditUnattributedDesc,
		auditOrphanedIntentsDesc, auditSealFailuresDesc, auditSegmentsPrunedDesc,
		auditReserveBreachedDesc, auditOriginatorDroppedDesc, auditDelegationLookupsDesc,
		auditLostToRetentionDesc,
		auditSinkConnectedDesc, auditSinkExportedDesc, auditSinkExportFailuresDesc,
		auditSinkPoisonDesc, auditSinkLagDropsDesc, auditSinkLagBytesDesc, auditSinkLagSecondsDesc,
	} {
		ch <- d
	}
}

// Collect implements prometheus.Collector. Each family is emitted at its
// own constructor call, so the runtime type is readable from the source.
func (auditCollector) Collect(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(auditResultWriteFailuresDesc, prometheus.CounterValue, float64(AuditResultDrops()))
	ch <- prometheus.MustNewConstMetric(auditOriginatorDroppedDesc, prometheus.CounterValue, float64(AuditOriginatorDropped()))
	ch <- prometheus.MustNewConstMetric(auditDelegationLookupsDesc, prometheus.CounterValue, float64(AuditDelegationLookups()))

	w := AuditWriter()
	if w == nil {
		ch <- prometheus.MustNewConstMetric(auditWriterUpDesc, prometheus.GaugeValue, 0)
		return
	}
	st := w.Stats()
	up := 0.0
	if st.Running {
		up = 1
	}
	ch <- prometheus.MustNewConstMetric(auditWriterUpDesc, prometheus.GaugeValue, up)
	dropped := map[audit.Stream]map[string]uint64{}
	for _, d := range st.Dropped {
		if dropped[d.Stream] == nil {
			dropped[d.Stream] = map[string]uint64{}
		}
		dropped[d.Stream][d.Reason] = d.Count
	}
	for _, stream := range audit.Streams() {
		ch <- prometheus.MustNewConstMetric(auditRecordsWrittenDesc, prometheus.CounterValue, float64(st.Accepted[stream]), string(stream))
		for _, reason := range audit.DropReasons() {
			ch <- prometheus.MustNewConstMetric(auditRecordsDroppedDesc, prometheus.CounterValue, float64(dropped[stream][reason]), string(stream), reason)
		}
	}
	ch <- prometheus.MustNewConstMetric(auditWriteFailuresDesc, prometheus.CounterValue, float64(st.WriteFailures))
	ch <- prometheus.MustNewConstMetric(auditSyncFailuresDesc, prometheus.CounterValue, float64(st.SyncFailures))
	ch <- prometheus.MustNewConstMetric(auditMgmtTimeoutsDesc, prometheus.CounterValue, float64(st.MgmtTimeouts))
	ch <- prometheus.MustNewConstMetric(auditWriterPanicsDesc, prometheus.CounterValue, float64(st.Panics))
	ch <- prometheus.MustNewConstMetric(auditWriterRestartsDesc, prometheus.CounterValue, float64(st.Restarts))
	ch <- prometheus.MustNewConstMetric(auditLastWriteDesc, prometheus.GaugeValue, float64(st.LastWriteUnix))
	ch <- prometheus.MustNewConstMetric(auditLastHeartbeatDesc, prometheus.GaugeValue, float64(st.LastHeartbeatUnix))
	ch <- prometheus.MustNewConstMetric(auditUnattributedDesc, prometheus.CounterValue, float64(st.Unattributed))
	ch <- prometheus.MustNewConstMetric(auditOrphanedIntentsDesc, prometheus.CounterValue, float64(st.OrphanedIntents))
	ch <- prometheus.MustNewConstMetric(auditSealFailuresDesc, prometheus.CounterValue, float64(st.RotationFailed))
	ch <- prometheus.MustNewConstMetric(auditSegmentsPrunedDesc, prometheus.CounterValue, float64(st.Pruned))
	breached := 0.0
	if st.ReserveBreached {
		breached = 1
	}
	ch <- prometheus.MustNewConstMetric(auditReserveBreachedDesc, prometheus.GaugeValue, breached)
	ch <- prometheus.MustNewConstMetric(auditLostToRetentionDesc, prometheus.CounterValue, float64(st.LostToRetention))

	// The tailers are read without the sink lock: a scrape must not wait
	// for a handler that is waiting for a tailer to stop.
	p := auditSinkTailers.Load()
	if p == nil {
		return
	}
	now := time.Now()
	for _, t := range *p {
		ts, place := t.Stats(), t.Place()
		connected := 0.0
		if ts.State == audit.SinkConnected {
			connected = 1
		}
		seconds := 0.0
		if !place.Idle && !place.Oldest.IsZero() {
			if d := now.Sub(place.Oldest).Seconds(); d > 0 {
				seconds = d
			}
		}
		ch <- prometheus.MustNewConstMetric(auditSinkConnectedDesc, prometheus.GaugeValue, connected, ts.Name)
		ch <- prometheus.MustNewConstMetric(auditSinkExportedDesc, prometheus.CounterValue, float64(ts.Submitted), ts.Name)
		ch <- prometheus.MustNewConstMetric(auditSinkExportFailuresDesc, prometheus.CounterValue, float64(ts.SubmitErrors), ts.Name)
		ch <- prometheus.MustNewConstMetric(auditSinkPoisonDesc, prometheus.CounterValue, float64(ts.Poison), ts.Name)
		ch <- prometheus.MustNewConstMetric(auditSinkLagDropsDesc, prometheus.CounterValue, float64(ts.LagDrops), ts.Name)
		ch <- prometheus.MustNewConstMetric(auditSinkLagBytesDesc, prometheus.GaugeValue, float64(w.TrailBytesBehind(place)), ts.Name)
		ch <- prometheus.MustNewConstMetric(auditSinkLagSecondsDesc, prometheus.GaugeValue, seconds, ts.Name)
	}
}

func init() {
	prometheus.MustRegister(auditCollector{})
}
