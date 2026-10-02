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
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/loxilb-io/loxilb/api/models"
	"github.com/loxilb-io/loxilb/pkg/audit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// Without a writer the collector still answers: the up gauge is 0 and the
// gate's own counters are present, so a gateway whose audit directory was
// unusable at start is visible as such on the first scrape.
func TestAuditMetricsWithoutWriter(t *testing.T) {
	SetAuditWriter(nil)
	want := fmt.Sprintf(`
# HELP loxilb_audit_writer_up 1 while the audit writer goroutine is running; 0 while it restarts after a failure, and 0 when no writer was configured because the audit directory was unusable at start. Every audited management call is refused while this is 0.
# TYPE loxilb_audit_writer_up gauge
loxilb_audit_writer_up 0
# HELP loxilb_audit_result_write_failures_total Management result records lost after the change had been applied; the durable intent stays in the trail without its outcome.
# TYPE loxilb_audit_result_write_failures_total counter
loxilb_audit_result_write_failures_total %d
`, AuditResultDrops())
	if err := testutil.CollectAndCompare(auditCollector{}, strings.NewReader(want),
		"loxilb_audit_writer_up", "loxilb_audit_result_write_failures_total"); err != nil {
		t.Fatal(err)
	}
	if n := testutil.CollectAndCount(auditCollector{}, "loxilb_audit_records_written_total"); n != 0 {
		t.Fatalf("%d written series without a writer", n)
	}
}

// With a writer every counter is present from zero, the per-stream and
// per-reason series exist whether or not anything was dropped, and a
// gated request moves the written counter by its two records.
func TestAuditMetricsFollowTheWriter(t *testing.T) {
	withAuthMode(t, true)
	f := newGateFixture(t)
	if rec := f.do(http.MethodPost, "/netlox/v1/config/loadbalancer", `{"x":1}`); rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
	for deadline := time.Now().Add(5 * time.Second); f.w.Stats().Accepted[audit.StreamMgmt] < 2; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the pair never landed")
		}
	}
	st := f.w.Stats()
	if st.Accepted[audit.StreamMgmt] != 2 {
		t.Fatalf("mgmt accepted %d, want 2", st.Accepted[audit.StreamMgmt])
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# HELP loxilb_audit_writer_up 1 while the audit writer goroutine is running; 0 while it restarts after a failure, and 0 when no writer was configured because the audit directory was unusable at start. Every audited management call is refused while this is 0.\n# TYPE loxilb_audit_writer_up gauge\nloxilb_audit_writer_up 1\n")
	fmt.Fprintf(&b, "# HELP loxilb_audit_records_written_total Audit records appended to the trail, by stream (mgmt, data, audit_system).\n# TYPE loxilb_audit_records_written_total counter\n")
	for _, s := range audit.Streams() {
		fmt.Fprintf(&b, "loxilb_audit_records_written_total{stream=%q} %d\n", s, st.Accepted[s])
	}
	fmt.Fprintf(&b, "# HELP loxilb_audit_records_dropped_total Audit records the writer could not accept, by stream and reason (queue_full, writer_down, invalid, disk_reserve). A management drop refused the call; a data or system drop is a record that does not exist.\n# TYPE loxilb_audit_records_dropped_total counter\n")
	for _, s := range audit.Streams() {
		for _, r := range audit.DropReasons() {
			fmt.Fprintf(&b, "loxilb_audit_records_dropped_total{reason=%q,stream=%q} 0\n", r, s)
		}
	}
	if err := testutil.CollectAndCompare(auditCollector{}, strings.NewReader(b.String()),
		"loxilb_audit_writer_up", "loxilb_audit_records_written_total", "loxilb_audit_records_dropped_total"); err != nil {
		t.Fatal(err)
	}
	// Every family the collector describes is emitted, so a consumer can
	// tell a zero from an absence.
	if n := testutil.CollectAndCount(auditCollector{}); n < 19 {
		t.Fatalf("%d series emitted, want every family present", n)
	}
	if v := gatheredGauge(t, "loxilb_audit_last_write_timestamp_seconds"); v == 0 {
		t.Fatal("last write timestamp is 0 after a durable write")
	}
	if v := gatheredGauge(t, "loxilb_audit_last_heartbeat_timestamp_seconds"); v == 0 {
		t.Fatal("heartbeat timestamp is 0 on a running writer")
	}
}

// A sink is on the scrape while it is configured, under its name: whether
// its receiver is there, what it was sent, and how far behind it is. With
// the receiver away the sink holds the oldest record it could not send, and
// the lag is counted from that record and from the place in the file.
func TestAuditMetricsFollowTheSinks(t *testing.T) {
	withAuthMode(t, true)
	f := newGateFixture(t)
	resetAuditSink(t)
	if n := testutil.CollectAndCount(auditCollector{}, "loxilb_audit_sink_connected"); n != 0 {
		t.Fatalf("%d sink series with no sink configured", n)
	}
	if v := sinkSeries(t, "loxilb_audit_records_lost_to_retention_total", ""); v != 0 {
		t.Fatalf("%v records lost to retention on a fresh trail", v)
	}
	pki := newSinkPKI(t)
	all, some := newSinkReceiver(t, pki), newSinkReceiver(t, pki)
	if code := postSink(f, models.AuditSink{Enabled: true, Address: all.addr, CaBundlePath: pki.caPath}); code != http.StatusNoContent {
		t.Fatalf("enabling the compliance sink answered %d", code)
	}
	if code := putNamedSink(f, "mgmt-only", mgmtOnly(some, pki)); code != http.StatusNoContent {
		t.Fatalf("configuring the secondary sink answered %d", code)
	}
	mutate(f, 3)
	some.waitCount(10)
	caughtUp := func(sink string) {
		t.Helper()
		for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
			if sinkSeries(t, "loxilb_audit_sink_connected", sink) == 1 && sinkSeries(t, "loxilb_audit_sink_cursor_lag_bytes", sink) == 0 {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("sink %s did not come to connected with nothing behind it", sink)
			}
		}
	}
	caughtUp(auditComplianceSink)
	caughtUp("mgmt-only")
	if n := testutil.CollectAndCount(auditCollector{}, "loxilb_audit_sink_connected"); n != 2 {
		t.Fatalf("%d connected series, want one for each of the two sinks", n)
	}
	if got, want := sinkSeries(t, "loxilb_audit_sink_records_exported_total", "mgmt-only"), float64(namedTailer("mgmt-only").Stats().Submitted); got != want || got < 10 {
		t.Errorf("exported %v for the secondary sink, want its %v submissions (at least 10)", got, want)
	}
	for _, name := range []string{"loxilb_audit_sink_cursor_lag_seconds", "loxilb_audit_sink_export_failures_total", "loxilb_audit_sink_poison_total", "loxilb_audit_sink_lag_drops_total"} {
		if v := sinkSeries(t, name, auditComplianceSink); v != 0 {
			t.Errorf("%s is %v for a sink that kept up", name, v)
		}
	}

	// The compliance receiver goes away; what is written now stays behind
	// that sink and not behind the other.
	all.stop()
	mutate(f, 3)
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if sinkSeries(t, "loxilb_audit_sink_connected", auditComplianceSink) == 0 &&
			sinkSeries(t, "loxilb_audit_sink_export_failures_total", auditComplianceSink) > 0 &&
			sinkSeries(t, "loxilb_audit_sink_cursor_lag_seconds", auditComplianceSink) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the lost receiver is not on the scrape: connected %v, failures %v, lag %v s",
				sinkSeries(t, "loxilb_audit_sink_connected", auditComplianceSink),
				sinkSeries(t, "loxilb_audit_sink_export_failures_total", auditComplianceSink),
				sinkSeries(t, "loxilb_audit_sink_cursor_lag_seconds", auditComplianceSink))
		}
	}
	if v := sinkSeries(t, "loxilb_audit_sink_cursor_lag_bytes", auditComplianceSink); v <= 0 {
		t.Errorf("%v bytes behind a sink whose receiver is away", v)
	}
	caughtUp("mgmt-only")
}

// sinkSeries scrapes the collector and returns the named family's value for
// one sink, or the unlabelled value when sink is empty.
func sinkSeries(t *testing.T, name, sink string) float64 {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	if err := reg.Register(auditCollector{}); err != nil {
		t.Fatal(err)
	}
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, fam := range families {
		if fam.GetName() != name {
			continue
		}
		for _, m := range fam.Metric {
			label := ""
			for _, l := range m.Label {
				if l.GetName() == "sink" {
					label = l.GetValue()
				}
			}
			if label == sink {
				if m.Gauge != nil {
					return m.GetGauge().GetValue()
				}
				return m.GetCounter().GetValue()
			}
		}
	}
	t.Fatalf("no series of %s for sink %q", name, sink)
	return 0
}

// gatheredGauge scrapes the collector through a registry of its own and
// returns the named unlabelled family's value.
func gatheredGauge(t *testing.T, name string) float64 {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	if err := reg.Register(auditCollector{}); err != nil {
		t.Fatal(err)
	}
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, fam := range families {
		if fam.GetName() == name && len(fam.Metric) == 1 {
			return fam.Metric[0].GetGauge().GetValue()
		}
	}
	t.Fatalf("family %s not gathered", name)
	return 0
}
