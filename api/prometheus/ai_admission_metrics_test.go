/*
 * Copyright (c) 2026 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 */

package prometheus

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestAdmissionServiceLabel(t *testing.T) {
	if got := admissionServiceLabel(0x0a01a8c0, 8080); got != "192.168.1.10:8080" {
		t.Errorf("admissionServiceLabel = %q, want 192.168.1.10:8080", got)
	}
}

func TestAdmissionPoolLabel(t *testing.T) {
	cases := map[string]string{
		"":                      "-",
		"llm.example|/v1":       "llm.example__v1",
		"model-a":               "model-a",
		strings.Repeat("p", 80): strings.Repeat("p", 64),
	}
	for key, want := range cases {
		if got := admissionPoolLabel(key); got != want {
			t.Errorf("admissionPoolLabel(%q) = %q, want %q", key, got, want)
		}
	}
}

func TestSortAndDedupeAdmissionSamples(t *testing.T) {
	samples := []admissionSample{
		{service: "10.0.0.2:80", pool: "a", inflight: 1},
		{service: "10.0.0.1:80", pool: "b", inflight: 2},
		{service: "10.0.0.1:80", pool: "a", inflight: 3},
		{service: "10.0.0.1:80", pool: "a", inflight: 4},
	}
	sortAdmissionSamples(samples)
	samples = dedupeAdmissionSamples(samples)

	want := []string{"10.0.0.1:80/a", "10.0.0.1:80/b", "10.0.0.2:80/a"}
	if len(samples) != len(want) {
		t.Fatalf("got %d samples, want %d", len(samples), len(want))
	}
	for i, w := range want {
		if got := samples[i].service + "/" + samples[i].pool; got != w {
			t.Errorf("sorted[%d] = %q, want %q", i, got, w)
		}
	}
	// The first of the two duplicate rows is the one kept.
	if samples[0].inflight != 3 {
		t.Errorf("duplicate resolution kept inflight=%v, want the first row (3)", samples[0].inflight)
	}
}

func withAdmissionStore(t *testing.T, samples []admissionSample, anomalies [2]float64) {
	t.Helper()
	admissionStoreMutex.Lock()
	savedStore, savedAnomalies := admissionStore, admissionAnomalies
	admissionStore, admissionAnomalies = samples, anomalies
	admissionStoreMutex.Unlock()
	t.Cleanup(func() {
		admissionStoreMutex.Lock()
		admissionStore, admissionAnomalies = savedStore, savedAnomalies
		admissionStoreMutex.Unlock()
	})
}

func TestAdmissionCollectorEmptyStore(t *testing.T) {
	withAdmissionStore(t, nil, [2]float64{})

	// No pool: only the two process-wide anomaly counters, at zero, so
	// "never anomalous" and "not exported" are distinguishable.
	if n := testutil.CollectAndCount(admissionCollector{}); n != 2 {
		t.Errorf("empty store emitted %d metrics, want 2 (the anomaly counters)", n)
	}
	want := `
# HELP loxilb_ai_admission_anomalies_total Accounting anomalies in the capacity gate, process-wide: underflow (a release found its counter at zero) and unknown_permit (an executing permit with no pool). Any increment is a defect, not load.
# TYPE loxilb_ai_admission_anomalies_total counter
loxilb_ai_admission_anomalies_total{kind="underflow"} 0
loxilb_ai_admission_anomalies_total{kind="unknown_permit"} 0
`
	if err := testutil.CollectAndCompare(admissionCollector{}, strings.NewReader(want),
		"loxilb_ai_admission_anomalies_total"); err != nil {
		t.Errorf("anomaly series mismatch: %v", err)
	}
}

func TestAdmissionCollectorEmitsLabelledSeries(t *testing.T) {
	withAdmissionStore(t, []admissionSample{{
		service:        "192.168.1.10:8080",
		pool:           "llm",
		mode:           2,
		maxOutstanding: 64,
		inflight:       5,
		epCap:          [3]float64{8, 4, 0},
		epInflight:     [3]float64{5, 0, 0},
		decisions:      [12]float64{100, 7, 1, 0, 12, 30, 2, 3, 4, 5, 0, 6},
		queued:         3,
		queueDepth:     16,
		qwaitBuckets:   [8]uint64{10, 5, 0, 0, 2, 0, 0, 1},
		qwaitSumMs:     8_250,
		qwaitCount:     18,
	}}, [2]float64{0, 1})

	want := `
# HELP loxilb_ai_admission_inflight Capacity units held right now. role="service" is the pool-wide count, one per executing inference request; the other roles sum the endpoint units held across the pool's endpoints for that role. Zero with the gate off.
# TYPE loxilb_ai_admission_inflight gauge
loxilb_ai_admission_inflight{pool="llm",role="decode",service="192.168.1.10:8080"} 0
loxilb_ai_admission_inflight{pool="llm",role="normal",service="192.168.1.10:8080"} 5
loxilb_ai_admission_inflight{pool="llm",role="prefill",service="192.168.1.10:8080"} 0
loxilb_ai_admission_inflight{pool="llm",role="service",service="192.168.1.10:8080"} 5
`
	if err := testutil.CollectAndCompare(admissionCollector{}, strings.NewReader(want),
		"loxilb_ai_admission_inflight"); err != nil {
		t.Errorf("inflight series mismatch: %v", err)
	}

	want = `
# HELP loxilb_ai_admission_limit Ceiling in force for the role: role="service" is the pool-wide bound on executing requests, role="queue" is the bound on requests waiting for a unit (0: over a ceiling is refused at once), the other roles are the per-endpoint bound for that role. 0 means unlimited at that level.
# TYPE loxilb_ai_admission_limit gauge
loxilb_ai_admission_limit{pool="llm",role="decode",service="192.168.1.10:8080"} 0
loxilb_ai_admission_limit{pool="llm",role="normal",service="192.168.1.10:8080"} 8
loxilb_ai_admission_limit{pool="llm",role="prefill",service="192.168.1.10:8080"} 4
loxilb_ai_admission_limit{pool="llm",role="queue",service="192.168.1.10:8080"} 16
loxilb_ai_admission_limit{pool="llm",role="service",service="192.168.1.10:8080"} 64
`
	if err := testutil.CollectAndCompare(admissionCollector{}, strings.NewReader(want),
		"loxilb_ai_admission_limit"); err != nil {
		t.Errorf("limit series mismatch: %v", err)
	}

	want = `
# HELP loxilb_ai_admission_queued Inference requests parked on the pool right now, waiting for a capacity unit. Zero with no queue depth configured.
# TYPE loxilb_ai_admission_queued gauge
loxilb_ai_admission_queued{pool="llm",service="192.168.1.10:8080"} 3
`
	if err := testutil.CollectAndCompare(admissionCollector{}, strings.NewReader(want),
		"loxilb_ai_admission_queued"); err != nil {
		t.Errorf("queued series mismatch: %v", err)
	}

	// The C side counts each wait once, in its bucket; the exposition is
	// cumulative, with the sum in seconds.
	want = `
# HELP loxilb_ai_admission_queue_wait_seconds Time a request waited in the pool's queue before it was resumed and dispatched; requests that timed out, were cancelled or were drained are counted under their decision reason instead.
# TYPE loxilb_ai_admission_queue_wait_seconds histogram
loxilb_ai_admission_queue_wait_seconds_bucket{pool="llm",service="192.168.1.10:8080",le="0.01"} 10
loxilb_ai_admission_queue_wait_seconds_bucket{pool="llm",service="192.168.1.10:8080",le="0.05"} 15
loxilb_ai_admission_queue_wait_seconds_bucket{pool="llm",service="192.168.1.10:8080",le="0.1"} 15
loxilb_ai_admission_queue_wait_seconds_bucket{pool="llm",service="192.168.1.10:8080",le="0.25"} 15
loxilb_ai_admission_queue_wait_seconds_bucket{pool="llm",service="192.168.1.10:8080",le="0.5"} 17
loxilb_ai_admission_queue_wait_seconds_bucket{pool="llm",service="192.168.1.10:8080",le="1"} 17
loxilb_ai_admission_queue_wait_seconds_bucket{pool="llm",service="192.168.1.10:8080",le="2.5"} 17
loxilb_ai_admission_queue_wait_seconds_bucket{pool="llm",service="192.168.1.10:8080",le="5"} 18
loxilb_ai_admission_queue_wait_seconds_bucket{pool="llm",service="192.168.1.10:8080",le="+Inf"} 18
loxilb_ai_admission_queue_wait_seconds_sum{pool="llm",service="192.168.1.10:8080"} 8.25
loxilb_ai_admission_queue_wait_seconds_count{pool="llm",service="192.168.1.10:8080"} 18
`
	if err := testutil.CollectAndCompare(admissionCollector{}, strings.NewReader(want),
		"loxilb_ai_admission_queue_wait_seconds"); err != nil {
		t.Errorf("queue wait histogram mismatch: %v", err)
	}

	want = `
# HELP loxilb_ai_admission_decisions_total Gate decisions per pool and reason: admitted, capacity_shed (429), no_healthy_capacity (503), observe_would_shed (admitted in observe mode where enforce would have refused, counted at each ceiling that would have refused it), bypass_non_inference (not an inference request, no unit taken), queued (parked to wait for a unit), queue_full (429, the queue at its depth), queue_timeout (504, waited the whole window), cancelled (the client left while waiting), drained (the pool or the process stopped taking work while it waited), observe_would_queue (admitted in observe mode where enforce would have parked it), draining (503, the process is draining for maintenance).
# TYPE loxilb_ai_admission_decisions_total counter
loxilb_ai_admission_decisions_total{pool="llm",reason="admitted",service="192.168.1.10:8080"} 100
loxilb_ai_admission_decisions_total{pool="llm",reason="bypass_non_inference",service="192.168.1.10:8080"} 12
loxilb_ai_admission_decisions_total{pool="llm",reason="cancelled",service="192.168.1.10:8080"} 4
loxilb_ai_admission_decisions_total{pool="llm",reason="capacity_shed",service="192.168.1.10:8080"} 7
loxilb_ai_admission_decisions_total{pool="llm",reason="drained",service="192.168.1.10:8080"} 5
loxilb_ai_admission_decisions_total{pool="llm",reason="draining",service="192.168.1.10:8080"} 6
loxilb_ai_admission_decisions_total{pool="llm",reason="no_healthy_capacity",service="192.168.1.10:8080"} 1
loxilb_ai_admission_decisions_total{pool="llm",reason="observe_would_queue",service="192.168.1.10:8080"} 0
loxilb_ai_admission_decisions_total{pool="llm",reason="observe_would_shed",service="192.168.1.10:8080"} 0
loxilb_ai_admission_decisions_total{pool="llm",reason="queue_full",service="192.168.1.10:8080"} 2
loxilb_ai_admission_decisions_total{pool="llm",reason="queue_timeout",service="192.168.1.10:8080"} 3
loxilb_ai_admission_decisions_total{pool="llm",reason="queued",service="192.168.1.10:8080"} 30
`
	if err := testutil.CollectAndCompare(admissionCollector{}, strings.NewReader(want),
		"loxilb_ai_admission_decisions_total"); err != nil {
		t.Errorf("decisions series mismatch: %v", err)
	}

	want = `
# HELP loxilb_ai_admission_mode Capacity gate mode on the pool: 0 off (dispatch path unchanged), 1 observe (decisions counted, everything admitted), 2 enforce (over a ceiling is refused). Present for every model pool of an AI-gateway service.
# TYPE loxilb_ai_admission_mode gauge
loxilb_ai_admission_mode{pool="llm",service="192.168.1.10:8080"} 2
`
	if err := testutil.CollectAndCompare(admissionCollector{}, strings.NewReader(want),
		"loxilb_ai_admission_mode"); err != nil {
		t.Errorf("mode series mismatch: %v", err)
	}

	// Per pool: 1 mode + 4 inflight + 5 limit + 1 queued + 1 wait histogram
	// + 12 decisions = 24, plus the 2 process-wide anomaly counters.
	if n := testutil.CollectAndCount(admissionCollector{}); n != 26 {
		t.Errorf("collected %d metrics for one pool, want 26", n)
	}
}

func TestAdmissionQwaitCumulative(t *testing.T) {
	got := admissionQwaitCumulative([8]uint64{1, 0, 2, 0, 0, 3, 0, 0})
	want := map[float64]uint64{0.01: 1, 0.05: 1, 0.1: 3, 0.25: 3, 0.5: 3, 1: 6, 2.5: 6, 5: 6}
	if len(got) != len(want) {
		t.Fatalf("got %d buckets, want %d", len(got), len(want))
	}
	for le, n := range want {
		if got[le] != n {
			t.Errorf("bucket le=%v = %d, want %d", le, got[le], n)
		}
	}
	// The reason vocabulary is the C enum's, in its order: a new reason
	// appended there must be appended here, never inserted.
	if admissionReasonLabels[5] != "queued" || admissionReasonLabels[11] != "draining" {
		t.Errorf("reason order drifted from enum fc_reason: %v", admissionReasonLabels)
	}
}

// A scrape that lands between a wait's bucket and its count still emits a
// histogram whose count covers every bucket; a settled one keeps its own
// count, which also covers waits past the last bound.
func TestAdmissionQwaitHistogramCountCoversBuckets(t *testing.T) {
	cases := []struct {
		name      string
		buckets   [8]uint64
		count     uint64
		wantCount uint64
	}{
		{"mid-update: a bucket ahead of the count", [8]uint64{1, 0, 2, 0, 0, 3, 0, 0}, 5, 6},
		{"settled", [8]uint64{1, 0, 2, 0, 0, 3, 0, 0}, 6, 6},
		{"waits past the last bound", [8]uint64{1, 0, 0, 0, 0, 0, 0, 1}, 4, 4},
		{"empty", [8]uint64{}, 0, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			count, cum := admissionQwaitHistogram(c.buckets, c.count)
			if count != c.wantCount {
				t.Fatalf("count = %d, want %d", count, c.wantCount)
			}
			for le, n := range cum {
				if n > count {
					t.Errorf("bucket le=%v = %d exceeds the count %d", le, n, count)
				}
			}
		})
	}
}
