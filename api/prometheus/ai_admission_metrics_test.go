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
		decisions:      [5]float64{100, 7, 1, 0, 12},
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
# HELP loxilb_ai_admission_decisions_total Gate decisions per pool and reason: admitted, capacity_shed (429), no_healthy_capacity (503), observe_would_shed (admitted in observe mode where enforce would have refused, counted at each ceiling that would have refused it), bypass_non_inference (not an inference request, no unit taken).
# TYPE loxilb_ai_admission_decisions_total counter
loxilb_ai_admission_decisions_total{pool="llm",reason="admitted",service="192.168.1.10:8080"} 100
loxilb_ai_admission_decisions_total{pool="llm",reason="bypass_non_inference",service="192.168.1.10:8080"} 12
loxilb_ai_admission_decisions_total{pool="llm",reason="capacity_shed",service="192.168.1.10:8080"} 7
loxilb_ai_admission_decisions_total{pool="llm",reason="no_healthy_capacity",service="192.168.1.10:8080"} 1
loxilb_ai_admission_decisions_total{pool="llm",reason="observe_would_shed",service="192.168.1.10:8080"} 0
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

	// Per pool: 1 mode + 4 inflight + 4 limit + 5 decisions = 14, plus the
	// 2 process-wide anomaly counters.
	if n := testutil.CollectAndCount(admissionCollector{}); n != 16 {
		t.Errorf("collected %d metrics for one pool, want 16", n)
	}
}
