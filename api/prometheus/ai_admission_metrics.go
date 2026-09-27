/*
 * Copyright (c) 2026 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 */

package prometheus

/*
#cgo CFLAGS: -I../../loxilb-ebpf/common
#include <stdint.h>

// Twin declaration of proxy_fc_svc_stat_t. CANONICAL definition lives in
// loxilb-ebpf/common/sockproxy_metrics.h; a weak stub for CGO-only builds
// (go test, no sockproxy object) lives in proxy_metrics_stub.c. All THREE
// must move in lockstep, same commit -- tail-append only, never reorder.
//
// Role index 0 = normal, 1 = prefill, 2 = decode; reason index follows the
// gate's enum fc_reason. Cap on pools reported per call; lockstep with
// PROXY_FC_STAT_MAX in sockproxy_metrics.h.
#define PROXY_FC_STAT_MAX 256
#define PROXY_FC_ROLES 3
#define PROXY_FC_REASONS 5
#define PROXY_FC_POOL_LEN 64

typedef struct proxy_fc_svc_stat {
    uint32_t xip;
    uint16_t xport;
    uint8_t  protocol;
    uint8_t  mode;
    uint32_t max_outstanding;
    uint32_t ep_cap[PROXY_FC_ROLES];
    uint32_t inflight;
    uint32_t ep_inflight[PROXY_FC_ROLES];
    uint64_t decisions[PROXY_FC_REASONS];
    char     pool[PROXY_FC_POOL_LEN];
} proxy_fc_svc_stat_t;

extern int proxy_get_fc_stats(proxy_fc_svc_stat_t *out, int max);
extern uint64_t proxy_get_fc_anomaly(int kind);
*/
import "C"

import (
	"fmt"
	"sort"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// ============================================================================
// AI ADMISSION GATE (capacity) METRICS - per service, per model pool
// ============================================================================
// The capacity gate keeps its state on the pool (loxilb-ebpf/common/
// sockproxy_fc.h): the units in flight at the service and at each endpoint
// per role, the ceilings in force, and one counter per decision the gate
// took. Without this file none of that leaves the process, and an operator
// reading a 429 storm cannot tell a ceiling set too low from a backend that
// stopped answering.
//
// Collection follows the shaper's idiom in qos_shaper_metrics.go: the 10s
// RunSockproxyMetrics cycle refreshes a Go-side store (writer) and the
// collector emits ConstMetrics from it on scrape (reader). The C call walks
// the service list under the proxy read lock, off the scrape path.
//
// Every model pool of an AI-gateway service gets a row whatever the gate's
// mode. A pool with the gate off reports mode 0 and zeros, so the mode
// series answers "is this pool gated" without a second source of truth, and
// the gauges read 0 rather than being absent. Counters are exported raw: a
// pool that is deleted and re-created starts from zero, which Prometheus
// already reads as a counter reset.
// ============================================================================

// Role label values, indexed as the C arrays are; "service" is the pool-wide
// unit that every inference request holds once however many legs it opens.
var admissionRoleLabels = [3]string{"normal", "prefill", "decode"}

const admissionRoleService = "service"

// Decision reasons, indexed as the gate's enum fc_reason. The wire vocabulary
// is closed: a reason the gate does not have cannot appear here.
var admissionReasonLabels = [5]string{
	"admitted",
	"capacity_shed",
	"no_healthy_capacity",
	"observe_would_shed",
	"bypass_non_inference",
}

// Anomaly kinds, indexed as the gate's enum fc_anomaly.
var admissionAnomalyLabels = [2]string{"underflow", "unknown_permit"}

// admissionSample is one pool's gate state, converted to Go types and label
// strings.
type admissionSample struct {
	service string
	pool    string

	mode           float64
	maxOutstanding float64
	inflight       float64
	epCap          [3]float64
	epInflight     [3]float64
	decisions      [5]float64
}

// admissionStore is the state shared between the collection loop (writer)
// and admissionCollector.Collect (reader, on scrape). Replaced wholesale
// each cycle so a deleted pool's series stop being emitted instead of
// freezing at their last value. The anomaly counters are process-wide and
// ride along in the same publish.
var (
	admissionStoreMutex sync.Mutex
	admissionStore      []admissionSample
	admissionAnomalies  [2]float64
)

var admissionPoolLabels = []string{"service", "pool"}
var admissionRoleLabelNames = []string{"service", "pool", "role"}
var admissionReasonLabelNames = []string{"service", "pool", "reason"}
var admissionAnomalyLabelNames = []string{"kind"}

var (
	admissionModeDesc = prometheus.NewDesc(
		"loxilb_ai_admission_mode",
		"Capacity gate mode on the pool: 0 off (dispatch path unchanged), 1 observe (decisions counted, everything admitted), 2 enforce (over a ceiling is refused). Present for every model pool of an AI-gateway service.",
		admissionPoolLabels, nil,
	)
	admissionInflightDesc = prometheus.NewDesc(
		"loxilb_ai_admission_inflight",
		"Capacity units held right now. role=\"service\" is the pool-wide count, one per executing inference request; the other roles sum the endpoint units held across the pool's endpoints for that role. Zero with the gate off.",
		admissionRoleLabelNames, nil,
	)
	admissionLimitDesc = prometheus.NewDesc(
		"loxilb_ai_admission_limit",
		"Ceiling in force for the role: role=\"service\" is the pool-wide bound on executing requests, the other roles are the per-endpoint bound for that role. 0 means unlimited at that level.",
		admissionRoleLabelNames, nil,
	)
	admissionDecisionsDesc = prometheus.NewDesc(
		"loxilb_ai_admission_decisions_total",
		"Gate decisions per pool and reason: admitted, capacity_shed (429), no_healthy_capacity (503), observe_would_shed (admitted in observe mode where enforce would have refused, counted at each ceiling that would have refused it), bypass_non_inference (not an inference request, no unit taken).",
		admissionReasonLabelNames, nil,
	)
	admissionAnomaliesDesc = prometheus.NewDesc(
		"loxilb_ai_admission_anomalies_total",
		"Accounting anomalies in the capacity gate, process-wide: underflow (a release found its counter at zero) and unknown_permit (an executing permit with no pool). Any increment is a defect, not load.",
		admissionAnomalyLabelNames, nil,
	)
)

// admissionCollector emits the gate series from admissionStore on scrape.
// With no AI-gateway service configured the store is empty and only the
// two anomaly counters are emitted.
type admissionCollector struct{}

// Describe implements prometheus.Collector.
func (admissionCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- admissionModeDesc
	ch <- admissionInflightDesc
	ch <- admissionLimitDesc
	ch <- admissionDecisionsDesc
	ch <- admissionAnomaliesDesc
}

// Collect implements prometheus.Collector.
func (admissionCollector) Collect(ch chan<- prometheus.Metric) {
	admissionStoreMutex.Lock()
	samples := admissionStore
	anomalies := admissionAnomalies
	admissionStoreMutex.Unlock()

	for _, s := range samples {
		ch <- prometheus.MustNewConstMetric(admissionModeDesc, prometheus.GaugeValue, s.mode, s.service, s.pool)
		ch <- prometheus.MustNewConstMetric(admissionInflightDesc, prometheus.GaugeValue, s.inflight, s.service, s.pool, admissionRoleService)
		ch <- prometheus.MustNewConstMetric(admissionLimitDesc, prometheus.GaugeValue, s.maxOutstanding, s.service, s.pool, admissionRoleService)
		for r, role := range admissionRoleLabels {
			ch <- prometheus.MustNewConstMetric(admissionInflightDesc, prometheus.GaugeValue, s.epInflight[r], s.service, s.pool, role)
			ch <- prometheus.MustNewConstMetric(admissionLimitDesc, prometheus.GaugeValue, s.epCap[r], s.service, s.pool, role)
		}
		for d, reason := range admissionReasonLabels {
			ch <- prometheus.MustNewConstMetric(admissionDecisionsDesc, prometheus.CounterValue, s.decisions[d], s.service, s.pool, reason)
		}
	}
	for k, kind := range admissionAnomalyLabels {
		ch <- prometheus.MustNewConstMetric(admissionAnomaliesDesc, prometheus.CounterValue, anomalies[k], kind)
	}
}

// init registers the gate collector once with the default registry (the
// same registry the promauto metrics use).
func init() {
	prometheus.MustRegister(admissionCollector{})
}

// admissionServiceLabel renders the service identity the audit trail and the
// admission gate already use: "VIP:port". Pure Go.
func admissionServiceLabel(xip uint32, xport uint16) string {
	return fmt.Sprintf("%s:%d", qosVipString(xip), xport)
}

// admissionPoolLabel bounds the pool key for use as a label. The key is the
// pool's "host|path" or "host" as configured; sanitizeLabel keeps the
// character set closed and the length bounded, and an empty key (a service
// with one anonymous pool) reads as "-" so it is legible in a query. Pure Go.
func admissionPoolLabel(key string) string {
	p := sanitizeLabel(key)
	if p == "" {
		p = "-"
	}
	return p
}

// sortAdmissionSamples orders the store deterministically (service, pool)
// so the exposition output is stable between scrapes. Pure Go.
func sortAdmissionSamples(samples []admissionSample) {
	sort.Slice(samples, func(i, j int) bool {
		if samples[i].service != samples[j].service {
			return samples[i].service < samples[j].service
		}
		return samples[i].pool < samples[j].pool
	})
}

// dedupeAdmissionSamples drops every sample after the first per (service,
// pool) label pair. Distinct pool keys can sanitize to the same label; two
// samples on one label set would fail the whole scrape with a duplicate
// series error, so the first wins -- the rule the other collectors follow.
// Expects a sorted input. Pure Go.
func dedupeAdmissionSamples(samples []admissionSample) []admissionSample {
	out := samples[:0]
	for i, s := range samples {
		if i > 0 && s.service == samples[i-1].service && s.pool == samples[i-1].pool {
			continue
		}
		out = append(out, s)
	}
	return out
}

// refreshAdmissionStore pulls the per-pool gate state from the sockproxy and
// republishes the store. Called once per RunSockproxyMetrics cycle.
func refreshAdmissionStore() {
	var raw [C.PROXY_FC_STAT_MAX]C.proxy_fc_svc_stat_t

	n := int(C.proxy_get_fc_stats(&raw[0], C.int(len(raw))))
	if n < 0 {
		n = 0
	}
	if n > len(raw) {
		n = len(raw)
	}

	samples := make([]admissionSample, 0, n)
	for i := 0; i < n; i++ {
		st := raw[i]
		s := admissionSample{
			service:        admissionServiceLabel(uint32(st.xip), uint16(st.xport)),
			pool:           admissionPoolLabel(C.GoString(&st.pool[0])),
			mode:           float64(st.mode),
			maxOutstanding: float64(st.max_outstanding),
			inflight:       float64(st.inflight),
		}
		for r := 0; r < len(admissionRoleLabels); r++ {
			s.epCap[r] = float64(st.ep_cap[r])
			s.epInflight[r] = float64(st.ep_inflight[r])
		}
		for d := 0; d < len(admissionReasonLabels); d++ {
			s.decisions[d] = float64(st.decisions[d])
		}
		samples = append(samples, s)
	}
	sortAdmissionSamples(samples)
	samples = dedupeAdmissionSamples(samples)

	var anomalies [2]float64
	for k := range admissionAnomalyLabels {
		anomalies[k] = float64(C.proxy_get_fc_anomaly(C.int(k)))
	}

	admissionStoreMutex.Lock()
	admissionStore = samples
	admissionAnomalies = anomalies
	admissionStoreMutex.Unlock()
}
