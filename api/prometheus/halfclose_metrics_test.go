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

package prometheus

import (
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

const hcCoreHeader = "../../loxilb-ebpf/common/sockproxy_hc_core.h"

// readSubmoduleFile returns a file from the datapath submodule, or skips when
// the submodule is not checked out.
func readSubmoduleFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("datapath submodule not available: %v", err)
	}
	return string(b)
}

// cArrayU64 reads the initialiser of `static const uint64_t name[...] = {...}`.
func cArrayU64(t *testing.T, src, name string) []uint64 {
	t.Helper()
	re := regexp.MustCompile(`(?s)` + regexp.QuoteMeta(name) + `\[[^\]]*\]\s*=\s*\{(.*?)\}`)
	m := re.FindStringSubmatch(src)
	if m == nil {
		t.Fatalf("%s not found in %s", name, hcCoreHeader)
	}
	var out []uint64
	for _, f := range strings.Split(m[1], ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		v, err := strconv.ParseUint(f, 10, 64)
		if err != nil {
			t.Fatalf("%s: %q: %v", name, f, err)
		}
		out = append(out, v)
	}
	return out
}

// cEnumNames lists an enum's enumerators, without its trailing *_MAX.
func cEnumNames(t *testing.T, src, enum string) []string {
	t.Helper()
	re := regexp.MustCompile(`(?s)enum ` + enum + ` \{(.*?)\};`)
	m := re.FindStringSubmatch(src)
	if m == nil {
		t.Fatalf("enum %s not found", enum)
	}
	body := regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(m[1], "")
	var names []string
	for _, f := range strings.Split(body, ",") {
		f = strings.TrimSpace(strings.SplitN(f, "=", 2)[0])
		if f == "" || strings.HasSuffix(f, "_MAX") {
			continue
		}
		names = append(names, f)
	}
	return names
}

// The bounds are written twice, in microseconds on the C side and in seconds
// here; a bucket that moved on one side only would mislabel every sample.
func TestHalfCloseBoundsMatchDatapath(t *testing.T) {
	src := readSubmoduleFile(t, hcCoreHeader)
	for _, c := range []struct {
		name string
		goB  [hcBounds]float64
	}{
		{"hc_fin_bounds_us", hcFinBounds},
		{"hc_prog_bounds_us", hcProgBounds},
	} {
		cb := cArrayU64(t, src, c.name)
		if len(cb) != hcBounds {
			t.Fatalf("%s: %d bounds in C, %d in Go", c.name, len(cb), hcBounds)
		}
		for i, us := range cb {
			if got := float64(us) / 1e6; got != c.goB[i] {
				t.Errorf("%s[%d]: C %gs, Go %gs", c.name, i, got, c.goB[i])
			}
		}
	}
}

// The label arrays are indexed by the C enums; their order is the contract.
func TestHalfCloseLabelsMatchDatapathEnums(t *testing.T) {
	src := readSubmoduleFile(t, hcCoreHeader)
	suffix := func(prefix string, names []string) []string {
		out := make([]string, len(names))
		for i, n := range names {
			out[i] = strings.ToLower(strings.TrimPrefix(n, prefix))
		}
		return out
	}
	if got := suffix("HC_ENTRY_", cEnumNames(t, src, "hc_entry")); !reflect.DeepEqual(got, hcEntryLabels[:]) {
		t.Errorf("entry labels %v, C enum %v", hcEntryLabels, got)
	}
	if got := suffix("HC_OUT_", cEnumNames(t, src, "hc_outcome")); !reflect.DeepEqual(got, hcOutcomeLabels[:]) {
		t.Errorf("outcome labels %v, C enum %v", hcOutcomeLabels, got)
	}
	if got := suffix("HC_TLS_", cEnumNames(t, src, "hc_tls_path")); !reflect.DeepEqual(got, hcTLSPathLabels[:]) {
		t.Errorf("TLS path labels %v, C enum %v", hcTLSPathLabels, got)
	}
	// These two spell their values differently from the enumerators, so only
	// the order is pinned: the enumerators, in order, are the ones below.
	if got := cEnumNames(t, src, "hc_stream"); !reflect.DeepEqual(got,
		[]string{"HC_STREAM_UNKNOWN", "HC_STREAM_YES", "HC_STREAM_NO"}) {
		t.Errorf("hc_stream is %v; hcStreamLabels assumes unknown, yes, no", got)
	}
	if got := cEnumNames(t, src, "hc_ua"); !reflect.DeepEqual(got, []string{
		"HC_UA_NONE", "HC_UA_CURL", "HC_UA_PY_REQUESTS", "HC_UA_PY_HTTPX", "HC_UA_PY_AIOHTTP",
		"HC_UA_PY_URLLIB", "HC_UA_OPENAI_PY", "HC_UA_OPENAI_NODE", "HC_UA_GO", "HC_UA_NODE",
		"HC_UA_JAVA", "HC_UA_BROWSER", "HC_UA_OTHER"}) {
		t.Errorf("hc_ua is %v; hcUALabels assumes the order it was written for", got)
	}
	if n := len(cEnumNames(t, src, "hc_ua")); n != hcUAFamilies {
		t.Errorf("hc_ua has %d families, Go %d", n, hcUAFamilies)
	}
	if !strings.Contains(src, "#define HC_ENTRY_SAMPLED 4") || hcEntrySampled != 4 {
		t.Errorf("HC_ENTRY_SAMPLED and hcEntrySampled disagree")
	}
}

// The snapshot struct is declared three times; a field added to one only
// shifts every field after it in the others.
func TestProxyMetricsSnapshotLockstep(t *testing.T) {
	fieldRe := regexp.MustCompile(`\b(?:uint64_t|uint32_t|float|double|int)\s+(\w+(?:\[[^\]]*\])*)\s*;`)
	fields := func(path string) []string {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Skipf("%s: %v", path, err)
		}
		s := string(b)
		i := strings.Index(s, "typedef struct proxy_metrics_snapshot {")
		if i < 0 {
			t.Fatalf("%s: no proxy_metrics_snapshot", path)
		}
		j := strings.Index(s[i:], "} proxy_metrics_snapshot_t;")
		body := s[i : i+j]
		body = regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(body, "")
		body = regexp.MustCompile(`//[^\n]*`).ReplaceAllString(body, "")
		var out []string
		for _, m := range fieldRe.FindAllStringSubmatch(body, -1) {
			out = append(out, m[1])
		}
		return out
	}
	canon := fields("../../loxilb-ebpf/common/sockproxy_metrics.h")
	for _, p := range []string{"sockproxy_metrics.go", "proxy_metrics_stub.c"} {
		if got := fields(p); !reflect.DeepEqual(got, canon) {
			t.Errorf("%s declares %d fields, sockproxy_metrics.h %d; first difference at %s",
				p, len(got), len(canon), firstDiff(got, canon))
		}
	}
}

func firstDiff(a, b []string) string {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] + " / " + b[i]
		}
	}
	return "the tail"
}

func TestHalfCloseMergeTornReadAndMonotonic(t *testing.T) {
	var prev, raw halfCloseSnapshot
	prev.finTotal[0][0] = 10
	prev.finGap[0][1].buckets[0] = 3
	prev.finGap[0][1].count = 5

	raw.finTotal[0][0] = 9 // cannot go backwards
	raw.finTotal[1][2] = 4
	h := &raw.finGap[0][1]
	h.buckets[0], h.buckets[1], h.buckets[2] = 4, 2, 6 // torn: 2 < 4
	h.count = 5                                        // below the highest bucket
	h.sumSecs = 0.5

	m := mergeHalfClose(prev, raw)
	if m.finTotal[0][0] != 10 || m.finTotal[1][2] != 4 {
		t.Fatalf("counters: %v", m.finTotal)
	}
	g := m.finGap[0][1]
	if g.buckets[1] != 4 || g.buckets[2] != 6 || g.buckets[hcBounds-1] != 6 {
		t.Fatalf("torn buckets not clamped: %v", g.buckets)
	}
	if g.count != 6 {
		t.Fatalf("count %d, want at least the highest bucket (6)", g.count)
	}
}

func TestHalfCloseCollectorSeries(t *testing.T) {
	halfCloseStoreMutex.Lock()
	saved := halfCloseStore
	var s halfCloseSnapshot
	s.finGap[1][2].buckets = [hcBounds]uint64{1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3}
	s.finGap[1][2].count = 4
	s.finGap[1][2].sumSecs = 70.012
	s.finTotal[5][2] = 7
	s.tlsFin[1][1] = 2
	s.userAgent[3] = 5
	s.clientReset = 9
	halfCloseStore = s
	halfCloseStoreMutex.Unlock()
	defer func() {
		halfCloseStoreMutex.Lock()
		halfCloseStore = saved
		halfCloseStoreMutex.Unlock()
	}()

	reg := prometheus.NewRegistry()
	reg.MustRegister(halfCloseCollector{})
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{
		"loxilb_proxy_halfclose_fin_gap_seconds":        hcEntrySampled * hcStreams,
		"loxilb_proxy_halfclose_fin_total":              hcEntries * hcOutcomes,
		"loxilb_proxy_halfclose_accel_early_fin_total":  1,
		"loxilb_proxy_halfclose_tls_fin_total":          hcTLSPaths * 2,
		"loxilb_proxy_client_reset_total":               1,
		"loxilb_proxy_halfclose_user_agent_total":       hcUAFamilies,
		"loxilb_proxy_response_first_write_gap_seconds": hcStreams,
		"loxilb_proxy_response_max_write_gap_seconds":   hcStreams,
	}
	byName := map[string]*dto.MetricFamily{}
	for _, mf := range mfs {
		byName[mf.GetName()] = mf
	}
	for name, n := range want {
		mf := byName[name]
		if mf == nil {
			t.Errorf("%s not collected", name)
			continue
		}
		if len(mf.GetMetric()) != n {
			t.Errorf("%s: %d series, want %d", name, len(mf.GetMetric()), n)
		}
	}
	if len(byName) != len(want) {
		t.Errorf("collected %d families, want %d", len(byName), len(want))
	}

	labels := func(m *dto.Metric) map[string]string {
		out := map[string]string{}
		for _, lp := range m.GetLabel() {
			out[lp.GetName()] = lp.GetValue()
		}
		return out
	}
	find := func(name string, lv map[string]string) *dto.Metric {
		for _, m := range byName[name].GetMetric() {
			if reflect.DeepEqual(labels(m), lv) {
				return m
			}
		}
		t.Fatalf("%s%v not found", name, lv)
		return nil
	}
	h := find("loxilb_proxy_halfclose_fin_gap_seconds",
		map[string]string{"entry": "connect_wait", "stream": "false"}).GetHistogram()
	if h.GetSampleCount() != 4 || h.GetSampleSum() != 70.012 {
		t.Errorf("histogram count/sum %d/%g", h.GetSampleCount(), h.GetSampleSum())
	}
	for _, b := range h.GetBucket() {
		if b.GetUpperBound() == 0.1 && b.GetCumulativeCount() != 3 {
			t.Errorf("le=0.1 holds %d, want 3", b.GetCumulativeCount())
		}
	}
	if v := find("loxilb_proxy_halfclose_fin_total",
		map[string]string{"entry": "backpressure", "outcome": "partial"}).GetCounter().GetValue(); v != 7 {
		t.Errorf("fin_total{backpressure,partial} = %g", v)
	}
	if v := find("loxilb_proxy_halfclose_tls_fin_total",
		map[string]string{"path": "close_notify", "early_owed": "true"}).GetCounter().GetValue(); v != 2 {
		t.Errorf("tls_fin_total{close_notify,true} = %g", v)
	}
	if v := find("loxilb_proxy_halfclose_user_agent_total",
		map[string]string{"family": "python_httpx"}).GetCounter().GetValue(); v != 5 {
		t.Errorf("user_agent_total{python_httpx} = %g", v)
	}
}
