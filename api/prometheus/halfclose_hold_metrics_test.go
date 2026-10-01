/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
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
	"reflect"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

const holdCoreHeader = "../../loxilb-ebpf/common/sockproxy_hold_core.h"

// holdEndLabels is indexed by enum sp_hold_end; its order is the contract.
func TestHoldEndLabelsMatchDatapathEnum(t *testing.T) {
	src := readSubmoduleFile(t, holdCoreHeader)
	names := cEnumNames(t, src, "sp_hold_end")
	if len(names) != holdEndReasons {
		t.Fatalf("sp_hold_end has %d values, Go %d", len(names), holdEndReasons)
	}
	for i, n := range names {
		want := strings.ToLower(strings.TrimPrefix(n, "SP_HOLD_END_"))
		if i == 0 {
			want = "" // none: never counted, never exported
		}
		if holdEndLabels[i] != want {
			t.Errorf("holdEndLabels[%d] = %q, C enum %s", i, holdEndLabels[i], n)
		}
	}
}

// Gauges are taken as read; counters never go backwards.
func TestHoldMerge(t *testing.T) {
	prev := holdSnapshot{held: 5, oldestMs: 9000, begun: 10, refusedResidue: 3, accelSkipped: 2}
	prev.ended[1] = 7
	prev.expired[1][2] = 4
	next := holdSnapshot{held: 1, oldestMs: 100, allowed: 1, capSec: 240, begun: 9, refusedResidue: 4}
	next.ended[1] = 6
	next.expired[1][2] = 5
	m := mergeHold(prev, next)
	if m.held != 1 || m.oldestMs != 100 || m.allowed != 1 || m.capSec != 240 {
		t.Errorf("gauges not taken as read: %+v", m)
	}
	if m.begun != 10 || m.ended[1] != 7 || m.accelSkipped != 2 {
		t.Errorf("a counter went backwards: begun %d ended %d accelSkipped %d", m.begun, m.ended[1], m.accelSkipped)
	}
	if m.refusedResidue != 4 || m.expired[1][2] != 5 {
		t.Errorf("a counter did not advance: refused %d expired %d", m.refusedResidue, m.expired[1][2])
	}
}

func TestHoldCollectorSeries(t *testing.T) {
	holdStoreMutex.Lock()
	saved := holdStore
	s := holdSnapshot{held: 2, oldestMs: 1500, allowed: 1, capSec: 240, begun: 11,
		refusedResidue: 3, reentry: 0, emptyOut: 4, accelSkipped: 6}
	s.ended[2] = 5      // backend_first
	s.expired[0][1] = 7 // answer not begun, stream true
	holdStore = s
	holdStoreMutex.Unlock()
	defer func() {
		holdStoreMutex.Lock()
		holdStore = saved
		holdStoreMutex.Unlock()
	}()

	reg := prometheus.NewRegistry()
	reg.MustRegister(halfCloseHoldCollector{})
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{
		"loxilb_proxy_halfclose_held":                        1,
		"loxilb_proxy_halfclose_held_oldest_seconds":         1,
		"loxilb_proxy_halfclose_hold_allowed":                1,
		"loxilb_proxy_halfclose_hold_cap_seconds":            1,
		"loxilb_proxy_halfclose_hold_total":                  1,
		"loxilb_proxy_halfclose_hold_ended_total":            holdEndReasons - 1,
		"loxilb_proxy_halfclose_hold_expired_total":          2 * hcStreams,
		"loxilb_proxy_halfclose_hold_refused_total":          1,
		"loxilb_proxy_halfclose_hold_spurious_wakeups_total": 2,
		"loxilb_proxy_halfclose_accel_skipped_total":         1,
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
	value := func(name string, lv map[string]string) float64 {
		for _, m := range byName[name].GetMetric() {
			if reflect.DeepEqual(labels(m), lv) {
				if m.GetGauge() != nil {
					return m.GetGauge().GetValue()
				}
				return m.GetCounter().GetValue()
			}
		}
		t.Fatalf("%s%v not found", name, lv)
		return 0
	}
	for _, c := range []struct {
		name string
		lv   map[string]string
		want float64
	}{
		{"loxilb_proxy_halfclose_held", map[string]string{}, 2},
		{"loxilb_proxy_halfclose_held_oldest_seconds", map[string]string{}, 1.5},
		{"loxilb_proxy_halfclose_hold_cap_seconds", map[string]string{}, 240},
		{"loxilb_proxy_halfclose_hold_total", map[string]string{}, 11},
		{"loxilb_proxy_halfclose_hold_ended_total", map[string]string{"reason": "backend_first"}, 5},
		{"loxilb_proxy_halfclose_hold_ended_total", map[string]string{"reason": "answered"}, 0},
		{"loxilb_proxy_halfclose_hold_expired_total",
			map[string]string{"answer_started": "false", "stream": "true"}, 7},
		{"loxilb_proxy_halfclose_hold_refused_total", map[string]string{"reason": "pipeline_residue"}, 3},
		{"loxilb_proxy_halfclose_hold_spurious_wakeups_total", map[string]string{"kind": "eof_reentry"}, 0},
		{"loxilb_proxy_halfclose_hold_spurious_wakeups_total", map[string]string{"kind": "empty_out"}, 4},
		{"loxilb_proxy_halfclose_accel_skipped_total", map[string]string{}, 6},
	} {
		if got := value(c.name, c.lv); got != c.want {
			t.Errorf("%s%v = %g, want %g", c.name, c.lv, got, c.want)
		}
	}
}
