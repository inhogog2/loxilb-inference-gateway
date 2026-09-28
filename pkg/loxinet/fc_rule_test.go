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
package loxinet

import (
	"errors"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

// A replace keeps each gate field it omits and replaces each one it
// carries, zero and "inherit" included; a create takes the request as is.
// Out-of-range values are refused here too, for callers without the
// handler's checks (a snapshot restore, the Go API).
func TestFcRuleResolveOnReplace(t *testing.T) {
	stored := &ruleEnt{fcCfg: fcRuleCfg{mode: cmn.FcRuleModeEnforce, maxOutstanding: 8,
		epMaxInflight: 4, prefillMaxInflight: 2, decodeMaxInflight: 6, telemetryStaleMs: 60000}}
	cases := []struct {
		name  string
		eRule *ruleEnt
		serv  cmn.LbServiceArg
		want  fcRuleCfg
	}{
		{"create: declared", nil,
			cmn.LbServiceArg{FcMode: "observe", FcMaxOutstanding: 3, FcTelemetryStaleMs: 1000},
			fcRuleCfg{mode: cmn.FcRuleModeObserve, maxOutstanding: 3, telemetryStaleMs: 1000}},
		{"create: nothing inherits", nil, cmn.LbServiceArg{}, fcRuleCfg{}},
		{"replace: nothing present keeps all", stored, cmn.LbServiceArg{}, stored.fcCfg},
		{"replace: one ceiling changes, the rest kept", stored,
			cmn.LbServiceArg{FcMaxOutstanding: 16, FcMaxOutstandingPresent: true},
			fcRuleCfg{mode: cmn.FcRuleModeEnforce, maxOutstanding: 16, epMaxInflight: 4,
				prefillMaxInflight: 2, decodeMaxInflight: 6, telemetryStaleMs: 60000}},
		{"replace: explicit zero and inherit reset", stored,
			cmn.LbServiceArg{FcMode: "inherit", FcModePresent: true, FcDecodeMaxInflightPresent: true,
				FcTelemetryStaleMsPresent: true},
			fcRuleCfg{maxOutstanding: 8, epMaxInflight: 4, prefillMaxInflight: 2}},
		{"replace: the gate switched off", stored,
			cmn.LbServiceArg{FcMode: "off", FcModePresent: true},
			fcRuleCfg{mode: cmn.FcRuleModeOff, maxOutstanding: 8, epMaxInflight: 4,
				prefillMaxInflight: 2, decodeMaxInflight: 6, telemetryStaleMs: 60000}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := fcRuleResolve(c.eRule, &c.serv)
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if got != c.want {
				t.Fatalf("resolved %+v, want %+v", got, c.want)
			}
		})
	}

	for _, c := range []struct {
		name string
		serv cmn.LbServiceArg
	}{
		{"an unknown mode", cmn.LbServiceArg{FcMode: "yes"}},
		{"a ceiling above 100000", cmn.LbServiceArg{FcEpMaxInflight: cmn.FcCapMax + 1}},
		{"a window above an hour", cmn.LbServiceArg{FcTelemetryStaleMs: cmn.FcTelemetryStaleMsMax + 1}},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := fcRuleResolve(nil, &c.serv)
			var invalid *cmn.ValidationError
			if !errors.As(err, &invalid) {
				t.Fatalf("err=%v, want a validation refusal", err)
			}
		})
	}
}

// The read-back carries the declaration back onto the service arguments;
// an inherited mode reads as empty, so it is omitted.
func TestFcRuleToServ(t *testing.T) {
	var s cmn.LbServiceArg
	fcRuleCfg{mode: cmn.FcRuleModeObserve, maxOutstanding: 3, decodeMaxInflight: 6}.toServ(&s)
	if s.FcMode != "observe" || s.FcMaxOutstanding != 3 || s.FcDecodeMaxInflight != 6 {
		t.Fatalf("read back %+v", s)
	}
	fcRuleCfg{}.toServ(&s)
	if s.FcMode != "" || s.FcMaxOutstanding != 0 {
		t.Fatalf("an inherited declaration read back %+v", s)
	}
}
