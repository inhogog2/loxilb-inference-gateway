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

// The adaptive switch, the warm-up window and the TTFT target follow the
// replace rules of the rest of the gate: omitted keeps, present replaces.
func TestFcRuleAdaptiveOnReplace(t *testing.T) {
	stored := &ruleEnt{fcCfg: fcRuleCfg{maxOutstanding: 8, adaptive: cmn.FcRuleAdaptiveOn,
		warmupMs: 20000, ttftTargetMs: 800}}
	for _, c := range []struct {
		name  string
		eRule *ruleEnt
		serv  cmn.LbServiceArg
		want  fcRuleCfg
	}{
		{"create: declared", nil,
			cmn.LbServiceArg{FcAdaptive: "on", FcWarmupMs: 5000, FcTtftTargetMs: 300},
			fcRuleCfg{adaptive: cmn.FcRuleAdaptiveOn, warmupMs: 5000, ttftTargetMs: 300}},
		{"replace: nothing present keeps all", stored, cmn.LbServiceArg{}, stored.fcCfg},
		{"replace: switched off, windows kept", stored,
			cmn.LbServiceArg{FcAdaptive: "off", FcAdaptivePresent: true},
			fcRuleCfg{maxOutstanding: 8, adaptive: cmn.FcRuleAdaptiveOff, warmupMs: 20000, ttftTargetMs: 800}},
		{"replace: inherit and explicit zeros reset", stored,
			cmn.LbServiceArg{FcAdaptive: "inherit", FcAdaptivePresent: true,
				FcWarmupMsPresent: true, FcTtftTargetMsPresent: true},
			fcRuleCfg{maxOutstanding: 8}},
	} {
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
		{"an unknown switch", cmn.LbServiceArg{FcAdaptive: "yes"}},
		{"a warm-up above an hour", cmn.LbServiceArg{FcWarmupMs: cmn.FcWarmupMsMax + 1}},
		{"a TTFT target above an hour", cmn.LbServiceArg{FcTtftTargetMs: cmn.FcTtftTargetMsMax + 1}},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := fcRuleResolve(nil, &c.serv)
			var invalid *cmn.ValidationError
			if !errors.As(err, &invalid) {
				t.Fatalf("err=%v, want a validation refusal", err)
			}
		})
	}

	var s cmn.LbServiceArg
	stored.fcCfg.toServ(&s)
	if s.FcAdaptive != "on" || s.FcWarmupMs != 20000 || s.FcTtftTargetMs != 800 {
		t.Fatalf("read back %+v", s)
	}
	fcRuleCfg{}.toServ(&s)
	if s.FcAdaptive != "" {
		t.Fatalf("an inherited switch read back %q", s.FcAdaptive)
	}
}

// Whether the pool adapts, and so whether the rule needs its scraper: the
// rule's own switch wins; with none, the process default decides.
func TestFcRuleAdaptiveInForce(t *testing.T) {
	t.Setenv("LLB_FC_ADAPTIVE", "on")
	if !(fcRuleCfg{}).adaptiveInForce() {
		t.Fatal("an inheriting rule under LLB_FC_ADAPTIVE=on does not adapt")
	}
	if (fcRuleCfg{adaptive: cmn.FcRuleAdaptiveOff}).adaptiveInForce() {
		t.Fatal("a rule that switched it off adapts")
	}
	t.Setenv("LLB_FC_ADAPTIVE", "")
	if (fcRuleCfg{}).adaptiveInForce() {
		t.Fatal("an inheriting rule adapts with no process default")
	}
	if !(fcRuleCfg{adaptive: cmn.FcRuleAdaptiveOn}).adaptiveInForce() {
		t.Fatal("a rule that switched it on does not adapt")
	}
}

// The tenant share follows the replace rules of the rest of the gate and is
// a percentage: omitted keeps, present replaces, above 100 is refused.
func TestFcRuleTenantShareOnReplace(t *testing.T) {
	stored := &ruleEnt{fcCfg: fcRuleCfg{maxOutstanding: 8, tenantSharePct: 25}}
	for _, c := range []struct {
		name  string
		eRule *ruleEnt
		serv  cmn.LbServiceArg
		want  fcRuleCfg
	}{
		{"create: declared", nil, cmn.LbServiceArg{FcTenantMaxSharePct: 40},
			fcRuleCfg{tenantSharePct: 40}},
		{"replace: omitted keeps", stored, cmn.LbServiceArg{FcMaxOutstanding: 9,
			FcMaxOutstandingPresent: true}, fcRuleCfg{maxOutstanding: 9, tenantSharePct: 25}},
		{"replace: present replaces", stored, cmn.LbServiceArg{FcTenantMaxSharePct: 100,
			FcTenantMaxSharePctPresent: true}, fcRuleCfg{maxOutstanding: 8, tenantSharePct: 100}},
		{"replace: explicit zero inherits", stored,
			cmn.LbServiceArg{FcTenantMaxSharePctPresent: true}, fcRuleCfg{maxOutstanding: 8}},
	} {
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
	_, err := fcRuleResolve(nil, &cmn.LbServiceArg{FcTenantMaxSharePct: cmn.FcTenantMaxSharePctMax + 1})
	var invalid *cmn.ValidationError
	if !errors.As(err, &invalid) {
		t.Fatalf("a share above 100: err=%v, want a validation refusal", err)
	}
	var s cmn.LbServiceArg
	stored.fcCfg.toServ(&s)
	if s.FcTenantMaxSharePct != 25 {
		t.Fatalf("read back %d", s.FcTenantMaxSharePct)
	}
}

// The admission headers switch follows the adaptive switch's replace rules:
// omitted keeps, present replaces, "inherit" clears, anything else is refused.
func TestFcRuleExposeHeadersOnReplace(t *testing.T) {
	stored := &ruleEnt{fcCfg: fcRuleCfg{maxOutstanding: 8, exposeHeaders: cmn.FcRuleAdaptiveOn}}
	for _, c := range []struct {
		name  string
		eRule *ruleEnt
		serv  cmn.LbServiceArg
		want  fcRuleCfg
	}{
		{"create: on", nil, cmn.LbServiceArg{FcExposeHeaders: "on"},
			fcRuleCfg{exposeHeaders: cmn.FcRuleAdaptiveOn}},
		{"create: off", nil, cmn.LbServiceArg{FcExposeHeaders: "off"},
			fcRuleCfg{exposeHeaders: cmn.FcRuleAdaptiveOff}},
		{"replace: omitted keeps", stored, cmn.LbServiceArg{FcMaxOutstanding: 9,
			FcMaxOutstandingPresent: true},
			fcRuleCfg{maxOutstanding: 9, exposeHeaders: cmn.FcRuleAdaptiveOn}},
		{"replace: present replaces", stored, cmn.LbServiceArg{FcExposeHeaders: "off",
			FcExposeHeadersPresent: true},
			fcRuleCfg{maxOutstanding: 8, exposeHeaders: cmn.FcRuleAdaptiveOff}},
		{"replace: inherit clears", stored, cmn.LbServiceArg{FcExposeHeaders: "inherit",
			FcExposeHeadersPresent: true}, fcRuleCfg{maxOutstanding: 8}},
	} {
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
	_, err := fcRuleResolve(nil, &cmn.LbServiceArg{FcExposeHeaders: "yes"})
	var invalid *cmn.ValidationError
	if !errors.As(err, &invalid) {
		t.Fatalf("an unknown switch value: err=%v, want a validation refusal", err)
	}
	var s cmn.LbServiceArg
	stored.fcCfg.toServ(&s)
	if s.FcExposeHeaders != "on" {
		t.Fatalf("read back %q", s.FcExposeHeaders)
	}
}

// The headers are refused where the kernel may carry the responses, and only
// there; a restore replay is let through.
func TestFcExposeSockMapErr(t *testing.T) {
	on := fcRuleCfg{exposeHeaders: cmn.FcRuleAdaptiveOn}
	for _, c := range []struct {
		name    string
		cfg     fcRuleCfg
		code    uint8
		replay  bool
		refused bool
	}{
		{"on, sockmap off", on, 0, false, false},
		{"on, sockmap both", on, 1, false, true},
		{"on, sockmap request", on, 2, false, false},
		{"on, sockmap response", on, 3, false, true},
		{"off, sockmap both", fcRuleCfg{exposeHeaders: cmn.FcRuleAdaptiveOff}, 1, false, false},
		{"inherit, sockmap both", fcRuleCfg{}, 1, false, false},
		{"on, sockmap both, restore", on, 1, true, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			serv := cmn.LbServiceArg{ServIP: "10.0.0.1", ServPort: 80,
				SockMapMode: cmn.SockMapCodeToMode(c.code), RestoreReplay: c.replay}
			err := fcExposeSockMapErr(&serv, c.cfg, c.code)
			var invalid *cmn.ValidationError
			if c.refused != (err != nil) || (err != nil && !errors.As(err, &invalid)) {
				t.Fatalf("err=%v, want refused=%v as a validation error", err, c.refused)
			}
		})
	}
}
