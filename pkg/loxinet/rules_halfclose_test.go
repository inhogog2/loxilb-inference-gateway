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

package loxinet

import (
	"errors"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

// A rule's half-close mode follows fc_mode's replace rules: omitted keeps,
// present replaces, "inherit" clears. hold+parked and unknown words are
// refused; hold is refused off fullproxy, on TLS services and on P/D services,
// judged on the rule as it will stand after a replace, except on a restore
// replay, which drops it.
func TestHalfCloseResolve(t *testing.T) {
	stored := &ruleEnt{halfCloseMode: cmn.HalfCloseRuleHold}
	fp := cmn.LBModeFullProxy
	for _, c := range []struct {
		name  string
		eRule *ruleEnt
		serv  cmn.LbServiceArg
		mode  cmn.LBMode
		want  uint8
	}{
		{"create: omitted", nil, cmn.LbServiceArg{}, fp, cmn.HalfCloseRuleUnset},
		{"create: hold", nil, cmn.LbServiceArg{HalfCloseMode: "hold"}, fp, cmn.HalfCloseRuleHold},
		{"create: off", nil, cmn.LbServiceArg{HalfCloseMode: "off"}, fp, cmn.HalfCloseRuleOff},
		{"create: inherit", nil, cmn.LbServiceArg{HalfCloseMode: "inherit"}, fp, cmn.HalfCloseRuleUnset},
		{"replace: omitted keeps", stored, cmn.LbServiceArg{}, fp, cmn.HalfCloseRuleHold},
		{"replace: present replaces", stored,
			cmn.LbServiceArg{HalfCloseMode: "off", HalfCloseModePresent: true}, fp, cmn.HalfCloseRuleOff},
		{"replace: inherit clears", stored,
			cmn.LbServiceArg{HalfCloseMode: "inherit", HalfCloseModePresent: true}, fp, cmn.HalfCloseRuleUnset},
		// A caller without presence (a read-back re-posted) carries the value.
		{"replace: value without presence", &ruleEnt{},
			cmn.LbServiceArg{HalfCloseMode: "hold"}, fp, cmn.HalfCloseRuleHold},
		{"off on a service that is not fullproxy", nil,
			cmn.LbServiceArg{HalfCloseMode: "off"}, cmn.LBModeDefault, cmn.HalfCloseRuleOff},
		{"hold restored on a service that is not fullproxy", nil,
			cmn.LbServiceArg{HalfCloseMode: "hold", RestoreReplay: true}, cmn.LBModeDefault, cmn.HalfCloseRuleUnset},
		{"off on a TLS service", nil,
			cmn.LbServiceArg{HalfCloseMode: "off", Security: cmn.LBServHTTPS}, fp, cmn.HalfCloseRuleOff},
		{"off on a P/D service", nil,
			cmn.LbServiceArg{HalfCloseMode: "off", PDDisaggMode: true}, fp, cmn.HalfCloseRuleOff},
		{"hold restored on a TLS service", nil,
			cmn.LbServiceArg{HalfCloseMode: "hold", Security: cmn.LBServE2EHTTPS, RestoreReplay: true}, fp, cmn.HalfCloseRuleUnset},
		{"hold restored on a P/D service", nil,
			cmn.LbServiceArg{HalfCloseMode: "hold", PDDisaggMode: true, RestoreReplay: true}, fp, cmn.HalfCloseRuleUnset},
		// A replace that turns P/D off may keep a hold it then could not have had.
		{"P/D switched off under a hold", stored, cmn.LbServiceArg{}, fp, cmn.HalfCloseRuleHold},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := halfCloseResolve(c.eRule, &c.serv, c.mode)
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if got != c.want {
				t.Fatalf("resolved %d, want %d", got, c.want)
			}
		})
	}

	for _, c := range []struct {
		name  string
		eRule *ruleEnt
		serv  cmn.LbServiceArg
		mode  cmn.LBMode
	}{
		{"hold+parked", nil, cmn.LbServiceArg{HalfCloseMode: "hold+parked"}, fp},
		{"an unknown word", nil, cmn.LbServiceArg{HalfCloseMode: "yes"}, fp},
		{"hold on a service that is not fullproxy", nil, cmn.LbServiceArg{HalfCloseMode: "hold"}, cmn.LBModeDefault},
		// A replace that keeps a stored hold cannot move it off fullproxy either.
		{"hold kept on a service that is not fullproxy", stored, cmn.LbServiceArg{}, cmn.LBModeDefault},
		{"hold on a TLS-terminating service", nil, cmn.LbServiceArg{HalfCloseMode: "hold", Security: cmn.LBServHTTPS}, fp},
		{"hold on an end-to-end TLS service", nil, cmn.LbServiceArg{HalfCloseMode: "hold", Security: cmn.LBServE2EHTTPS}, fp},
		{"hold on a P/D service", nil, cmn.LbServiceArg{HalfCloseMode: "hold", PDDisaggMode: true}, fp},
		// Either order of the same combination: hold given to a P/D rule, and
		// P/D switched on under a stored hold by a replace that omits the field.
		{"hold given to a P/D rule by a replace", &ruleEnt{},
			cmn.LbServiceArg{HalfCloseMode: "hold", HalfCloseModePresent: true, PDDisaggMode: true}, fp},
		{"P/D switched on under a stored hold", stored, cmn.LbServiceArg{PDDisaggMode: true}, fp},
		// A replace is judged on the stored security mode, which cannot change:
		// a TLS rule replaced without naming its security is still TLS.
		{"hold given to a TLS rule by a replace that omits security", &ruleEnt{secMode: cmn.LBServHTTPS},
			cmn.LbServiceArg{HalfCloseMode: "hold", HalfCloseModePresent: true}, fp},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := halfCloseResolve(c.eRule, &c.serv, c.mode)
			var invalid *cmn.ValidationError
			if !errors.As(err, &invalid) {
				t.Fatalf("err=%v, want a validation refusal", err)
			}
		})
	}

	for m, want := range map[uint8]string{
		cmn.HalfCloseRuleUnset: "", cmn.HalfCloseRuleOff: "off", cmn.HalfCloseRuleHold: "hold",
	} {
		if got := cmn.HalfCloseModeFromRule(m); got != want {
			t.Fatalf("read back %d as %q, want %q", m, got, want)
		}
	}
}

// The mode a rule sends the data plane and the mode its GET shows come from
// the same check: a rule that leaves its mode unset is sent unset (the
// process default) exactly where the default is shown as reaching it, and
// off - with the reason shown - where hold is refused on it.
func TestHalfCloseRuleModeAndEffective(t *testing.T) {
	rule := func(mode cmn.LBMode, sec cmn.LBSec, pd bool, hc uint8) *ruleEnt {
		return &ruleEnt{act: ruleAct{action: &ruleLBActs{mode: mode}},
			secMode: sec, pdDisaggMode: pd, halfCloseMode: hc}
	}
	fp, plain := cmn.LBModeFullProxy, cmn.LBServPlain
	allowOff := cmn.HalfCloseConfig{Allow: true, CapSeconds: 240, DefaultMode: cmn.HalfCloseModeOff}
	allowHold := cmn.HalfCloseConfig{Allow: true, CapSeconds: 240, DefaultMode: cmn.HalfCloseModeHold}
	blocked := cmn.HalfCloseConfig{Allow: false, CapSeconds: 240, DefaultMode: cmn.HalfCloseModeHold}
	for _, c := range []struct {
		name   string
		r      *ruleEnt
		cfg    cmn.HalfCloseConfig
		dp     uint8
		mode   string
		source string
		notApp bool
	}{
		{"unset, plain fullproxy, default hold", rule(fp, plain, false, cmn.HalfCloseRuleUnset), allowHold,
			cmn.HalfCloseRuleUnset, "hold", "default", false},
		{"unset, plain fullproxy, default off", rule(fp, plain, false, cmn.HalfCloseRuleUnset), allowOff,
			cmn.HalfCloseRuleUnset, "off", "default", false},
		{"unset, TLS", rule(fp, cmn.LBServHTTPS, false, cmn.HalfCloseRuleUnset), allowHold,
			cmn.HalfCloseRuleOff, "off", "default", true},
		{"unset, end-to-end TLS", rule(fp, cmn.LBServE2EHTTPS, false, cmn.HalfCloseRuleUnset), allowHold,
			cmn.HalfCloseRuleOff, "off", "default", true},
		{"unset, P/D", rule(fp, plain, true, cmn.HalfCloseRuleUnset), allowHold,
			cmn.HalfCloseRuleOff, "off", "default", true},
		{"unset, not fullproxy", rule(cmn.LBModeDefault, plain, false, cmn.HalfCloseRuleUnset), allowHold,
			cmn.HalfCloseRuleOff, "off", "default", true},
		{"own hold over default off", rule(fp, plain, false, cmn.HalfCloseRuleHold), allowOff,
			cmn.HalfCloseRuleHold, "hold", "rule", false},
		{"own off over default hold", rule(fp, plain, false, cmn.HalfCloseRuleOff), allowHold,
			cmn.HalfCloseRuleOff, "off", "rule", false},
		{"blocked over own hold", rule(fp, plain, false, cmn.HalfCloseRuleHold), blocked,
			cmn.HalfCloseRuleHold, "off", "blocked", false},
		{"blocked over default hold", rule(fp, plain, false, cmn.HalfCloseRuleUnset), blocked,
			cmn.HalfCloseRuleUnset, "off", "blocked", false},
		// A document written before the default existed carries none: off.
		{"empty default reads off", rule(fp, plain, false, cmn.HalfCloseRuleUnset),
			cmn.HalfCloseConfig{Allow: true, CapSeconds: 240}, cmn.HalfCloseRuleUnset, "off", "default", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := c.r.halfCloseDpMode(); got != c.dp {
				t.Fatalf("data plane mode %d, want %d", got, c.dp)
			}
			eff := c.r.halfCloseEffective(c.cfg)
			if eff.Mode != c.mode || eff.Source != c.source || (eff.NotApplied != "") != c.notApp {
				t.Fatalf("effective %+v, want mode=%s source=%s not_applied=%v", *eff, c.mode, c.source, c.notApp)
			}
			// Sent off for an unset rule exactly where the default is shown
			// as not reaching it.
			if c.r.halfCloseMode == cmn.HalfCloseRuleUnset &&
				(c.r.halfCloseDpMode() == cmn.HalfCloseRuleOff) != (c.r.halfCloseRefusal() != "") {
				t.Fatalf("sent %d but the refusal reads %q", c.r.halfCloseDpMode(), c.r.halfCloseRefusal())
			}
			if eff.NotApplied != "" && eff.NotApplied != c.r.halfCloseRefusal() {
				t.Fatalf("not_applied %q, refusal %q", eff.NotApplied, c.r.halfCloseRefusal())
			}
		})
	}
}
