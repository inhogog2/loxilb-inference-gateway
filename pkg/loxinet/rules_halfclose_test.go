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
// refused; hold is refused off fullproxy, except on a restore replay, which
// drops it.
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
