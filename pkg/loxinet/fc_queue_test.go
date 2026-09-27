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

// A replace is judged on the rule it leaves behind. Stored 10 / 3000 is the
// starting point of every replace case: one carrying only a new depth keeps
// the stored wait and is accepted; one carrying only a zero wait would leave
// the depth without a window and is refused, whatever the request alone says.
func TestFcQueueResolveJudgesTheStoredResult(t *testing.T) {
	stored := &ruleEnt{fcMaxQueueDepth: 10, fcMaxQueueWaitMs: 3000}
	cases := []struct {
		name      string
		eRule     *ruleEnt
		serv      cmn.LbServiceArg
		wantDepth uint32
		wantWait  uint32
		wantErr   bool
	}{
		{"create: both declared", nil,
			cmn.LbServiceArg{FcMaxQueueDepth: 4, FcMaxQueueWaitMs: 4000}, 4, 4000, false},
		{"create: a depth without a window", nil,
			cmn.LbServiceArg{FcMaxQueueDepth: 4}, 0, 0, true},
		{"create: neither, the process default", nil,
			cmn.LbServiceArg{}, 0, 0, false},
		{"replace: only a new depth keeps the stored wait", stored,
			cmn.LbServiceArg{FcMaxQueueDepth: 20, FcMaxQueueDepthPresent: true}, 20, 3000, false},
		{"replace: only a zero wait would strand the stored depth", stored,
			cmn.LbServiceArg{FcMaxQueueWaitMs: 0, FcMaxQueueWaitMsPresent: true}, 0, 0, true},
		{"replace: both reset to the process default", stored,
			cmn.LbServiceArg{FcMaxQueueDepthPresent: true, FcMaxQueueWaitMsPresent: true}, 0, 0, false},
		{"replace: neither present keeps both", stored,
			cmn.LbServiceArg{}, 10, 3000, false},
		{"replace: a zero depth alone keeps the wait for an environment depth", stored,
			cmn.LbServiceArg{FcMaxQueueDepthPresent: true}, 0, 3000, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			depth, wait, err := fcQueueResolve(c.eRule, &c.serv)
			if c.wantErr {
				var invalid *cmn.ValidationError
				if !errors.As(err, &invalid) {
					t.Fatalf("got depth=%d wait=%d err=%v, want a validation refusal", depth, wait, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if depth != c.wantDepth || wait != c.wantWait {
				t.Fatalf("resolved %d / %d, want %d / %d", depth, wait, c.wantDepth, c.wantWait)
			}
		})
	}
}
