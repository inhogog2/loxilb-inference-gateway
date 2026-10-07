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
	"net"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

func replaceTestEp(ip string, port uint16) ruleLBEp {
	return ruleLBEp{xIP: net.ParseIP(ip), xPort: port, weight: 1}
}

// A replace takes the members a request declares for an endpoint the rule
// already has, and counts a difference as a change. Each member is tried on
// its own, so that one of them missing from the merge shows.
func TestReplaceTakesDeclaredEndpointMembers(t *testing.T) {
	for _, c := range []struct {
		name string
		set  func(*ruleLBEp)
		got  func(ruleLBEp) bool
	}{
		{"ep_role", func(e *ruleLBEp) { e.epRole = 2 }, func(e ruleLBEp) bool { return e.epRole == 2 }},
		{"nixl_port", func(e *ruleLBEp) { e.nixlPort = 5999 }, func(e ruleLBEp) bool { return e.nixlPort == 5999 }},
		{"backup", func(e *ruleLBEp) { e.backup = true }, func(e ruleLBEp) bool { return e.backup }},
		{"subnetId", func(e *ruleLBEp) { e.subnetId = "sn-2" }, func(e ruleLBEp) bool { return e.subnetId == "sn-2" }},
		{"monitorAddress", func(e *ruleLBEp) { e.monAddr = "31.31.31.9" }, func(e ruleLBEp) bool { return e.monAddr == "31.31.31.9" }},
	} {
		old := []ruleLBEp{replaceTestEp("31.31.31.1", 8080), replaceTestEp("31.31.31.2", 8080)}
		old[0].epCreated = true
		want := []ruleLBEp{replaceTestEp("31.31.31.1", 8080), replaceTestEp("31.31.31.2", 8080)}
		c.set(&want[0])

		chg, ret, del := getLBConsolidatedEPs(old, want, cmn.LBOPAdd)
		if !chg {
			t.Errorf("%s: a changed member is not counted as a change", c.name)
		}
		if len(ret) != 2 || len(del) != 0 {
			t.Fatalf("%s: endpoint set %d kept, %d removed, want 2 and 0", c.name, len(ret), len(del))
		}
		if !c.got(ret[0]) {
			t.Errorf("%s: the endpoint keeps its old value: %+v", c.name, ret[0])
		}
		if !ret[0].epCreated {
			t.Errorf("%s: the endpoint lost what the rule knows of it", c.name)
		}
		if c.got(ret[1]) {
			t.Errorf("%s: the endpoint that was not changed took the value", c.name)
		}
	}

	// The control: the same set again is no change.
	old := []ruleLBEp{replaceTestEp("31.31.31.1", 8080)}
	old[0].epRole, old[0].monAddr = 1, "31.31.31.9"
	if chg, _, _ := getLBConsolidatedEPs(old, snapshotLBEndpoints(old), cmn.LBOPAdd); chg {
		t.Error("an identical endpoint set is counted as a change")
	}

	// A detach names endpoints and declares nothing about the ones it keeps.
	old = []ruleLBEp{replaceTestEp("31.31.31.1", 8080), replaceTestEp("31.31.31.2", 8080)}
	old[0].epRole = 1
	_, ret, del := getLBConsolidatedEPs(old, []ruleLBEp{replaceTestEp("31.31.31.2", 8080)}, cmn.LBOPDetach)
	if len(ret) != 1 || len(del) != 1 || ret[0].epRole != 1 {
		t.Errorf("detach: kept %+v removed %+v", ret, del)
	}
}

func replaceTestSources(prefixes ...string) []*allowedSrcElem {
	var out []*allowedSrcElem
	for _, p := range prefixes {
		_, n, _ := net.ParseCIDR(p)
		out = append(out, &allowedSrcElem{srcPref: n})
	}
	return out
}

func replaceTestWanted(prefixes ...string) []cmn.LbAllowedSrcIPArg {
	var out []cmn.LbAllowedSrcIPArg
	for _, p := range prefixes {
		out = append(out, cmn.LbAllowedSrcIPArg{Prefix: p})
	}
	return out
}

func TestAllowedSourcesChanged(t *testing.T) {
	for _, c := range []struct {
		name string
		have []string
		want []string
		chg  bool
	}{
		{"one source, the same", []string{"10.1.0.0/24"}, []string{"10.1.0.0/24"}, false},
		{"one source, another", []string{"10.1.0.0/24"}, []string{"10.2.0.0/24"}, true},
		{"two sources, the same", []string{"10.1.0.0/24", "10.3.0.0/24"}, []string{"10.1.0.0/24", "10.3.0.0/24"}, false},
		{"two sources, another order", []string{"10.1.0.0/24", "10.3.0.0/24"}, []string{"10.3.0.0/24", "10.1.0.0/24"}, false},
		{"two sources, one replaced", []string{"10.1.0.0/24", "10.3.0.0/24"}, []string{"10.1.0.0/24", "10.4.0.0/24"}, true},
		{"one added", []string{"10.1.0.0/24"}, []string{"10.1.0.0/24", "10.3.0.0/24"}, true},
		{"all removed", []string{"10.1.0.0/24"}, nil, true},
		{"none, none", nil, nil, false},
		{"the same prefix written with host bits", []string{"10.1.0.0/24"}, []string{"10.1.0.7/24"}, false},
		{"one prefix twice against two prefixes", []string{"10.1.0.0/24", "10.3.0.0/24"}, []string{"10.1.0.0/24", "10.1.0.0/24"}, true},
	} {
		if got := lbAllowedSourcesChanged(replaceTestSources(c.have...), replaceTestWanted(c.want...)); got != c.chg {
			t.Errorf("%s: changed = %v, want %v", c.name, got, c.chg)
		}
	}
}

func TestEndpointsToReprobe(t *testing.T) {
	old := []ruleLBEp{replaceTestEp("31.31.31.1", 8080), replaceTestEp("31.31.31.2", 8080), replaceTestEp("31.31.31.3", 8080)}
	old[0].epCreated, old[1].epCreated = true, true // the third has no probe registered
	next := snapshotLBEndpoints(old)

	if eps := lbEpsToReprobe(old, next, false); len(eps) != 0 {
		t.Errorf("nothing changed, %d endpoint(s) to register again", len(eps))
	}
	if eps := lbEpsToReprobe(old, next, true); len(eps) != 2 {
		t.Errorf("probe settings changed: %d endpoint(s) to register again, want the 2 that have a probe", len(eps))
	}

	old[1].monAddr = "31.31.31.8"
	next[1].monAddr = "31.31.31.9"
	eps := lbEpsToReprobe(old, next, false)
	if len(eps) != 1 || eps[0].monAddr != "31.31.31.8" {
		t.Fatalf("probe address changed: got %+v, want the endpoint under the address it was attached with", eps)
	}

	lbEpsMarkDetached(next, eps)
	if !next[0].epCreated || next[1].epCreated {
		t.Errorf("marks after the detach: %v %v, want true false", next[0].epCreated, next[1].epCreated)
	}
}

func TestNameClass(t *testing.T) {
	for _, c := range []struct {
		name      string
		unmanaged bool
		inst      string
	}{
		{"web", false, cmn.CIDefault},
		{"", false, cmn.CIDefault},
		{"web:zone1", false, "zone1"},
		{"ipvs_10.0.0.1:80", true, "80"},
		{"static-web", true, cmn.CIDefault},
	} {
		unmanaged, inst := lbNameClass(c.name)
		if unmanaged != c.unmanaged || inst != c.inst {
			t.Errorf("%q: got %v %q, want %v %q", c.name, unmanaged, inst, c.unmanaged, c.inst)
		}
	}
}
