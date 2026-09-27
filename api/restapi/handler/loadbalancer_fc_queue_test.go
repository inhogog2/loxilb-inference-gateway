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
package handler

import (
	"encoding/json"
	"testing"

	"github.com/loxilb-io/loxilb/api/restapi/operations"
	cmn "github.com/loxilb-io/loxilb/common"
)

// The capacity queue's two fields round trip the way connectionLimit does:
// a POST declaration reaches the rule layer, a value the data plane could
// not honour is refused before any rule hook runs, GET reports the stored
// values and the data plane's effective state, and PATCH overlays only the
// keys present. The bounds asserted here are the ones the data plane holds
// (a depth of 65536 waiters, an hour of waiting) and the one rule that has no
// numeric form: a depth without a wait window would park a request forever.

func TestFcQueueCreateCopiesDeclaration(t *testing.T) {
	prev := ApiHooks
	defer func() { ApiHooks = prev }()

	cases := []struct {
		name      string
		field     string
		wantDepth uint32
		wantWait  uint32
	}{
		{"declared", `,"fc_max_queue_depth":4,"fc_max_queue_wait_ms":4000`, 4, 4000},
		{"omitted keeps the process default", ``, 0, 0},
		{"explicit zero keeps the process default", `,"fc_max_queue_depth":0,"fc_max_queue_wait_ms":0`, 0, 0},
		{"the ceilings", `,"fc_max_queue_depth":65536,"fc_max_queue_wait_ms":3600000`, 65536, 3600000},
		{"a wait alone is kept for a depth the environment sets", `,"fc_max_queue_wait_ms":250`, 0, 250},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stub := &stubLbAddHook{}
			ApiHooks = stub
			raw := sprintfBody(connectionLimitCreateBody, c.field)
			res := ConfigPostLoadbalancer(connectionLimitCreateParams(t, raw), nil)
			if stub.captured == nil {
				t.Fatalf("create handler never reached NetLbRuleAdd: %T", res)
			}
			if got := stub.captured.Serv.FcMaxQueueDepth; got != c.wantDepth {
				t.Fatalf("fc_max_queue_depth reached the rule layer as %d, want %d", got, c.wantDepth)
			}
			if got := stub.captured.Serv.FcMaxQueueWaitMs; got != c.wantWait {
				t.Fatalf("fc_max_queue_wait_ms reached the rule layer as %d, want %d", got, c.wantWait)
			}
		})
	}
}

func TestFcQueueCreateRefusedBeforeRuleHook(t *testing.T) {
	prev := ApiHooks
	defer func() { ApiHooks = prev }()

	cases := []struct {
		name  string
		field string
	}{
		{"null depth", `,"fc_max_queue_depth":null,"fc_max_queue_wait_ms":1000`},
		{"null wait", `,"fc_max_queue_depth":4,"fc_max_queue_wait_ms":null`},
		{"a depth without a wait window", `,"fc_max_queue_depth":4`},
		{"a depth above the ceiling", `,"fc_max_queue_depth":65537,"fc_max_queue_wait_ms":1000`},
		{"a wait above an hour", `,"fc_max_queue_depth":4,"fc_max_queue_wait_ms":3600001`},
		{"a negative depth", `,"fc_max_queue_depth":-1,"fc_max_queue_wait_ms":1000`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stub := &stubLbAddHook{}
			ApiHooks = stub
			raw := sprintfBody(connectionLimitCreateBody, c.field)
			res := ConfigPostLoadbalancer(connectionLimitCreateParams(t, raw), nil)
			if stub.captured != nil {
				t.Fatalf("%s reached the rule layer as depth=%d wait=%d", c.name,
					stub.captured.Serv.FcMaxQueueDepth, stub.captured.Serv.FcMaxQueueWaitMs)
			}
			if _, ok := res.(*ResultResponse); ok {
				t.Fatalf("%s answered success: %T", c.name, res)
			}
		})
	}
}

func TestFcQueueReadBack(t *testing.T) {
	lb := cmn.LbRuleMod{}
	lb.Serv.ServIP = "20.20.20.5"
	lb.Serv.ServPort = 8080
	lb.Serv.Proto = "tcp"

	wireOf := func() map[string]any {
		wire, err := json.Marshal(serializeLBRule(lb).ServiceArguments)
		if err != nil {
			t.Fatal(err)
		}
		m := map[string]any{}
		if err := json.Unmarshal(wire, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}

	// Nothing declared, nothing read from the data plane: the three keys are
	// absent, so a rule that predates the queue reads exactly as it did.
	m := wireOf()
	for _, k := range []string{"fc_max_queue_depth", "fc_max_queue_wait_ms", "fc_effective"} {
		if _, ok := m[k]; ok {
			t.Fatalf("%s present on the wire with nothing declared", k)
		}
	}

	lb.Serv.FcMaxQueueDepth = 4
	lb.Serv.FcMaxQueueWaitMs = 4000
	lb.Serv.FcEffective = &cmn.FcEffectiveArg{
		Mode: "enforce", MaxOutstanding: 8, EpMaxInflight: 5,
		QueueDepth: 4, QueueWaitMs: 4000, Inflight: 8, Queued: 2, QueueMemoryBoundMib: 4,
	}
	m = wireOf()
	if v, ok := m["fc_max_queue_depth"]; !ok || v.(float64) != 4 {
		t.Fatalf("wire fc_max_queue_depth = %v (present %v), want 4", v, ok)
	}
	if v, ok := m["fc_max_queue_wait_ms"]; !ok || v.(float64) != 4000 {
		t.Fatalf("wire fc_max_queue_wait_ms = %v (present %v), want 4000", v, ok)
	}
	eff, ok := m["fc_effective"].(map[string]any)
	if !ok {
		t.Fatalf("fc_effective absent or not an object: %v", m["fc_effective"])
	}
	want := map[string]float64{
		"max_outstanding": 8, "ep_max_inflight": 5, "queue_depth": 4, "queue_wait_ms": 4000,
		"inflight": 8, "queued": 2, "queue_memory_bound_mib": 4,
	}
	for k, w := range want {
		if v, ok := eff[k]; !ok || v.(float64) != w {
			t.Fatalf("fc_effective.%s = %v (present %v), want %v", k, v, ok, w)
		}
	}
	if eff["mode"] != "enforce" {
		t.Fatalf("fc_effective.mode = %v, want enforce", eff["mode"])
	}
}

func TestFcQueuePatchOverlay(t *testing.T) {
	prev := ApiHooks
	defer func() { ApiHooks = prev }()

	current := cmn.LbRuleMod{}
	current.Serv.ServIP = "20.20.20.5"
	current.Serv.ServPort = 8080
	current.Serv.Proto = "tcp"
	current.Serv.FcMaxQueueDepth = 4
	current.Serv.FcMaxQueueWaitMs = 4000

	cases := []struct {
		name      string
		raw       string
		wantDepth uint32
		wantWait  uint32
	}{
		{"depth raised, wait kept", `{"serviceArguments":{"fc_max_queue_depth":8}}`, 8, 4000},
		{"absent is preserved", `{"serviceArguments":{"name":"kept"}}`, 4, 4000},
		{"explicit zero depth switches the queue off", `{"serviceArguments":{"fc_max_queue_depth":0}}`, 0, 4000},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stub := &stubLbAddHook{rules: []cmn.LbRuleMod{current}}
			ApiHooks = stub
			res := ConfigPatchLoadbalancer(connectionLimitPatchParams(t, c.raw), nil)
			if _, ok := res.(*operations.PatchConfigLoadbalancerExternalipaddressIPAddressPortPortProtocolProtoOK); !ok {
				t.Fatalf("response=%T, want PATCH 200", res)
			}
			if stub.captured == nil {
				t.Fatal("patch handler never reached NetLbRuleAdd")
			}
			if got := stub.captured.Serv.FcMaxQueueDepth; got != c.wantDepth {
				t.Fatalf("merged fc_max_queue_depth = %d, want %d", got, c.wantDepth)
			}
			if got := stub.captured.Serv.FcMaxQueueWaitMs; got != c.wantWait {
				t.Fatalf("merged fc_max_queue_wait_ms = %d, want %d", got, c.wantWait)
			}
		})
	}

	for _, c := range []struct{ name, raw string }{
		{"null rejected before the rule hook", `{"serviceArguments":{"fc_max_queue_depth":null}}`},
		{"a depth without a wait window rejected", `{"serviceArguments":{"fc_max_queue_depth":4,"fc_max_queue_wait_ms":0}}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			stub := &stubLbAddHook{rules: []cmn.LbRuleMod{current}}
			ApiHooks = stub
			res := ConfigPatchLoadbalancer(connectionLimitPatchParams(t, c.raw), nil)
			if _, ok := res.(*operations.PatchConfigLoadbalancerExternalipaddressIPAddressPortPortProtocolProtoBadRequest); !ok {
				t.Fatalf("response=%T, want PATCH 400", res)
			}
			if stub.captured != nil {
				t.Fatal("the refused value reached the rule layer")
			}
		})
	}
}
