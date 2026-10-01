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

// The admission gate's rule fields round trip like the queue pair: a POST
// declaration reaches the rule layer with its presence, a value the data
// plane could not honour is refused before any rule hook runs, GET reports
// the declaration and the data plane's resolved state with the source of
// each value, and PATCH overlays only the keys present.

const fcGateAll = `,"fc_mode":"enforce","fc_max_outstanding":8,"fc_ep_max_inflight":4,` +
	`"fc_prefill_max_inflight":2,"fc_decode_max_inflight":6,"fc_telemetry_stale_ms":60000`

func TestFcGateCreateCopiesDeclaration(t *testing.T) {
	prev := ApiHooks
	defer func() { ApiHooks = prev }()

	stub := &stubLbAddHook{}
	ApiHooks = stub
	res := ConfigPostLoadbalancer(connectionLimitCreateParams(t, sprintfBody(connectionLimitCreateBody, fcGateAll)), nil)
	if stub.captured == nil {
		t.Fatalf("create handler never reached NetLbRuleAdd: %T", res)
	}
	s := stub.captured.Serv
	if s.FcMode != "enforce" || !s.FcModePresent || s.FcMaxOutstanding != 8 || s.FcEpMaxInflight != 4 ||
		s.FcPrefillMaxInflight != 2 || s.FcDecodeMaxInflight != 6 || s.FcTelemetryStaleMs != 60000 {
		t.Fatalf("reached the rule layer as %+v", s)
	}
	if !s.FcMaxOutstandingPresent || !s.FcEpMaxInflightPresent || !s.FcPrefillMaxInflightPresent ||
		!s.FcDecodeMaxInflightPresent || !s.FcTelemetryStaleMsPresent {
		t.Fatalf("a declared field lost its presence bit: %+v", s)
	}

	// Omitted: nothing declared and nothing present, so a replace keeps the
	// stored value. Explicit zero and "inherit": present, so a replace resets.
	for _, c := range []struct {
		name, field string
		present     bool
	}{
		{"omitted", ``, false},
		{"explicit zero and inherit", `,"fc_mode":"inherit","fc_max_outstanding":0,"fc_telemetry_stale_ms":0`, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			stub := &stubLbAddHook{}
			ApiHooks = stub
			ConfigPostLoadbalancer(connectionLimitCreateParams(t, sprintfBody(connectionLimitCreateBody, c.field)), nil)
			if stub.captured == nil {
				t.Fatal("never reached the rule layer")
			}
			s := stub.captured.Serv
			if s.FcMaxOutstanding != 0 || s.FcTelemetryStaleMs != 0 {
				t.Fatalf("zero reached the rule layer as %d / %d", s.FcMaxOutstanding, s.FcTelemetryStaleMs)
			}
			if s.FcModePresent != c.present || s.FcMaxOutstandingPresent != c.present ||
				s.FcTelemetryStaleMsPresent != c.present {
				t.Fatalf("presence %v/%v/%v, want %v", s.FcModePresent, s.FcMaxOutstandingPresent,
					s.FcTelemetryStaleMsPresent, c.present)
			}
		})
	}
}

func TestFcGateCreateRefusedBeforeRuleHook(t *testing.T) {
	prev := ApiHooks
	defer func() { ApiHooks = prev }()

	for _, c := range []struct{ name, field string }{
		{"null mode", `,"fc_mode":null`},
		{"null ceiling", `,"fc_max_outstanding":null`},
		{"an unknown mode", `,"fc_mode":"yes"`},
		{"a ceiling above 100000", `,"fc_max_outstanding":100001`},
		{"a negative endpoint ceiling", `,"fc_ep_max_inflight":-1`},
		{"a prefill ceiling above 100000", `,"fc_prefill_max_inflight":100001`},
		{"a decode ceiling above 100000", `,"fc_decode_max_inflight":100001`},
		{"a telemetry window above an hour", `,"fc_telemetry_stale_ms":3600001`},
		{"null adaptive switch", `,"fc_adaptive":null`},
		{"an unknown adaptive switch", `,"fc_adaptive":"yes"`},
		{"null warm-up window", `,"fc_warmup_ms":null`},
		{"a warm-up window above an hour", `,"fc_warmup_ms":3600001`},
		{"a negative TTFT target", `,"fc_ttft_target_ms":-1`},
		{"a TTFT target above an hour", `,"fc_ttft_target_ms":3600001`},
		{"null tenant share", `,"fc_tenant_max_share_pct":null`},
		{"a negative tenant share", `,"fc_tenant_max_share_pct":-1`},
		{"a tenant share above 100", `,"fc_tenant_max_share_pct":101`},
		{"null admission headers switch", `,"fc_expose_headers":null`},
		{"an admission headers switch not on, off or inherit", `,"fc_expose_headers":"yes"`},
	} {
		t.Run(c.name, func(t *testing.T) {
			stub := &stubLbAddHook{}
			ApiHooks = stub
			res := ConfigPostLoadbalancer(connectionLimitCreateParams(t, sprintfBody(connectionLimitCreateBody, c.field)), nil)
			if stub.captured != nil {
				t.Fatalf("%s reached the rule layer as %+v", c.name, stub.captured.Serv)
			}
			if _, ok := res.(*ResultResponse); ok {
				t.Fatalf("%s answered success: %T", c.name, res)
			}
		})
	}
}

func TestFcGateReadBack(t *testing.T) {
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

	// Nothing declared: every key absent, so a rule reads as it did before.
	m := wireOf()
	for _, k := range fcGateKeys {
		if _, ok := m[k]; ok {
			t.Fatalf("%s present on the wire with nothing declared", k)
		}
	}

	lb.Serv.FcMode = "observe"
	lb.Serv.FcMaxOutstanding = 8
	lb.Serv.FcEpMaxInflight = 4
	lb.Serv.FcPrefillMaxInflight = 2
	lb.Serv.FcDecodeMaxInflight = 6
	lb.Serv.FcTelemetryStaleMs = 60000
	lb.Serv.FcEffective = &cmn.FcEffectiveArg{
		Mode: "observe", MaxOutstanding: 8, EpMaxInflight: 4, PrefillMaxInflight: 2,
		DecodeMaxInflight: 6, TelemetryStaleMs: 60000,
		Source: cmn.FcEffectiveSource{Mode: "rule", MaxOutstanding: "rule", EpMaxInflight: "rule",
			PrefillMaxInflight: "rule", DecodeMaxInflight: "rule", QueueDepth: "env",
			QueueWaitMs: "default", TelemetryStaleMs: "rule"},
	}
	m = wireOf()
	if m["fc_mode"] != "observe" {
		t.Fatalf("wire fc_mode = %v, want observe", m["fc_mode"])
	}
	for k, w := range map[string]float64{"fc_max_outstanding": 8, "fc_ep_max_inflight": 4,
		"fc_prefill_max_inflight": 2, "fc_decode_max_inflight": 6, "fc_telemetry_stale_ms": 60000} {
		if v, ok := m[k]; !ok || v.(float64) != w {
			t.Fatalf("wire %s = %v (present %v), want %v", k, v, ok, w)
		}
	}
	eff, ok := m["fc_effective"].(map[string]any)
	if !ok {
		t.Fatalf("fc_effective absent: %v", m["fc_effective"])
	}
	if v, ok := eff["telemetry_stale_ms"]; !ok || v.(float64) != 60000 {
		t.Fatalf("fc_effective.telemetry_stale_ms = %v (present %v), want 60000", v, ok)
	}
	src, ok := eff["source"].(map[string]any)
	if !ok {
		t.Fatalf("fc_effective.source absent: %v", eff["source"])
	}
	for k, w := range map[string]string{"mode": "rule", "max_outstanding": "rule", "ep_max_inflight": "rule",
		"prefill_max_inflight": "rule", "decode_max_inflight": "rule", "queue_depth": "env",
		"queue_wait_ms": "default", "telemetry_stale_ms": "rule"} {
		if src[k] != w {
			t.Fatalf("fc_effective.source.%s = %v, want %s", k, src[k], w)
		}
	}
}

func TestFcGatePatchOverlay(t *testing.T) {
	prev := ApiHooks
	defer func() { ApiHooks = prev }()

	current := cmn.LbRuleMod{}
	current.Serv.ServIP = "20.20.20.5"
	current.Serv.ServPort = 8080
	current.Serv.Proto = "tcp"
	current.Serv.FcMode = "enforce"
	current.Serv.FcMaxOutstanding = 8

	for _, c := range []struct {
		name     string
		raw      string
		wantMode string
		wantMax  uint32
	}{
		{"ceiling raised, mode kept", `{"serviceArguments":{"fc_max_outstanding":16}}`, "enforce", 16},
		{"absent is preserved", `{"serviceArguments":{"name":"kept"}}`, "enforce", 8},
		{"mode switched off", `{"serviceArguments":{"fc_mode":"off"}}`, "off", 8},
	} {
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
			if got := stub.captured.Serv; got.FcMode != c.wantMode || got.FcMaxOutstanding != c.wantMax {
				t.Fatalf("merged %q / %d, want %q / %d", got.FcMode, got.FcMaxOutstanding, c.wantMode, c.wantMax)
			}
		})
	}

	stub := &stubLbAddHook{rules: []cmn.LbRuleMod{current}}
	ApiHooks = stub
	res := ConfigPatchLoadbalancer(connectionLimitPatchParams(t, `{"serviceArguments":{"fc_max_outstanding":null}}`), nil)
	if _, ok := res.(*operations.PatchConfigLoadbalancerExternalipaddressIPAddressPortPortProtocolProtoBadRequest); !ok {
		t.Fatalf("null answered %T, want PATCH 400", res)
	}
	if stub.captured != nil {
		t.Fatal("the refused value reached the rule layer")
	}
}

// The adaptive switch, the warm-up window and the TTFT target reach the rule
// layer as declared, each with its presence bit, like the rest of the gate.
func TestFcAdaptCreateCopiesDeclaration(t *testing.T) {
	prev := ApiHooks
	defer func() { ApiHooks = prev }()

	for _, c := range []struct {
		name, field      string
		adaptive         string
		warmup, ttft     uint32
		present, adPrsnt bool
	}{
		{"declared", `,"fc_adaptive":"on","fc_warmup_ms":20000,"fc_ttft_target_ms":800`, "on", 20000, 800, true, true},
		{"omitted", ``, "", 0, 0, false, false},
		{"explicit zero and inherit", `,"fc_adaptive":"inherit","fc_warmup_ms":0,"fc_ttft_target_ms":0`, "inherit", 0, 0, true, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			stub := &stubLbAddHook{}
			ApiHooks = stub
			ConfigPostLoadbalancer(connectionLimitCreateParams(t, sprintfBody(connectionLimitCreateBody, c.field)), nil)
			if stub.captured == nil {
				t.Fatal("never reached the rule layer")
			}
			s := stub.captured.Serv
			if s.FcAdaptive != c.adaptive || s.FcWarmupMs != c.warmup || s.FcTtftTargetMs != c.ttft {
				t.Fatalf("reached the rule layer as %q/%d/%d", s.FcAdaptive, s.FcWarmupMs, s.FcTtftTargetMs)
			}
			if s.FcAdaptivePresent != c.adPrsnt || s.FcWarmupMsPresent != c.present ||
				s.FcTtftTargetMsPresent != c.present {
				t.Fatalf("presence %v/%v/%v", s.FcAdaptivePresent, s.FcWarmupMsPresent, s.FcTtftTargetMsPresent)
			}
		})
	}
}

// The tenant share reaches the rule layer as declared, with its presence
// bit, like the rest of the gate.
func TestFcTenantShareCreateCopiesDeclaration(t *testing.T) {
	prev := ApiHooks
	defer func() { ApiHooks = prev }()

	for _, c := range []struct {
		name, field string
		pct         uint32
		present     bool
	}{
		{"declared", `,"fc_tenant_max_share_pct":30`, 30, true},
		{"omitted", ``, 0, false},
		{"explicit zero", `,"fc_tenant_max_share_pct":0`, 0, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			stub := &stubLbAddHook{}
			ApiHooks = stub
			ConfigPostLoadbalancer(connectionLimitCreateParams(t, sprintfBody(connectionLimitCreateBody, c.field)), nil)
			if stub.captured == nil {
				t.Fatal("never reached the rule layer")
			}
			s := stub.captured.Serv
			if s.FcTenantMaxSharePct != c.pct || s.FcTenantMaxSharePctPresent != c.present {
				t.Fatalf("reached the rule layer as %d (present %v)", s.FcTenantMaxSharePct, s.FcTenantMaxSharePctPresent)
			}
		})
	}
}

// The admission headers switch reaches the rule layer as declared, with its
// presence bit, like the adaptive switch.
func TestFcExposeHeadersCreateCopiesDeclaration(t *testing.T) {
	prev := ApiHooks
	defer func() { ApiHooks = prev }()

	for _, c := range []struct {
		name, field, want string
		present           bool
	}{
		{"on", `,"fc_expose_headers":"on"`, "on", true},
		{"off", `,"fc_expose_headers":"off"`, "off", true},
		{"inherit", `,"fc_expose_headers":"inherit"`, "inherit", true},
		{"omitted", ``, "", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			stub := &stubLbAddHook{}
			ApiHooks = stub
			ConfigPostLoadbalancer(connectionLimitCreateParams(t, sprintfBody(connectionLimitCreateBody, c.field)), nil)
			if stub.captured == nil {
				t.Fatal("never reached the rule layer")
			}
			s := stub.captured.Serv
			if s.FcExposeHeaders != c.want || s.FcExposeHeadersPresent != c.present {
				t.Fatalf("reached the rule layer as %q (present %v)", s.FcExposeHeaders, s.FcExposeHeadersPresent)
			}
		})
	}
}
