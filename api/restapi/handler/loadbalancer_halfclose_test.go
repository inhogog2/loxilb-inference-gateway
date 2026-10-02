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
	"net/http"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

// half_close_mode round trips like fc_mode: a POST declaration reaches the
// rule layer with its presence, a value the data plane does not have is
// refused (400) before any rule hook runs, and GET reports it only when
// declared, on a fullproxy rule.

func TestHalfCloseModeCreateCopiesDeclaration(t *testing.T) {
	prev := ApiHooks
	defer func() { ApiHooks = prev }()

	for _, c := range []struct {
		name, field, want string
		present           bool
	}{
		{"hold", `,"half_close_mode":"hold"`, "hold", true},
		{"off", `,"half_close_mode":"off"`, "off", true},
		{"inherit", `,"half_close_mode":"inherit"`, "inherit", true},
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
			if s.HalfCloseMode != c.want || s.HalfCloseModePresent != c.present {
				t.Fatalf("reached the rule layer as %q (present %v)", s.HalfCloseMode, s.HalfCloseModePresent)
			}
		})
	}
}

func TestHalfCloseModeCreateRefusedBeforeRuleHook(t *testing.T) {
	prev := ApiHooks
	defer func() { ApiHooks = prev }()

	for _, c := range []struct{ name, field string }{
		{"null", `,"half_close_mode":null`},
		{"hold+parked, not available yet", `,"half_close_mode":"hold+parked"`},
		{"not one of its words", `,"half_close_mode":"yes"`},
	} {
		t.Run(c.name, func(t *testing.T) {
			stub := &stubLbAddHook{}
			ApiHooks = stub
			res := ConfigPostLoadbalancer(connectionLimitCreateParams(t, sprintfBody(connectionLimitCreateBody, c.field)), nil)
			if stub.captured != nil {
				t.Fatalf("reached the rule layer as %+v", stub.captured.Serv)
			}
			er, ok := res.(*ErrorResponse)
			if !ok {
				t.Fatalf("answered %T, want an error", res)
			}
			if er.Payload.Code != http.StatusBadRequest {
				t.Fatalf("answered %d, want 400: %s", er.Payload.Code, er.Payload.Message)
			}
		})
	}
}

func TestHalfCloseModeReadBack(t *testing.T) {
	lb := cmn.LbRuleMod{}
	lb.Serv.ServIP = "20.20.20.5"
	lb.Serv.ServPort = 8080
	lb.Serv.Proto = "tcp"
	lb.Serv.Mode = cmn.LBModeFullProxy

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

	// Not declared: absent, so a rule reads as it did before.
	if v, ok := wireOf()["half_close_mode"]; ok {
		t.Fatalf("half_close_mode present on the wire with nothing declared: %v", v)
	}
	lb.Serv.HalfCloseMode = "hold"
	if v := wireOf()["half_close_mode"]; v != "hold" {
		t.Fatalf("wire half_close_mode = %v, want hold", v)
	}
}
