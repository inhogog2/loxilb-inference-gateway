/*
 * Copyright (c) 2025 LoxiLB Authors
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

// Clock-template attestation: a template that prints the current date
// renders differently every day, so the probe must derive its expectation
// at check time (and re-derive once across a UTC midnight) instead of
// comparing against ids banked on one day.

package loxinet

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	kvClockTestModel = "acme/clock-model"
	kvClockTestTpl   = "Today {{ strftime_now('%d %b %Y') }}|{% for m in messages %}{{ m.content }}{% endfor %}"
	kvClockTestReq   = `{"model":"acme/clock-model","messages":[{"role":"user","content":"hi"}]}`
)

// kvClockTestEncode is a byte-per-id fake tokenizer: any render difference
// is an id difference.
func kvClockTestEncode(text string) []int64 {
	out := make([]int64, len(text))
	for i := 0; i < len(text); i++ {
		out[i] = int64(text[i])
	}
	return out
}

// kvClockTestSetup publishes a utc-date profile, installs the fake encoder
// and returns a fixture whose banked ids are the render at oracleNow.
func kvClockTestSetup(t *testing.T, oracleNow time.Time) kvProbeFixture {
	t.Helper()
	kvTestPublishChatProfile(t, kvClockTestModel, kvClockTestTpl,
		KvRenderPolicy{ClockPolicy: KvClockPolicyUTCDate})
	prevEnc := kvTrtllmOracleEncodeFn
	kvTrtllmOracleEncodeFn = func(text, model string, max int, addSpecials bool) []uint32 {
		ids := kvClockTestEncode(text)
		out := make([]uint32, len(ids))
		for i, id := range ids {
			out[i] = uint32(id)
		}
		return out
	}
	prevClock := kvChatClock
	t.Cleanup(func() { kvTrtllmOracleEncodeFn = prevEnc; kvChatClock = prevClock })
	return kvProbeFixture{
		Name:         "chat-clock",
		RequestBytes: []byte(kvClockTestReq),
		ExpectedIDs:  kvClockTestEncode(kvClockTestRender(oracleNow)),
		API:          "chat",
		OracleNow:    oracleNow,
	}
}

func kvClockTestRender(at time.Time) string {
	return "Today " + at.UTC().Format("02 Jan 2006") + "|hi"
}

// kvClockTestEngine answers /tokenize with the render of the day it holds
// and counts how often it was asked.
func kvClockTestEngine(t *testing.T, day *atomic.Value, hits *int32) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(hits, 1)
		ids := kvClockTestEncode(kvClockTestRender(day.Load().(time.Time)))
		raw, _ := json.Marshal(ids)
		fmt.Fprintf(w, `{"count":%d,"tokens":%s,"max_model_len":4096}`, len(ids), raw)
	}))
	t.Cleanup(ts.Close)
	return ts
}

func kvClockProbe(ts *httptest.Server, fx kvProbeFixture) KvAttestFinding {
	return kvTokenizeFixtureProbe(newKvVllmAttest().client, ts.URL+"/tokenize", fx, kvClockTestModel)
}

// TestKvClockFixtureDerivedAtProbeTime: days after the fixture was banked,
// an engine printing today's UTC date still attests; an engine printing a
// different date (a TZ offset window, or a frontend without strftime_now)
// is a token mismatch.
func TestKvClockFixtureDerivedAtProbeTime(t *testing.T) {
	oracleNow := time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)
	fx := kvClockTestSetup(t, oracleNow)
	today := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	kvChatClock = func() time.Time { return today }

	var day atomic.Value
	var hits int32
	ts := kvClockTestEngine(t, &day, &hits)

	day.Store(today)
	if f := kvClockProbe(ts, fx); !f.OK {
		t.Fatalf("engine on today's UTC date must attest %d days after banking: %s %s",
			6, f.Reason, f.Detail)
	}
	day.Store(today.Add(-24 * time.Hour))
	if f := kvClockProbe(ts, fx); f.OK || f.Reason != KvAttestReasonTokenMismatch {
		t.Fatalf("engine on yesterday's date must be a token mismatch, got %+v", f)
	}
	day.Store(time.Date(2024, 7, 26, 0, 0, 0, 0, time.UTC)) // the Llama-3.2 fallback date
	if f := kvClockProbe(ts, fx); f.OK || f.Reason != KvAttestReasonTokenMismatch {
		t.Fatalf("engine without strftime_now (fallback date) must be a token mismatch, got %+v", f)
	}
}

// TestKvClockFixtureMidnightRederive: the UTC date turns between the
// gateway's derivation and the engine's render. The engine holding the new
// day is correct, so the probe re-derives once on the new day; on an
// unchanged day a mismatch is final.
func TestKvClockFixtureMidnightRederive(t *testing.T) {
	fx := kvClockTestSetup(t, time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC))
	before := time.Date(2026, 10, 5, 23, 59, 59, 0, time.UTC)
	after := before.Add(2 * time.Second)
	var calls int32
	kvChatClock = func() time.Time {
		if atomic.AddInt32(&calls, 1) == 1 {
			return before
		}
		return after
	}

	var day atomic.Value
	var hits int32
	ts := kvClockTestEngine(t, &day, &hits)
	day.Store(after)
	if f := kvClockProbe(ts, fx); !f.OK {
		t.Fatalf("engine on the new UTC day must attest after the re-derive: %s %s", f.Reason, f.Detail)
	}

	// Same day throughout: no second derivation rescues a wrong engine.
	kvChatClock = func() time.Time { return before }
	day.Store(before.Add(-24 * time.Hour))
	if f := kvClockProbe(ts, fx); f.OK || f.Reason != KvAttestReasonTokenMismatch {
		t.Fatalf("same-day mismatch must stay a token mismatch, got %+v", f)
	}
}

// TestKvClockFixtureStaleOracleRefused: the banked ids must be the gateway's
// own render at oracleNow. A fixture whose ids belong to another instant is
// refused before the engine is asked.
func TestKvClockFixtureStaleOracleRefused(t *testing.T) {
	oracleNow := time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)
	fx := kvClockTestSetup(t, oracleNow)
	fx.ExpectedIDs = kvClockTestEncode(kvClockTestRender(oracleNow.Add(24 * time.Hour)))
	kvChatClock = func() time.Time { return oracleNow }

	var day atomic.Value
	var hits int32
	ts := kvClockTestEngine(t, &day, &hits)
	day.Store(oracleNow)
	f := kvClockProbe(ts, fx)
	if f.OK || f.Reason != KvAttestReasonTokenMismatch || !strings.Contains(f.Detail, "oracle") {
		t.Fatalf("stale banked ids must fail the oracle check, got %+v", f)
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Fatalf("engine was asked %d times; the oracle check must run first", hits)
	}
}

// TestKvFixtureSetClockPairing: a clock-declaring profile needs oracleNow on
// every chat fixture, and oracleNow belongs only to a clock-declaring
// profile.
func TestKvFixtureSetClockPairing(t *testing.T) {
	info := kvAttestRuleInfo{modelName: kvClockTestModel, apiChat: true}
	fx := kvClockTestSetup(t, time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC))

	if f := kvFixtureSetCheck([]kvProbeFixture{fx}, info); !f.OK {
		t.Fatalf("clock profile + oracleNow fixture must pass: %s %s", f.Reason, f.Detail)
	}
	static := fx
	static.OracleNow = time.Time{}
	if f := kvFixtureSetCheck([]kvProbeFixture{static}, info); f.OK || f.Reason != KvAttestReasonFixturesMissing {
		t.Fatalf("static chat fixture on a clock profile must be refused, got %+v", f)
	}

	kvTestPublishChatProfile(t, kvClockTestModel, "{% for m in messages %}{{ m.content }}{% endfor %}", KvRenderPolicy{})
	if f := kvFixtureSetCheck([]kvProbeFixture{fx}, info); f.OK || f.Reason != KvAttestReasonFixturesMissing {
		t.Fatalf("oracleNow fixture on a profile without a clock policy must be refused, got %+v", f)
	}
	if f := kvFixtureSetCheck([]kvProbeFixture{static}, info); !f.OK {
		t.Fatalf("static chat fixture without a clock policy must pass: %s %s", f.Reason, f.Detail)
	}
}

// TestKvProbeFixtureOracleNowOnlyOnChat: the loader refuses oracleNow on a
// completions fixture (only a chat render reads the clock).
func TestKvProbeFixtureOracleNowOnlyOnChat(t *testing.T) {
	root := kvAttestFixtureRoot(t, "prof-clock", "m-probe")
	req := []byte(`{"model":"m-probe","prompt":"p"}`)
	kvWriteProbeFixture(t, root, "prof-clock", "plain", req, []int64{1})
	expPath := filepath.Join(root, "probefixtures", "prof-clock", "plain.expect.json")
	raw, err := os.ReadFile(expPath)
	if err != nil {
		t.Fatal(err)
	}
	var exp map[string]any
	if err := json.Unmarshal(raw, &exp); err != nil {
		t.Fatal(err)
	}
	exp["oracleNow"] = "2026-09-29T10:00:00Z"
	raw, _ = json.Marshal(exp)
	if err := os.WriteFile(expPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := kvProbeFixturesLoadDir("probefixtures/prof-clock"); err == nil || !strings.Contains(err.Error(), "oracleNow") {
		t.Fatalf("oracleNow on a completions fixture must be refused, got %v", err)
	}
}
