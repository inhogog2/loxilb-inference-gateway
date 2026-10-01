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

// ai_kv_attest_vllm.go — the vLLM attestation adapter's probe half (plan §5,
// vLLM-adapter-only per §17.8): byte-exact /tokenize fixture probes and the
// §6.4 identity probes. The §6.2 echo challenge half lives in
// ai_kv_attest_echo.go.
//
// Probe payloads are COMMITTED FILES, sent verbatim — no runtime templating
// of probe payloads, so what was reviewed is what goes on the wire. Each
// fixture is a pair beneath the profile-registry trust root:
//
//   probefixtures/<profileId>/<name>.request.json   exact request bytes
//   probefixtures/<profileId>/<name>.expect.json    {"requestSha256", "expectedTokenIds", "api"}
//
// Both load with the registry's trusted-file discipline (beneath-only, no
// symlinks, owner/mode/size checks), and the request bytes must hash to the
// expect file's pinned sha256 — a drifted fixture is an attestation failure,
// never silently re-pinned. A chat fixture of a clock-declaring profile
// (renderPolicy.clockPolicy) additionally pins "oracleNow", the instant its
// banked ids were rendered at: its template prints the current date, so the
// live probe derives the expected ids from the gateway's own render+encode
// at probe time, and the banked ids are the offline oracle cross-check.
// Fixture regeneration is a profile-revision event; the repo's committed source set lives under
// cicd/common/kv_hash/fixtures/probe/ and is staged to the registry root by
// deployment.
//
// Transport hardening (§5): probes go only to the rule's registered endpoint
// addresses (the URL is CONSTRUCTED from the endpoint set — there is no
// configurable probe host), redirects are refused, requests time out
// (default 5s), responses are size-capped (256 KiB), and receipts carry
// digests only.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Additional probe-layer reason codes.
const (
	KvAttestReasonFixturesMissing = "probe_fixtures_missing"
	KvAttestReasonFixtureDrift    = "probe_fixture_drift"
)

const (
	kvProbeRespCap        = 256 * 1024
	kvProbeFixtureCap     = 256 * 1024
	kvProbeTimeoutDefault = 5 * time.Second
)

var (
	kvProbeTimeoutOnce sync.Once
	kvProbeTimeoutV    = kvProbeTimeoutDefault
)

func kvProbeTimeout() time.Duration {
	kvProbeTimeoutOnce.Do(func() {
		if v := os.Getenv("LOXILB_KV_ATTEST_PROBE_TIMEOUT_S"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				kvProbeTimeoutV = time.Duration(n) * time.Second
			}
		}
	})
	return kvProbeTimeoutV
}

// kvVllmAttest implements kvAttestAdapter for the vLLM engine family. The
// echoChallenge seam lets the GPU-free suite exercise the adapter's probe
// half against httptest servers while faking the event-plane half.
type kvVllmAttest struct {
	client *http.Client
}

var (
	kvVllmAdapterOnce sync.Once
	kvVllmAdapterInst *kvVllmAttest
)

// kvVllmAdapter returns the process-wide vLLM attestation adapter.
func kvVllmAdapter() kvAttestAdapter {
	kvVllmAdapterOnce.Do(func() {
		kvVllmAdapterInst = newKvVllmAttest()
	})
	return kvVllmAdapterInst
}

func newKvVllmAttest() *kvVllmAttest {
	return &kvVllmAttest{
		client: &http.Client{
			Timeout: kvProbeTimeout(),
			// Redirects are refused outright: a probe that gets redirected
			// is no longer talking to the registered endpoint address.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return fmt.Errorf("kv-attest: probe redirect refused")
			},
		},
	}
}

// ---- fixtures ----

// kvProbeFixture is one loaded probe fixture.
type kvProbeFixture struct {
	Name          string
	RequestBytes  []byte
	RequestSha256 string
	ExpectedIDs   []int64
	API           string // "completions" | "chat"
	// OracleNow is the instant a clock-template chat fixture's banked ids
	// were rendered at; zero for every static fixture.
	OracleNow time.Time
}

// kvProbeExpect is the strict schema of <name>.expect.json.
type kvProbeExpect struct {
	RequestSha256    string  `json:"requestSha256"`
	ExpectedTokenIds []int64 `json:"expectedTokenIds"`
	API              string  `json:"api"`
	OracleNow        string  `json:"oracleNow,omitempty"`
}

// kvProbeFixturesLoad loads and verifies the fixture set for a profile from
// the registry trust root. Empty set or any verification failure returns an
// error — a strict rule cannot attest without its reviewed fixtures.
func kvProbeFixturesLoad(profileID string) ([]kvProbeFixture, error) {
	return kvProbeFixturesLoadDir("probefixtures/" + profileID)
}

// kvProbeFixturesLoadDir loads a fixture set from an explicit path beneath
// the registry trust root. Engine-scoped fixture sets (the SGLang adapter
// loads probefixtures/<profileId>/sglang) reuse the identical trusted-file
// discipline; the vLLM set stays at the profile root unchanged.
func kvProbeFixturesLoadDir(dirRel string) ([]kvProbeFixture, error) {
	root := kvAttestManifestRoot()
	rootFd, err := unix.Open(root, unix.O_DIRECTORY|unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("registry root %s: %w", root, err)
	}
	defer unix.Close(rootFd)

	dirFd, err := kvOpenBeneath(rootFd, dirRel)
	if err != nil {
		return nil, fmt.Errorf("fixture dir %s: %w", dirRel, err)
	}
	f := os.NewFile(uintptr(dirFd), dirRel)
	names, err := f.Readdirnames(-1)
	f.Close()
	if err != nil {
		return nil, fmt.Errorf("fixture dir %s: %w", dirRel, err)
	}
	sort.Strings(names)

	var out []kvProbeFixture
	for _, n := range names {
		if !strings.HasSuffix(n, ".expect.json") {
			continue
		}
		base := strings.TrimSuffix(n, ".expect.json")
		expRaw, _, err := kvReadTrustedFile(rootFd, dirRel+"/"+n, kvProbeFixtureCap)
		if err != nil {
			return nil, fmt.Errorf("fixture %s: %w", n, err)
		}
		var exp kvProbeExpect
		dec := json.NewDecoder(strings.NewReader(string(expRaw)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&exp); err != nil {
			return nil, fmt.Errorf("fixture %s: parse: %w", n, err)
		}
		if exp.API != "completions" && exp.API != "chat" {
			return nil, fmt.Errorf("fixture %s: api %q not in {completions, chat}", n, exp.API)
		}
		if len(exp.ExpectedTokenIds) == 0 || exp.RequestSha256 == "" {
			return nil, fmt.Errorf("fixture %s: missing expectedTokenIds/requestSha256", n)
		}
		var oracleNow time.Time
		if exp.OracleNow != "" {
			if exp.API != "chat" {
				return nil, fmt.Errorf("fixture %s: oracleNow on a %s fixture (only a chat render reads the clock)", n, exp.API)
			}
			if oracleNow, err = time.Parse(time.RFC3339, exp.OracleNow); err != nil {
				return nil, fmt.Errorf("fixture %s: oracleNow: %w", n, err)
			}
		}
		reqRaw, _, err := kvReadTrustedFile(rootFd, dirRel+"/"+base+".request.json", kvProbeFixtureCap)
		if err != nil {
			return nil, fmt.Errorf("fixture %s: request: %w", base, err)
		}
		got := sha256.Sum256(reqRaw)
		if hex.EncodeToString(got[:]) != strings.ToLower(exp.RequestSha256) {
			return nil, fmt.Errorf("fixture %s: request bytes drifted from pinned sha256", base)
		}
		out = append(out, kvProbeFixture{
			Name:          base,
			RequestBytes:  reqRaw,
			RequestSha256: exp.RequestSha256,
			ExpectedIDs:   exp.ExpectedTokenIds,
			API:           exp.API,
			OracleNow:     oracleNow,
		})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no fixtures under %s", dirRel)
	}
	return out, nil
}

// ---- probes ----

// kvVllmTokenizeResp is the pinned /tokenize response schema (§5): count,
// tokens, max_model_len are REQUIRED with these types; count must equal
// len(tokens). Divergence is probe_schema_mismatch (engine-version drift),
// distinguished from token mismatch.
type kvVllmTokenizeResp struct {
	Count       *int     `json:"count"`
	Tokens      *[]int64 `json:"tokens"`
	MaxModelLen *int     `json:"max_model_len"`
}

// TokenParityProbe sends the request bytes of every fixture on a surface the
// rule serves verbatim to the endpoint's /tokenize and compares the FULL
// token array (§5: never a length or prefix check).
func (a *kvVllmAttest) TokenParityProbe(ep KvAttestEndpoint, info kvAttestRuleInfo) KvAttestFinding {
	fixtures, err := kvProbeFixturesLoad(info.profileID)
	if err != nil {
		return KvAttestFinding{Reason: KvAttestReasonFixturesMissing, Detail: err.Error()}
	}
	if f := kvFixtureSetCheck(fixtures, info); !f.OK {
		return f
	}
	fixtures = kvFixturesForRule(fixtures, info)
	for _, fx := range fixtures {
		if f := a.tokenizeProbeOne(ep, fx, info.modelName); !f.OK {
			return f
		}
	}
	return KvAttestFinding{OK: true, Detail: fmt.Sprintf("%d fixtures byte-exact", len(fixtures))}
}

// kvFixtureSurfaceCheck enforces that every API surface the rule serves is
// covered by at least one fixture, or parity would attest a surface subset
// while the uncovered surface routes unverified: a chat-declaring rule whose
// fixture set holds only completions probes would reach READY with its chat
// render+encode never checked against the deployed engine.
func kvFixtureSurfaceCheck(fixtures []kvProbeFixture, info kvAttestRuleInfo) KvAttestFinding {
	haveChat, haveCompl := false, false
	for _, fx := range fixtures {
		switch fx.API {
		case "chat":
			haveChat = true
		case "completions":
			haveCompl = true
		}
	}
	if info.apiChat && !haveChat {
		return KvAttestFinding{Reason: KvAttestReasonFixturesMissing,
			Detail: "declared chat surface has no chat-shape probe fixtures"}
	}
	if info.apiCompl && !haveCompl {
		return KvAttestFinding{Reason: KvAttestReasonFixturesMissing,
			Detail: "declared completions surface has no completions-shape probe fixtures"}
	}
	return KvAttestFinding{OK: true}
}

// kvFixturesForRule keeps the fixtures of the API surfaces the rule serves.
// A surface the rule does not declare routes no strict request, so its
// fixtures say nothing about this rule; probing them would hold the rule
// below READY on a surface admission already refused (an engine that encodes
// completions with a BOS the gateway does not add, on a chat-only rule).
// A rule info that declares neither surface carries no declaration to scope
// by and keeps the whole set, so the probe can never run on an empty one:
// kvFixtureSurfaceCheck has already required a fixture for every declared
// surface.
func kvFixturesForRule(fixtures []kvProbeFixture, info kvAttestRuleInfo) []kvProbeFixture {
	if !info.apiChat && !info.apiCompl {
		return fixtures
	}
	out := make([]kvProbeFixture, 0, len(fixtures))
	for _, fx := range fixtures {
		if (fx.API == "chat" && !info.apiChat) || (fx.API == "completions" && !info.apiCompl) {
			continue
		}
		out = append(out, fx)
	}
	return out
}

// kvFixtureSetCheck is the per-set gate every adapter applies before
// probing: surface coverage, then the clock pairing. A clock-declaring
// profile's chat renders carry the current date, so a static chat fixture
// would match the engine only on the day it was generated; an oracleNow
// fixture on a profile without the declaration would re-derive from a
// render that never reads the clock. Either is a fixture set that does not
// belong to the bound profile.
func kvFixtureSetCheck(fixtures []kvProbeFixture, info kvAttestRuleInfo) KvAttestFinding {
	if f := kvFixtureSurfaceCheck(fixtures, info); !f.OK {
		return f
	}
	clock := false
	if e, ok := kvProfileByModel(info.modelName); ok {
		clock = e.Profile.RenderPolicy.ClockPolicy != ""
	}
	for _, fx := range fixtures {
		if fx.API != "chat" {
			continue
		}
		if clock && fx.OracleNow.IsZero() {
			return KvAttestFinding{Reason: KvAttestReasonFixturesMissing,
				Detail: fmt.Sprintf("fixture %s: static chat fixture for a clock-declaring profile (oracleNow required)", fx.Name)}
		}
		if !clock && !fx.OracleNow.IsZero() {
			return KvAttestFinding{Reason: KvAttestReasonFixturesMissing,
				Detail: fmt.Sprintf("fixture %s: oracleNow on a profile that declares no clock policy", fx.Name)}
		}
	}
	return KvAttestFinding{OK: true}
}

func (a *kvVllmAttest) tokenizeProbeOne(ep KvAttestEndpoint, fx kvProbeFixture, model string) KvAttestFinding {
	url := fmt.Sprintf("http://%s:%d/tokenize", ep.IP, ep.Port)
	return kvTokenizeFixtureProbe(a.client, url, fx, model)
}

// kvClockFixtureExpect derives a clock fixture's expected ids at instant
// now through the gateway's own render+encode chain — the same chain a
// served chat request is hashed with, so a green probe proves the engine
// and the router agree on today's render.
func kvClockFixtureExpect(fx kvProbeFixture, model string, now time.Time) ([]int64, KvAttestFinding) {
	msgs, ok := kvParseChatMessages(string(fx.RequestBytes))
	if !ok || len(msgs) == 0 {
		return nil, KvAttestFinding{Reason: KvAttestReasonProbeSchema,
			Detail: fmt.Sprintf("fixture %s: chat fixture carries no parseable messages", fx.Name)}
	}
	rendered, ok := kvRenderChatTemplateAt(model, msgs, func() time.Time { return now })
	if !ok {
		return nil, KvAttestFinding{Reason: KvAttestReasonProfileResolution,
			Detail: fmt.Sprintf("fixture %s: no validated chat renderer for model %q", fx.Name, model)}
	}
	// Chat renders carry their own special tokens (encode-mode contract,
	// kvBridgeTokenizeChat).
	ids := kvTrtllmOracleEncodeFn(rendered, model, kvTrtllmOracleMaxTokens, false)
	if len(ids) == 0 {
		return nil, KvAttestFinding{Reason: KvAttestReasonProfileResolution,
			Detail: fmt.Sprintf("fixture %s: tokenizer produced no tokens for model %q", fx.Name, model)}
	}
	out := make([]int64, len(ids))
	for i, id := range ids {
		out[i] = int64(id)
	}
	return out, KvAttestFinding{OK: true}
}

// kvTokenizeFixtureProbe posts one committed fixture's request bytes
// verbatim and applies the pinned {count, tokens, max_model_len} response
// schema plus the FULL token-array comparison (§5). Engine adapters differ
// only in the tokenize URL they construct. A clock fixture's expectation is
// derived at probe time; when the UTC date turns between that derivation
// and the engine's render, the engine may hold either day, so the probe
// re-derives once on the new day before it may fail.
func kvTokenizeFixtureProbe(client *http.Client, url string, fx kvProbeFixture, model string) KvAttestFinding {
	want := fx.ExpectedIDs
	var derivedAt time.Time
	if !fx.OracleNow.IsZero() {
		// The banked ids must still be the gateway's own render at
		// oracleNow: a stale or edited fixture fails here, before the
		// engine is asked anything.
		if f := kvTrtllmOracleFixtureCheck(fx, model); !f.OK {
			return f
		}
		derivedAt = kvChatClock().UTC()
		var f KvAttestFinding
		if want, f = kvClockFixtureExpect(fx, model, derivedAt); !f.OK {
			return f
		}
	}
	resp, err := client.Post(url, "application/json", strings.NewReader(string(fx.RequestBytes)))
	if err != nil {
		return KvAttestFinding{Reason: KvAttestReasonEndpointUnreach,
			Detail: fmt.Sprintf("fixture %s: %v", fx.Name, err)}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, kvProbeRespCap+1))
	if err != nil {
		return KvAttestFinding{Reason: KvAttestReasonEndpointUnreach,
			Detail: fmt.Sprintf("fixture %s: read: %v", fx.Name, err)}
	}
	if len(body) > kvProbeRespCap {
		return KvAttestFinding{Reason: KvAttestReasonProbeSchema,
			Detail: fmt.Sprintf("fixture %s: response exceeds %d bytes", fx.Name, kvProbeRespCap)}
	}
	if resp.StatusCode != http.StatusOK {
		return KvAttestFinding{Reason: KvAttestReasonProbeSchema,
			Detail: fmt.Sprintf("fixture %s: HTTP %d", fx.Name, resp.StatusCode)}
	}
	var tr kvVllmTokenizeResp
	if err := json.Unmarshal(body, &tr); err != nil {
		return KvAttestFinding{Reason: KvAttestReasonProbeSchema,
			Detail: fmt.Sprintf("fixture %s: unparseable response: %v", fx.Name, err)}
	}
	if tr.Count == nil || tr.Tokens == nil || tr.MaxModelLen == nil {
		return KvAttestFinding{Reason: KvAttestReasonProbeSchema,
			Detail: fmt.Sprintf("fixture %s: pinned fields missing (count/tokens/max_model_len)", fx.Name)}
	}
	toks := *tr.Tokens
	if *tr.Count != len(toks) {
		return KvAttestFinding{Reason: KvAttestReasonProbeSchema,
			Detail: fmt.Sprintf("fixture %s: count %d != len(tokens) %d", fx.Name, *tr.Count, len(toks))}
	}
	f := kvTokenArrayCompare(fx.Name, toks, want)
	if f.OK || derivedAt.IsZero() {
		return f
	}
	now := kvChatClock().UTC()
	y1, m1, d1 := derivedAt.Date()
	y2, m2, d2 := now.Date()
	if y1 == y2 && m1 == m2 && d1 == d2 {
		return f
	}
	want2, f2 := kvClockFixtureExpect(fx, model, now)
	if !f2.OK {
		return f2
	}
	return kvTokenArrayCompare(fx.Name, toks, want2)
}

// kvTokenArrayCompare is the FULL token-array comparison (§5).
func kvTokenArrayCompare(name string, toks, want []int64) KvAttestFinding {
	if len(toks) != len(want) {
		return KvAttestFinding{Reason: KvAttestReasonTokenMismatch,
			Detail: fmt.Sprintf("fixture %s: %d tokens, expected %d", name, len(toks), len(want))}
	}
	for i := range toks {
		if toks[i] != want[i] {
			return KvAttestFinding{Reason: KvAttestReasonTokenMismatch,
				Detail: fmt.Sprintf("fixture %s: token[%d]=%d, expected %d", name, i, toks[i], want[i])}
		}
	}
	return KvAttestFinding{OK: true}
}

// kvVllmVersionResp / kvVllmModelsResp pin the identity-probe schemas.
type kvVllmVersionResp struct {
	Version *string `json:"version"`
}

type kvVllmModelsResp struct {
	Data []struct {
		ID string `json:"id"`
	} `json:"data"`
}

// IdentityProbe checks the running endpoint's self-reported identity against
// the manifest (§6.4): /version must equal the manifest's engineVersion and
// /v1/models must serve the attested model. A probe/manifest inconsistency
// is an attestation FAILURE, not a warning.
func (a *kvVllmAttest) IdentityProbe(ep KvAttestEndpoint, manifest *KvAttestManifest) KvAttestFinding {
	verBody, f := a.getCapped(fmt.Sprintf("http://%s:%d/version", ep.IP, ep.Port))
	if !f.OK {
		return f
	}
	var vr kvVllmVersionResp
	if err := json.Unmarshal(verBody, &vr); err != nil || vr.Version == nil {
		return KvAttestFinding{Reason: KvAttestReasonProbeSchema,
			Detail: fmt.Sprintf("/version unparseable: %v", err)}
	}
	if *vr.Version != manifest.EngineVersion {
		return KvAttestFinding{Reason: KvAttestReasonIdentityMismatch,
			Detail: fmt.Sprintf("/version %q != manifest engineVersion %q", *vr.Version, manifest.EngineVersion)}
	}
	return KvAttestFinding{OK: true}
}

// kvVllmModelServed checks /v1/models for a served model id (used by the
// echo challenge's pre-flight; separated from IdentityProbe so the version
// check runs even for manifest-less functional-only sites).
func (a *kvVllmAttest) kvVllmModelServed(ep KvAttestEndpoint, model string) KvAttestFinding {
	body, f := a.getCapped(fmt.Sprintf("http://%s:%d/v1/models", ep.IP, ep.Port))
	if !f.OK {
		return f
	}
	var mr kvVllmModelsResp
	if err := json.Unmarshal(body, &mr); err != nil {
		return KvAttestFinding{Reason: KvAttestReasonProbeSchema,
			Detail: fmt.Sprintf("/v1/models unparseable: %v", err)}
	}
	for _, m := range mr.Data {
		if m.ID == model {
			return KvAttestFinding{OK: true}
		}
	}
	return KvAttestFinding{Reason: KvAttestReasonIdentityMismatch,
		Detail: fmt.Sprintf("model %q not served by endpoint", model)}
}

func (a *kvVllmAttest) getCapped(url string) ([]byte, KvAttestFinding) {
	return kvAttestGetCapped(a.client, url)
}

// kvAttestGetCapped is the shared size-capped identity GET (both adapters).
func kvAttestGetCapped(client *http.Client, url string) ([]byte, KvAttestFinding) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, KvAttestFinding{Reason: KvAttestReasonEndpointUnreach, Detail: err.Error()}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, kvProbeRespCap+1))
	if err != nil || len(body) > kvProbeRespCap {
		return nil, KvAttestFinding{Reason: KvAttestReasonProbeSchema, Detail: "identity response unreadable/oversize"}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, KvAttestFinding{Reason: KvAttestReasonProbeSchema,
			Detail: fmt.Sprintf("%s: HTTP %d", url, resp.StatusCode)}
	}
	return body, KvAttestFinding{OK: true}
}
