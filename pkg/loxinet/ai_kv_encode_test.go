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
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/loxilb-io/loxilb/pkg/enginecontract"
)

const kvEncTestBos = 151646

// kvEncTestBase is a recording base tokenizer: ids 10, 11, ... one per byte
// of text, cut to max; with specials it appends 99 so a caller's mode shows
// in the ids as well as in the record.
type kvEncTestBase struct{ modes []bool }

func (b *kvEncTestBase) fn(text, _ string, max int, addSpecial bool) []uint32 {
	b.modes = append(b.modes, addSpecial)
	out := make([]uint32, 0, len(text)+1)
	for i := range text {
		out = append(out, uint32(10+i))
	}
	if addSpecial {
		out = append(out, 99)
	}
	if len(out) > max {
		out = out[:max]
	}
	return out
}

func kvEncTestBosEncoding(contract string) kvCompletionsEncoding {
	return kvCompletionsEncoding{contractID: contract,
		quirks: KvEngineQuirks{CompletionsBos: true}, bosID: kvEncTestBos, bosOK: true}
}

// TestKvEngineEncoderPerFamily: every engine family of the compiled contract
// registry has its own encoder module, and a family without one resolves to
// nothing — it is never encoded by another engine's rule.
func TestKvEngineEncoderPerFamily(t *testing.T) {
	seen := map[string]bool{}
	for i := range enginecontract.Profiles {
		fam := enginecontract.Profiles[i].Engine
		enc := kvEngineEncoderFor(fam)
		if enc == nil {
			t.Fatalf("engine family %q (contract %s) has no completions encoder module", fam, enginecontract.Profiles[i].ID)
		}
		if !seen[fam] {
			for other := range seen {
				if reflect.TypeOf(kvEngineEncoderFor(other)) == reflect.TypeOf(enc) {
					t.Fatalf("engine families %q and %q share one encoder module", fam, other)
				}
			}
		}
		seen[fam] = true
	}
	if len(seen) < 4 {
		t.Fatalf("registry walk saw only %v", seen)
	}
	for _, fam := range []string{"", "ollama", "SGLANG"} {
		if kvEngineEncoderFor(fam) != nil {
			t.Fatalf("family %q must have no encoder", fam)
		}
	}
	if _, err := kvEncodeCompletions((&kvEncTestBase{}).fn, kvCompletionsEncoding{contractID: "no-such-contract"}, "ab", "m", 8); err == nil {
		t.Fatal("an uncompiled contract must not encode")
	}
	if _, err := kvEncodeCompletions((&kvEncTestBase{}).fn, kvCompletionsEncoding{}, "ab", "m", 8); err == nil {
		t.Fatal("an encoding without a contract must not encode")
	}
}

// TestKvSglangEncoderCompletionsBos: under the measured fact SGLang encodes a
// text prompt as BOS + the text without the tokenizer file's post-processor;
// the BOS counts against the cap, is unconditional, and is not added without
// the fact.
func TestKvSglangEncoderCompletionsBos(t *testing.T) {
	base := &kvEncTestBase{}
	e := kvEncTestBosEncoding("sglang-kv-rank-v1")
	got, err := kvEncodeCompletions(base.fn, e, "abc", "m", 16)
	if err != nil || !reflect.DeepEqual(got, []uint32{kvEncTestBos, 10, 11, 12}) {
		t.Fatalf("BOS encoding = %v (%v), want BOS + the text ids without specials", got, err)
	}
	if !reflect.DeepEqual(base.modes, []bool{false}) {
		t.Fatalf("base modes %v, want one encode without specials (the rebuilt post-processor replaces the file's)", base.modes)
	}
	// The BOS counts against the cap.
	if got, _ := kvEncodeCompletions(base.fn, e, "abcdef", "m", 4); !reflect.DeepEqual(got, []uint32{kvEncTestBos, 10, 11, 12}) {
		t.Fatalf("capped BOS encoding = %v, want 4 ids starting with the BOS", got)
	}
	// A base tokenizer that yields nothing yields nothing: never a lone BOS.
	empty := func(string, string, int, bool) []uint32 { return nil }
	if got, err := kvEncodeCompletions(empty, e, "abc", "m", 16); err != nil || len(got) != 0 {
		t.Fatalf("empty base = %v (%v), want no ids", got, err)
	}
	// Without the fact SGLang encodes as the tokenizer file says.
	base = &kvEncTestBase{}
	got, err = kvEncodeCompletions(base.fn, kvCompletionsEncoding{contractID: "sglang-kv-rank-v1", bosID: kvEncTestBos, bosOK: true}, "abc", "m", 16)
	if err != nil || !reflect.DeepEqual(got, []uint32{10, 11, 12, 99}) || !reflect.DeepEqual(base.modes, []bool{true}) {
		t.Fatalf("no-fact encoding = %v modes %v (%v), want the file's own post-processor and no BOS", got, base.modes, err)
	}
	// The fact without a resolved BOS id is refused, not encoded bare.
	e.bosOK = false
	if _, err := kvEncodeCompletions(base.fn, e, "abc", "m", 16); err == nil || !strings.Contains(err.Error(), "bosToken") {
		t.Fatalf("fact without a BOS id must be refused, got %v", err)
	}
}

// TestKvEncoderDispatchByContract: the module is chosen by the rule's engine
// contract. The same recorded fact means a BOS on the SGLang contract and a
// refusal on every other engine's contract — never a BOS there, never a
// silent plain encode either.
func TestKvEncoderDispatchByContract(t *testing.T) {
	for _, c := range []string{"vllm-kv-map-v2", "vllm-kv-array-v1", "trtllm-kv-http-v1", "trtllm-kv-http-preview-v1", "llamacpp-nokv-v1"} {
		base := &kvEncTestBase{}
		if got, err := kvEncodeCompletions(base.fn, kvEncTestBosEncoding(c), "abc", "m", 16); err == nil || len(got) != 0 || len(base.modes) != 0 {
			t.Fatalf("contract %s with completionsBos: got %v (%v) after %d base encodes, want a refusal before any encode", c, got, err, len(base.modes))
		}
	}
	for _, c := range []string{"vllm-kv-map-v2", "vllm-kv-array-v1", "trtllm-kv-http-v1", "trtllm-kv-http-preview-v1", "sglang-kv-rank-v1"} {
		base := &kvEncTestBase{}
		got, err := kvEncodeCompletions(base.fn, kvCompletionsEncoding{contractID: c}, "abc", "m", 16)
		if err != nil || !reflect.DeepEqual(got, []uint32{10, 11, 12, 99}) || !reflect.DeepEqual(base.modes, []bool{true}) {
			t.Fatalf("contract %s without quirks: got %v modes %v (%v), want the tokenizer's own post-processor", c, got, base.modes, err)
		}
	}
	if _, err := kvEncodeCompletions((&kvEncTestBase{}).fn, kvCompletionsEncoding{contractID: "llamacpp-nokv-v1"}, "abc", "m", 16); err == nil {
		t.Fatal("llama.cpp has no KV-exact surface and must not encode")
	}
}

// TestKvTokenizerSpecialID: the BOS string resolves to exactly one special
// added token of the pinned tokenizer.
func TestKvTokenizerSpecialID(t *testing.T) {
	const tok = `{"added_tokens":[
		{"id":151643,"content":"<eos>","special":true},
		{"id":151646,"content":"<bos>","special":true},
		{"id":151650,"content":"<tool>","special":false},
		{"id":7,"content":"<dup>","special":true},
		{"id":8,"content":"<dup>","special":true}]}`
	if id, err := kvTokenizerSpecialID([]byte(tok), "<bos>"); err != nil || id != 151646 {
		t.Fatalf("<bos> = %d (%v), want 151646", id, err)
	}
	for name, c := range map[string]string{"absent": "<nope>", "not special": "<tool>", "ambiguous": "<dup>"} {
		if _, err := kvTokenizerSpecialID([]byte(tok), c); err == nil {
			t.Errorf("%s token %q must not resolve", name, c)
		}
	}
	if _, err := kvTokenizerSpecialID([]byte("{"), "<bos>"); err == nil {
		t.Error("an unparseable tokenizer must not resolve")
	}
}

// kvEncTestStrictRule binds svc to a published profile carrying the
// completionsBos fact for the SGLang contract, on the given contract.
func kvEncTestStrictRule(t *testing.T, svc uint32, ident, model, contract string) *KvExactBinding {
	t.Helper()
	kvDataplaneTestSetup(t)
	kvTestRegister(svc, ident, KvContractAPIBoth)
	kvTestPublishChatProfile(t, model, "{% for m in messages %}{{ m['content'] }}{% endfor %}",
		KvRenderPolicy{AddGenerationPrompt: true, BosToken: "<bos>"})
	e, _ := kvProfileByID("test-chat-profile")
	e.Profile.EngineQuirks = map[string]KvEngineQuirks{"sglang-kv-rank-v1": {CompletionsBos: true}}
	e.Profile.completionsBosID, e.Profile.completionsBosOK = kvEncTestBos, true
	c := kvTestComponents(1)
	c.Profile.ID = "test-chat-profile"
	c.Contract.ID = contract
	b, err := KvBindingAllocate(ident, c)
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	kvSvcContractOutcome(svc, false, "")
	return b
}

// TestKvBridgeTokenizeEngineEncoder: the completions bridge of a strict rule
// encodes through the encoder of the contract its binding names — BOS + text
// on the SGLang contract of a profile that records the fact, the tokenizer's
// own encoding on a vLLM contract of the SAME profile — while the chat bridge
// and a legacy rule are untouched by the fact.
func TestKvBridgeTokenizeEngineEncoder(t *testing.T) {
	const model = "acme/bos-model"
	t.Run("sglang contract adds the BOS", func(t *testing.T) {
		b := kvEncTestStrictRule(t, 61, "rule-enc-sgl", model, "sglang-kv-rank-v1")
		rec := kvEncodeModeInstallTokenizer(t, model)
		tokens, rc := kvBridgeTokenize(61, b.BindingGen, "raw completion prompt", model, 100)
		if rc != 0 || !reflect.DeepEqual(tokens, []uint32{kvEncTestBos, 1, 2, 3}) {
			t.Fatalf("strict SGLang completions = %v rc %d, want BOS + the text ids", tokens, rc)
		}
		if !reflect.DeepEqual(rec.modes, []bool{false}) {
			t.Fatalf("encoded with modes %v, want [false]", rec.modes)
		}
		// The BOS counts against the caller's cap.
		if tokens, rc := kvBridgeTokenize(61, b.BindingGen, "raw completion prompt", model, 2); rc != 0 || !reflect.DeepEqual(tokens, []uint32{kvEncTestBos, 1}) {
			t.Fatalf("capped strict SGLang completions = %v rc %d, want [BOS 1]", tokens, rc)
		}
		// Chat renders carry their own specials: no BOS from the fact.
		rec.modes = nil
		tokens, rc = kvBridgeTokenizeChat(61, b.BindingGen, `{"messages":[{"role":"user","content":"hi"}]}`, model, 100)
		if rc != 0 || !reflect.DeepEqual(tokens, []uint32{1, 2, 3}) || !reflect.DeepEqual(rec.modes, []bool{false}) {
			t.Fatalf("strict chat = %v rc %d modes %v, want the render's ids without a BOS", tokens, rc, rec.modes)
		}
		// A legacy request for the same model carries no binding: unchanged.
		rec.modes = nil
		tokens, rc = kvBridgeTokenize(0, 0, "raw completion prompt", model, 100)
		if rc != 0 || !reflect.DeepEqual(tokens, []uint32{1, 2, 3}) || !reflect.DeepEqual(rec.modes, []bool{true}) {
			t.Fatalf("legacy completions = %v rc %d modes %v, want the specials-included encoding and no BOS", tokens, rc, rec.modes)
		}
	})
	t.Run("vllm contract of the same profile does not", func(t *testing.T) {
		b := kvEncTestStrictRule(t, 62, "rule-enc-vllm", model, "vllm-kv-map-v2")
		rec := kvEncodeModeInstallTokenizer(t, model)
		tokens, rc := kvBridgeTokenize(62, b.BindingGen, "raw completion prompt", model, 100)
		if rc != 0 || !reflect.DeepEqual(tokens, []uint32{1, 2, 3}) || !reflect.DeepEqual(rec.modes, []bool{true}) {
			t.Fatalf("strict vLLM completions = %v rc %d modes %v, want the tokenizer's own encoding", tokens, rc, rec.modes)
		}
	})
	t.Run("unresolvable profile or contract is a profile fault", func(t *testing.T) {
		b := kvEncTestStrictRule(t, 63, "rule-enc-bad", model, "no-such-contract")
		kvEncodeModeInstallTokenizer(t, model)
		if tokens, rc := kvBridgeTokenize(63, b.BindingGen, "raw completion prompt", model, 100); rc != KvTokErrProfile || tokens != nil {
			t.Fatalf("uncompiled contract = %v rc %d, want the profile fault", tokens, rc)
		}
		b = kvEncTestStrictRule(t, 64, "rule-enc-noprof", model, "sglang-kv-rank-v1")
		kvProfileReg.Store(nil)
		if tokens, rc := kvBridgeTokenize(64, b.BindingGen, "raw completion prompt", model, 100); rc != KvTokErrProfile || tokens != nil {
			t.Fatalf("unpublished profile = %v rc %d, want the profile fault", tokens, rc)
		}
	})
}

// TestKvTrtllmOracleEncodesThroughEncoder: the TensorRT-LLM oracle probe
// encodes a completions fixture through the rule's encoder module, so a fact
// its module does not model fails the probe instead of banking a plain
// encode.
func TestKvTrtllmOracleEncodesThroughEncoder(t *testing.T) {
	prev := kvTrtllmOracleEncodeFn
	base := &kvEncTestBase{}
	kvTrtllmOracleEncodeFn = base.fn
	t.Cleanup(func() { kvTrtllmOracleEncodeFn = prev })

	info := kvAttestRuleInfo{modelName: "m", engine: "trtllm"}
	got, err := kvTrtllmOracleEncodeCompletions(info, "abc")
	if err != nil || !reflect.DeepEqual(got, []uint32{10, 11, 12, 99}) || !reflect.DeepEqual(base.modes, []bool{true}) {
		t.Fatalf("oracle encode = %v modes %v (%v), want the tokenizer's own encoding", got, base.modes, err)
	}
	info.challenge = kvChallengePlanFor(kvEncTestBosEncoding("trtllm-kv-http-v1"))
	if _, err := kvTrtllmOracleEncodeCompletions(info, "abc"); err == nil {
		t.Fatal("a completionsBos fact on a TensorRT-LLM contract must fail the oracle encode")
	}
}

// TestKvProfileRegistryCompletionsBosID: a profile that records
// completionsBos publishes with renderPolicy.bosToken resolved to its id in
// the pinned tokenizer; a tokenizer that cannot name that token refuses the
// publish, and a profile without the fact resolves nothing.
func TestKvProfileRegistryCompletionsBosID(t *testing.T) {
	const quirk = "renderPolicy:\n  bosToken: \"<bos>\"\nengineQuirks:\n  sglang-kv-rank-v1:\n    completionsBos: true\n"
	appendDoc := func(t *testing.T, root, id, tail string) {
		t.Helper()
		f, err := os.OpenFile(filepath.Join(root, id+".yaml"), os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if _, err := f.WriteString(tail); err != nil {
			t.Fatal(err)
		}
	}

	root := kvRegistryTestSetup(t)
	kvWriteProfileFixture(t, root, "p-bos", "acme/bos-m1", []byte(`{"added_tokens":[{"id":151646,"content":"<bos>","special":true}]}`))
	appendDoc(t, root, "p-bos", quirk)
	kvWriteProfileFixture(t, root, "p-plain", "acme/bos-m2", []byte("not json, never parsed"))
	if err := KvProfileRegistryLoadFrom(root); err != nil {
		t.Fatalf("load: %v", err)
	}
	e, ok := kvProfileByID("p-bos")
	if !ok || !e.Profile.completionsBosOK || e.Profile.completionsBosID != 151646 {
		t.Fatalf("p-bos: BOS id not resolved at publish: %+v", e)
	}
	enc := kvCompletionsEncodingOf(&e.Profile, "sglang-kv-rank-v1")
	if enc != kvEncTestBosEncoding("sglang-kv-rank-v1") {
		t.Fatalf("p-bos encoding on the SGLang contract = %+v", enc)
	}
	if enc := kvCompletionsEncodingOf(&e.Profile, "vllm-kv-map-v2"); enc.quirks.CompletionsBos {
		t.Fatalf("p-bos encoding on a vLLM contract carries the SGLang fact: %+v", enc)
	}
	if e, ok := kvProfileByID("p-plain"); !ok || e.Profile.completionsBosOK {
		t.Fatalf("p-plain records no fact and must resolve no BOS id: %+v", e)
	}

	bad := kvRegistryTestSetup(t)
	kvWriteProfileFixture(t, bad, "p-nobos", "acme/bos-m3", []byte(`{"added_tokens":[{"id":1,"content":"<other>","special":true}]}`))
	appendDoc(t, bad, "p-nobos", quirk)
	if err := KvProfileRegistryLoadFrom(bad); err == nil || !strings.Contains(err.Error(), "completionsBos") {
		t.Fatalf("a tokenizer without the BOS token must refuse the publish, got %v", err)
	}
}
