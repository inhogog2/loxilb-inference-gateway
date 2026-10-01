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

import "testing"

// The engines' request models match keys exactly and ignore unknown ones, so
// a case-variant twin of a key must neither replace the real value nor hide
// a refused field. Each body below was observed to render different prompt ids
// in vLLM v0.28.0 than in the gateway before exact-key decoding.
func TestKvChatParseExactKeys(t *testing.T) {
	cases := []struct {
		name, body string
		want       []kvChatMessage
	}{
		{"content twin", `{"messages":[{"role":"user","content":"alpha","Content":"beta"}]}`,
			[]kvChatMessage{{"user", "alpha"}}},
		{"role twin", `{"messages":[{"role":"user","Role":"system","content":"hi"}]}`,
			[]kvChatMessage{{"user", "hi"}}},
		{"messages twin", `{"messages":[{"role":"user","content":"engine"}],"Messages":[{"role":"user","content":"other"}]}`,
			[]kvChatMessage{{"user", "engine"}}},
		{"duplicate exact key keeps the last value", `{"messages":[{"role":"user","content":"first","content":"second"}]}`,
			[]kvChatMessage{{"user", "second"}}},
		{"null content renders empty", `{"messages":[{"role":"user","content":"q"},{"role":"assistant","content":null}]}`,
			[]kvChatMessage{{"user", "q"}, {"assistant", ""}}},
		{"text parts join with newline, other parts skipped", `{"messages":[{"role":"user","content":[{"type":"text","text":"a"},{"type":"image_url","image_url":{"url":"x"}},{"type":"text","text":"b"}]}]}`,
			[]kvChatMessage{{"user", "a\nb"}}},
	}
	for _, c := range cases {
		got, ok := kvParseChatMessages(c.body)
		if !ok || len(got) != len(c.want) {
			t.Fatalf("%s: ok=%v got %v, want %v", c.name, ok, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("%s: message %d = %+v, want %+v", c.name, i, got[i], c.want[i])
			}
		}
	}
}

// Shapes the engines reject with 400 have no engine render to match.
func TestKvChatParseRejectsEngineInvalidShapes(t *testing.T) {
	for name, body := range map[string]string{
		"number content":     `{"messages":[{"role":"user","content":42}]}`,
		"object content":     `{"messages":[{"role":"user","content":{"text":"x"}}]}`,
		"typeless part":      `{"messages":[{"role":"user","content":[{"text":"x"}]}]}`,
		"text part, no text": `{"messages":[{"role":"user","content":[{"type":"text"}]}]}`,
		"non-object part":    `{"messages":[{"role":"user","content":["x"]}]}`,
		"missing role":       `{"messages":[{"content":"x"}]}`,
		"null role":          `{"messages":[{"role":null,"content":"x"}]}`,
		"numeric role":       `{"messages":[{"role":1,"content":"x"}]}`,
		"string message":     `{"messages":["x"]}`,
		"messages object":    `{"messages":{"role":"user"}}`,
		"no messages":        `{"model":"m"}`,
		"empty messages":     `{"messages":[]}`,
		"not an object":      `[1]`,
	} {
		if msgs, ok := kvParseChatMessages(body); ok {
			t.Fatalf("%s: parsed %v, want refusal", name, msgs)
		}
	}
}

func TestKvChatExcludedFeatureExactKeys(t *testing.T) {
	cases := []struct {
		name, body, want string
	}{
		// The case-variant twin used to overwrite the real value and
		// silence the refusal.
		{"add_generation_prompt twin", `{"messages":[{"role":"user","content":"x"}],"add_generation_prompt":false,"ADD_GENERATION_PROMPT":true}`, "add_generation_prompt"},
		{"continue_final_message twin", `{"messages":[{"role":"user","content":"x"}],"continue_final_message":true,"CONTINUE_FINAL_MESSAGE":false}`, "continue_final_message"},
		{"tools twin does not hide tools", `{"messages":[{"role":"user","content":"x"}],"tools":[{"type":"function"}],"Tools":null}`, "tools"},
		// A variant the engine ignores must not be refused either.
		{"variant alone is ignored", `{"messages":[{"role":"user","content":"x"}],"Add_Generation_Prompt":false}`, ""},
		{"kwargs variant alone is ignored", `{"messages":[{"role":"user","content":"x"}],"Chat_Template_Kwargs":{"enable_thinking":false}}`, ""},
		{"unparseable body is never feature-free", `{"messages":[{"role":"user","content":"x"}]`, "unparseable"},
		{"multimodal part", `{"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"x"}}]}]}`, "multimodal"},
	}
	for _, c := range cases {
		if got := kvChatExcludedFeature(c.body, true); got != c.want {
			t.Fatalf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestKvChatTemplateFeature(t *testing.T) {
	const plain = `{% for m in messages %}{{ m['role'] }}: {{ m['content'] }}{% endfor %}`
	const readsName = `{% for m in messages %}{% if m.name %}{{ m.name }}{% endif %}{{ m['content'] }}{% endfor %}`
	const toolCalls = `{% for m in messages %}{% if m['content'] is none %}{% for t in m['tool_calls'] %}{{ t['id'] }}{% endfor %}{% else %}{{ m['content'] }}{% endif %}{% endfor %}`
	cases := []struct {
		name, body, tpl, want string
	}{
		{"developer role", `{"messages":[{"role":"developer","content":"be brief"},{"role":"user","content":"q"}]}`, plain, "developer_role"},
		{"message tools", `{"messages":[{"role":"system","content":"s","tools":[{"type":"function"}]},{"role":"user","content":"q"}]}`, plain, "message_tools"},
		{"name read by the template", `{"messages":[{"role":"user","content":"q","name":"bob"}]}`, readsName, "message_field"},
		{"name the template never reads", `{"messages":[{"role":"user","content":"q","name":"bob"}]}`, plain, ""},
		{"tool_calls read by the template", `{"messages":[{"role":"assistant","content":null,"tool_calls":[{"id":"a"}]}]}`, toolCalls, "message_field"},
		{"null content tested by the template", `{"messages":[{"role":"user","content":"q"},{"role":"assistant","content":null}]}`, toolCalls, "null_content"},
		{"absent content tested by the template", `{"messages":[{"role":"user","content":"q"},{"role":"assistant"}]}`, toolCalls, "null_content"},
		{"null content, template never tests it", `{"messages":[{"role":"user","content":"q"},{"role":"assistant","content":null}]}`, plain, ""},
		{"null extra key is not a field", `{"messages":[{"role":"user","content":"q","name":null}]}`, readsName, ""},
		{"substring is not a mention", `{"messages":[{"role":"user","content":"q","nam":"x"}]}`, readsName, ""},
		{"plain request", `{"messages":[{"role":"system","content":"s"},{"role":"user","content":"q"}]}`, plain, ""},
	}
	for _, c := range cases {
		if got := kvChatTemplateFeature(c.body, c.tpl); got != c.want {
			t.Fatalf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestKvBridgeNulGuard(t *testing.T) {
	if rc := kvBridgeNulGuard("a\x00b", true); rc != KvTokErrUnsupported {
		t.Fatalf("strict NUL: rc %d, want %d", rc, KvTokErrUnsupported)
	}
	if rc := kvBridgeNulGuard("a\x00b", false); rc != KvTokErrRequest {
		t.Fatalf("legacy NUL: rc %d, want %d", rc, KvTokErrRequest)
	}
	if rc := kvBridgeNulGuard("ab", true); rc != 0 {
		t.Fatalf("no NUL: rc %d, want 0", rc)
	}
	// Legacy code stays the generic request failure. The bridges' use of the
	// guard is proven on the strict path below, where it is distinguishable
	// from a missing tokenizer.
	if _, rc := kvBridgeTokenize(0, 0, "a\x00b", "no/such-model", 16); rc != KvTokErrRequest {
		t.Fatalf("completions bridge NUL: rc %d, want %d", rc, KvTokErrRequest)
	}
}

// TestKvBridgeStrictRefusalsPrecedeTheTokenizer drives both strict bridges
// with no tokenizer staged: a body that reaches the tokenizer comes back as
// the tokenizer runtime fault, so UNSUPPORTED proves the refusal ran first
// and the rule was never kicked for a client-shaped request.
func TestKvBridgeStrictRefusalsPrecedeTheTokenizer(t *testing.T) {
	kvDataplaneTestSetup(t)
	kvTestRegister(52, "rule-chat-shapes", KvContractAPIBoth)
	b, err := KvBindingAllocate("rule-chat-shapes", kvTestComponents(1))
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	kvSvcContractOutcome(52, false, "")

	const model = "acme/plain-template"
	kvTestPublishChatProfile(t, model, `{% for m in messages %}{{ m['content'] }}{% endfor %}`,
		KvRenderPolicy{AddGenerationPrompt: true})

	const plainBody = `{"messages":[{"role":"user","content":"ab"}]}`
	if _, rc := kvBridgeTokenizeChat(52, b.BindingGen, plainBody, model, 16); rc != KvTokErrTokenizer {
		t.Fatalf("control: rc %d, want the tokenizer fault %d (the body must reach the tokenizer)", rc, KvTokErrTokenizer)
	}
	const onePart = `{"messages":[{"role":"user","content":[{"type":"text","text":"ab"}]}]}`
	if _, rc := kvBridgeTokenizeChat(52, b.BindingGen, onePart, model, 16); rc != KvTokErrTokenizer {
		t.Fatalf("one text part: rc %d, want the tokenizer fault %d (a single part renders the same everywhere)", rc, KvTokErrTokenizer)
	}
	if _, rc := kvBridgeTokenize(52, b.BindingGen, "ab", model, 16); rc != KvTokErrTokenizer {
		t.Fatalf("completions control: rc %d, want the tokenizer fault %d", rc, KvTokErrTokenizer)
	}

	chat := []struct{ name, body string }{
		{"NUL in content", `{"messages":[{"role":"user","content":"a\u0000b"}]}`},
		{"developer role", `{"messages":[{"role":"developer","content":"be brief"},{"role":"user","content":"ab"}]}`},
		{"message-level tools", `{"messages":[{"role":"system","content":"s","tools":[{"type":"function"}]},{"role":"user","content":"ab"}]}`},
		{"two text parts", `{"messages":[{"role":"user","content":[{"type":"text","text":"a"},{"type":"text","text":"b"}]}]}`},
	}
	for _, c := range chat {
		if _, rc := kvBridgeTokenizeChat(52, b.BindingGen, c.body, model, 16); rc != KvTokErrUnsupported {
			t.Fatalf("chat %s: rc %d, want UNSUPPORTED %d", c.name, rc, KvTokErrUnsupported)
		}
	}
	if _, rc := kvBridgeTokenize(52, b.BindingGen, "a\x00b", model, 16); rc != KvTokErrUnsupported {
		t.Fatalf("completions NUL: rc %d, want UNSUPPORTED %d", rc, KvTokErrUnsupported)
	}
}
