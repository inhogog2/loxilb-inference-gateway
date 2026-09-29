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

/*
 * ai_kv_chat_template.go — chat-template parity for KV-exact.
 *
 * For /v1/chat/completions, engines cache the tokens of the
 * CHAT-TEMPLATE-APPLIED prompt, not the raw user-message text.
 * daulet/tokenizers has no apply_chat_template, so loxilb renders the
 * template itself and feeds the rendered string through the SAME Encode path
 * completions uses (WithEncodeSpecialTokens, add_special_tokens=false).
 *
 * This is correct because — confirmed live on Qwen/Qwen2.5-7B-Instruct and
 * re-proven per model by the offline HF oracle
 * (cicd/common/kv_hash/fixtures/kv_chat_render_parity.json) —
 *   Encode(apply_chat_template(msgs, tokenize=False)) == apply_chat_template(msgs, tokenize=True)
 * for every case, so one tokenizer path serves both chat and completions.
 *
 * Rendering is profile-driven: the model resolves to a published
 * ModelPromptProfile whose digest-pinned template artifact is executed by the
 * in-process Jinja executor (ai_kv_jinja.go) over the request's messages.
 * There are deliberately NO per-model Go renderers and NO vendor-prefix
 * fallback: template dialects vary within a vendor line (Qwen3 renders
 * without Qwen2.5's default system prompt, for example), so a model without
 * a published profile must fall back, never inherit a relative's template.
 */

package loxinet

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// kvChatMessage is one role/content turn extracted from a chat request body.
type kvChatMessage struct {
	Role    string
	Content string
}

// kvChatClock is the clock strftime_now reads under the utc-date policy
// (a variable so tests can pin the instant).
var kvChatClock = time.Now

// kvJinjaChatContext builds the render context the engine's own renderer
// receives: the message list (each message a {"role", "content"} dict in
// that key order, as the engine builds it), tools and documents as None,
// the generation-prompt knob, and the tokenizer's special-token strings (HF
// passes special_tokens_map into apply_chat_template; a template
// referencing a token the profile does not declare fails the render loudly
// instead of rendering different bytes). strftime_now exists only under a
// declared clock policy and reads kvChatClock.
func kvJinjaChatContext(messages []kvChatMessage, pol KvRenderPolicy) map[string]any {
	return kvJinjaChatContextAt(messages, pol, kvChatClock)
}

// kvJinjaChatContextAt is kvJinjaChatContext with an explicit clock, so a
// render pinned to one instant (the attestor re-deriving a probe fixture
// at the instant its oracle rendered) never touches the shared kvChatClock.
func kvJinjaChatContextAt(messages []kvChatMessage, pol KvRenderPolicy, clock func() time.Time) map[string]any {
	msgs := make([]any, 0, len(messages))
	for _, m := range messages {
		d := kvJjNewDict()
		d.set("role", m.Role)
		d.set("content", m.Content)
		msgs = append(msgs, d)
	}
	ctx := map[string]any{
		"messages":              msgs,
		"tools":                 nil,
		"documents":             nil,
		"add_generation_prompt": pol.AddGenerationPrompt,
	}
	if pol.BosToken != "" {
		ctx["bos_token"] = pol.BosToken
	}
	if pol.EosToken != "" {
		ctx["eos_token"] = pol.EosToken
	}
	if pol.ClockPolicy == KvClockPolicyUTCDate {
		ctx["strftime_now"] = kvJjStrftimeNow(func() time.Time { return clock().UTC() })
	}
	return ctx
}

// kvCheckClockPolicy ties a template's use of strftime_now to the profile's
// clock declaration, both ways: an undeclared date would render from a
// clock the engine does not share, and a declaration the template never
// uses would impose a launch requirement (TZ=UTC) for nothing.
func kvCheckClockPolicy(tpl *kvJinjaTemplate, pol *KvRenderPolicy) error {
	uses := tpl.References("strftime_now")
	switch {
	case uses && pol.ClockPolicy == "":
		return errors.New("template reads strftime_now; the profile must declare renderPolicy.clockPolicy: utc-date")
	case !uses && pol.ClockPolicy != "":
		return fmt.Errorf("renderPolicy.clockPolicy %q declared but the template never reads strftime_now", pol.ClockPolicy)
	}
	return nil
}

// kvRenderChatTemplate renders the chat-template-applied prompt for modelName
// through its published profile's pinned template artifact. Returns ok=false
// when no chat-declaring profile serves the exact model or the render fails —
// the caller must NOT route such a request through KV-exact chat tokenization
// (it would silently mis-hash); it should fall back rather than guess a
// template.
func kvRenderChatTemplate(modelName string, messages []kvChatMessage) (string, bool) {
	return kvRenderChatTemplateAt(modelName, messages, kvChatClock)
}

// kvRenderChatTemplateAt is kvRenderChatTemplate with an explicit clock for
// strftime_now (only a clock-declaring profile's template reads it).
func kvRenderChatTemplateAt(modelName string, messages []kvChatMessage, clock func() time.Time) (string, bool) {
	out, err := kvRenderChatTemplateReq(modelName, messages, clock)
	return out, err == nil
}

// errKvNoChatRenderer: no chat-declaring profile serves the model, or its
// pinned template artifact is missing or does not compile.
var errKvNoChatRenderer = errors.New("kv-chat: no validated chat renderer for the model")

// kvRenderChatTemplateReq renders like kvRenderChatTemplateAt but keeps the
// failure class. errKvNoChatRenderer means the renderer itself is unusable (a
// runtime fault for a strict rule, whose admission proved it usable). Any
// other error means the compiled template refused THIS request's messages —
// raise_exception on a role order or content shape (the engines answer 400
// for the same request), a construct only this shape reaches, or an empty
// render: a request-class failure that must never fence the rule, or any
// client could degrade it at will.
func kvRenderChatTemplateReq(modelName string, messages []kvChatMessage, clock func() time.Time) (string, error) {
	e, ok := kvProfileByModel(modelName)
	if !ok || !kvProfileDeclaresChat(&e.Profile) {
		return "", errKvNoChatRenderer
	}
	tpl, err := e.chatTemplate()
	if err != nil {
		return "", errKvNoChatRenderer
	}
	out, err := tpl.Render(kvJinjaChatContextAt(messages, e.Profile.RenderPolicy, clock))
	if err != nil {
		return "", err
	}
	if out == "" {
		return "", errors.New("kv-chat: template rendered no text for these messages")
	}
	return out, nil
}

// kvModelTypeGptOss is the config.json model_type the engines serve through
// the Harmony encoder (vLLM v0.28.0 render_chat, TRT-LLM 1.3.0rc24
// openai_chat) rather than the chat template. SGLang v0.5.18 renders its chat
// with the template.
const kvModelTypeGptOss = "gpt_oss"

// kvChatTemplateServesEngine reports whether engine renders the profile's
// chat requests with the pinned chat template the gateway executes. When it
// does not, the gateway's hash describes a prompt the engine never builds —
// and the engine's /tokenize still uses the template, so the attestation
// probe cannot notice.
func kvChatTemplateServesEngine(p *ModelPromptProfile, engine string) bool {
	return p.ModelType != kvModelTypeGptOss || engine == "sglang"
}

// kvProfileDeclaresChat reports whether a profile declares the chat surface.
func kvProfileDeclaresChat(p *ModelPromptProfile) bool {
	for _, a := range p.SupportedApis {
		if a == KvProfileAPIChat {
			return true
		}
	}
	return false
}

// kvChatTemplateSupported reports whether a validated chat renderer exists
// for modelName: a published profile serves the model, declares chat, and its
// pinned template artifact compiles. Admission consults this so a declared
// chat surface is refused at create time exactly when the serving path would
// have to fall back untemplated. It deliberately does NOT execute the
// template — support is a property of the published identity, and a render
// error on live traffic is a runtime fault the bridge already fences
// (kvBridgeTokenizeChat), never a reason to admit-then-degrade.
func kvChatTemplateSupported(modelName string) bool {
	e, ok := kvProfileByModel(modelName)
	if !ok || !kvProfileDeclaresChat(&e.Profile) {
		return false
	}
	_, err := e.chatTemplate()
	return err == nil
}

// kvChatDecodeExact decodes a chat request body with exact, case-sensitive
// key matching: the top-level object and every messages[] entry as raw
// key/value maps. encoding/json's struct decoding matches keys
// case-insensitively, while the engines' request models (pydantic) match
// them exactly and ignore unknown keys — so a body carrying both "content"
// and "Content" would render one prompt engine-side and another here. A
// duplicated key keeps its last value, as Python's json module does.
// ok=false when the body, messages or any message is not the expected shape.
func kvChatDecodeExact(body string) (map[string]json.RawMessage, []map[string]json.RawMessage, bool) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &top); err != nil || top == nil {
		return nil, nil, false
	}
	var raw []json.RawMessage
	if err := json.Unmarshal(top["messages"], &raw); err != nil {
		return top, nil, false
	}
	msgs := make([]map[string]json.RawMessage, 0, len(raw))
	for _, r := range raw {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(r, &m); err != nil || m == nil {
			return top, nil, false
		}
		msgs = append(msgs, m)
	}
	return top, msgs, true
}

// kvJSONPresent reports a key that is set to anything but null.
func kvJSONPresent(raw json.RawMessage) bool {
	return len(raw) > 0 && string(raw) != "null"
}

// kvParseChatMessages extracts the ordered role/content turns from a raw chat
// request body (the JSON loxilb's C side has in its receive buffer). Keys are
// matched exactly (kvChatDecodeExact). Content may be a plain string or the
// OpenAI array form ([{type:"text",text:"..."}]); the text segments are joined
// with "\n" to match the engine's string-content-format part handling.
// Returns ok=false on parse failure, no messages, a role that is not a JSON
// string, or content of a shape the engines reject — there is no engine
// render to match for a request the engine refuses.
func kvParseChatMessages(body string) ([]kvChatMessage, bool) {
	_, msgs, ok := kvChatDecodeExact(body)
	if !ok || len(msgs) == 0 {
		return nil, false
	}
	out := make([]kvChatMessage, 0, len(msgs))
	for _, m := range msgs {
		role := m["role"]
		if len(role) == 0 || role[0] != '"' {
			return nil, false
		}
		var r string
		if err := json.Unmarshal(role, &r); err != nil {
			return nil, false
		}
		content, ok := kvExtractMessageContent(m["content"])
		if !ok {
			return nil, false
		}
		out = append(out, kvChatMessage{Role: r, Content: content})
	}
	return out, true
}

// kvExtractMessageContent normalizes a chat message "content" field (string or
// OpenAI content-part array) into plain text. Multiple text parts are joined
// with "\n": string-content-format chat templates receive parts joined that
// way by the engine's request parser, so any other separator renders (and
// therefore tokenizes and hashes) different bytes than the engine caches.
// Absent or null content is "". ok=false for any other JSON type, a part that
// is not an object with a string "type", or a text part without a string
// "text" — shapes the engines reject with 400.
func kvExtractMessageContent(raw json.RawMessage) (string, bool) {
	if !kvJSONPresent(raw) {
		return "", true
	}
	var s string
	if raw[0] == '"' {
		if err := json.Unmarshal(raw, &s); err != nil {
			return "", false
		}
		return s, true
	}
	var parts []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &parts); err != nil {
		return "", false
	}
	texts := make([]string, 0, len(parts))
	for _, p := range parts {
		var typ string
		if t := p["type"]; len(t) == 0 || t[0] != '"' || json.Unmarshal(t, &typ) != nil {
			return "", false
		}
		if typ != "text" {
			continue
		}
		var text string
		if t := p["text"]; len(t) == 0 || t[0] != '"' || json.Unmarshal(t, &text) != nil {
			return "", false
		}
		texts = append(texts, text)
	}
	return strings.Join(texts, "\n"), true
}

// kvChatExcludedFeature inspects a raw chat request body for the plan-§4
// excluded-feature vocabulary and returns the first feature found ("" =
// none). Consulted on STRICT bridge paths only (kvBridgeTokenizeChat):
// requests carrying these features hash differently engine-side than the
// gateway's plain-text render, so a strict rule refuses to score them
// (request-class UNSUPPORTED — never readiness-affecting, I-12) instead of
// routing a mis-hashed prefix. Legacy rules keep today's behavior untouched.
//
// Besides the plan-§4 features, it refuses every request field that changes
// the engine's prompt ids while the gateway renders from the profile alone.
// The set is the union over the engines' chat paths (vLLM v0.28.0
// build_chat_params/build_tok_params, SGLang v0.5.18 _apply_jinja_template,
// TRT-LLM 1.3.0rc24 openai_chat): add_generation_prompt when it differs from
// the profile's addGenerationPrompt; continue_final_message and
// add_special_tokens unless false; documents, reasoning_effort, a
// per-request chat_template, truncate_prompt_tokens and
// prompt_token_ids(_b64) whenever set. A field one engine ignores is still
// refused: the gateway does not know which engine serves the rule, and a
// refusal only costs scoring, while acceptance would mis-hash.
func kvChatExcludedFeature(body string, addGenerationPrompt bool) string {
	top, msgs, ok := kvChatDecodeExact(body)
	if !ok {
		// Unparseable here is unparseable for the render too (the bridge
		// refuses it as a request error); never report "no feature" for a
		// body this detector could not read.
		return "unparseable"
	}
	// differs reports a set flag whose value is not the JSON boolean want.
	// Anything but a plain boolean differs: the engines' request models
	// coerce strings and numbers, so their meaning is not the gateway's to
	// guess.
	differs := func(raw json.RawMessage, want bool) bool {
		if !kvJSONPresent(raw) {
			return false
		}
		var v bool
		return json.Unmarshal(raw, &v) != nil || v != want
	}
	switch {
	case kvJSONPresent(top["tools"]) || kvJSONPresent(top["tool_choice"]):
		return "tools"
	case kvJSONPresent(top["cache_salt"]):
		return "cache_salt"
	case kvJSONPresent(top["prompt_embeds"]):
		return "prompt_embeds"
	case kvJSONPresent(top["chat_template_kwargs"]):
		return "template_kwargs"
	case differs(top["add_generation_prompt"], addGenerationPrompt):
		return "add_generation_prompt"
	case differs(top["continue_final_message"], false):
		return "continue_final_message"
	case differs(top["add_special_tokens"], false):
		return "add_special_tokens"
	case kvJSONPresent(top["documents"]):
		return "documents"
	case kvJSONPresent(top["reasoning_effort"]):
		return "reasoning_effort"
	case kvJSONPresent(top["chat_template"]):
		return "chat_template"
	case kvJSONPresent(top["truncate_prompt_tokens"]):
		return "truncate_prompt_tokens"
	case kvJSONPresent(top["prompt_token_ids"]) || kvJSONPresent(top["prompt_token_ids_b64"]):
		return "prompt_token_ids"
	}
	for _, m := range msgs {
		var parts []map[string]json.RawMessage
		if err := json.Unmarshal(m["content"], &parts); err == nil {
			for _, p := range parts {
				var typ string
				if json.Unmarshal(p["type"], &typ) == nil && typ != "" && typ != "text" {
					return "multimodal"
				}
			}
		}
	}
	return ""
}

// kvChatTemplateFeature refuses message shapes whose engine render the
// gateway cannot reproduce for this template (strict paths only, like
// kvChatExcludedFeature; "" = none):
//
//   - role "developer": vLLM v0.28.0 rewrites it to "system" and merges every
//     system turn into one at position 0 unless the template names
//     'developer'; TRT-LLM 1.3.0rc24 passes it through unchanged. The engines
//     disagree, so no single render is right.
//   - message-level "tools": SGLang v0.5.18 folds a system/developer turn's
//     tools into the template's tools argument.
//   - any other message key the template mentions (name, tool_calls,
//     reasoning_content, ...): the gateway renders role/content only, while
//     the engines pass such keys into the message the template reads. A key
//     the template never mentions cannot change the render. The test is
//     textual (like vLLM's own developer-role detection): a false positive
//     only refuses.
//   - a null or absent content when the template tests content for none or
//     definedness: the gateway renders "" and cannot know the engine's value.
func kvChatTemplateFeature(body, templateSrc string) string {
	_, msgs, ok := kvChatDecodeExact(body)
	if !ok {
		return "unparseable"
	}
	for _, m := range msgs {
		var role string
		_ = json.Unmarshal(m["role"], &role)
		if role == "developer" {
			return "developer_role"
		}
		for k, v := range m {
			switch k {
			case "role", "content":
				continue
			case "tools":
				if kvJSONPresent(v) {
					return "message_tools"
				}
				continue
			}
			if kvJSONPresent(v) && kvTemplateMentions(templateSrc, k) {
				return "message_field"
			}
		}
		if !kvJSONPresent(m["content"]) && kvTemplateTestsContent(templateSrc) {
			return "null_content"
		}
	}
	return ""
}

// kvTemplateMentions reports whether key appears in the template source as a
// whole word (attribute, subscript or string literal).
func kvTemplateMentions(src, key string) bool {
	for i := 0; ; {
		j := strings.Index(src[i:], key)
		if j < 0 {
			return false
		}
		j += i
		end := j + len(key)
		if (j == 0 || !kvIdentByte(src[j-1])) && (end == len(src) || !kvIdentByte(src[end])) {
			return true
		}
		i = j + 1
	}
}

func kvIdentByte(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// kvTemplateTestsContent reports a template that branches on whether a
// message's content is none or defined.
func kvTemplateTestsContent(src string) bool {
	return kvContentTestRe.MatchString(src)
}

var kvContentTestRe = regexp.MustCompile(`content['"]?\]?\s+is\s+(not\s+)?(none|defined|undefined)`)
