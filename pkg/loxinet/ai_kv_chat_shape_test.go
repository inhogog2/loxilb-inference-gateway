package loxinet

import (
	"encoding/json"
	"os"
	"sort"
	"testing"
	"time"
)

// kvJjEngineOpenAIFormat is the content format both engines detect for each
// pinned candidate template: vLLM v0.28.0 renderers/hf.py
// _detect_content_format and SGLang v0.5.18
// detect_jinja_template_content_format, run on the templates in
// kv_chat_render_candidates.json inside the engine images (they agree on all
// eighteen). Every other candidate is "string".
var kvJjEngineOpenAIFormat = map[string]bool{
	"google__gemma-3-1b-it":                   true,
	"google__gemma-4-E2B-it":                  true,
	"meta-models__Muse-Glimmer-30B":           true,
	"mistralai__Ministral-3-3B-Instruct-2512": true,
	"Qwen__Qwen3.6-27B-FP8":                   true,
	"Qwen__Qwen3.8-27B-FP8":                   true,
}

func kvJjLoadCandidates(t *testing.T) kvJjCandidateFixture {
	t.Helper()
	data, err := os.ReadFile(kvHashFixturePath(t, "kv_chat_render_candidates.json"))
	if err != nil {
		t.Fatalf("candidate goldens missing: %v", err)
	}
	var f kvJjCandidateFixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse candidate goldens: %v", err)
	}
	return f
}

// TestKvJinjaIteratesContentCoversEngines: the gateway's content-loop
// detection must flag every template an engine serves in "openai" content
// format, or the shape check would skip a template the engine hands lists.
func TestKvJinjaIteratesContentCoversEngines(t *testing.T) {
	f := kvJjLoadCandidates(t)
	slugs := make([]string, 0, len(f.Models))
	for slug := range f.Models {
		slugs = append(slugs, slug)
	}
	sort.Strings(slugs)
	for slug := range kvJjEngineOpenAIFormat {
		if _, ok := f.Models[slug]; !ok {
			t.Fatalf("%s: no longer in the candidate goldens; re-derive the engine table", slug)
		}
	}
	for _, slug := range slugs {
		tpl, err := kvJinjaCompile(f.Models[slug].Template)
		if err != nil {
			// A template the gateway cannot compile never serves strict chat.
			continue
		}
		if kvJjEngineOpenAIFormat[slug] && !tpl.IteratesContent() {
			t.Errorf("%s: the engines treat it as openai content format, the gateway sees no content loop", slug)
		}
	}
}

func TestKvJinjaIsContentAccessShapes(t *testing.T) {
	cases := []struct {
		src  string
		want bool
	}{
		{`{% for m in messages %}{% for p in m.content %}{{ p.text }}{% endfor %}{% endfor %}`, true},
		{`{% for m in messages %}{% for p in m['content'] %}{{ p.text }}{% endfor %}{% endfor %}`, true},
		{`{% macro r(content) %}{% for p in content %}{{ p.text }}{% endfor %}{% endmacro %}`, true},
		{`{% for p in messages[0]['content'] | list %}{{ p.text }}{% endfor %}`, true},
		{`{% for m in messages %}{% for p in m.content[1:] %}{{ p.text }}{% endfor %}{% endfor %}`, true},
		{`{% for m in messages %}{{ m.content }}{% endfor %}`, false},
		{`{% for m in messages %}{% for p in m.contents %}{{ p }}{% endfor %}{% endfor %}`, false},
		{`{% for m in messages %}{% for p in m.content_parts %}{{ p }}{% endfor %}{% endfor %}`, false},
	}
	for _, c := range cases {
		tpl, err := kvJinjaCompile(c.src)
		if err != nil {
			t.Fatalf("%s: compile: %v", c.src, err)
		}
		if got := tpl.IteratesContent(); got != c.want {
			t.Errorf("%s: IteratesContent %v, want %v", c.src, got, c.want)
		}
	}
}

// TestKvChatContentShapeDependentPinned drives the check with the pinned
// templates. gemma-4 prints a system text part with a trailing space, so a
// leading system message depends on the shape (vLLM v0.28.0 measured one
// extra token); Qwen3.6/3.8 and gemma-3 render both shapes alike (vLLM
// measured no difference), and a string-format template never pays the
// second render.
func TestKvChatContentShapeDependentPinned(t *testing.T) {
	f := kvJjLoadCandidates(t)
	sys := `{"messages":[{"role":"system","content":"You are terse."},{"role":"user","content":"hi"}]}`
	sysList := `{"messages":[{"role":"system","content":[{"type":"text","text":"You are terse."}]},{"role":"user","content":"hi"}]}`
	emptySys := `{"messages":[{"role":"system","content":""},{"role":"user","content":"hi"}]}`
	user := `{"messages":[{"role":"user","content":"hi"}]}`
	userList := `{"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`
	cases := []struct {
		slug, body string
		want       bool
	}{
		{"google__gemma-4-E2B-it", sys, true},
		{"google__gemma-4-E2B-it", sysList, true},
		{"google__gemma-4-E2B-it", emptySys, true},
		{"google__gemma-4-E2B-it", user, false},
		{"google__gemma-4-E2B-it", userList, false},
		{"Qwen__Qwen3.6-27B-FP8", sys, false},
		{"Qwen__Qwen3.8-27B-FP8", sysList, false},
		{"google__gemma-3-1b-it", sys, false},
		{"allenai__OLMo-2-0425-1B-Instruct", sys, false},
	}
	clock := func() time.Time { return time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC) }
	for _, c := range cases {
		m := f.Models[c.slug]
		pol := KvRenderPolicy{AddGenerationPrompt: true}
		if m.BosToken != nil {
			pol.BosToken = *m.BosToken
		}
		if m.EosToken != nil {
			pol.EosToken = *m.EosToken
		}
		kvTestPublishChatProfile(t, m.Model, m.Template, pol)
		msgs, ok := kvParseChatMessages(c.body)
		if !ok {
			t.Fatalf("%s: body does not parse", c.slug)
		}
		rendered, err := kvRenderChatTemplateReq(m.Model, msgs, clock)
		if err != nil {
			t.Fatalf("%s: render: %v", c.slug, err)
		}
		if got := kvChatContentShapeDependent(m.Model, c.body, msgs, rendered, clock); got != c.want {
			t.Errorf("%s %s: shape dependent %v, want %v", c.slug, c.body, got, c.want)
		}
	}
}

// TestKvBridgeChatShapeAndTrailingAssistantRefusals drives the strict bridge
// with no tokenizer staged, so a body that reaches the tokenizer returns the
// tokenizer fault and UNSUPPORTED proves a refusal ran first.
func TestKvBridgeChatShapeAndTrailingAssistantRefusals(t *testing.T) {
	kvDataplaneTestSetup(t)
	kvTestRegister(53, "rule-chat-shape", KvContractAPIBoth)
	b, err := KvBindingAllocate("rule-chat-shape", kvTestComponents(1))
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	kvSvcContractOutcome(53, false, "")

	cases := []struct {
		name, tpl, body string
		want            int
	}{
		// gemma-4's construct: a text part gains a trailing space.
		{"part_space_string", `{% for m in messages %}{% if m.content is string %}{{ m.content | trim }}{% else %}{% for p in m.content %}{{ p.text | trim + ' ' }}{% endfor %}{% endif %}{% endfor %}`,
			`{"messages":[{"role":"user","content":"hi"}]}`, KvTokErrUnsupported},
		// Both shapes render alike: nothing to refuse.
		{"shape_invariant", `{% for m in messages %}{% if m.content is string %}{{ m.content }}{% else %}{% for p in m.content %}{{ p.text }}{% endfor %}{% endif %}{% endfor %}`,
			`{"messages":[{"role":"user","content":"hi"}]}`, KvTokErrTokenizer},
		// A list render the template refuses is a dependence too.
		{"list_raises", `{% for m in messages %}{% if m.content is string %}{{ m.content }}{% else %}{% for p in m.content %}{{ raise_exception('no lists') }}{% endfor %}{% endif %}{% endfor %}`,
			`{"messages":[{"role":"user","content":"hi"}]}`, KvTokErrUnsupported},
		// SGLang keeps a client list for a template mentioning image; this
		// one prints the list itself.
		{"media_word_client_list", `{# image #}{% for m in messages %}{{ m.content }}{% endfor %}`,
			`{"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`, KvTokErrUnsupported},
		{"media_word_client_string", `{# image #}{% for m in messages %}{{ m.content }}{% endfor %}`,
			`{"messages":[{"role":"user","content":"hi"}]}`, KvTokErrTokenizer},
		// No engine hands this template a list: a client list is joined.
		{"string_format_client_list", `{% for m in messages %}{{ m.content }}{% endfor %}`,
			`{"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`, KvTokErrTokenizer},
		{"trailing_assistant", `{% for m in messages %}{{ m.content }}{% endfor %}`,
			`{"messages":[{"role":"user","content":"q"},{"role":"assistant","content":"a"}]}`, KvTokErrUnsupported},
		{"assistant_then_user", `{% for m in messages %}{{ m.content }}{% endfor %}`,
			`{"messages":[{"role":"user","content":"q"},{"role":"assistant","content":"a"},{"role":"user","content":"r"}]}`, KvTokErrTokenizer},
	}
	for i, c := range cases {
		model := "acme/shape-" + c.name
		kvTestPublishChatProfile(t, model, c.tpl, KvRenderPolicy{AddGenerationPrompt: true})
		if _, rc := kvBridgeTokenizeChat(53, b.BindingGen, c.body, model, 16); rc != c.want {
			t.Errorf("%d %s: strict rc %d, want %d", i, c.name, rc, c.want)
		}
		// Legacy rules never consult the refusals.
		if _, rc := kvBridgeTokenizeChat(0, 0, c.body, model, 16); rc == KvTokErrUnsupported {
			t.Errorf("%d %s: legacy path refused UNSUPPORTED", i, c.name)
		}
	}
}
