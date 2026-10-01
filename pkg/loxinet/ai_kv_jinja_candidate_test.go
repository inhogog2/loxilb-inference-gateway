// SPDX-License-Identifier: Apache-2.0
//
// ai_kv_jinja_candidate_test.go — whole-template parity for candidate models.
//
// cicd/common/kv_hash/fixtures/kv_chat_render_candidates.json carries, per
// pinned candidate model, the template source and the engine renderer's
// output for a battery of conversations (gen_chat_render_candidates.py, run
// inside the engine image). Rendering goes through the SERVING context
// builder (kvJinjaChatContext) with only what a profile can declare —
// bos/eos, and the utc-date clock policy for templates that print a date —
// so a template that depends on anything else (another special token, a
// template kwarg) shows up here as a mismatch or a refusal.

package loxinet

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"
	"time"
)

// kvJjCandidateExact is the set of candidate models whose every golden case
// the executor reproduces byte-for-byte. It must equal the computed set: a
// model that becomes exact is added here deliberately, and one that stops
// being exact fails the test.
var kvJjCandidateExact = map[string]bool{
	"LGAI-EXAONE__EXAONE-3.5-7.8B-Instruct":      true,
	"LGAI-EXAONE__EXAONE-4.0-1.2B":               true,
	"NousResearch__Meta-Llama-3.1-8B-Instruct":   true,
	"Qwen__Qwen2.5-7B-Instruct":                  true,
	"Qwen__Qwen3-0.6B":                           true,
	"Qwen__Qwen3.6-27B-FP8":                      true,
	"Qwen__Qwen3.8-27B-FP8":                      true,
	"allenai__OLMo-2-0425-1B-Instruct":           true,
	"deepseek-ai__DeepSeek-R1-Distill-Qwen-1.5B": true,
	"google__gemma-3-1b-it":                      true,
	"google__gemma-4-E2B-it":                     true,
	"ibm-granite__granite-4.2-3b":                true,
	"meta-llama__Llama-3.2-1B-Instruct":          true,
	"meta-models__Muse-Glimmer-30B":              true,
	"microsoft__Phi-4-mini-instruct":             true,
	"mistralai__Ministral-3-3B-Instruct-2512":    true,
	"openai__gpt-oss-20b":                        true,
	"skt__A.X-3.1-Light":                         true,
}

type kvJjCandidateFixture struct {
	FrozenNow string `json:"frozen_now"`
	Models    map[string]struct {
		Model          string  `json:"model"`
		Revision       string  `json:"revision"`
		TemplateSha256 string  `json:"template_sha256"`
		Template       string  `json:"template"`
		BosToken       *string `json:"bos_token"`
		EosToken       *string `json:"eos_token"`
		Cases          map[string]struct {
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
			Rendered *string `json:"rendered"`
			Error    string  `json:"error"`
		} `json:"cases"`
	} `json:"models"`
}

func TestKvJinjaCandidateParity(t *testing.T) {
	data, err := os.ReadFile(kvHashFixturePath(t, "kv_chat_render_candidates.json"))
	if err != nil {
		t.Fatalf("candidate goldens missing: %v", err)
	}
	var f kvJjCandidateFixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse candidate goldens: %v", err)
	}
	frozen, err := time.Parse("2006-01-02T15:04:05", f.FrozenNow)
	if err != nil {
		t.Fatalf("frozen_now: %v", err)
	}
	prevClock := kvChatClock
	kvChatClock = func() time.Time { return frozen }
	t.Cleanup(func() { kvChatClock = prevClock })

	exact := map[string]bool{}
	status := map[string]string{}
	slugs := make([]string, 0, len(f.Models))
	for slug := range f.Models {
		slugs = append(slugs, slug)
	}
	sort.Strings(slugs)
	for _, slug := range slugs {
		m := f.Models[slug]
		t.Run(slug, func(t *testing.T) {
			sum := sha256.Sum256([]byte(m.Template))
			if hex.EncodeToString(sum[:]) != m.TemplateSha256 {
				t.Fatalf("embedded template does not hash to its recorded digest")
			}
			tpl, err := kvJinjaCompile(m.Template)
			if err != nil {
				status[slug] = "compile: " + err.Error()
				t.Logf("REFUSED at compile: %v", err)
				return
			}
			pol := KvRenderPolicy{AddGenerationPrompt: true}
			if m.BosToken != nil {
				pol.BosToken = *m.BosToken
			}
			if m.EosToken != nil {
				pol.EosToken = *m.EosToken
			}
			if tpl.References("strftime_now") {
				pol.ClockPolicy = KvClockPolicyUTCDate
			}
			if err := kvCheckClockPolicy(tpl, &pol); err != nil {
				t.Fatalf("clock policy: %v", err)
			}
			names := make([]string, 0, len(m.Cases))
			for n := range m.Cases {
				names = append(names, n)
			}
			sort.Strings(names)
			var refused []string
			for _, name := range names {
				c := m.Cases[name]
				msgs := make([]kvChatMessage, len(c.Messages))
				for i, x := range c.Messages {
					msgs[i] = kvChatMessage{Role: x.Role, Content: x.Content}
				}
				got, rerr := tpl.Render(kvJinjaChatContext(msgs, pol))
				switch {
				case c.Rendered == nil:
					if rerr == nil {
						t.Errorf("%s: template raises (%s) but the executor rendered %q", name, c.Error, got)
					}
				case rerr != nil:
					refused = append(refused, name+": "+rerr.Error())
				case got != *c.Rendered:
					t.Errorf("%s: SILENT MISMATCH\n got:  %q\n want: %q", name, got, *c.Rendered)
				}
			}
			if t.Failed() {
				status[slug] = "MISMATCH"
				return
			}
			if len(refused) > 0 {
				status[slug] = "refused " + strings.Join(refused, "; ")
				t.Logf("refused %d case(s): %s", len(refused), strings.Join(refused, " | "))
				return
			}
			exact[slug] = true
			status[slug] = "exact"
		})
	}
	for _, slug := range slugs {
		t.Logf("%-45s %s", slug, status[slug])
	}
	for slug := range exact {
		if !kvJjCandidateExact[slug] {
			t.Errorf("%s is now byte-exact on every case; add it to kvJjCandidateExact", slug)
		}
	}
	for slug := range kvJjCandidateExact {
		if !exact[slug] {
			t.Errorf("%s is listed in kvJjCandidateExact but is not exact: %s", slug, status[slug])
		}
	}
}
