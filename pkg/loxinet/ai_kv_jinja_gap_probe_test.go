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
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// TestKvJinjaGapProbe compiles and renders every candidate model's chat
// template through the in-process executor and reports the first construct
// each one trips on. It is a survey, not a gate: it runs only when
// KV_JINJA_GAP_DIR points at a directory of <model>/_effective_template.jinja
// files plus a pins.json carrying each model's bos/eos strings.
func TestKvJinjaGapProbe(t *testing.T) {
	dir := os.Getenv("KV_JINJA_GAP_DIR")
	if dir == "" {
		t.Skip("KV_JINJA_GAP_DIR not set")
	}
	var pins map[string]struct {
		BosToken *string `json:"bos_token"`
		EosToken *string `json:"eos_token"`
	}
	if b, err := os.ReadFile(filepath.Join(dir, "..", "pins.json")); err == nil {
		_ = json.Unmarshal(b, &pins)
	}
	paths, _ := filepath.Glob(filepath.Join(dir, "*", "_effective_template.jinja"))
	sort.Strings(paths)
	if len(paths) == 0 {
		t.Fatalf("no templates under %s", dir)
	}
	convs := map[string][]kvChatMessage{
		"user":       {{Role: "user", Content: "Hello"}},
		"sys+user":   {{Role: "system", Content: "Be brief."}, {Role: "user", Content: "Hello"}},
		"multi-turn": {{Role: "user", Content: "Hi"}, {Role: "assistant", Content: "Hello!"}, {Role: "user", Content: "Bye"}},
	}
	names := []string{"user", "sys+user", "multi-turn"}
	for _, p := range paths {
		slug := filepath.Base(filepath.Dir(p))
		src, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("%s: %v", slug, err)
		}
		tpl, err := kvJinjaCompile(string(src))
		if err != nil {
			t.Logf("GAP %-45s COMPILE %v", slug, err)
			continue
		}
		pol := KvRenderPolicy{AddGenerationPrompt: true}
		if pin, ok := pins[slug]; ok {
			if pin.BosToken != nil {
				pol.BosToken = *pin.BosToken
			}
			if pin.EosToken != nil {
				pol.EosToken = *pin.EosToken
			}
		}
		verdict := "OK"
		for _, n := range names {
			if _, err := tpl.Render(kvJinjaChatContext(convs[n], pol)); err != nil {
				verdict = "RENDER[" + n + "] " + err.Error()
				break
			}
		}
		t.Logf("GAP %-45s %s", slug, verdict)
	}
}
