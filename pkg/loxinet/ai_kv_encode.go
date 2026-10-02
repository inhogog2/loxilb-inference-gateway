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

// ai_kv_encode.go — the per-engine completions-encoder seam. An engine's
// serving path encodes a text completions prompt from more than
// tokenizer.json: its own tokenizer loader decides which settings of
// tokenizer_config.json apply. Each engine family owns one module
// (ai_kv_encode_<engine>.go) that states how that engine encodes; this file
// only resolves a rule's engine contract to its module. The tokenize bridge,
// the echo challenge and the oracle probe all encode through
// kvEncodeCompletions, so serving and attestation cannot drift apart.

import (
	"encoding/json"
	"fmt"

	"github.com/loxilb-io/loxilb/pkg/enginecontract"
)

// kvBaseTokenizeFn is the pinned tokenizer an engine module encodes with:
// the profile's tokenizer.json, with or without its own post-processor.
type kvBaseTokenizeFn func(text, model string, max int, addSpecialTokens bool) []uint32

// kvCompletionsEncoding is what an engine module needs of one bound rule:
// the rule's engine contract, the profile's measured quirks for that
// contract, and the profile's BOS id where the pinned tokenizer resolves one.
// Comparable: the challenge plan carries it.
type kvCompletionsEncoding struct {
	contractID string
	quirks     KvEngineQuirks
	bosID      uint32
	bosOK      bool
}

// kvEngineEncoder is one engine family's completions encoding.
type kvEngineEncoder interface {
	// CompletionsCheck reports whether this module reproduces the encoding e
	// describes. A measured fact the module does not model is an error:
	// encoding as if the fact were absent would hash a prompt the engine
	// never builds.
	CompletionsCheck(e kvCompletionsEncoding) error
	// EncodeCompletions returns the ids the engine's serving path encodes a
	// TEXT completions prompt to, cut to max. Called only after
	// CompletionsCheck passed.
	EncodeCompletions(base kvBaseTokenizeFn, e kvCompletionsEncoding, text, model string, max int) []uint32
}

// kvEngineEncoderFor maps an engine family to its encoder module. A family
// without a module returns nil and is refused by every caller — never
// encoded by another engine's rule.
func kvEngineEncoderFor(engine string) kvEngineEncoder {
	switch engine {
	case "vllm":
		return kvVllmEncoder{}
	case "sglang":
		return kvSglangEncoder{}
	case "trtllm":
		return kvTrtllmEncoder{}
	case "llamacpp":
		return kvLlamacppEncoder{}
	default:
		return nil
	}
}

// kvEncoderForContract resolves the module by the rule's engine CONTRACT
// (the key the quirks are recorded under), then checks the encoding.
func kvEncoderForContract(e kvCompletionsEncoding) (kvEngineEncoder, error) {
	cp, ok := enginecontract.ProfileByID(e.contractID)
	if !ok {
		return nil, fmt.Errorf("engine contract %q is not a compiled contract profile", e.contractID)
	}
	enc := kvEngineEncoderFor(cp.Engine)
	if enc == nil {
		return nil, fmt.Errorf("engine %q (contract %s) has no completions encoder", cp.Engine, e.contractID)
	}
	if err := enc.CompletionsCheck(e); err != nil {
		return nil, err
	}
	return enc, nil
}

// kvEncodeCompletions encodes a text completions prompt the way the engine
// behind contract e.contractID does.
func kvEncodeCompletions(base kvBaseTokenizeFn, e kvCompletionsEncoding, text, model string, max int) ([]uint32, error) {
	enc, err := kvEncoderForContract(e)
	if err != nil {
		return nil, err
	}
	return enc.EncodeCompletions(base, e, text, model, max), nil
}

// kvCompletionsEncodingOf composes the encoding of profile p on a contract.
func kvCompletionsEncodingOf(p *ModelPromptProfile, contractID string) kvCompletionsEncoding {
	return kvCompletionsEncoding{
		contractID: contractID,
		quirks:     p.EngineQuirks[contractID],
		bosID:      p.completionsBosID,
		bosOK:      p.completionsBosOK,
	}
}

// kvProfileNeedsBosID reports whether any contract of p records an
// engine-added completions BOS.
func kvProfileNeedsBosID(p *ModelPromptProfile) bool {
	for _, q := range p.EngineQuirks {
		if q.CompletionsBos {
			return true
		}
	}
	return false
}

// kvTokenizerSpecialID resolves a special-token string to its id in a
// tokenizer.json: exactly one added token with that content, marked special.
func kvTokenizerSpecialID(tokenizerJSON []byte, content string) (uint32, error) {
	var doc struct {
		AddedTokens []struct {
			ID      *uint32 `json:"id"`
			Content string  `json:"content"`
			Special bool    `json:"special"`
		} `json:"added_tokens"`
	}
	if err := json.Unmarshal(tokenizerJSON, &doc); err != nil {
		return 0, fmt.Errorf("tokenizer.json unparseable: %w", err)
	}
	var id uint32
	n := 0
	for _, at := range doc.AddedTokens {
		if at.Content != content {
			continue
		}
		if at.ID == nil || !at.Special {
			return 0, fmt.Errorf("added token %q is not a special token with an id", content)
		}
		id = *at.ID
		n++
	}
	if n != 1 {
		return 0, fmt.Errorf("%d added tokens match %q, want exactly one", n, content)
	}
	return id, nil
}

// kvPrependCapped returns [first] + ids cut to max: the prepended id counts
// against the cap, as it does in the engine's own prompt.
func kvPrependCapped(first uint32, ids []uint32, max int) []uint32 {
	if max <= 0 {
		return nil
	}
	out := make([]uint32, 0, len(ids)+1)
	out = append(out, first)
	out = append(out, ids...)
	if len(out) > max {
		out = out[:max]
	}
	return out
}
