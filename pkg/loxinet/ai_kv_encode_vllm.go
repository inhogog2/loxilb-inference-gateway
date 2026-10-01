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

// ai_kv_encode_vllm.go — vLLM's completions encoding. vLLM serves the
// tokenizer transformers loads, and transformers v5 drops add_bos_token /
// add_eos_token when a tokenizer.json exists: a text prompt is encoded by the
// file's own post-processor with add_special_tokens=True, nothing else.

import "errors"

type kvVllmEncoder struct{}

func (kvVllmEncoder) CompletionsCheck(e kvCompletionsEncoding) error {
	if e.quirks.CompletionsBos {
		return errors.New("completionsBos is recorded for a vLLM contract, but vLLM encodes completions with the tokenizer's own post-processor; the vLLM encoder does not add a BOS")
	}
	return nil
}

func (kvVllmEncoder) EncodeCompletions(base kvBaseTokenizeFn, _ kvCompletionsEncoding, text, model string, max int) []uint32 {
	return base(text, model, max, true)
}
