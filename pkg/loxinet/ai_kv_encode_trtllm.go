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

// ai_kv_encode_trtllm.go — TensorRT-LLM's completions encoding. trtllm-serve
// encodes a text prompt with the transformers tokenizer as loaded
// (add_special_tokens=True, the tokenizer file's own post-processor), the
// same rule as vLLM. It is a module of its own so a TRT-LLM divergence is
// recorded here and never inherited from another engine.

import "errors"

type kvTrtllmEncoder struct{}

func (kvTrtllmEncoder) CompletionsCheck(e kvCompletionsEncoding) error {
	if e.quirks.CompletionsBos {
		return errors.New("completionsBos is recorded for a TensorRT-LLM contract, but the TensorRT-LLM encoder does not add a BOS")
	}
	return nil
}

func (kvTrtllmEncoder) EncodeCompletions(base kvBaseTokenizeFn, _ kvCompletionsEncoding, text, model string, max int) []uint32 {
	return base(text, model, max, true)
}
