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

// ai_kv_encode_llamacpp.go — llama.cpp has no KV-exact contract: the gateway
// never hashes a prompt for it, so there is no completions encoding to
// reproduce. The module exists so the family is refused by name instead of
// being encoded by another engine's rule.

import "errors"

type kvLlamacppEncoder struct{}

func (kvLlamacppEncoder) CompletionsCheck(kvCompletionsEncoding) error {
	return errors.New("llama.cpp has no KV-exact surface; there is no completions encoding to reproduce")
}

func (kvLlamacppEncoder) EncodeCompletions(kvBaseTokenizeFn, kvCompletionsEncoding, string, string, int) []uint32 {
	return nil
}
