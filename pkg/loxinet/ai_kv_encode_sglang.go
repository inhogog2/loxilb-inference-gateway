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

// ai_kv_encode_sglang.go — SGLang's completions encoding. SGLang's tokenizer
// loader restores tokenizer_config.json's add_bos_token for the tokenizer
// classes that honoured it before transformers v5 and rebuilds the
// post-processor as "BOS, then the text" (get_tokenizer →
// _fix_v5_add_bos_eos_token → update_post_processor). Where that happens the
// profile records engineQuirks.<contract>.completionsBos, measured on the
// live engine; this module owns what the fact means:
//
//   - every TEXT prompt is encoded as BOS + the text without the file's own
//     post-processor (the rebuilt one replaced it);
//   - the BOS is unconditional: a text that already starts with the BOS
//     string gets a second one, and add_special_tokens:false in the request
//     is ignored;
//   - a prompt given as token ids is not encoded at all, so it never reaches
//     an encoder.
//
// Without the fact SGLang encodes like the tokenizer file says.

import "errors"

type kvSglangEncoder struct{}

func (kvSglangEncoder) CompletionsCheck(e kvCompletionsEncoding) error {
	if e.quirks.CompletionsBos && !e.bosOK {
		return errors.New("completionsBos is recorded, but the profile's renderPolicy.bosToken resolves to no single special token id in the pinned tokenizer")
	}
	return nil
}

func (kvSglangEncoder) EncodeCompletions(base kvBaseTokenizeFn, e kvCompletionsEncoding, text, model string, max int) []uint32 {
	if !e.quirks.CompletionsBos {
		return base(text, model, max, true)
	}
	ids := base(text, model, max, false)
	if len(ids) == 0 {
		return nil
	}
	return kvPrependCapped(e.bosID, ids, max)
}
