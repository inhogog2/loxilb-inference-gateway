# SGLang `/v1/tokenize` fix (0.5.12 - 0.5.18)

`serving_tokenize.py` is SGLang **v0.5.19**'s
`python/sglang/srt/entrypoints/openai/serving_tokenize.py`, unmodified (sha256
`7ef745d2d1ba1bee722a3ddc3ec0feb700a6e0aef40645ad67b7d04876e921f2`). SGLang is licensed under the Apache
License 2.0; the file is redistributed here under that license.

Between v0.5.18 and v0.5.19 the file changes by one upstream commit, `032fe91bf1` "Handle unlimited tokenizer
context lengths" (sgl-project/sglang#37054). Tokenizers that declare no length limit carry transformers'
sentinel `model_max_length = int(1e30)`; v0.5.18 returns it as `max_model_len`, orjson cannot encode an
integer that large, and `/v1/tokenize` answers 500. v0.5.19 reports the model's context length instead.
Nothing else in the file differs.

SGLang 0.5.12 through 0.5.18 ship one byte-identical `serving_tokenize.py` (sha256 `f1791dbe…`), so this
same file replaces it in all seven. The one dependency the fix adds, `tokenizer_manager.model_config.context_len`,
exists in each of them (checked in source); the live P/D legs ran on 0.5.18. `engine.sh` mounts the file
read-only over the image's copy only when the image's own file hashes to `f1791dbe…` (the table in `env.sh`).
It changes the tokenize endpoint only: the chat and completion serving paths are untouched, so the gateway's
token-parity probe still compares the engine's real tokenizer with the pinned one.
