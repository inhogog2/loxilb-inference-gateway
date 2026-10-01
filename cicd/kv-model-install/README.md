# kv-model-install — supported-models manifest, drift gate and installer

Runs without a GPU and without a gateway.

```bash
./validation.sh                                   # everything, including one real install from the hub
REAL=0 ./validation.sh                            # no network
REF_REG=/etc/loxilb/kvprofiles ./validation.sh    # also compare the real install with a registry a gateway loaded
```

What it proves (labels as printed):

| Group | Claim |
|---|---|
| D1 | `scripts/models/modelctl.py check` is green on the committed tree: `docs/SUPPORTED-MODELS.md`, `scripts/models/validated-models.yaml`, the committed profiles and engine manifests, `SOURCES.json`, the weights indexes and `engine-contracts/support-catalog.yaml` agree. |
| D2–D10 | Each single edit to one of those is reported by name — on a scratch copy, never on the repository. Includes the two promotion rules: a row cannot be `validated` with an evidence gate that did not run, nor on an engine entry the support catalog has not validated. |
| I1–I7 | The installer against a local stand-in for the hub (`hf_stub.py`): candidates are not installed by default; `--dry-run` writes nothing; an install stages the registry layout with verified digests and 0644 files; a re-run with the hub down downloads nothing; a partial weight file resumes with a Range request. |
| N1–N13 | Refusals, each typed: tampered tokenizer (nothing staged), tampered weight (set aside as `.rejected`), a symlink beneath an install root (nothing written through it), relative or `..` install roots, a symlink in the committed fixtures, unknown model, blocked row, gated model without a token, a branch name instead of a pinned commit, a denied download, a token file readable by others. With a token the request carries it and the output does not. |
| R1 | One real install from the hub at the pinned revision; the downloaded `tokenizer.json` is the committed profile's. With `REF_REG`, the staged files are byte-identical to that registry's. |

Needs `python3` with PyYAML, `git` (for `git hash-object`), GNU coreutils. Nothing is written outside a
temporary directory, which is removed on exit.
