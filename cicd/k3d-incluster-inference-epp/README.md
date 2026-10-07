# k3d-incluster-inference-epp

loxilb (in-cluster DaemonSet) asks an **Endpoint Picker (EPP)** where every
request of a fullproxy rule goes, over Envoy's ext_proc protocol (Phase 1 of
the EPP integration).

The EPP is `cmd/epp-fake`, a pure-Go ext_proc server built by `config.sh` and
run on the CI host (the k3d node's gateway on the cluster network). It names
one mock vLLM pod for every request and plays the response phase like the
llm-d EPP, so neither the InferencePool CRDs nor kube-loxilb are needed: the
rules go in over REST (`eppEndpoint`, `eppFailureMode`, `eppTimeoutMs`,
`eppPlaintext`).

`validation.sh` checks that

1. the EPP rules are accepted and read back;
2. every request is served by the pod the EPP named (`X-Served-By`), and the
   `loxilb_ai_epp_*` metrics account for it;
3. with the EPP stopped, a FailOpen rule falls back to its own selector and a
   FailClose rule answers `503 epp_unavailable`;
4. with the EPP back, routing follows it again;
5. an EPP that sheds requests gets its 429 relayed to the client.

A loxilb image without EPP support makes the scenario report `[SKIPPED]`.
Run with `IGW_IMAGE=<image built from this tree>` to test a branch.
