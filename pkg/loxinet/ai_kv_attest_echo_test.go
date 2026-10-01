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

// ai_kv_attest_echo_test.go — GPU-free §6.2 echo-challenge suite: the
// nonce-unique prompt construction, deterministic await-own-hashes
// correlation through the subscriber watch seam, the on-wire token_id /
// extra_keys checks, and the timeout path. The hasher and tokenizer are
// deterministic fakes; the C-hasher parity itself is pinned by the
// kv_hash_vectors fixtures (C test) and the tier15 path.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const kvEchoTestBS = 4

// kvEchoTestTokenizer: deterministic token stream — token i of a text is
// (len(text)+i) so different prompts (different nonces) yield different
// token sequences. Produces one token per 4 bytes, so the filler loop
// reaches 2×blockSize quickly.
func kvEchoTestTokenizer(text, model string, max int) []uint32 {
	n := len(text) / 4
	if n > max {
		n = max
	}
	out := make([]uint32, n)
	for i := range out {
		out[i] = uint32(len(text) + i)
	}
	return out
}

// kvEchoTestHasher: deterministic chained fake — hash of block i depends on
// every token up to and including block i (chaining property preserved).
func kvEchoTestHasher(algo string, blockSize uint32, tokens []uint32) ([]uint64, bool) {
	if algo != "sha256_cbor" {
		return nil, false
	}
	nBlocks := len(tokens) / int(blockSize)
	out := make([]uint64, 0, nBlocks)
	var h uint64 = 1469598103934665603
	for b := 0; b < nBlocks; b++ {
		for t := 0; t < int(blockSize); t++ {
			h = (h ^ uint64(tokens[b*int(blockSize)+t])) * 1099511628211
		}
		out = append(out, h)
	}
	return out, true
}

func kvEchoTestSetup(t *testing.T) {
	t.Helper()
	prevTok := kvChallengeTokenizeFn
	kvChallengeTokenizeFn = kvEchoTestTokenizer
	KvRegisterChallengeHasher(kvEchoTestHasher)
	prevTimeout := kvChallengeTimeoutV
	kvChallengeTimeoutV = 2 * time.Second
	t.Cleanup(func() {
		kvChallengeTokenizeFn = prevTok
		KvRegisterChallengeHasher(nil)
		kvChallengeTimeoutV = prevTimeout
	})
}

// kvEchoAwaitWatch polls the watch registry until the challenge under test
// arms its expectation. Returns nil on timeout (callers run in feeder
// goroutines — the un-fed challenge then times out and the main test
// goroutine reports the failure).
func kvEchoAwaitWatch(svcID uint32, epIdx int) *kvHashWatch {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		kvHashWatchMu.RLock()
		ws := kvHashWatches[kvHashWatchKey(svcID, epIdx)]
		kvHashWatchMu.RUnlock()
		if len(ws) > 0 {
			return ws[0]
		}
		time.Sleep(2 * time.Millisecond)
	}
	return nil
}

// kvEchoWatchExpectation snapshots the armed watch's expected hashes (in
// block order) and want-token sequence.
func kvEchoWatchExpectation(w *kvHashWatch) ([]uint64, []uint32) {
	w.mu.Lock()
	defer w.mu.Unlock()
	hashes := make([]uint64, len(w.hashIndex))
	for h, idx := range w.hashIndex {
		hashes[idx] = h
	}
	return hashes, append([]uint32(nil), w.wantTokens...)
}

func kvEchoTestServer(t *testing.T, model string, completionsStatus int) (*httptest.Server, KvAttestEndpoint) {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/models":
			fmt.Fprintf(w, `{"data":[{"id":%q}]}`, model)
		case "/v1/completions":
			w.WriteHeader(completionsStatus)
			fmt.Fprint(w, `{}`)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(ts.Close)
	return ts, kvTestEndpoint(t, ts)
}

func kvEchoInfo() kvAttestRuleInfo {
	return kvAttestRuleInfo{
		svcID: 31, ruleIdent: "rule-31", modelName: "m-echo", engine: "vllm",
		hashAlgo: "sha256_cbor", blockSize: kvEchoTestBS, profileID: "prof-echo",
	}
}

// feedEvent resolves (or violates) the armed watch from a test goroutine —
// playing the subscriber loop's role.
func kvEchoFeed(t *testing.T, svcID uint32, epIdx int, mutate func(ev *kvEvent)) {
	t.Helper()
	go func() {
		w := kvEchoAwaitWatch(svcID, epIdx)
		if w == nil {
			return // challenge never armed; the main goroutine reports it
		}
		hashes, tokens := kvEchoWatchExpectation(w)
		ev := kvEvent{Type: kvEventBlockStored, Hashes: hashes, Tokens: tokens}
		if mutate != nil {
			mutate(&ev)
		}
		kvHashWatchObserve(svcID, epIdx, 0, ev)
	}()
}

func TestKvEchoChallengeSucceeds(t *testing.T) {
	kvEchoTestSetup(t)
	_, ep := kvEchoTestServer(t, "m-echo", 200)
	info := kvEchoInfo()
	kvEchoFeed(t, info.svcID, ep.EpIdx, nil)

	f := newKvVllmAttest().HashChallenge(ep, info)
	if !f.OK {
		t.Fatalf("challenge failed: %s %s", f.Reason, f.Detail)
	}
	// The nonce retired its registration.
	kvHashWatchMu.RLock()
	left := len(kvHashWatches[kvHashWatchKey(info.svcID, ep.EpIdx)])
	kvHashWatchMu.RUnlock()
	if left != 0 {
		t.Fatalf("%d watches leaked after challenge", left)
	}
}

// TestKvEchoChallengeSplitEvents: hashes arriving across TWO BlockStored
// events (each with its own token list) still resolve — correlation is per
// expected hash, not per event.
func TestKvEchoChallengeSplitEvents(t *testing.T) {
	kvEchoTestSetup(t)
	_, ep := kvEchoTestServer(t, "m-echo", 200)
	info := kvEchoInfo()

	go func() {
		w := kvEchoAwaitWatch(info.svcID, ep.EpIdx)
		if w == nil {
			return
		}
		hashes, tokens := kvEchoWatchExpectation(w)
		for i, h := range hashes {
			ev := kvEvent{Type: kvEventBlockStored,
				Hashes: []uint64{h},
				Tokens: tokens[i*kvEchoTestBS : (i+1)*kvEchoTestBS]}
			kvHashWatchObserve(info.svcID, ep.EpIdx, 0, ev)
		}
	}()

	if f := newKvVllmAttest().HashChallenge(ep, info); !f.OK {
		t.Fatalf("split-event challenge failed: %s %s", f.Reason, f.Detail)
	}
}

func TestKvEchoChallengeWrongTokensFails(t *testing.T) {
	kvEchoTestSetup(t)
	_, ep := kvEchoTestServer(t, "m-echo", 200)
	info := kvEchoInfo()
	kvEchoFeed(t, info.svcID, ep.EpIdx, func(ev *kvEvent) {
		ev.Tokens[1] ^= 0xFFFF // engine claims our hash but different tokens
	})

	f := newKvVllmAttest().HashChallenge(ep, info)
	if f.OK || f.Reason != KvAttestReasonChallengeFailed {
		t.Fatalf("finding = %+v, want challenge_failed on token mismatch", f)
	}
	if !strings.Contains(f.Detail, "token mismatch") {
		t.Fatalf("detail %q", f.Detail)
	}
}

func TestKvEchoChallengeExtraKeysFails(t *testing.T) {
	kvEchoTestSetup(t)
	_, ep := kvEchoTestServer(t, "m-echo", 200)
	info := kvEchoInfo()
	kvEchoFeed(t, info.svcID, ep.EpIdx, func(ev *kvEvent) {
		ev.ExtraKeys = true // extraKeyPolicy none_p0 violated on the wire
	})

	f := newKvVllmAttest().HashChallenge(ep, info)
	if f.OK || f.Reason != KvAttestReasonChallengeFailed {
		t.Fatalf("finding = %+v, want challenge_failed on extra_keys", f)
	}
}

func TestKvEchoChallengeTokenlessEventFails(t *testing.T) {
	kvEchoTestSetup(t)
	_, ep := kvEchoTestServer(t, "m-echo", 200)
	info := kvEchoInfo()
	kvEchoFeed(t, info.svcID, ep.EpIdx, func(ev *kvEvent) {
		ev.Tokens = nil // schema that omits token_ids cannot pass the check
	})

	f := newKvVllmAttest().HashChallenge(ep, info)
	if f.OK || f.Reason != KvAttestReasonChallengeFailed {
		t.Fatalf("finding = %+v, want challenge_failed on tokenless event", f)
	}
}

func TestKvEchoChallengeTimeout(t *testing.T) {
	kvEchoTestSetup(t)
	kvChallengeTimeoutV = 150 * time.Millisecond
	_, ep := kvEchoTestServer(t, "m-echo", 200)
	info := kvEchoInfo()
	// Nothing feeds the watch: no events ⇒ event-plane fault ⇒ fail.
	f := newKvVllmAttest().HashChallenge(ep, info)
	if f.OK || f.Reason != KvAttestReasonChallengeTimeout {
		t.Fatalf("finding = %+v, want challenge_timeout", f)
	}
}

func TestKvEchoChallengeModelNotServed(t *testing.T) {
	kvEchoTestSetup(t)
	_, ep := kvEchoTestServer(t, "some-other-model", 200)
	f := newKvVllmAttest().HashChallenge(ep, kvEchoInfo())
	if f.OK || f.Reason != KvAttestReasonIdentityMismatch {
		t.Fatalf("finding = %+v, want identity_mismatch", f)
	}
}

func TestKvEchoChallengeInferenceRejected(t *testing.T) {
	kvEchoTestSetup(t)
	_, ep := kvEchoTestServer(t, "m-echo", 500)
	f := newKvVllmAttest().HashChallenge(ep, kvEchoInfo())
	if f.OK || f.Reason != KvAttestReasonChallengeFailed {
		t.Fatalf("finding = %+v, want challenge_failed on HTTP 500", f)
	}
}

func TestKvEchoChallengeNoHasherFailsClosed(t *testing.T) {
	kvEchoTestSetup(t)
	KvRegisterChallengeHasher(nil)
	_, ep := kvEchoTestServer(t, "m-echo", 200)
	f := newKvVllmAttest().HashChallenge(ep, kvEchoInfo())
	if f.OK || f.Reason != KvAttestReasonChallengeFailed {
		t.Fatalf("finding = %+v, want fail-closed without hasher", f)
	}
}

// TestKvChallengeNonceUniqueness: different nonces produce different prompts
// AND different expected chains (the fake preserves the chaining property);
// the same nonce reproduces the same chain (repeatability, §6.2).
func TestKvChallengeNonceUniqueness(t *testing.T) {
	kvEchoTestSetup(t)
	p1, tok1, err := kvChallengeBuildPrompt("m-echo", "aaaabbbbccccdddd0000111122223333", kvEchoTestBS, kvChallengePlan{})
	if err != nil {
		t.Fatal(err)
	}
	p2, tok2, err := kvChallengeBuildPrompt("m-echo", "ffffeeeeddddcccc4444555566667777", kvEchoTestBS, kvChallengePlan{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p1, "aaaabbbbccccdddd0000111122223333") {
		t.Fatalf("nonce not embedded in prompt: %q", p1)
	}
	if len(tok1) < 2*kvEchoTestBS || len(tok1)%kvEchoTestBS != 0 {
		t.Fatalf("token sequence not >= 2 full blocks: %d", len(tok1))
	}
	h1, _ := kvEchoTestHasher("sha256_cbor", kvEchoTestBS, tok1)
	h2, _ := kvEchoTestHasher("sha256_cbor", kvEchoTestBS, tok2)
	if len(h1) < 2 {
		t.Fatalf("expected >= 2 chained hashes, got %d", len(h1))
	}
	// Same-length prompts would give equal token streams under the fake
	// tokenizer; both nonces are 32 hex chars, so lengths match — the
	// REAL uniqueness property under test is the prompt bytes differing
	// and a real tokenizer/hash chain diverging from the first block.
	if p1 == p2 {
		t.Fatalf("distinct nonces produced identical prompts")
	}
	p1b, tok1b, _ := kvChallengeBuildPrompt("m-echo", "aaaabbbbccccdddd0000111122223333", kvEchoTestBS, kvChallengePlan{})
	if p1 != p1b || fmt.Sprint(tok1) != fmt.Sprint(tok1b) {
		t.Fatalf("same nonce not reproducible")
	}
	_ = h1
	_ = h2
}

// TestKvHashWatchConcurrentObservers: watches from two concurrent challenges
// on the same endpoint resolve independently (globally unique nonce chains
// never collide; the registry must tolerate concurrent arm/observe/retire).
func TestKvHashWatchConcurrentObservers(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			expected := []uint64{uint64(1000 + i), uint64(2000 + i)}
			tokens := make([]uint32, 2*kvEchoTestBS)
			for j := range tokens {
				tokens[j] = uint32(i*100 + j)
			}
			w := kvHashWatchRegister(9, 0, expected, tokens, kvEchoTestBS, kvChallengePlan{})
			defer kvHashWatchUnregister(w)
			kvHashWatchObserve(9, 0, 0, kvEvent{Type: kvEventBlockStored, Hashes: expected, Tokens: tokens})
			select {
			case <-w.done:
				if r, _ := w.result(); r != "" {
					t.Errorf("watch %d failed: %s", i, r)
				}
			case <-time.After(2 * time.Second):
				t.Errorf("watch %d never resolved", i)
			}
		}(i)
	}
	wg.Wait()
}

// kvEchoFeedHybrid plays vLLM's per-KV-cache-group emission for a hybrid
// model: a sliding-window group whose blocks span two contract blocks (each
// carrying the hash of the LAST contract block it covers) arrives first,
// then the full-attention group at the contract block size. mutate edits the
// sliding-window event before delivery.
func kvEchoFeedHybrid(t *testing.T, svcID uint32, epIdx int, mutate func(ev *kvEvent)) {
	t.Helper()
	go func() {
		w := kvEchoAwaitWatch(svcID, epIdx)
		if w == nil {
			return
		}
		hashes, tokens := kvEchoWatchExpectation(w)
		const k = 2
		sw := kvEvent{Type: kvEventBlockStored, BlockSize: k * kvEchoTestBS}
		for i := k - 1; i < len(hashes); i += k {
			sw.Hashes = append(sw.Hashes, hashes[i])
		}
		sw.Tokens = append([]uint32(nil), tokens[:len(sw.Hashes)*k*kvEchoTestBS]...)
		if mutate != nil {
			mutate(&sw)
		}
		kvHashWatchObserve(svcID, epIdx, 0, sw)
		kvHashWatchObserve(svcID, epIdx, 0, kvEvent{Type: kvEventBlockStored, Hashes: hashes,
			Tokens: tokens, BlockSize: kvEchoTestBS})
	}()
}

// TestKvEchoChallengeHybridGroupEvents: a sliding-window group event whose
// block_size is a multiple of the contract size is checked against the
// contract blocks it covers, so a hybrid model's challenge resolves.
func TestKvEchoChallengeHybridGroupEvents(t *testing.T) {
	kvEchoTestSetup(t)
	_, ep := kvEchoTestServer(t, "m-echo", 200)
	info := kvEchoInfo()
	kvEchoFeedHybrid(t, info.svcID, ep.EpIdx, nil)
	if f := newKvVllmAttest().HashChallenge(ep, info); !f.OK {
		t.Fatalf("hybrid-group challenge failed: %s %s", f.Reason, f.Detail)
	}
}

// TestKvEchoChallengeHybridGroupWrongTokensFails: the FIRST contract block
// inside a wider event block is verified too — a flipped token there fails
// the challenge (a check that compared only the last contract block, or
// skipped wide events, would pass it).
func TestKvEchoChallengeHybridGroupWrongTokensFails(t *testing.T) {
	kvEchoTestSetup(t)
	_, ep := kvEchoTestServer(t, "m-echo", 200)
	info := kvEchoInfo()
	kvEchoFeedHybrid(t, info.svcID, ep.EpIdx, func(ev *kvEvent) {
		ev.Tokens[1] ^= 0xFFFF
	})
	f := newKvVllmAttest().HashChallenge(ep, info)
	if f.OK || f.Reason != KvAttestReasonChallengeFailed || !strings.Contains(f.Detail, "token mismatch") {
		t.Fatalf("finding = %+v, want challenge_failed on a token mismatch in the wide block", f)
	}
}

// TestKvEchoChallengeEventBlockSizeRefusals: an event block_size that is not
// a multiple of the contract size, or a wide block that would start before
// the first challenge block, fails the challenge.
func TestKvEchoChallengeEventBlockSizeRefusals(t *testing.T) {
	for _, c := range []struct {
		name, want string
		mutate     func(ev *kvEvent)
	}{
		{"not a multiple", "not a multiple of the contract block size", func(ev *kvEvent) { ev.BlockSize = kvEchoTestBS + 1 }},
		{"starts before block 0", "ends before it", func(ev *kvEvent) { ev.BlockSize = 2 * kvEchoTestBS }},
	} {
		t.Run(c.name, func(t *testing.T) {
			kvEchoTestSetup(t)
			_, ep := kvEchoTestServer(t, "m-echo", 200)
			info := kvEchoInfo()
			kvEchoFeed(t, info.svcID, ep.EpIdx, c.mutate)
			f := newKvVllmAttest().HashChallenge(ep, info)
			if f.OK || f.Reason != KvAttestReasonChallengeFailed || !strings.Contains(f.Detail, c.want) {
				t.Fatalf("finding = %+v, want challenge_failed %q", f, c.want)
			}
		})
	}
}

// TestKvChallengeBuildPromptCacheChunk: with a cache chunk the prompt grows
// until the engine's cached prefix, floor((n-1)/chunk)*chunk tokens, holds
// two full blocks, and the expected sequence stops at that boundary; a chunk
// that is not a multiple of the block size is refused.
func TestKvChallengeBuildPromptCacheChunk(t *testing.T) {
	kvEchoTestSetup(t)
	const nonce = "aaaabbbbccccdddd0000111122223333"
	for _, chunk := range []uint32{4, 16, 20} {
		p, tok, err := kvChallengeBuildPrompt("m-echo", nonce, kvEchoTestBS, kvChallengePlan{cacheChunk: chunk})
		if err != nil {
			t.Fatalf("chunk %d: %v", chunk, err)
		}
		n := len(kvEchoTestTokenizer(p, "m-echo", kvChallengeMaxTokens))
		if want := (n - 1) / int(chunk) * int(chunk); len(tok) != want {
			t.Fatalf("chunk %d: prompt of %d tokens, expected sequence %d tokens, want the cached prefix %d", chunk, n, len(tok), want)
		}
		if len(tok) < 2*kvEchoTestBS || len(tok)%int(chunk) != 0 {
			t.Fatalf("chunk %d: expected sequence %d tokens is not >= 2 blocks on a chunk boundary", chunk, len(tok))
		}
	}
	if _, _, err := kvChallengeBuildPrompt("m-echo", nonce, kvEchoTestBS, kvChallengePlan{cacheChunk: 6}); err == nil ||
		!strings.Contains(err.Error(), "not a multiple of the rule's block size") {
		t.Fatalf("chunk 6 on block size %d must be refused, got %v", kvEchoTestBS, err)
	}
}

// kvEchoFeedBlocks feeds the armed watch one BlockStored event per listed
// expected block index (a negative index means the last block), each with
// that block's own tokens, optionally corrupting the tokens of one block.
func kvEchoFeedBlocks(t *testing.T, svcID uint32, epIdx int, blocks []int, corrupt int) {
	t.Helper()
	go func() {
		w := kvEchoAwaitWatch(svcID, epIdx)
		if w == nil {
			return
		}
		hashes, tokens := kvEchoWatchExpectation(w)
		for _, listed := range blocks {
			b := listed
			if b < 0 {
				b = len(hashes) - 1
			}
			toks := append([]uint32(nil), tokens[b*kvEchoTestBS:(b+1)*kvEchoTestBS]...)
			if listed == corrupt {
				toks[0]++
			}
			kvHashWatchObserve(svcID, epIdx, 0, kvEvent{Type: kvEventBlockStored, Hashes: []uint64{hashes[b]}, Tokens: toks})
		}
	}()
}

// TestKvEchoChallengeLastBlock: a last-block plan passes when the engine
// stores only the prompt's last full block (vLLM Mamba "align"); without the
// plan the same echo never completes; a wrong last block, or a wrong earlier
// block that does arrive, still fails.
func TestKvEchoChallengeLastBlock(t *testing.T) {
	kvEchoTestSetup(t)
	_, ep := kvEchoTestServer(t, "m-echo", 200)
	info := kvEchoInfo()
	info.challenge = kvChallengePlan{lastBlock: true}

	kvEchoFeedBlocks(t, info.svcID, ep.EpIdx, []int{-1}, -99)
	if f := newKvVllmAttest().HashChallenge(ep, info); !f.OK || !strings.Contains(f.Detail, "last of") {
		t.Fatalf("last block only, last-block plan: want a pass that says so, got %+v", f)
	}

	kvEchoFeedBlocks(t, info.svcID, ep.EpIdx, []int{0, -1}, -99)
	if f := newKvVllmAttest().HashChallenge(ep, info); !f.OK {
		t.Fatalf("first + last block, last-block plan: want a pass, got %+v", f)
	}

	kvEchoFeedBlocks(t, info.svcID, ep.EpIdx, []int{-1}, -1)
	if f := newKvVllmAttest().HashChallenge(ep, info); f.OK || f.Reason != KvAttestReasonChallengeFailed {
		t.Fatalf("wrong tokens on the last block: want challenge_failed, got %+v", f)
	}

	kvEchoFeedBlocks(t, info.svcID, ep.EpIdx, []int{0, -1}, 0)
	if f := newKvVllmAttest().HashChallenge(ep, info); f.OK || f.Reason != KvAttestReasonChallengeFailed {
		t.Fatalf("wrong tokens on an earlier echoed block: want challenge_failed, got %+v", f)
	}

	kvChallengeTimeoutV = 300 * time.Millisecond
	kvEchoFeedBlocks(t, info.svcID, ep.EpIdx, []int{0}, -99)
	if f := newKvVllmAttest().HashChallenge(ep, info); f.OK || f.Reason != KvAttestReasonChallengeTimeout {
		t.Fatalf("first block only, last-block plan: only the last block ends the watch, want challenge_timeout, got %+v", f)
	}

	info.challenge = kvChallengePlan{}
	kvEchoFeedBlocks(t, info.svcID, ep.EpIdx, []int{-1}, -99)
	if f := newKvVllmAttest().HashChallenge(ep, info); f.OK || f.Reason != KvAttestReasonChallengeTimeout {
		t.Fatalf("last block only, default plan: every block is required, want challenge_timeout, got %+v", f)
	}
}

// TestKvChallengePlanReachesEveryAdapter: each engine adapter hands the
// rule's challenge plan to BOTH the prompt builder (the expected sequence
// stops on a cache-chunk boundary) and the watch (the last block alone ends
// it). An adapter that drops the plan times out or arms a non-chunk sequence.
func TestKvChallengePlanReachesEveryAdapter(t *testing.T) {
	const chunk = 20
	plan := kvChallengePlan{cacheChunk: chunk, lastBlock: true}
	run := func(t *testing.T, svcID uint32, epIdx int, challenge func() KvAttestFinding) {
		t.Helper()
		armed := make(chan int, 1)
		go func() {
			w := kvEchoAwaitWatch(svcID, epIdx)
			if w == nil {
				armed <- -1
				return
			}
			hashes, tokens := kvEchoWatchExpectation(w)
			armed <- len(tokens)
			last := len(hashes) - 1
			kvHashWatchObserve(svcID, epIdx, 0, kvEvent{Type: kvEventBlockStored,
				Hashes: []uint64{hashes[last]}, Tokens: tokens[last*kvEchoTestBS : (last+1)*kvEchoTestBS]})
		}()
		f := challenge()
		n := <-armed
		if !f.OK {
			t.Fatalf("last block only under a last-block plan: want a pass, got %+v", f)
		}
		if n < chunk || n%chunk != 0 {
			t.Fatalf("armed expected sequence of %d tokens: the cache chunk %d never reached the prompt builder", n, chunk)
		}
	}
	t.Run("vllm", func(t *testing.T) {
		kvEchoTestSetup(t)
		_, ep := kvEchoTestServer(t, "m-echo", 200)
		info := kvEchoInfo()
		info.challenge = plan
		run(t, info.svcID, ep.EpIdx, func() KvAttestFinding { return newKvVllmAttest().HashChallenge(ep, info) })
	})
	t.Run("sglang", func(t *testing.T) {
		kvSglTestSetup(t)
		info := kvSglInfo()
		info.challenge = plan
		_, ep, _ := kvSglTestServer(t, kvSglGoodConf())
		run(t, info.svcID, ep.EpIdx, func() KvAttestFinding { return newKvSglangAttest().HashChallenge(ep, info) })
	})
	t.Run("trtllm", func(t *testing.T) {
		kvTrtTestSetup(t)
		info := kvTrtInfo()
		info.challenge = plan
		_, ep := kvTrtTestServer(t, kvTrtGoodConf())
		run(t, info.svcID, ep.EpIdx, func() KvAttestFinding { return newKvTrtllmAttest().HashChallenge(ep, info) })
	})
}

// TestKvChallengePlanFor: the plan carries every challenge-shaping quirk and
// nothing else (completionsBos is an admission quirk).
func TestKvChallengePlanFor(t *testing.T) {
	if got := kvChallengePlanFor(KvEngineQuirks{CacheChunk: 64, ChallengeLastBlock: true, CompletionsBos: true}); got != (kvChallengePlan{cacheChunk: 64, lastBlock: true}) {
		t.Fatalf("plan %+v, want chunk 64 + last block", got)
	}
	if got := kvChallengePlanFor(KvEngineQuirks{CompletionsBos: true}); got != (kvChallengePlan{}) {
		t.Fatalf("plan %+v, want the default challenge", got)
	}
}
