package loxinet

import "testing"

// TestKvLegacyVllmWireOverride pins the opt-in that lets a profile-less vLLM
// rule bind the native tagged-map decoder (vLLM >= v0.24.0 wire).
func TestKvLegacyVllmWireOverride(t *testing.T) {
	cases := []struct{ engine, value, want string }{
		{"", "", ""},
		{"vllm", "", ""},
		{"", "array", ""},
		{"", "v1", ""},
		{"", "map", "vllm-kv-map-v2"},
		{"vllm", "MAP", "vllm-kv-map-v2"},
		{"", " v2 ", "vllm-kv-map-v2"},
		{"", "vllm-kv-map-v2", "vllm-kv-map-v2"},
		{"sglang", "map", ""},
		{"trtllm", "map", ""},
		{"llamacpp", "map", ""},
	}
	for _, c := range cases {
		if got := kvLegacyVllmWireOverride(c.engine, c.value); got != c.want {
			t.Errorf("engine=%q value=%q: got %q want %q", c.engine, c.value, got, c.want)
		}
	}
}

func TestKvResolveWireSchemaLegacyVllmEnv(t *testing.T) {
	t.Setenv(kvLegacyVllmWireEnv, "")
	ws, err := kvResolveWireSchema("", "")
	if err != nil || ws != KvWireVllmArrayV1 {
		t.Fatalf("unset env: got %q, %v; want %q", ws, err, KvWireVllmArrayV1)
	}
	t.Setenv(kvLegacyVllmWireEnv, "map")
	ws, err = kvResolveWireSchema("", "")
	if err != nil || ws != KvWireVllmMapV2 {
		t.Fatalf("env=map: got %q, %v; want %q", ws, err, KvWireVllmMapV2)
	}
	// A rule that carries a contract reference is never affected.
	ws, err = kvResolveWireSchema("", "vllm-kv-array-v1")
	if err != nil || ws != KvWireVllmArrayV1 {
		t.Fatalf("contract ref: got %q, %v; want %q", ws, err, KvWireVllmArrayV1)
	}
	// Non-vLLM engines keep their own profile.
	ws, err = kvResolveWireSchema("sglang", "")
	if err != nil || ws != KvWireSglangRankV1 {
		t.Fatalf("sglang: got %q, %v; want %q", ws, err, KvWireSglangRankV1)
	}
}
