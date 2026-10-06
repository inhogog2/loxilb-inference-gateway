/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package snapshot

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// retiredMTLSBackendFixture was written by a release whose mtls_backend
// object still carried path and inline-material keys: one rule has every such
// key set to a value containing "SENTINEL", a second rule has no mtls_backend.
// It is kept as written; regenerating it with the current encoder would drop
// the keys this test is about.
const retiredMTLSBackendFixture = "snapshot-retired-mtls-backend-keys.json"

var retiredMTLSBackendKeys = []string{
	"backend_ca_path", "client_cert_path", "client_key_path", "client_cert_data", "client_key_data",
}

func requireNoRetiredMaterial(t *testing.T, what string, b []byte) {
	t.Helper()
	if bytes.Contains(b, []byte("SENTINEL")) {
		t.Fatalf("%s carries retired mtls_backend material:\n%s", what, b)
	}
}

// TestRestoreDropsRetiredMTLSBackendKeys: a document written by an earlier
// release still decodes strictly and verifies its checksum, restores with a
// warning for the dropped keys and one for the reset verification request,
// and nothing downstream of the restore -- the result, the live rule, the
// next captured document -- carries those keys or the request.
func TestRestoreDropsRetiredMTLSBackendKeys(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", retiredMTLSBackendFixture))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	for _, k := range append([]string{"SENTINEL"}, retiredMTLSBackendKeys...) {
		if !bytes.Contains(raw, []byte(k)) {
			t.Fatalf("fixture no longer contains %q -- it must stay as the earlier release wrote it", k)
		}
	}

	for _, mode := range []struct {
		name string
		opts RestoreOptions
	}{
		{"commit", RestoreOptions{Mode: ModeCommit}},
		{"boot", RestoreOptions{Boot: true}},
		{"dry-run", RestoreOptions{Mode: ModeDryRun}},
	} {
		t.Run(mode.name, func(t *testing.T) {
			hooks := newMockHooks()
			e := newTestEngine(hooks, t.TempDir())
			res, err := e.Restore(raw, mode.opts)
			if err != nil {
				t.Fatalf("Restore: %v", err)
			}
			if len(res.Errors) != 0 || res.Result != ResultOK {
				t.Fatalf("restore of an earlier-release document: result %q errors %v", res.Result, res.Errors)
			}

			var warns []string
			for _, w := range res.Warnings {
				if strings.Contains(w, "mtls_backend") {
					warns = append(warns, w)
				}
			}
			if len(warns) != 2 {
				t.Fatalf("want two mtls_backend warnings for the one affected rule (dropped keys, reset request), got %v", res.Warnings)
			}
			for _, want := range append([]string{"20.20.20.1:8443/tcp"}, retiredMTLSBackendKeys...) {
				if !strings.Contains(warns[0], want) {
					t.Fatalf("warning %q does not name %q", warns[0], want)
				}
			}
			for _, want := range []string{"20.20.20.1:8443/tcp", "verify_server_cert", "reset to false"} {
				if !strings.Contains(warns[1], want) {
					t.Fatalf("warning %q does not name %q", warns[1], want)
				}
			}
			resJSON, err := json.Marshal(res)
			if err != nil {
				t.Fatal(err)
			}
			requireNoRetiredMaterial(t, "restore result", resJSON)

			if mode.opts.isDryRun() {
				return
			}
			if len(hooks.lbRules) != 2 {
				t.Fatalf("applied %d rule(s), want 2", len(hooks.lbRules))
			}
			doc, err := Capture(hooks, "0.9.8.6-beta", "test-host", TriggerManual, []string{DomainLoadBalancer})
			if err != nil {
				t.Fatalf("Capture: %v", err)
			}
			enc, err := Encode(doc)
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			requireNoRetiredMaterial(t, "document captured after the restore", enc)
			for _, k := range retiredMTLSBackendKeys {
				if bytes.Contains(enc, []byte(k)) {
					t.Fatalf("document captured after the restore still has key %q:\n%s", k, enc)
				}
			}
			// The object stays, with the request reset: what a read returns
			// can be posted again.
			if !bytes.Contains(enc, []byte(`"mtls_backend":{"verify_server_cert":false}`)) {
				t.Fatalf("mtls_backend not kept with verify_server_cert reset across the restore:\n%s", enc)
			}
			if bytes.Contains(enc, []byte(`"verify_server_cert":true`)) {
				t.Fatalf("a verification request survived the restore:\n%s", enc)
			}
		})
	}
}
