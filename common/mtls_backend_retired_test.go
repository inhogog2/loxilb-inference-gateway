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

package common

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// earlierMTLSBackend is the object an earlier release wrote, every key set.
const earlierMTLSBackend = `{"verify_server_cert":true,` +
	`"backend_ca_path":"/c/SENTINEL-ca&<1>.crt",` +
	`"client_cert_path":"/c/SENTINEL-cert.crt",` +
	`"client_key_path":"/c/SENTINEL-key.key",` +
	`"client_cert_data":"SENTINEL-cert-data",` +
	`"client_key_data":"SENTINEL-key-data"}`

func encodeNoEscape(t *testing.T, v any) string {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		t.Fatal(err)
	}
	return strings.TrimRight(buf.String(), "\n")
}

// A document written by an earlier release must re-encode to the bytes it
// was read from until the loader drops the retired keys, or its checksum
// would no longer verify.
func TestMTLSBackendRetiredKeysReEncodeUntilDropped(t *testing.T) {
	var serv LbServiceArg
	in := `{"mtls_backend":` + earlierMTLSBackend + `}`
	if err := json.Unmarshal([]byte(in), &serv); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := encodeNoEscape(t, serv.MTLSBackend); got != earlierMTLSBackend {
		t.Fatalf("re-encoded object differs from the document:\n got %s\nwant %s", got, earlierMTLSBackend)
	}
	// The default encoder escapes HTML characters; so did the earlier struct.
	esc, err := json.Marshal(serv.MTLSBackend)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(esc), `SENTINEL-ca`+"\\u0026\\u003c1\\u003e.crt") {
		t.Fatalf("default encoder did not escape the re-encoded object: %s", esc)
	}

	names := serv.MTLSBackend.DropRetired()
	want := []string{"backend_ca_path", "client_cert_path", "client_key_path", "client_cert_data", "client_key_data"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("DropRetired names = %v, want %v", names, want)
	}
	if got := encodeNoEscape(t, serv.MTLSBackend); got != `{"verify_server_cert":true}` {
		t.Fatalf("after DropRetired the object encodes as %s", got)
	}
	if again := serv.MTLSBackend.DropRetired(); again != nil {
		t.Fatalf("second DropRetired returned %v, want nil", again)
	}
}

// The copy a rule keeps never carries a retired key, dropped or not.
func TestMTLSBackendStoredCopyCarriesRequestOnly(t *testing.T) {
	var cfg MTLSBackendConfig
	if err := json.Unmarshal([]byte(earlierMTLSBackend), &cfg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	stored := cfg.Stored()
	if !reflect.DeepEqual(stored, &MTLSBackendConfig{VerifyServerCert: true}) {
		t.Fatalf("stored copy = %+v", stored)
	}
	if got := encodeNoEscape(t, stored); strings.Contains(got, "SENTINEL") {
		t.Fatalf("stored copy encodes retired material: %s", got)
	}
	if (*MTLSBackendConfig)(nil).Stored() != nil {
		t.Fatal("Stored on nil must stay nil")
	}
	if (*MTLSBackendConfig)(nil).DropRetired() != nil {
		t.Fatal("DropRetired on nil must return nil")
	}
}

func TestMTLSBackendDecode(t *testing.T) {
	cases := []struct {
		name, in string
		want     MTLSBackendConfig
		wantErr  bool
	}{
		{"current object", `{"verify_server_cert":true}`, MTLSBackendConfig{VerifyServerCert: true}, false},
		{"empty object", `{}`, MTLSBackendConfig{}, false},
		{"empty retired key is absent", `{"verify_server_cert":false,"client_key_data":""}`, MTLSBackendConfig{}, false},
		{"unknown key refused", `{"verify_server_cert":true,"client_key":"x"}`, MTLSBackendConfig{}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var got MTLSBackendConfig
			err := json.Unmarshal([]byte(c.in), &got)
			if (err != nil) != c.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, c.wantErr)
			}
			if err == nil && !reflect.DeepEqual(got, c.want) {
				t.Fatalf("decoded %+v, want %+v", got, c.want)
			}
		})
	}
}

func TestMTLSBackendResetUnavailable(t *testing.T) {
	cfg := &MTLSBackendConfig{VerifyServerCert: true}
	if !cfg.ResetUnavailable() || cfg.VerifyServerCert {
		t.Fatalf("a verification request was not reset: %+v", cfg)
	}
	if cfg.ResetUnavailable() {
		t.Fatal("second ResetUnavailable reported a request")
	}
	if (*MTLSBackendConfig)(nil).ResetUnavailable() {
		t.Fatal("ResetUnavailable on nil reported a request")
	}
}
