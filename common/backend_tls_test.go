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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// certDir fills a managed directory with one entry per usage and points the
// registry at it for the test.
func certDir(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	for id, files := range map[string][]string{
		"be-ca":       {"ca.crt"},
		"be-client":   {"client.crt", "client.key"},
		"listener":    {"server.crt", "server.key"},
		"half-client": {"client.crt"},
	} {
		if err := os.MkdirAll(filepath.Join(dir, id), 0o700); err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if err := os.WriteFile(filepath.Join(dir, id, f), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	prev := CertManagedDir
	CertManagedDir = dir
	t.Cleanup(func() { CertManagedDir = prev })
}

func TestCertDiskUsage(t *testing.T) {
	certDir(t)
	for id, want := range map[string]string{
		"be-ca": CertUsageCA, "be-client": CertUsageClient, "listener": CertUsageServer,
		"half-client": "", "absent": "", "../be-ca": "", "": "",
	} {
		if got := CertDiskUsage(id); got != want {
			t.Errorf("CertDiskUsage(%q) = %q, want %q", id, got, want)
		}
	}
}

// TestValidateBackendTLS is the matrix of what a rule may ask of its backend
// leg. Each refusal must name the argument at fault.
func TestValidateBackendTLS(t *testing.T) {
	certDir(t)
	base := func() LbServiceArg {
		return LbServiceArg{Mode: LBModeFullProxy, Security: LBServE2EHTTPS}
	}
	verify := func(s *LbServiceArg) { s.MTLSBackend = &MTLSBackendConfig{VerifyServerCert: true} }
	cases := []struct {
		name string
		edit func(*LbServiceArg)
		want string // "" accepts; otherwise the error must contain it
	}{
		{"nothing asked", func(*LbServiceArg) {}, ""},
		{"explicit false is nothing asked", func(s *LbServiceArg) { s.MTLSBackend = &MTLSBackendConfig{} }, ""},
		{"nothing asked on another mode", func(s *LbServiceArg) { s.Mode = LBModeDefault; s.Security = 0 }, ""},
		{"verify with its CA", func(s *LbServiceArg) { verify(s); s.BackendCaCertId = "be-ca" }, ""},
		{"verify, CA, client and name", func(s *LbServiceArg) {
			verify(s)
			s.BackendCaCertId, s.BackendClientCertId, s.BackendTLSServerName = "be-ca", "be-client", "backend.example.com"
		}, ""},
		{"client certificate without verification", func(s *LbServiceArg) { s.BackendClientCertId = "be-client" }, ""},
		{"server name alone", func(s *LbServiceArg) { s.BackendTLSServerName = "backend.example.com" }, ""},

		{"verify without a CA", verify, "mtls_backend.verify_server_cert"},
		{"CA without verify", func(s *LbServiceArg) { s.BackendCaCertId = "be-ca" }, "backend_ca_cert_id"},
		{"CA ID nothing is registered under", func(s *LbServiceArg) { verify(s); s.BackendCaCertId = "absent" }, "backend_ca_cert_id"},
		{"CA ID that is a listener certificate", func(s *LbServiceArg) { verify(s); s.BackendCaCertId = "listener" }, "backend_ca_cert_id"},
		{"CA ID that is a client certificate", func(s *LbServiceArg) { verify(s); s.BackendCaCertId = "be-client" }, "backend_ca_cert_id"},
		{"CA ID that leaves the directory", func(s *LbServiceArg) { verify(s); s.BackendCaCertId = "../be-ca" }, "backend_ca_cert_id"},
		{"client ID nothing is registered under", func(s *LbServiceArg) { s.BackendClientCertId = "absent" }, "backend_client_cert_id"},
		{"client ID that is a CA", func(s *LbServiceArg) { s.BackendClientCertId = "be-ca" }, "backend_client_cert_id"},
		{"client ID that is a listener certificate", func(s *LbServiceArg) { s.BackendClientCertId = "listener" }, "backend_client_cert_id"},
		{"client ID without its key", func(s *LbServiceArg) { s.BackendClientCertId = "half-client" }, "backend_client_cert_id"},
		{"server name that is an address", func(s *LbServiceArg) { s.BackendTLSServerName = "10.1.1.1" }, "backend_tls_server_name"},
		{"server name with a space", func(s *LbServiceArg) { s.BackendTLSServerName = "a b.example.com" }, "backend_tls_server_name"},
		{"server name with an empty label", func(s *LbServiceArg) { s.BackendTLSServerName = "a..example.com" }, "backend_tls_server_name"},
		{"wrong mode", func(s *LbServiceArg) { s.Mode = LBModeDefault; s.BackendClientCertId = "be-client" }, "fullproxy"},
		{"wrong security", func(s *LbServiceArg) { s.Security = LBServHTTPS; s.BackendClientCertId = "be-client" }, "e2ehttps"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := base()
			c.edit(&s)
			err := ValidateBackendTLS(&s)
			asked := BackendTLSPolicyOf(&s).Requested()
			if !MTLSBuild {
				// Without client-certificate support a rule may ask for nothing.
				if asked && err == nil {
					t.Fatal("a backend TLS request was accepted by a build that cannot honour it")
				}
				if !asked && err != nil {
					t.Fatalf("a rule that asks for nothing was refused: %v", err)
				}
				return
			}
			if c.want == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error does not name %q: %v", c.want, err)
			}
		})
	}
}
