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

// loadbalancer_backend_tls_test.go — the backend TLS arguments at the REST
// boundary: what a create request may carry, and what a read returns.
//
// These tests run on the remote gate: darwin cannot compile this package
// (Linux cgo / regen-dependent).

package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/swag"
	"github.com/loxilb-io/loxilb/api/models"
	"github.com/loxilb-io/loxilb/api/restapi/operations"
	cmn "github.com/loxilb-io/loxilb/common"
)

var retiredMTLSBackendKeys = []string{
	"backend_ca_path", "client_cert_path", "client_key_path", "client_cert_data", "client_key_data",
}

func renderResponse(t *testing.T, r middleware.Responder) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	r.WriteResponse(rec, runtime.JSONProducer())
	return rec.Code, rec.Body.String()
}

// TestBackendTLSReadBackCarriesNoMaterial: every read of a rule returns the
// verification request and nothing else of mtls_backend, checked on the
// response bytes. The stored rule here is the worst case -- decoded from an
// earlier release's document, with the retired keys not yet dropped by a
// loader. The read handlers do not branch on the caller's role, so one caller
// stands for all of them.
func TestBackendTLSReadBackCarriesNoMaterial(t *testing.T) {
	prev := ApiHooks
	defer func() { ApiHooks = prev }()

	lb := cmn.LbRuleMod{}
	lb.Serv.ServIP = "20.20.20.5"
	lb.Serv.ServPort = 8443
	lb.Serv.Proto = "tcp"
	lb.Serv.Id = "3c1f9df2-2f2e-4c3e-9d9b-2b6f6d1a0001"
	lb.Serv.MTLSBackend = &cmn.MTLSBackendConfig{}
	if err := json.Unmarshal([]byte(`{"verify_server_cert":true,`+
		`"backend_ca_path":"/c/SENTINEL-ca.crt","client_cert_path":"/c/SENTINEL-cert.crt",`+
		`"client_key_path":"/c/SENTINEL-key.key","client_cert_data":"SENTINEL-cert-data",`+
		`"client_key_data":"SENTINEL-key-data"}`), lb.Serv.MTLSBackend); err != nil {
		t.Fatalf("decode stored rule: %v", err)
	}
	ApiHooks = &stubLbAddHook{rules: []cmn.LbRuleMod{lb}}

	req, _ := http.NewRequest("GET", "/config/loadbalancer/all", nil)
	reads := map[string]middleware.Responder{
		"list": ConfigGetLoadbalancer(operations.GetConfigLoadbalancerAllParams{HTTPRequest: req}, nil),
		"by key": ConfigGetLoadbalancerByKey(operations.GetConfigLoadbalancerExternalipaddressIPAddressPortPortProtocolProtoParams{
			HTTPRequest: req, IPAddress: lb.Serv.ServIP, Port: float64(lb.Serv.ServPort), Proto: lb.Serv.Proto}, nil),
		"by id": ConfigGetLoadbalancerByID(operations.GetConfigLoadbalancerIDParams{HTTPRequest: req, ID: lb.Serv.Id}, nil),
	}
	for name, resp := range reads {
		t.Run(name, func(t *testing.T) {
			code, body := renderResponse(t, resp)
			if code != http.StatusOK {
				t.Fatalf("status %d, body %s", code, body)
			}
			if !strings.Contains(body, `"mtls_backend":{"verify_server_cert":true}`) {
				t.Fatalf("read does not return the verification request alone:\n%s", body)
			}
			for _, banned := range append([]string{"SENTINEL"}, retiredMTLSBackendKeys...) {
				if strings.Contains(body, banned) {
					t.Fatalf("read returns %q:\n%s", banned, body)
				}
			}
		})
	}
}

func newBackendTLSCreateParams(edit func(*models.LoadbalanceEntryServiceArguments)) operations.PostConfigLoadbalancerParams {
	p := newCreateParams("")
	p.Attr.ServiceArguments.Mode = 4
	p.Attr.ServiceArguments.Security = 2
	edit(p.Attr.ServiceArguments)
	return p
}

// TestBackendTLSCreateRefusedBeforeRuleHook: each retired mtls_backend key,
// and each backend TLS request that cannot be honoured (verification without
// a CA, a certificate ID nothing is registered under), is refused with 400
// before the rule layer is reached. The error names the argument and never
// echoes its value.
func TestBackendTLSCreateRefusedBeforeRuleHook(t *testing.T) {
	prev := ApiHooks
	defer func() { ApiHooks = prev }()

	backend := func(edit func(*models.LoadbalanceEntryServiceArgumentsMtlsBackend)) func(*models.LoadbalanceEntryServiceArguments) {
		return func(sa *models.LoadbalanceEntryServiceArguments) {
			sa.MtlsBackend = &models.LoadbalanceEntryServiceArgumentsMtlsBackend{}
			edit(sa.MtlsBackend)
		}
	}
	cases := []struct {
		name string // the argument the error must name
		edit func(*models.LoadbalanceEntryServiceArguments)
	}{
		{"mtls_backend.backend_ca_path", backend(func(m *models.LoadbalanceEntryServiceArgumentsMtlsBackend) { m.BackendCaPath = "/c/SENTINEL-ca.crt" })},
		{"mtls_backend.client_cert_path", backend(func(m *models.LoadbalanceEntryServiceArgumentsMtlsBackend) { m.ClientCertPath = "/c/SENTINEL-cert.crt" })},
		{"mtls_backend.client_key_path", backend(func(m *models.LoadbalanceEntryServiceArgumentsMtlsBackend) { m.ClientKeyPath = "/c/SENTINEL-key.key" })},
		{"mtls_backend.client_cert_data", backend(func(m *models.LoadbalanceEntryServiceArgumentsMtlsBackend) { m.ClientCertData = "SENTINEL-cert-data" })},
		{"mtls_backend.client_key_data", backend(func(m *models.LoadbalanceEntryServiceArgumentsMtlsBackend) { m.ClientKeyData = "SENTINEL-key-data" })},
		{"mtls_backend.verify_server_cert", backend(func(m *models.LoadbalanceEntryServiceArgumentsMtlsBackend) { m.VerifyServerCert = swag.Bool(true) })},
		{"backend_ca_cert_id", func(sa *models.LoadbalanceEntryServiceArguments) {
			sa.MtlsBackend = &models.LoadbalanceEntryServiceArgumentsMtlsBackend{VerifyServerCert: swag.Bool(true)}
			sa.BackendCaCertID = "SENTINEL-ca-id"
		}},
		{"backend_client_cert_id", func(sa *models.LoadbalanceEntryServiceArguments) { sa.BackendClientCertID = "SENTINEL-client-id" }},
		{"backend_tls_server_name", func(sa *models.LoadbalanceEntryServiceArguments) { sa.BackendTLSServerName = "SENTINEL not a name" }},
	}
	if !cmn.MTLSBuild {
		// Without client-certificate support every backend request is refused
		// by one message that names the build, not the argument.
		cases = cases[:5]
	}
	prevDir := cmn.CertManagedDir
	cmn.CertManagedDir = t.TempDir()
	defer func() { cmn.CertManagedDir = prevDir }()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stub := &stubLbAddHook{}
			ApiHooks = stub
			code, body := renderResponse(t, ConfigPostLoadbalancer(newBackendTLSCreateParams(c.edit), nil))
			if code != http.StatusBadRequest {
				t.Fatalf("status %d, want 400; body %s", code, body)
			}
			if stub.captured != nil {
				t.Fatal("a refused request reached NetLbRuleAdd")
			}
			if !strings.Contains(body, c.name) {
				t.Fatalf("error does not name %s: %s", c.name, body)
			}
			if strings.Contains(body, "SENTINEL") {
				t.Fatalf("error echoes the refused value: %s", body)
			}
		})
	}
}

// TestBackendTLSCreateAccepted: a request that asks for nothing of the
// backend leg is unaffected, with or without an mtls_backend object.
func TestBackendTLSCreateAccepted(t *testing.T) {
	prev := ApiHooks
	defer func() { ApiHooks = prev }()

	cases := []struct {
		name        string
		edit        func(*models.LoadbalanceEntryServiceArguments)
		wantBackend *cmn.MTLSBackendConfig
	}{
		{"no mtls_backend", func(*models.LoadbalanceEntryServiceArguments) {}, nil},
		{"empty mtls_backend", func(sa *models.LoadbalanceEntryServiceArguments) {
			sa.MtlsBackend = &models.LoadbalanceEntryServiceArgumentsMtlsBackend{}
		}, &cmn.MTLSBackendConfig{}},
		{"verify_server_cert false", func(sa *models.LoadbalanceEntryServiceArguments) {
			sa.MtlsBackend = &models.LoadbalanceEntryServiceArgumentsMtlsBackend{VerifyServerCert: swag.Bool(false)}
		}, &cmn.MTLSBackendConfig{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stub := &stubLbAddHook{}
			ApiHooks = stub
			ConfigPostLoadbalancer(newBackendTLSCreateParams(c.edit), nil)
			if stub.captured == nil {
				t.Fatal("create handler never reached NetLbRuleAdd")
			}
			got := stub.captured.Serv.MTLSBackend
			if (got == nil) != (c.wantBackend == nil) || (got != nil && *got != *c.wantBackend) {
				t.Fatalf("rule layer received mtls_backend %+v, want %+v", got, c.wantBackend)
			}
		})
	}
}
