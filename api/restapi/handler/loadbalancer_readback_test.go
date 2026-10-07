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

package handler

import (
	"encoding/json"
	"reflect"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

// A rule reads back the member timeouts, the TLS hardening values and the
// CRL path it stores.
func TestSerializeLBRuleReadsBackStoredValues(t *testing.T) {
	lb := cmn.LbRuleMod{Serv: cmn.LbServiceArg{
		TimeoutMemberConnect:  1500,
		TimeoutMemberData:     30000,
		TimeoutTcpInspect:     250,
		AlpnProtocols:         []string{"h2", "http/1.1"},
		TlsCiphers:            "ECDHE-RSA-AES256-GCM-SHA384",
		TlsVersions:           []string{"TLSv1.2", "TLSv1.3"},
		HstsMaxAge:            31536000,
		HstsIncludeSubdomains: true,
		HstsPreload:           true,
		MTLSFrontend: &cmn.MTLSFrontendConfig{
			ClientCertMode: "require",
			ClientCRLPath:  "/etc/loxilb/crl/clients.pem",
		},
	}}

	wire, err := json.Marshal(serializeLBRule(lb).ServiceArguments)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(wire, &got); err != nil {
		t.Fatal(err)
	}

	want := map[string]interface{}{
		"timeoutMemberConnect":    float64(1500),
		"timeoutMemberData":       float64(30000),
		"timeoutTcpInspect":       float64(250),
		"alpn_protocols":          []interface{}{"h2", "http/1.1"},
		"tls_ciphers":             "ECDHE-RSA-AES256-GCM-SHA384",
		"tls_versions":            []interface{}{"TLSv1.2", "TLSv1.3"},
		"hsts_max_age":            float64(31536000),
		"hsts_include_subdomains": true,
		"hsts_preload":            true,
	}
	for key, value := range want {
		if !reflect.DeepEqual(got[key], value) {
			t.Errorf("%s reads back %v, want %v", key, got[key], value)
		}
	}
	mtls, _ := got["mtls_frontend"].(map[string]interface{})
	if mtls["client_crl_path"] != "/etc/loxilb/crl/clients.pem" {
		t.Errorf("mtls_frontend.client_crl_path reads back %v", mtls["client_crl_path"])
	}

	// A rule that stores none of them reads back none of them.
	wire, _ = json.Marshal(serializeLBRule(cmn.LbRuleMod{}).ServiceArguments)
	got = nil
	_ = json.Unmarshal(wire, &got)
	for _, key := range []string{"timeoutMemberConnect", "timeoutMemberData", "timeoutTcpInspect",
		"tls_ciphers", "hsts_max_age", "hsts_include_subdomains", "hsts_preload"} {
		if value, present := got[key]; present {
			t.Errorf("%s reads back %v on a rule that does not store it", key, value)
		}
	}
}
