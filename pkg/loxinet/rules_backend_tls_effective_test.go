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

package loxinet

import (
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

func TestBackendTLSEffective(t *testing.T) {
	asked := listenerTLS{security: cmn.LBServE2EHTTPS, backend: cmn.BackendTLSPolicy{
		Verify: true, CACertID: "ca", ClientCertID: "client", ServerName: "be.example"}}
	tuples := listenerTestTuples("20.20.20.1", 2041, "", "", "")
	rule := func() *ruleEnt { return listenerTestRule(tuples, cmn.LBModeFullProxy, asked) }
	installed := backendTLSInstalled{tls: true, verify: true, clientCert: true, generation: 3,
		caCertID: "ca", clientCertID: "client", serverName: "be.example"}

	// A rule whose backend leg is not TLS has nothing to report.
	if eff := listenerTestRule(tuples, cmn.LBModeDefault, asked).backendTLSEffective(installed, true, true); eff != nil {
		t.Errorf("a rule that is not a proxy reports %+v", eff)
	}
	terminated := listenerTestRule(tuples, cmn.LBModeFullProxy, listenerTLS{security: cmn.LBServHTTPS})
	if eff := terminated.backendTLSEffective(installed, true, true); eff != nil {
		t.Errorf("a rule with a plain backend leg reports %+v", eff)
	}
	// The data plane is asked for the rules that can report, and no other.
	if listenerTestRule(tuples, cmn.LBModeDefault, asked).hasBackendTLSLeg() || terminated.hasBackendTLSLeg() || !rule().hasBackendTLSLeg() {
		t.Errorf("which rules have a TLS backend leg: not a proxy %v, plain leg %v, TLS leg %v",
			listenerTestRule(tuples, cmn.LBModeDefault, asked).hasBackendTLSLeg(), terminated.hasBackendTLSLeg(), rule().hasBackendTLSLeg())
	}

	// What the listener runs is what is reported, member for member.
	eff := rule().backendTLSEffective(installed, true, true)
	want := cmn.BackendTLSEffectiveArg{Status: cmn.BackendTLSApplied, Verify: true, CA: "ca",
		ClientCert: true, ClientCertID: "client", ServerName: "be.example", Generation: 3}
	if eff == nil || *eff != want {
		t.Fatalf("installed as asked: %+v, want %+v", eff, want)
	}

	// No request and nothing installed is applied too, and never reads as
	// protected.
	bare := listenerTestRule(tuples, cmn.LBModeFullProxy, listenerTLS{security: cmn.LBServE2EHTTPS})
	eff = bare.backendTLSEffective(backendTLSInstalled{tls: true}, true, true)
	if eff == nil || eff.Status != cmn.BackendTLSApplied || eff.Verify || eff.ClientCert || eff.CA != cmn.BackendTLSNoCA {
		t.Errorf("an unverified leg: %+v", eff)
	}

	// No listener yet: nothing is installed, whatever the rule asks for.
	eff = rule().backendTLSEffective(backendTLSInstalled{}, false, true)
	if eff == nil || eff.Status != cmn.BackendTLSPending || eff.Verify || eff.ClientCert || eff.CA != cmn.BackendTLSNoCA {
		t.Errorf("no listener: %+v", eff)
	}

	// A build that cannot verify says so, and reports no protection even
	// when the rule carries a request from somewhere.
	eff = rule().backendTLSEffective(installed, true, false)
	if eff == nil || eff.Status != cmn.BackendTLSUnsupported || eff.Verify || eff.ClientCert {
		t.Errorf("a build without support: %+v", eff)
	}

	// The listener runs something else: the status says so and the members
	// stay those of what is installed, not of what was asked.
	for _, c := range []struct {
		name string
		st   backendTLSInstalled
	}{
		{"no verification", backendTLSInstalled{tls: true, clientCert: true, caCertID: "ca", clientCertID: "client", serverName: "be.example"}},
		{"another CA", backendTLSInstalled{tls: true, verify: true, clientCert: true, caCertID: "other", clientCertID: "client", serverName: "be.example"}},
		{"no client cert", backendTLSInstalled{tls: true, verify: true, caCertID: "ca", serverName: "be.example"}},
		{"client not loaded", backendTLSInstalled{tls: true, verify: true, caCertID: "ca", clientCertID: "client", serverName: "be.example"}},
		{"another name", backendTLSInstalled{tls: true, verify: true, clientCert: true, caCertID: "ca", clientCertID: "client"}},
	} {
		name, st := c.name, c.st
		eff := rule().backendTLSEffective(st, true, true)
		if eff == nil || eff.Status != cmn.BackendTLSFailed {
			t.Errorf("%s: %+v, want failed", name, eff)
			continue
		}
		if eff.Verify != st.verify || eff.ClientCert != st.clientCert || eff.ClientCertID != st.clientCertID || eff.ServerName != st.serverName {
			t.Errorf("%s: the report %+v is not what is installed %+v", name, eff, st)
		}
	}

	// The IDs agree but the listener kept a context older than the
	// certificate now under the ID.
	kept := rule()
	kept.backendTLSKept = true
	eff = kept.backendTLSEffective(installed, true, true)
	if eff == nil || eff.Status != cmn.BackendTLSFailed || eff.CA != "ca" {
		t.Errorf("a kept context: %+v, want failed with the installed policy", eff)
	}
}
