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
	"net"
	"reflect"
	"strings"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

func listenerTestTuples(ip string, port uint16, host, path, model string) ruleTuples {
	return ruleTuples{
		l3Dst:      ruleIPTuple{net.IPNet{IP: net.ParseIP(ip), Mask: net.CIDRMask(32, 32)}},
		l4Prot:     rule8Tuple{6, 0xff},
		l4Dst:      rule16RTuple{port, port, true},
		path:       host,
		pathPrefix: path,
		modelName:  model,
	}
}

func listenerTestRule(t ruleTuples, mode cmn.LBMode, want listenerTLS) *ruleEnt {
	r := &ruleEnt{tuples: t}
	r.act.action = &ruleLBActs{mode: mode}
	r.secMode = want.security
	r.backendCaCertId = want.backend.CACertID
	r.backendClientCertId = want.backend.ClientCertID
	r.backendTLSServerName = want.backend.ServerName
	if want.backend.Verify {
		r.mtlsBackend = &cmn.MTLSBackendConfig{VerifyServerCert: true}
	}
	return r
}

func listenerTestTable(rules ...*ruleEnt) *RuleH {
	R := &RuleH{}
	R.tables[RtLB].eMap = make(map[string]*ruleEnt)
	for _, r := range rules {
		R.tables[RtLB].eMap[r.tuples.ruleKey()] = r
	}
	return R
}

func TestListenerTLSDiffNamesEveryArgument(t *testing.T) {
	base := listenerTLS{security: cmn.LBServE2EHTTPS, backend: cmn.BackendTLSPolicy{
		Verify: true, CACertID: "ca", ClientCertID: "client", ServerName: "be.example"}}
	if diff := listenerTLSDiff(base, base); len(diff) != 0 {
		t.Fatalf("identical settings differ in %v", diff)
	}
	cases := []struct {
		arg    string
		change func(*listenerTLS)
	}{
		{"security", func(l *listenerTLS) { l.security = cmn.LBServHTTPS }},
		{"mtls_backend.verify_server_cert", func(l *listenerTLS) { l.backend.Verify = false }},
		{"backend_ca_cert_id", func(l *listenerTLS) { l.backend.CACertID = "other-ca" }},
		{"backend_client_cert_id", func(l *listenerTLS) { l.backend.ClientCertID = "" }},
		{"backend_tls_server_name", func(l *listenerTLS) { l.backend.ServerName = "" }},
	}
	var all listenerTLS = base
	var names []string
	for _, c := range cases {
		other := base
		c.change(&other)
		if diff := listenerTLSDiff(base, other); !reflect.DeepEqual(diff, []string{c.arg}) {
			t.Errorf("changing %s: diff = %v", c.arg, diff)
		}
		c.change(&all)
		names = append(names, c.arg)
	}
	if diff := listenerTLSDiff(base, all); !reflect.DeepEqual(diff, names) {
		t.Errorf("changing everything: diff = %v, want %v", diff, names)
	}
}

func TestLbListenerTLSConflict(t *testing.T) {
	verified := listenerTLS{security: cmn.LBServE2EHTTPS, backend: cmn.BackendTLSPolicy{Verify: true, CACertID: "ca"}}
	plain := listenerTLS{security: cmn.LBServE2EHTTPS}

	onListener := listenerTestRule(listenerTestTuples("20.20.20.1", 2041, "a.example", "", ""), cmn.LBModeFullProxy, verified)
	otherPort := listenerTestRule(listenerTestTuples("20.20.20.1", 2042, "a.example", "", ""), cmn.LBModeFullProxy, plain)
	otherAddr := listenerTestRule(listenerTestTuples("20.20.20.2", 2041, "a.example", "", ""), cmn.LBModeFullProxy, plain)
	notProxy := listenerTestRule(listenerTestTuples("20.20.20.1", 2041, "", "", ""), cmn.LBModeDefault, plain)
	R := listenerTestTable(onListener, otherPort, otherAddr, notProxy)

	incoming := listenerTestTuples("20.20.20.1", 2041, "b.example", "", "")

	// The same settings share the listener, whatever sits on other
	// listeners and whatever a rule that is not a proxy carries.
	if other, diff := R.lbListenerTLSConflict(nil, &incoming, verified); other != nil {
		t.Fatalf("identical settings refused against %s: %v", listenerRuleName(&other.tuples), diff)
	}

	// Different settings are refused, and the answer names the rule that is
	// already there and the argument, not a certificate ID.
	other, diff := R.lbListenerTLSConflict(nil, &incoming, plain)
	if other != onListener {
		t.Fatalf("a different backend policy was admitted (other=%v)", other)
	}
	if !reflect.DeepEqual(diff, []string{"mtls_backend.verify_server_cert", "backend_ca_cert_id"}) {
		t.Errorf("diff = %v", diff)
	}
	msg := listenerTLSConflictError(other, diff).Error()
	for _, want := range []string{`host "a.example"`, "mtls_backend.verify_server_cert", "backend_ca_cert_id"} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal %q does not name %s", msg, want)
		}
	}
	if strings.Contains(msg, `"ca"`) {
		t.Errorf("refusal %q carries a certificate ID", msg)
	}

	// A rule is never in conflict with itself: the only rule of a listener
	// can change its own policy.
	if other, _ := R.lbListenerTLSConflict(onListener, &onListener.tuples, plain); other != nil {
		t.Fatalf("a rule conflicts with itself")
	}

	// With a second rule on the listener, neither can move alone.
	second := listenerTestRule(incoming, cmn.LBModeFullProxy, verified)
	R.tables[RtLB].eMap[incoming.ruleKey()] = second
	if other, _ := R.lbListenerTLSConflict(onListener, &onListener.tuples, plain); other != second {
		t.Fatalf("a rule changed the policy of a listener it shares")
	}
}

func TestLbListenerTLSConflictIsStable(t *testing.T) {
	plain := listenerTLS{security: cmn.LBServE2EHTTPS}
	verified := listenerTLS{security: cmn.LBServE2EHTTPS, backend: cmn.BackendTLSPolicy{Verify: true, CACertID: "ca"}}
	var rules []*ruleEnt
	for _, host := range []string{"d.example", "b.example", "c.example", "a.example"} {
		rules = append(rules, listenerTestRule(listenerTestTuples("20.20.20.1", 2041, host, "", ""), cmn.LBModeFullProxy, plain))
	}
	R := listenerTestTable(rules...)
	incoming := listenerTestTuples("20.20.20.1", 2041, "e.example", "", "")
	for i := 0; i < 32; i++ {
		other, _ := R.lbListenerTLSConflict(nil, &incoming, verified)
		if other == nil || other.tuples.path != "a.example" {
			t.Fatalf("run %d named %v, want the rule with the smallest key", i, other)
		}
	}
}

func TestListenerRuleName(t *testing.T) {
	bare := listenerTestTuples("20.20.20.1", 2041, "", "", "")
	if got := listenerRuleName(&bare); got != "the rule without host, path or model" {
		t.Errorf("bare rule: %q", got)
	}
	full := listenerTestTuples("20.20.20.1", 2041, "a.example", "/v1", "m1")
	if got := listenerRuleName(&full); got != `the rule with host "a.example", path "/v1", model "m1"` {
		t.Errorf("full rule: %q", got)
	}
}
