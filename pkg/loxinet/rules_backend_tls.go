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
	"errors"
	"fmt"
	"sort"

	cmn "github.com/loxilb-io/loxilb/common"
	tk "github.com/loxilb-io/loxilib"
)

// backendVerifyOf reads the verification request of a rule; no object is the
// same request as an explicit false.
func backendVerifyOf(m *cmn.MTLSBackendConfig) bool {
	return m != nil && m.VerifyServerCert
}

// backendTLSFields is the backend TLS request as a rule stores it.
type backendTLSFields struct {
	caCertID     string
	clientCertID string
	serverName   string
	mtlsBackend  *cmn.MTLSBackendConfig
}

func backendTLSFieldsOf(r *ruleEnt) backendTLSFields {
	return backendTLSFields{
		caCertID:     r.backendCaCertId,
		clientCertID: r.backendClientCertId,
		serverName:   r.backendTLSServerName,
		mtlsBackend:  r.mtlsBackend,
	}
}

// restore puts a rule back to the backend TLS request it held.
func (f backendTLSFields) restore(r *ruleEnt) {
	r.backendCaCertId = f.caCertID
	r.backendClientCertId = f.clientCertID
	r.backendTLSServerName = f.serverName
	r.mtlsBackend = f.mtlsBackend
}

// backendTLSChanged reports whether a request asks for another backend TLS
// policy than the rule holds.
func backendTLSChanged(r *ruleEnt, serv *cmn.LbServiceArg) bool {
	return r.backendCaCertId != serv.BackendCaCertId ||
		r.backendClientCertId != serv.BackendClientCertId ||
		r.backendTLSServerName != serv.BackendTLSServerName ||
		backendVerifyOf(r.mtlsBackend) != backendVerifyOf(serv.MTLSBackend)
}

// lbPushRefusedError is the answer to a full-proxy rule the data plane did
// not install. The data plane keeps the reason in its own log; what is known
// here is that the listener or one of its TLS contexts could not be built.
func lbPushRefusedError(policyKept bool) error {
	if policyKept {
		return errors.New("the data plane could not build the backend TLS context for this policy; " +
			"the rule keeps its previous backend TLS policy, see the data plane log for the certificate that failed to load")
	}
	return errors.New("the data plane did not install the rule: its listener or a TLS context could not be built, " +
		"see the data plane log")
}

// lbRulesOfBackendCert returns the full-proxy rules whose backend leg refers
// to a certificate ID, in key order.
func (R *RuleH) lbRulesOfBackendCert(certID string) []*ruleEnt {
	var keys []string
	for key, r := range R.tables[RtLB].eMap {
		at, ok := r.act.action.(*ruleLBActs)
		if !ok || at.mode != cmn.LBModeFullProxy {
			continue
		}
		if r.backendCaCertId == certID || r.backendClientCertId == certID {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	rules := make([]*ruleEnt, 0, len(keys))
	for _, key := range keys {
		rules = append(rules, R.tables[RtLB].eMap[key])
	}
	return rules
}

// RefreshLbBackendCert pushes again every rule whose backend leg refers to a
// certificate ID, after the material under that ID was replaced, and waits
// for the data plane. A listener builds a new backend context when the files
// behind its IDs are not the ones its context was built from, and keeps the
// one it has when the new one cannot be built. It returns how many rules were
// pushed and names the ones whose listener kept its previous context. Those
// are not pushed again until the certificate or the rule is next written:
// the same files would be refused the same way.
func (R *RuleH) RefreshLbBackendCert(certID string) (int, []string) {
	rules := R.lbRulesOfBackendCert(certID)
	if len(rules) == 0 {
		return 0, nil
	}
	for _, r := range rules {
		r.DP(DpCreate)
	}
	DpBrokerSyncBarrier(mh.dp)
	var kept []string
	for _, r := range rules {
		if r.sync == 0 {
			continue
		}
		r.sync = 0
		name := fmt.Sprintf("%s:%d (%s)", r.tuples.l3Dst.addr.IP.String(), r.tuples.l4Dst.valMin, listenerRuleName(&r.tuples))
		kept = append(kept, name)
		tk.LogIt(tk.LogError, "lb-rule %s keeps its previous backend TLS context: the material now under certificate %q was not loaded\n",
			name, certID)
	}
	tk.LogIt(tk.LogInfo, "backend certificate %q replaced: %d rule(s) pushed, %d kept the previous context\n",
		certID, len(rules), len(kept))
	return len(rules), kept
}

// lbConfigReplay reports whether a rule add replays a saved configuration, a
// snapshot restore or the lbconfig.txt read at start, and not a request. A
// saved configuration is kept whole: what it holds ran before, and dropping
// one of its rules would lose it from the next save as well.
func lbConfigReplay(serv *cmn.LbServiceArg) bool {
	return serv.RestoreReplay || serv.BootReplay
}
