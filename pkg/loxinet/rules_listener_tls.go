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
	"fmt"
	"strings"

	cmn "github.com/loxilb-io/loxilb/common"
)

// listenerTLS is the part of a full-proxy rule that the data plane keeps once
// per listener and not once per rule. Rules that differ only in host, path or
// model share one listener, so they share its security mode and the TLS
// contexts of its backend leg: whichever rule created the listener decides
// for all of them.
type listenerTLS struct {
	security cmn.LBSec
	backend  cmn.BackendTLSPolicy
}

func listenerTLSOfServ(serv *cmn.LbServiceArg) listenerTLS {
	return listenerTLS{security: serv.Security, backend: cmn.BackendTLSPolicyOf(serv)}
}

func listenerTLSOfRule(r *ruleEnt) listenerTLS {
	return listenerTLS{
		security: r.secMode,
		backend: cmn.BackendTLSPolicy{
			Verify:       backendVerifyOf(r.mtlsBackend),
			CACertID:     r.backendCaCertId,
			ClientCertID: r.backendClientCertId,
			ServerName:   r.backendTLSServerName,
		},
	}
}

// listenerTLSDiff names the arguments in which two rules of one listener
// disagree, in a fixed order. Empty: the two can share the listener.
func listenerTLSDiff(a, b listenerTLS) []string {
	var diff []string
	if a.security != b.security {
		diff = append(diff, "security")
	}
	if a.backend.Verify != b.backend.Verify {
		diff = append(diff, "mtls_backend.verify_server_cert")
	}
	if a.backend.CACertID != b.backend.CACertID {
		diff = append(diff, "backend_ca_cert_id")
	}
	if a.backend.ClientCertID != b.backend.ClientCertID {
		diff = append(diff, "backend_client_cert_id")
	}
	if a.backend.ServerName != b.backend.ServerName {
		diff = append(diff, "backend_tls_server_name")
	}
	return diff
}

// listenerRuleName identifies a rule among the rules of one listener, by the
// arguments that tell them apart.
func listenerRuleName(t *ruleTuples) string {
	var parts []string
	if t.path != "" {
		parts = append(parts, fmt.Sprintf("host %q", t.path))
	}
	if t.pathPrefix != "" {
		parts = append(parts, fmt.Sprintf("path %q", t.pathPrefix))
	}
	if t.modelName != "" {
		parts = append(parts, fmt.Sprintf("model %q", t.modelName))
	}
	if len(parts) == 0 {
		return "the rule without host, path or model"
	}
	return "the rule with " + strings.Join(parts, ", ")
}

// lbListenerTLSConflict looks for a full-proxy rule on the listener of rt,
// other than self, whose listener-wide TLS settings differ from want. It
// returns that rule and the arguments that differ, or nil. Among several it
// returns the one with the smallest key, so the answer does not depend on
// map order.
func (R *RuleH) lbListenerTLSConflict(self *ruleEnt, rt *ruleTuples, want listenerTLS) (*ruleEnt, []string) {
	var found *ruleEnt
	var foundKey string
	var foundDiff []string
	for key, r := range R.tables[RtLB].eMap {
		if r == self {
			continue
		}
		at, ok := r.act.action.(*ruleLBActs)
		if !ok || at.mode != cmn.LBModeFullProxy {
			continue
		}
		if !r.tuples.l3Dst.addr.IP.Equal(rt.l3Dst.addr.IP) ||
			r.tuples.l4Prot.val != rt.l4Prot.val ||
			r.tuples.l4Dst.valMin != rt.l4Dst.valMin {
			continue
		}
		diff := listenerTLSDiff(want, listenerTLSOfRule(r))
		if len(diff) == 0 {
			continue
		}
		if found == nil || key < foundKey {
			found, foundKey, foundDiff = r, key, diff
		}
	}
	return found, foundDiff
}

// listenerTLSConflictError is the refusal of a rule that cannot share its
// listener. It names the rule already there and the arguments, never a value.
func listenerTLSConflictError(other *ruleEnt, diff []string) error {
	return fmt.Errorf("%s: %s is already on this address, port and protocol with a different value; "+
		"rules that share a listener share its security mode and backend TLS policy",
		strings.Join(diff, ", "), listenerRuleName(&other.tuples))
}
