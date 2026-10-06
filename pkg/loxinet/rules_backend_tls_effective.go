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
	cmn "github.com/loxilb-io/loxilb/common"
)

// backendTLSInstalled is the backend TLS policy a listener reports.
type backendTLSInstalled struct {
	tls          bool
	verify       bool
	clientCert   bool
	generation   uint32
	caCertID     string
	clientCertID string
	serverName   string
}

// hasBackendTLSLeg reports whether the rule's backend leg is TLS. Only such a
// rule has a backend TLS policy to report, so only for such a rule is the
// data plane asked.
func (r *ruleEnt) hasBackendTLSLeg() bool {
	at, ok := r.act.action.(*ruleLBActs)
	return ok && at.mode == cmn.LBModeFullProxy && r.secMode == cmn.LBServE2EHTTPS
}

// backendTLSEffective sets what a listener has installed beside what the rule
// asks for. It returns nil for a rule whose backend leg is not TLS, where
// there is nothing to report. listening says whether the data plane has a
// listener for the rule; build whether this build can verify a backend at
// all.
//
// The status is applied only when the listener runs what the rule asks for.
// A rule that shares a listener it disagrees with, and a rule whose listener
// could not load a certificate that was replaced under the same ID, read
// failed, with the policy the listener does run.
func (r *ruleEnt) backendTLSEffective(st backendTLSInstalled, listening, build bool) *cmn.BackendTLSEffectiveArg {
	if !r.hasBackendTLSLeg() {
		return nil
	}
	if !build {
		return &cmn.BackendTLSEffectiveArg{Status: cmn.BackendTLSUnsupported, CA: cmn.BackendTLSNoCA}
	}
	if !listening || !st.tls {
		return &cmn.BackendTLSEffectiveArg{Status: cmn.BackendTLSPending, CA: cmn.BackendTLSNoCA}
	}
	eff := &cmn.BackendTLSEffectiveArg{
		Status:       cmn.BackendTLSApplied,
		Verify:       st.verify,
		CA:           st.caCertID,
		ClientCert:   st.clientCert,
		ClientCertID: st.clientCertID,
		ServerName:   st.serverName,
		Generation:   st.generation,
	}
	if eff.CA == "" {
		eff.CA = cmn.BackendTLSNoCA
	}
	if r.backendTLSKept ||
		st.verify != backendVerifyOf(r.mtlsBackend) ||
		st.caCertID != r.backendCaCertId ||
		st.clientCertID != r.backendClientCertId ||
		st.clientCert != (r.backendClientCertId != "") ||
		st.serverName != r.backendTLSServerName {
		eff.Status = cmn.BackendTLSFailed
	}
	return eff
}
