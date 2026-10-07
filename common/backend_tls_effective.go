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

import "errors"

// The states of BackendTLSEffectiveArg.Status.
const (
	// BackendTLSApplied: the listener runs the policy the rule asks for.
	BackendTLSApplied = "applied"
	// BackendTLSPending: the rule has no listener in the data plane yet, so
	// nothing is installed.
	BackendTLSPending = "pending"
	// BackendTLSFailed: the listener runs something else than the rule asks
	// for. The other members say what it runs.
	BackendTLSFailed = "failed"
	// BackendTLSUnsupported: this build cannot verify a backend or present
	// a client certificate. The backend leg is TLS without either.
	BackendTLSUnsupported = "unsupported"
)

// BackendTLSNoCA is reported as the CA of a backend leg that verifies against
// none.
const BackendTLSNoCA = "none"

// CapabilityBackendTLSVerify names backend certificate verification and
// backend client certificates on the capabilities surface.
const CapabilityBackendTLSVerify = "backend_tls_verify"

// ReasonBackendTLSNotBuilt: the gateway was built without client-certificate
// support, so no rule can verify its backends or present a certificate.
const ReasonBackendTLSNotBuilt = "BACKEND_TLS_NOT_BUILT"

// BackendTLSEffectiveArg - what the data plane has installed for the backend
// TLS leg of a rule's listener, beside what the rule asks for. Everything but
// Status describes the installed policy and never the request. It says which
// policy new backend connections are made under, not that any connection was
// verified. A read model, never replayed into a POST.
type BackendTLSEffectiveArg struct {
	// Status - applied, pending, failed or unsupported
	Status string `json:"status"`
	// Verify - endpoint certificates are verified
	Verify bool `json:"verify"`
	// CA - the certificate ID of the CA bundle in use, or "none"
	CA string `json:"ca"`
	// ClientCert - a client certificate is presented to endpoints
	ClientCert bool `json:"client_cert"`
	// ClientCertID - the certificate ID of that client certificate
	ClientCertID string `json:"client_cert_id,omitempty"`
	// ServerName - the name sent as SNI and expected of the certificate
	ServerName string `json:"server_name,omitempty"`
	// Generation - how many times the listener's backend context was
	// replaced in place since the listener was created
	Generation uint32 `json:"generation"`
}

// BackendTLSBuildPrecondition is the one answer to whether this gateway can
// verify a backend or present a client certificate to it. Rule admission and
// the capabilities surface both ask it, so the verdict a client reads cannot
// part from the refusal it would get. build is MTLSBuild; it is an argument
// so that both answers can be tested in one build.
func BackendTLSBuildPrecondition(build bool) *ServerPreconditionError {
	if build {
		return nil
	}
	return &ServerPreconditionError{
		Reason: ReasonBackendTLSNotBuilt,
		Err: errors.New("backend TLS verification and backend client certificates need a gateway built with " +
			"client-certificate support; this one was built without it, and no request can change that"),
	}
}
