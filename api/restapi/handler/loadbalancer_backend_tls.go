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
	"fmt"

	"github.com/loxilb-io/loxilb/api/models"
)

// validateBackendTLSArguments refuses the backend TLS arguments a create
// request may not carry. It runs before the request reaches the rule layer,
// so a refused request changes nothing. An error names the argument and never
// echoes its value.
//
// The path and inline-material keys of mtls_backend are retired: a rule names
// backend trust and the client identity by certificate ID. Backend
// certificate verification and a backend client certificate are not available
// in this release, so the arguments that request them are refused too rather
// than accepted and left without effect.
func validateBackendTLSArguments(sa *models.LoadbalanceEntryServiceArguments) error {
	if mb := sa.MtlsBackend; mb != nil {
		for _, f := range []struct{ name, val string }{
			{"backend_ca_path", mb.BackendCaPath},
			{"client_cert_path", mb.ClientCertPath},
			{"client_key_path", mb.ClientKeyPath},
			{"client_cert_data", mb.ClientCertData},
			{"client_key_data", mb.ClientKeyData},
		} {
			if f.val != "" {
				return fmt.Errorf("mtls_backend.%s is no longer supported: upload the certificate through /config/cert and refer to it by certificate ID", f.name)
			}
		}
		if mb.VerifyServerCert != nil && *mb.VerifyServerCert {
			return fmt.Errorf("mtls_backend.verify_server_cert: backend certificate verification is not available in this release")
		}
	}
	if sa.BackendCaCertID != "" {
		return fmt.Errorf("backend_ca_cert_id: backend certificate verification is not available in this release")
	}
	if sa.BackendClientCertID != "" {
		return fmt.Errorf("backend_client_cert_id: a backend client certificate is not available in this release")
	}
	return nil
}
