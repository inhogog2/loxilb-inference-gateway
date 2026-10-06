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

package snapshot

import (
	"fmt"
	"strings"
)

// dropRetiredLbFields brings the loadbalancer rules of a document written by
// an earlier release to what this release carries: the retired mtls_backend
// keys are discarded and a verify_server_cert request is reset to false. It
// returns one warning per change; a warning names the rule and the keys,
// never a value. None of this reached the data plane, so the rule behaves as
// it did before.
func dropRetiredLbFields(doc *Document) []string {
	var warns []string
	for i := range doc.Domains.LoadBalancer {
		serv := &doc.Domains.LoadBalancer[i].Serv
		rule := fmt.Sprintf("loadbalancer %s:%d/%s", serv.ServIP, serv.ServPort, serv.Proto)
		if names := serv.MTLSBackend.DropRetired(); len(names) > 0 {
			warns = append(warns, rule+": mtls_backend keys no longer supported and ignored: "+strings.Join(names, ", "))
		}
		if serv.MTLSBackend.ResetUnavailable() {
			warns = append(warns, rule+": mtls_backend.verify_server_cert is not available in this release and was reset to false; it had no effect")
		}
	}
	return warns
}
