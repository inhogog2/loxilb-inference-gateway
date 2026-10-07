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

import (
	"errors"
	"testing"
)

func TestBackendTLSBuildPrecondition(t *testing.T) {
	if perr := BackendTLSBuildPrecondition(true); perr != nil {
		t.Fatalf("a build with support is not ready: %v", perr)
	}
	perr := BackendTLSBuildPrecondition(false)
	if perr == nil || perr.Reason != ReasonBackendTLSNotBuilt {
		t.Fatalf("a build without support: %+v", perr)
	}
}

// The refusal of a build without support is a server precondition, whatever
// wraps it on the way to the caller: the request is well formed and no other
// request would be accepted.
func TestValidateBackendTLSRefusalClass(t *testing.T) {
	serv := LbServiceArg{Mode: LBModeFullProxy, Security: LBServE2EHTTPS, BackendTLSServerName: "be.example"}
	err := ValidateBackendTLS(&serv)
	var precond *ServerPreconditionError
	if MTLSBuild {
		if errors.As(err, &precond) {
			t.Fatalf("a build with support refused with a precondition: %v", err)
		}
		return
	}
	if !errors.As(&RuleArgumentError{Err: err}, &precond) || precond.Reason != ReasonBackendTLSNotBuilt {
		t.Fatalf("a build without support refused with %v, want the build precondition", err)
	}
}
