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
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

// The certificate handlers tell "this instance has no rules" from "the rules
// could not be read" by this sentinel, so the two hooks they call must return
// it, not an error that only reads the same.
func TestBgpOnlyRuleHooksReturnTheSentinel(t *testing.T) {
	na := &NetAPIStruct{BgpPeerMode: true}

	if _, err := na.NetLbRuleGet(); !errors.Is(err, cmn.ErrBgpOnlyMode) {
		t.Errorf("NetLbRuleGet returned %v, want cmn.ErrBgpOnlyMode", err)
	}
	if _, _, err := na.NetLbBackendCertRefresh("any"); !errors.Is(err, cmn.ErrBgpOnlyMode) {
		t.Errorf("NetLbBackendCertRefresh returned %v, want cmn.ErrBgpOnlyMode", err)
	}
}
