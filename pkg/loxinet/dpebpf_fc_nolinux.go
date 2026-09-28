//go:build !linux

/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
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

	cmn "github.com/loxilb-io/loxilb/common"
)

// No sockproxy off Linux: no gate state to read, nothing to drain.

// DpFcStateGet - not available off Linux.
func (e *DpEbpfH) DpFcStateGet(svcIP net.IP, svcPort uint16, proto uint8,
	hostURL, pathPrefix, modelName string) (cmn.FcEffectiveArg, bool) {
	return cmn.FcEffectiveArg{}, false
}

// DpFcInflightTotal - not available off Linux.
func (e *DpEbpfH) DpFcInflightTotal() uint64 { return 0 }

// DpFcDrainSet - not available off Linux.
func (e *DpEbpfH) DpFcDrainSet(on bool) {}
