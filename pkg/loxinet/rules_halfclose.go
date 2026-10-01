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
	tk "github.com/loxilb-io/loxilib"
)

// halfCloseResolve returns the half-close mode a rule will store (enum
// sp_hold_mode): on create the declared value, on a replace the stored one
// unless the request names the field, where inherit returns it to unset.
//
// hold is refused on a service that is not fullproxy: only the proxy relays
// an answer it could hold a client for. A snapshot restore replay is let
// through as unset with a warning instead, so that one field cannot keep the
// rule from coming back.
func halfCloseResolve(eRule *ruleEnt, serv *cmn.LbServiceArg, mode cmn.LBMode) (uint8, error) {
	next, err := cmn.HalfCloseModeToRule(serv.HalfCloseMode)
	if err != nil {
		return 0, err
	}
	if eRule != nil && !serv.HalfCloseModePresent && serv.HalfCloseMode == "" {
		next = eRule.halfCloseMode
	}
	if next == cmn.HalfCloseRuleHold && mode != cmn.LBModeFullProxy {
		if serv.RestoreReplay {
			tk.LogIt(tk.LogWarning, "lb-rule %s:%d: half_close_mode hold restored on a service that is not fullproxy: dropped\n",
				serv.ServIP, serv.ServPort)
			return cmn.HalfCloseRuleUnset, nil
		}
		return 0, cmn.NewValidationError("half_close_mode",
			"half_close_mode hold is available on fullproxy services only")
	}
	return next, nil
}
