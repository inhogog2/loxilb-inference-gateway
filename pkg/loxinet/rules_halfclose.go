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
// hold is refused where the data plane would never hold a client, or has not
// been shown to: a service that is not fullproxy (only the proxy relays an
// answer it could hold a client for), one whose clients speak TLS (the hold
// leaves TLS connections alone), and a P/D service (not yet measured). The
// check is on the rule as it will stand after a replace - the mode it keeps
// and the P/D switch it is given - so neither order slips through: hold on a
// P/D rule, nor P/D switched on under a stored hold. The security mode cannot
// change on a live rule. A snapshot restore replay is let through as unset
// with a warning instead, so that one field cannot keep the rule from coming
// back.
func halfCloseResolve(eRule *ruleEnt, serv *cmn.LbServiceArg, mode cmn.LBMode) (uint8, error) {
	next, err := cmn.HalfCloseModeToRule(serv.HalfCloseMode)
	if err != nil {
		return 0, err
	}
	if eRule != nil && !serv.HalfCloseModePresent && serv.HalfCloseMode == "" {
		next = eRule.halfCloseMode
	}
	if next != cmn.HalfCloseRuleHold {
		return next, nil
	}
	why := ""
	switch {
	case mode != cmn.LBModeFullProxy:
		why = "available on fullproxy services only"
	case serv.Security != cmn.LBServPlain:
		why = "not available on a service whose clients use TLS: TLS connections are never held"
	case serv.PDDisaggMode:
		why = "not available on a P/D (pd_disagg_mode) service yet"
	default:
		return next, nil
	}
	if serv.RestoreReplay {
		tk.LogIt(tk.LogWarning, "lb-rule %s:%d: half_close_mode hold restored where it is %s: dropped\n",
			serv.ServIP, serv.ServPort, why)
		return cmn.HalfCloseRuleUnset, nil
	}
	return 0, cmn.NewValidationError("half_close_mode", "half_close_mode hold is %s", why)
}
