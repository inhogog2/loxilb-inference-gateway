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
	cmn "github.com/loxilb-io/loxilb/common"
)

// fcQueueResolve returns the capacity queue declaration a rule will store:
// on create the request's values, on a replace each field merged with the
// stored one (an omitted field keeps it, a present one, zero included,
// replaces it). The pair rule is judged on that result, never on the request
// alone: a replace carrying only a depth keeps its stored wait, and one
// carrying only a zero wait must not leave a stored depth without a window.
func fcQueueResolve(eRule *ruleEnt, serv *cmn.LbServiceArg) (depth, waitMs uint32, err error) {
	depth, waitMs = serv.FcMaxQueueDepth, serv.FcMaxQueueWaitMs
	if eRule != nil {
		depth = u32OnReplace(eRule.fcMaxQueueDepth, serv.FcMaxQueueDepth, serv.FcMaxQueueDepthPresent)
		waitMs = u32OnReplace(eRule.fcMaxQueueWaitMs, serv.FcMaxQueueWaitMs, serv.FcMaxQueueWaitMsPresent)
	}
	if err = cmn.FcQueuePairError(depth, waitMs); err != nil {
		return 0, 0, err
	}
	return depth, waitMs, nil
}
