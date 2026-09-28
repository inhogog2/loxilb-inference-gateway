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

// fcRuleCfg is a rule's declared admission gate beyond the queue pair, as
// stored and as sent to the data plane: 0 on any field runs on the process
// environment or the product default, which the data plane resolves.
type fcRuleCfg struct {
	mode               uint8 // cmn.FcRuleMode*
	maxOutstanding     uint32
	epMaxInflight      uint32
	prefillMaxInflight uint32
	decodeMaxInflight  uint32
	telemetryStaleMs   uint32
}

// fcRuleResolve returns the gate declaration a rule will store: on create
// the request's values, on a replace each field merged with the stored one
// (an omitted field keeps it; a present one, zero or "inherit" included,
// replaces it).
func fcRuleResolve(eRule *ruleEnt, serv *cmn.LbServiceArg) (fcRuleCfg, error) {
	mode, err := cmn.FcModeToRule(serv.FcMode)
	if err != nil {
		return fcRuleCfg{}, err
	}
	next := fcRuleCfg{
		mode:               mode,
		maxOutstanding:     serv.FcMaxOutstanding,
		epMaxInflight:      serv.FcEpMaxInflight,
		prefillMaxInflight: serv.FcPrefillMaxInflight,
		decodeMaxInflight:  serv.FcDecodeMaxInflight,
		telemetryStaleMs:   serv.FcTelemetryStaleMs,
	}
	if eRule != nil {
		cur := eRule.fcCfg
		if !serv.FcModePresent && serv.FcMode == "" {
			next.mode = cur.mode
		}
		next.maxOutstanding = u32OnReplace(cur.maxOutstanding, serv.FcMaxOutstanding, serv.FcMaxOutstandingPresent)
		next.epMaxInflight = u32OnReplace(cur.epMaxInflight, serv.FcEpMaxInflight, serv.FcEpMaxInflightPresent)
		next.prefillMaxInflight = u32OnReplace(cur.prefillMaxInflight, serv.FcPrefillMaxInflight, serv.FcPrefillMaxInflightPresent)
		next.decodeMaxInflight = u32OnReplace(cur.decodeMaxInflight, serv.FcDecodeMaxInflight, serv.FcDecodeMaxInflightPresent)
		next.telemetryStaleMs = u32OnReplace(cur.telemetryStaleMs, serv.FcTelemetryStaleMs, serv.FcTelemetryStaleMsPresent)
	}
	for _, c := range []struct {
		name string
		v    uint32
	}{
		{"fc_max_outstanding", next.maxOutstanding},
		{"fc_ep_max_inflight", next.epMaxInflight},
		{"fc_prefill_max_inflight", next.prefillMaxInflight},
		{"fc_decode_max_inflight", next.decodeMaxInflight},
	} {
		if c.v > cmn.FcCapMax {
			return fcRuleCfg{}, cmn.NewValidationError(c.name,
				"%s must be within 0..%d", c.name, cmn.FcCapMax)
		}
	}
	if next.telemetryStaleMs > cmn.FcTelemetryStaleMsMax {
		return fcRuleCfg{}, cmn.NewValidationError("fc_telemetry_stale_ms",
			"fc_telemetry_stale_ms must be within 0..%d", cmn.FcTelemetryStaleMsMax)
	}
	return next, nil
}

// toServ writes the stored declaration back onto a rule's service arguments
// for the read-back.
func (c fcRuleCfg) toServ(s *cmn.LbServiceArg) {
	s.FcMode = cmn.FcModeFromRule(c.mode)
	s.FcMaxOutstanding = c.maxOutstanding
	s.FcEpMaxInflight = c.epMaxInflight
	s.FcPrefillMaxInflight = c.prefillMaxInflight
	s.FcDecodeMaxInflight = c.decodeMaxInflight
	s.FcTelemetryStaleMs = c.telemetryStaleMs
}
