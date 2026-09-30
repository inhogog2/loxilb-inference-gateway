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
	"fmt"
	"os"
	"strings"

	cmn "github.com/loxilb-io/loxilb/common"
	tk "github.com/loxilb-io/loxilib"
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
	adaptive           uint8 // cmn.FcRuleAdaptive*
	warmupMs           uint32
	ttftTargetMs       uint32
	tenantSharePct     uint32
	exposeHeaders      uint8 // cmn.FcRuleAdaptive* encoding, enum fc_rule_expose
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
	adaptive, err := cmn.FcAdaptiveToRule(serv.FcAdaptive)
	if err != nil {
		return fcRuleCfg{}, err
	}
	expose, err := cmn.FcExposeHeadersToRule(serv.FcExposeHeaders)
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
		adaptive:           adaptive,
		warmupMs:           serv.FcWarmupMs,
		ttftTargetMs:       serv.FcTtftTargetMs,
		tenantSharePct:     serv.FcTenantMaxSharePct,
		exposeHeaders:      expose,
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
		if !serv.FcAdaptivePresent && serv.FcAdaptive == "" {
			next.adaptive = cur.adaptive
		}
		next.warmupMs = u32OnReplace(cur.warmupMs, serv.FcWarmupMs, serv.FcWarmupMsPresent)
		next.ttftTargetMs = u32OnReplace(cur.ttftTargetMs, serv.FcTtftTargetMs, serv.FcTtftTargetMsPresent)
		next.tenantSharePct = u32OnReplace(cur.tenantSharePct, serv.FcTenantMaxSharePct, serv.FcTenantMaxSharePctPresent)
		if !serv.FcExposeHeadersPresent && serv.FcExposeHeaders == "" {
			next.exposeHeaders = cur.exposeHeaders
		}
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
	if next.warmupMs > cmn.FcWarmupMsMax {
		return fcRuleCfg{}, cmn.NewValidationError("fc_warmup_ms",
			"fc_warmup_ms must be within 0..%d", cmn.FcWarmupMsMax)
	}
	if next.ttftTargetMs > cmn.FcTtftTargetMsMax {
		return fcRuleCfg{}, cmn.NewValidationError("fc_ttft_target_ms",
			"fc_ttft_target_ms must be within 0..%d", cmn.FcTtftTargetMsMax)
	}
	if next.tenantSharePct > cmn.FcTenantMaxSharePctMax {
		return fcRuleCfg{}, cmn.NewValidationError("fc_tenant_max_share_pct",
			"fc_tenant_max_share_pct must be within 0..%d", cmn.FcTenantMaxSharePctMax)
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
	s.FcAdaptive = cmn.FcAdaptiveFromRule(c.adaptive)
	s.FcWarmupMs = c.warmupMs
	s.FcTtftTargetMs = c.ttftTargetMs
	s.FcTenantMaxSharePct = c.tenantSharePct
	s.FcExposeHeaders = cmn.FcAdaptiveFromRule(c.exposeHeaders)
}

// fcExposeSockMapErr refuses the admission headers on a rule whose response
// direction the kernel may carry (sockMapMode both or response): the gateway
// never sees those responses, so it could not keep what the rule asks for.
// A snapshot restore replay is let through with a warning, as the sockmap
// checks do: the headers then appear only on responses the relay carries.
func fcExposeSockMapErr(serv *cmn.LbServiceArg, c fcRuleCfg, sockMapCode uint8) error {
	if c.exposeHeaders != cmn.FcRuleAdaptiveOn {
		return nil
	}
	if _, resp := sockMapDirs(sockMapCode); !resp {
		return nil
	}
	if serv.RestoreReplay {
		tk.LogIt(tk.LogWarning, "lb-rule %s:%d: fc_expose_headers on with sockMapMode %s restored: accelerated responses carry no admission headers\n",
			serv.ServIP, serv.ServPort, serv.SockMapMode)
		return nil
	}
	return cmn.NewValidationError("fc_expose_headers",
		"fc_expose_headers on is refused with sockMapMode %s: the response direction is not seen by the gateway",
		serv.SockMapMode)
}

// adaptiveInForce reports whether the rule's pool adapts its service
// ceiling: its own switch, or the process default when it declares none.
func (c fcRuleCfg) adaptiveInForce() bool {
	switch c.adaptive {
	case cmn.FcRuleAdaptiveOn:
		return true
	case cmn.FcRuleAdaptiveOff:
		return false
	}
	return strings.EqualFold(os.Getenv("LLB_FC_ADAPTIVE"), "on")
}

// syncVllmScraper runs the rule's vLLM metrics scraper while something
// reads what it scrapes: the P/D scorers, or the adaptive admission ceiling
// of an AI-gateway rule. The scraper addresses endpoints by their index in
// the rule, so a rule whose endpoints changed gets a fresh one.
func (r *ruleEnt) syncVllmScraper() {
	lbActs, ok := r.act.action.(*ruleLBActs)
	if !ok {
		return
	}
	want := r.pdDisaggMode || (r.aiGwMode() && r.fcCfg.adaptiveInForce())
	endpoints := make(map[int]string, len(lbActs.endPoints))
	if want {
		for i, ep := range lbActs.endPoints {
			endpoints[i] = fmt.Sprintf("%s:%d", ep.xIP.String(), ep.xPort)
		}
	}
	if r.vllmScraper != nil {
		if want && r.vllmScraper.sameEndpoints(endpoints) {
			return
		}
		r.vllmScraper.Stop()
		r.vllmScraper = nil
	}
	if !want {
		return
	}
	svcIP := tk.IPtonl(r.tuples.l3Dst.addr.IP)
	svcPort := r.tuples.l4Dst.valMin
	// updateFn mirrors samples into the Go-side worker-metrics cache so
	// the REST introspection/staleness APIs see the built-in scraper
	// (cache only — the data plane's queue-depth push happens inside the
	// sink).
	r.vllmScraper = NewVllmScraper(endpoints, svcIP, svcPort, 0,
		func(epIP string, m WorkerMetrics) {
			if mh.dpEbpf != nil {
				mh.dpEbpf.StoreWorkerMetricsCache(m.EndpointIP, m)
			}
		})
	// thread the mh-owned shutdown ctx so the scraper exits when the
	// workers stage cancels.
	go r.vllmScraper.Run(mh.shutdownCtx)
}
