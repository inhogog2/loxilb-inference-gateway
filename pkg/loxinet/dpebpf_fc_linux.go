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

/*
#include <stdint.h>
#include <stdlib.h>
// The service key as the health updates declare it in dpebpf_linux.go: one
// cgo package shares one definition, and the sockproxy compares a key on
// these three fields only (cmp_proxy_ent), never on the full entry.
struct proxy_ent {
  uint32_t xip;
  uint16_t xport;
  uint8_t inv;
  uint8_t protocol;
};
#include "../../loxilb-ebpf/common/sockproxy_metrics.h"
*/
import "C"

import (
	"net"
	"unsafe"

	cmn "github.com/loxilb-io/loxilb/common"
	tk "github.com/loxilb-io/loxilib"
)

// The capacity admission gate's read-back and drain, over the exports the
// sockproxy provides for them (loxilb-ebpf/common/sockproxy_metrics.h). The
// Prometheus collector reads the same rows for every pool; these are the
// two calls the management plane makes for one rule and for the process.

var fcModeNames = [...]string{"off", "observe", "enforce"}

// DpFcStateGet - the gate's resolved state on the rule's model pool: the
// pool is the one the rule's host, path prefix and model name resolve to on
// the service. ok is false when the service or the pool does not exist in
// the data plane (a rule that has not been pushed, or an IPv6 service).
func (e *DpEbpfH) DpFcStateGet(svcIP net.IP, svcPort uint16, proto uint8,
	hostURL, pathPrefix, modelName string) (cmn.FcEffectiveArg, bool) {
	var key C.struct_proxy_ent
	var st C.proxy_fc_svc_stat_t

	if svcIP.To4() == nil {
		return cmn.FcEffectiveArg{}, false
	}
	key.xip = C.uint(tk.IPtonl(svcIP))
	key.xport = C.ushort(tk.Htons(svcPort))
	key.protocol = C.uchar(proto)

	cHost := C.CString(hostURL)
	cPath := C.CString(pathPrefix)
	cModel := C.CString(modelName)
	defer C.free(unsafe.Pointer(cHost))
	defer C.free(unsafe.Pointer(cPath))
	defer C.free(unsafe.Pointer(cModel))

	if C.proxy_get_fc_state(&key, cHost, cPath, cModel, &st) != 0 {
		return cmn.FcEffectiveArg{}, false
	}
	mode := "unknown"
	if int(st.mode) < len(fcModeNames) {
		mode = fcModeNames[st.mode]
	}
	return cmn.FcEffectiveArg{
		Mode:                    mode,
		MaxOutstanding:          uint32(st.max_outstanding),
		EpMaxInflight:           uint32(st.ep_cap[0]),
		PrefillMaxInflight:      uint32(st.ep_cap[1]),
		DecodeMaxInflight:       uint32(st.ep_cap[2]),
		QueueDepth:              uint32(st.max_queue_depth),
		QueueWaitMs:             uint32(st.max_queue_wait_ms),
		Inflight:                uint32(st.inflight),
		Queued:                  uint32(st.queued),
		QueueMemoryBoundMib:     uint64(st.max_queue_depth),
		TelemetryStaleMs:        uint32(st.telemetry_stale_ms),
		Adaptive:                fcOnOff(st.adaptive),
		WarmupMs:                uint32(st.warmup_ms),
		TtftTargetMs:            uint32(st.ttft_target_ms),
		EffectiveMaxOutstanding: uint32(st.effective_max_outstanding),
		AdaptState:              fcNameOf(fcAdaptStateNames, uint8(st.adapt_state)),
		AdaptReason:             fcNameOf(fcAdaptReasonNames, uint8(st.adapt_reason)),
		WarmingEndpoints:        uint32(st.warming_eps),
		TenantMaxSharePct:       uint32(st.tenant_share_pct),
		TenantsActive:           uint32(st.tenants_active),
		ExposeHeaders:           fcOnOff(st.expose_headers),
		Source: cmn.FcEffectiveSource{
			Mode:               fcSourceName(st.src[0]),
			MaxOutstanding:     fcSourceName(st.src[1]),
			EpMaxInflight:      fcSourceName(st.src[2]),
			PrefillMaxInflight: fcSourceName(st.src[3]),
			DecodeMaxInflight:  fcSourceName(st.src[4]),
			QueueDepth:         fcSourceName(st.src[5]),
			QueueWaitMs:        fcSourceName(st.src[6]),
			TelemetryStaleMs:   fcSourceName(st.src[7]),
			Adaptive:           fcSourceName(st.src_adapt[0]),
			WarmupMs:           fcSourceName(st.src_adapt[1]),
			TtftTargetMs:       fcSourceName(st.src_adapt[2]),
			TenantMaxSharePct:  fcSourceName(st.src_tenant),
			ExposeHeaders:      fcSourceName(st.src_expose),
		},
	}, true
}

// The data plane's enum fc_adapt_state and enum fc_adapt_reason, spelled
// as sockproxy_fc.c spells them.
var (
	fcAdaptStateNames  = []string{"off", "open", "tightened", "frozen"}
	fcAdaptReasonNames = []string{"none", "queued", "ttft", "clear", "stale"}
)

func fcNameOf(names []string, v uint8) string {
	if int(v) < len(names) {
		return names[v]
	}
	return "unknown"
}

// fcOnOff names the adaptive switch in force.
func fcOnOff(v C.uint8_t) string {
	if v != 0 {
		return "on"
	}
	return "off"
}

// fcSourceName names enum fc_src: where a value in force came from.
func fcSourceName(src C.uint8_t) string {
	switch src {
	case 1:
		return "env"
	case 2:
		return "rule"
	}
	return "default"
}

// DpFcInflightTotal - inference requests executing under the gate, summed
// over every gated pool.
func (e *DpEbpfH) DpFcInflightTotal() uint64 {
	return uint64(C.proxy_get_fc_inflight_total())
}

// DpFcDrainSet - enter or leave the data path's maintenance drain.
func (e *DpEbpfH) DpFcDrainSet(on bool) {
	v := C.int(0)
	if on {
		v = 1
	}
	C.proxy_fc_drain_set(v)
	tk.LogIt(tk.LogInfo, "[DP] capacity gate drain %v\n", on)
}
