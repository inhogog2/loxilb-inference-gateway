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

// auditsink.go — NetHookInterface surface over the audit sinks
// (api/restapi/handler/audit_sink_snapshot.go), so the config
// snapshot/restore engine captures and replays them like any other domain.
// Certificate material never crosses this surface: a sink names it by path
// and it stays on the node. No BgpPeerMode guard: the audit trail runs in
// every mode.

package loxinet

import (
	"github.com/loxilb-io/loxilb/api/restapi/handler"
	cmn "github.com/loxilb-io/loxilb/common"
)

// NetAuditSinkGet - export the configured audit sinks as desired state.
func (na *NetAPIStruct) NetAuditSinkGet() ([]cmn.AuditSinkConfig, error) {
	return handler.AuditSinkExport(), nil
}

// NetAuditSinkAdd - configure one audit sink, replacing one of its name.
func (na *NetAPIStruct) NetAuditSinkAdd(cfg *cmn.AuditSinkConfig) (int, error) {
	if err := handler.AuditSinkApply(cfg); err != nil {
		return RuleErrBase, err
	}
	return 0, nil
}

// NetAuditSinkDel - stop one audit sink, keeping its place in the trail.
func (na *NetAPIStruct) NetAuditSinkDel(name string) (int, error) {
	if err := handler.AuditSinkRemove(name); err != nil {
		return RuleErrBase, err
	}
	return 0, nil
}
