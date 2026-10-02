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

// AuditSinkCompliance is the name the compliance sink of /audit/sink is
// kept under. A secondary sink of /audit/sinks/{name} cannot take it.
const AuditSinkCompliance = "compliance"

// AuditSinkConfig is one audit sink as desired state: where the trail is
// sent and, for a secondary sink, what is selected from it. Certificate
// material is named by path and stays on the node; the sink's place in the
// trail and its export sequence are kept under the audit directory and are
// not configuration.
type AuditSinkConfig struct {
	// Name is AuditSinkCompliance for the compliance sink and the sink's
	// own name for a secondary one.
	Name           string `json:"name"`
	Address        string `json:"address"`
	CABundlePath   string `json:"ca_bundle_path"`
	ServerName     string `json:"server_name,omitempty"`
	ClientCertPath string `json:"client_cert_path,omitempty"`
	ClientKeyPath  string `json:"client_key_path,omitempty"`
	MaxFrameBytes  int    `json:"max_frame_bytes,omitempty"`
	Facility       int    `json:"facility,omitempty"`
	// EnterpriseNumber qualifies the export sequence a secondary sink
	// sends beside each record. The compliance sink has none.
	EnterpriseNumber uint32 `json:"enterprise_number,omitempty"`
	// Filter is what a secondary sink selects; nil selects every record.
	Filter *AuditSinkFilter `json:"filter,omitempty"`
}

// AuditSinkFilter is a secondary sink's selection from the trail.
type AuditSinkFilter struct {
	Streams    []string `json:"streams,omitempty"`
	Services   []string `json:"services,omitempty"`
	Outcome    string   `json:"outcome,omitempty"`
	DataSample uint64   `json:"data_sample,omitempty"`
}
