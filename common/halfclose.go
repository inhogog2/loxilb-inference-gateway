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

package common

// Holding a half-closed client. A client that writes its request and then
// shuts down its write side is saying "that was my last request", not
// "forget the answer". On a FullProxy rule whose half-close mode is hold, the
// data plane keeps such a client open until its answer is out, where it can
// follow the answer: plaintext, the kernel never given a direction of the
// connection. The process-wide switch and bound below decide where that may
// apply.

// The idle bound on a hold, in seconds: its default and its limits (the data
// plane clamps to the same).
const (
	HalfCloseCapDefaultSec uint32 = 240
	HalfCloseCapMinSec     uint32 = 1
	HalfCloseCapMaxSec     uint32 = 3600
)

// HalfCloseConfig - the process-wide half-close hold settings
// (/config/halfclose). They apply to the services whose mode is hold.
type HalfCloseConfig struct {
	// Allow - whether new holds may be taken. Blocking stops new holds and
	// leaves the clients already held to finish; a release closes those.
	Allow bool `json:"allow"`
	// CapSeconds - the idle bound on a hold: a held client to which no
	// answer byte has been written for this long is closed.
	CapSeconds uint32 `json:"capSeconds"`
}

// DefaultHalfCloseConfig - the settings in force until they are set.
func DefaultHalfCloseConfig() HalfCloseConfig {
	return HalfCloseConfig{Allow: true, CapSeconds: HalfCloseCapDefaultSec}
}

// Validate refuses a bound outside its limits.
func (c HalfCloseConfig) Validate() error {
	if c.CapSeconds < HalfCloseCapMinSec || c.CapSeconds > HalfCloseCapMaxSec {
		return NewValidationError("capSeconds", "capSeconds must be within %d..%d",
			HalfCloseCapMinSec, HalfCloseCapMaxSec)
	}
	return nil
}
