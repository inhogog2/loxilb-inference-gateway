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
// "forget the answer". On a FullProxy rule whose half_close_mode is hold, the
// data plane keeps such a client open until its answer is out, where it can
// follow the answer: plaintext, the kernel never given a direction of the
// connection. A rule's value, and the process-wide switch and bound below,
// decide where that applies.

// A rule's half_close_mode, as the API carries it.
const (
	HalfCloseModeOff     = "off"
	HalfCloseModeHold    = "hold"
	HalfCloseModeInherit = "inherit"
	// HalfCloseModeHoldParked also holds a client whose FIN arrives while
	// its request is parked. Reserved: refused until the data plane has it.
	HalfCloseModeHoldParked = "hold+parked"
)

// The data plane's encoding of a rule's mode (enum sp_hold_mode). Unset runs
// on the process default (HalfCloseConfig.DefaultMode); a rule that cannot
// take hold is sent off instead, so the default never reaches it.
const (
	HalfCloseRuleUnset uint8 = 0
	HalfCloseRuleOff   uint8 = 1
	HalfCloseRuleHold  uint8 = 2
)

// HalfCloseModeToRule maps a rule's half_close_mode to the data plane's
// encoding. Empty and "inherit" both mean unset; hold+parked is refused until
// it is available; anything else is refused.
func HalfCloseModeToRule(v string) (uint8, error) {
	switch v {
	case "", HalfCloseModeInherit:
		return HalfCloseRuleUnset, nil
	case HalfCloseModeOff:
		return HalfCloseRuleOff, nil
	case HalfCloseModeHold:
		return HalfCloseRuleHold, nil
	case HalfCloseModeHoldParked:
		return 0, NewValidationError("half_close_mode",
			"half_close_mode hold+parked is not available yet; use hold")
	}
	return 0, NewValidationError("half_close_mode",
		"half_close_mode must be one of off, hold or inherit")
}

// HalfCloseModeFromRule is HalfCloseModeToRule's inverse for the read-back:
// unset reads as empty, so it is omitted.
func HalfCloseModeFromRule(m uint8) string {
	switch m {
	case HalfCloseRuleOff:
		return HalfCloseModeOff
	case HalfCloseRuleHold:
		return HalfCloseModeHold
	}
	return ""
}

// The idle bound on a hold, in seconds: its default and its limits (the data
// plane clamps to the same).
const (
	HalfCloseCapDefaultSec uint32 = 240
	HalfCloseCapMinSec     uint32 = 1
	HalfCloseCapMaxSec     uint32 = 3600
)

// HalfCloseConfig - the process-wide half-close hold settings
// (/config/halfclose). They apply to the services whose mode is hold, and
// the default mode to the ones that leave theirs unset.
type HalfCloseConfig struct {
	// Allow - whether new holds may be taken. Blocking stops new holds and
	// leaves the clients already held to finish; a release closes those.
	Allow bool `json:"allow"`
	// CapSeconds - the idle bound on a hold: a held client to which no
	// answer byte has been written for this long is closed.
	CapSeconds uint32 `json:"capSeconds"`
	// DefaultMode - the mode of a service that leaves its half_close_mode
	// unset: off or hold. It reaches only the services that could take hold
	// themselves - the check that refuses hold on a service decides it.
	// Empty, as a document written before the field existed carries it, is
	// off.
	DefaultMode string `json:"defaultMode,omitempty"`
}

// HalfCloseUpdate - a partial change of the settings: a nil field keeps the
// value in force.
type HalfCloseUpdate struct {
	Allow       *bool
	CapSeconds  *uint32
	DefaultMode *string
}

// DefaultHalfCloseConfig - the settings in force until they are set.
func DefaultHalfCloseConfig() HalfCloseConfig {
	return HalfCloseConfig{Allow: true, CapSeconds: HalfCloseCapDefaultSec,
		DefaultMode: HalfCloseModeOff}
}

// HalfCloseDefaultModeCheck refuses a default mode other than off or hold.
// inherit has nowhere to inherit from, and hold+parked is not available yet.
func HalfCloseDefaultModeCheck(v string) error {
	switch v {
	case HalfCloseModeOff, HalfCloseModeHold:
		return nil
	case HalfCloseModeInherit:
		return NewValidationError("defaultMode",
			"defaultMode inherit has nothing to inherit from: use off or hold")
	case HalfCloseModeHoldParked:
		return NewValidationError("defaultMode",
			"defaultMode hold+parked is not available yet; use hold")
	}
	return NewValidationError("defaultMode", "defaultMode must be off or hold")
}

// Normalized - the settings with an empty default mode read as off.
func (c HalfCloseConfig) Normalized() HalfCloseConfig {
	if c.DefaultMode == "" {
		c.DefaultMode = HalfCloseModeOff
	}
	return c
}

// DefaultRule - the default mode in the data plane's encoding.
func (c HalfCloseConfig) DefaultRule() uint8 {
	if c.DefaultMode == HalfCloseModeHold {
		return HalfCloseRuleHold
	}
	return HalfCloseRuleOff
}

// Validate refuses a bound outside its limits and a default mode other than
// off or hold (empty reads as off).
func (c HalfCloseConfig) Validate() error {
	if c.CapSeconds < HalfCloseCapMinSec || c.CapSeconds > HalfCloseCapMaxSec {
		return NewValidationError("capSeconds", "capSeconds must be within %d..%d",
			HalfCloseCapMinSec, HalfCloseCapMaxSec)
	}
	if c.DefaultMode != "" {
		return HalfCloseDefaultModeCheck(c.DefaultMode)
	}
	return nil
}

// Where a service's half-close mode in force comes from
// (HalfCloseEffectiveArg.Source).
const (
	// HalfCloseSourceRule - the service's own half_close_mode.
	HalfCloseSourceRule = "rule"
	// HalfCloseSourceDefault - the process-wide default mode, for a service
	// that leaves its own unset.
	HalfCloseSourceDefault = "default"
	// HalfCloseSourceBlocked - new holds are blocked process-wide.
	HalfCloseSourceBlocked = "blocked"
)

// HalfCloseEffectiveArg - a FullProxy service's half-close mode in force
// for new holds, and where it came from. A read model for GET, never
// replayed into a POST.
type HalfCloseEffectiveArg struct {
	// Mode - off or hold.
	Mode string `json:"mode"`
	// Source - rule, default or blocked.
	Source string `json:"source"`
	// NotApplied - why the default mode does not reach this service, when
	// it leaves its own mode unset and could not take hold.
	NotApplied string `json:"not_applied,omitempty"`
}
