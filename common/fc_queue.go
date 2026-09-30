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

// FcQueuePairError holds the one rule that spans a service's two capacity
// queue fields: a depth without a wait window would park a request forever,
// so the window is required with it. It is judged on the values that will be
// stored, which on a replace or a PATCH means after the request is merged
// with the stored rule: an update may carry one field and keep the other.
func FcQueuePairError(depth, waitMs uint32) error {
	if depth > 0 && waitMs == 0 {
		return NewValidationError("fc_max_queue_wait_ms",
			"fc_max_queue_wait_ms must be greater than 0 when fc_max_queue_depth is set")
	}
	return nil
}

// FcCapMax bounds a rule's service and per-endpoint admission ceilings.
const FcCapMax = 100000

// FcTelemetryStaleMsMax bounds a rule's telemetry window (an hour).
const FcTelemetryStaleMsMax = 3600000

// FcWarmupMsMax bounds a rule's endpoint warm-up window (an hour).
const FcWarmupMsMax = 3600000

// FcTtftTargetMsMax bounds a rule's TTFT target (an hour).
const FcTtftTargetMsMax = 3600000

// FcTenantMaxSharePctMax bounds a rule's tenant share, a percentage.
const FcTenantMaxSharePctMax = 100

// The data plane's encoding of a rule's adaptive switch (enum
// fc_rule_adaptive), shifted like the mode so a rule can say "off" under an
// environment that has it on.
const (
	FcRuleAdaptiveInherit uint8 = iota
	FcRuleAdaptiveOff
	FcRuleAdaptiveOn
)

// FcAdaptiveToRule maps a rule's fc_adaptive to the data plane's encoding.
// Empty and "inherit" both mean the process default; anything else is
// refused.
func FcAdaptiveToRule(v string) (uint8, error) {
	switch v {
	case "", "inherit":
		return FcRuleAdaptiveInherit, nil
	case "off":
		return FcRuleAdaptiveOff, nil
	case "on":
		return FcRuleAdaptiveOn, nil
	}
	return 0, NewValidationError("fc_adaptive",
		"fc_adaptive must be one of on, off or inherit")
}

// FcExposeHeadersToRule maps a rule's fc_expose_headers to the data plane's
// encoding (enum fc_rule_expose), shifted like the adaptive switch. Empty and
// "inherit" both mean the process default; anything else is refused.
func FcExposeHeadersToRule(v string) (uint8, error) {
	switch v {
	case "", "inherit":
		return FcRuleAdaptiveInherit, nil
	case "off":
		return FcRuleAdaptiveOff, nil
	case "on":
		return FcRuleAdaptiveOn, nil
	}
	return 0, NewValidationError("fc_expose_headers",
		"fc_expose_headers must be one of on, off or inherit")
}

// FcAdaptiveFromRule is FcAdaptiveToRule's inverse for the read-back: the
// process default reads as empty, so it is omitted.
func FcAdaptiveFromRule(a uint8) string {
	switch a {
	case FcRuleAdaptiveOff:
		return "off"
	case FcRuleAdaptiveOn:
		return "on"
	}
	return ""
}

// The data plane's encoding of a rule's gate mode (enum fc_rule_mode): 0
// runs on the process default, the others are shifted by one so a rule can
// say "off" under an enforcing environment.
const (
	FcRuleModeInherit uint8 = iota
	FcRuleModeOff
	FcRuleModeObserve
	FcRuleModeEnforce
)

// FcModeToRule maps a rule's fc_mode to the data plane's encoding. Empty
// and "inherit" both mean the process default; anything else is refused.
func FcModeToRule(mode string) (uint8, error) {
	switch mode {
	case "", "inherit":
		return FcRuleModeInherit, nil
	case "off":
		return FcRuleModeOff, nil
	case "observe":
		return FcRuleModeObserve, nil
	case "enforce":
		return FcRuleModeEnforce, nil
	}
	return 0, NewValidationError("fc_mode",
		"fc_mode must be one of off, observe, enforce or inherit")
}

// FcModeFromRule is FcModeToRule's inverse for the read-back: the process
// default reads as empty, so it is omitted.
func FcModeFromRule(m uint8) string {
	switch m {
	case FcRuleModeOff:
		return "off"
	case FcRuleModeObserve:
		return "observe"
	case FcRuleModeEnforce:
		return "enforce"
	}
	return ""
}
