/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package loxinet

import (
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

// What the data plane receives for a rule's Endpoint Picker: a mode word
// (EPP_MODE_* in sockproxy.h) and the resolved deadline, both zero on a
// rule without an EPP so its push stays byte-identical.
func TestEppDpModeWords(t *testing.T) {
	tests := []struct {
		name     string
		rule     ruleEnt
		wantMode uint8
		wantMs   uint32
	}{
		{"no epp", ruleEnt{eppFailureMode: cmn.EppFailureModeFailOpen, eppTimeoutMs: 1500}, eppDpModeOff, 0},
		{"fail close", ruleEnt{eppEndpoint: "epp:9002", eppFailureMode: cmn.EppFailureModeFailClose, eppTimeoutMs: 3000}, eppDpModeFailClose, 3000},
		{"fail open", ruleEnt{eppEndpoint: "epp:9002", eppFailureMode: cmn.EppFailureModeFailOpen, eppTimeoutMs: 250}, eppDpModeFailOpen, 250},
		// Admission resolves both defaults; the DP hop still never sends an
		// EPP rule with an empty mode or a zero deadline.
		{"unresolved defaults", ruleEnt{eppEndpoint: "epp:9002"}, eppDpModeFailClose, cmn.EppDefaultTimeoutMs},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.rule.eppDpMode(); got != tt.wantMode {
				t.Fatalf("mode=%d want %d", got, tt.wantMode)
			}
			if got := tt.rule.eppDpTimeoutMs(); got != tt.wantMs {
				t.Fatalf("timeout=%d want %d", got, tt.wantMs)
			}
		})
	}
}

// The cgo mirror of dp_proxy_tacts carries the two EPP words and the mode
// values agree with EPP_MODE_* on the C side (sockproxy.h is not included
// by this package, so the C literals are spelled here).
func TestEppDpBridgeMatchesCABI(t *testing.T) {
	var dat proxyActs
	dat.epp_mode = 2
	dat.epp_timeout_ms = 600000
	if uint8(dat.epp_mode) != eppDpModeFailClose || uint32(dat.epp_timeout_ms) != cmn.EppTimeoutMsMax {
		t.Fatalf("EPP words did not survive the cgo struct: %+v", dat)
	}
	if eppDpModeOff != 0 || eppDpModeFailOpen != 1 || eppDpModeFailClose != 2 {
		t.Fatal("eppDpMode words drifted from EPP_MODE_OFF/FAIL_OPEN/FAIL_CLOSE")
	}
}
