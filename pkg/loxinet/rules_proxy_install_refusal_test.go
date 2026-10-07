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

package loxinet

import (
	"errors"
	"net"
	"strings"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

// hostHolds stands in for the host: only the listed addresses can be bound.
func hostHolds(t *testing.T, held ...string) {
	t.Helper()
	orig := lbVIPBindable
	lbVIPBindable = func(vip net.IP) bool {
		for _, h := range held {
			if vip.Equal(net.ParseIP(h)) {
				return true
			}
		}
		return false
	}
	t.Cleanup(func() { lbVIPBindable = orig })
}

// A rule the data plane did not install is kept only where the listener has
// nothing to bind to because the VIP is with the cluster peer.
func TestListenerAwaitsVIP(t *testing.T) {
	hostHolds(t, "10.10.10.254")
	held, away := net.ParseIP("10.10.10.254"), net.ParseIP("10.10.10.200")
	for _, c := range []struct {
		state string
		vip   net.IP
		want  bool
	}{
		{cmn.CIBackupStateString, away, true},
		{cmn.CIFaultStateString, away, true},
		// The address is here, so the data plane refused for another reason.
		{cmn.CIBackupStateString, held, false},
		// A master and a gateway outside a cluster hold their VIPs or never will.
		{cmn.CIMasterStateString, away, false},
		{cmn.CIUnDefStateString, away, false},
		{cmn.CIMasterStateString, held, false},
	} {
		if got := lbListenerAwaitsVIP(c.state, c.vip); got != c.want {
			t.Errorf("state %s, VIP %s: kept = %v, want %v", c.state, c.vip, got, c.want)
		}
	}
}

// The refusal says whose it is: a VIP that is not the gateway's is the
// caller's and names the field, anything else is a condition of the gateway.
func TestPushRefusedErrorClass(t *testing.T) {
	hostHolds(t, "10.10.10.254")

	err := lbPushRefusedError(net.ParseIP("203.0.113.9"), false)
	var arg *cmn.RuleArgumentError
	var precond *cmn.ServerPreconditionError
	if !errors.As(err, &arg) || errors.As(err, &precond) {
		t.Fatalf("a VIP the gateway does not hold: got %T, want a rule argument refusal", err)
	}
	if !strings.Contains(err.Error(), "externalIP 203.0.113.9 is not an address of this gateway") {
		t.Errorf("the refusal does not name the field and the address: %q", err)
	}

	err = lbPushRefusedError(net.ParseIP("10.10.10.254"), false)
	if !errors.As(err, &precond) || errors.As(err, &arg) {
		t.Fatalf("a VIP the gateway holds: got %T, want a server precondition", err)
	}
	if precond.Reason != cmn.ReasonLbDataplaneInstallFailed {
		t.Errorf("reason = %q, want %q", precond.Reason, cmn.ReasonLbDataplaneInstallFailed)
	}
	if err.Error() != lbPushRefusedText(false) {
		t.Errorf("the sentence changed: %q", err)
	}

	// A policy that was not replaced was refused on a listener that exists,
	// so the address is never the reason.
	err = lbPushRefusedError(net.ParseIP("203.0.113.9"), true)
	if !errors.As(err, &precond) || err.Error() != lbPushRefusedText(true) {
		t.Errorf("a kept backend TLS policy: got %T %q", err, err)
	}
}

// The probe itself, against the host the test runs on.
func TestVIPBindableOnThisHost(t *testing.T) {
	if !lbVIPBindable(net.ParseIP("127.0.0.1")) {
		t.Error("the loopback address is reported as not bindable")
	}
	if !lbVIPBindable(net.IPv4zero) {
		t.Error("the unspecified address is reported as not bindable")
	}
	if lbVIPBindable(net.ParseIP("203.0.113.9")) {
		t.Skip("203.0.113.9 can be bound on this host")
	}
}
