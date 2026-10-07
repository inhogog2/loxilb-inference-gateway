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
	"strings"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

// A cipher string is refused at admission exactly when the rule would build
// a TLS context with it and the TLS library does not take it.
func TestLbTLSCiphersErr(t *testing.T) {
	const good = "TLS_AES_256_GCM_SHA384:ECDHE-RSA-AES256-GCM-SHA384"
	const bad = "NOT-A-CIPHER"

	// What the TLS library says about each half of the string.
	for _, c := range []struct {
		ciphers      string
		tls13, tls12 bool
	}{
		{good, false, false},
		{bad, true, true},
		{"ECDHE-RSA-AES256-GCM-SHA384", true, false},
		{"TLS_AES_256_GCM_SHA384", false, true},
	} {
		tls13, tls12, asked := tlsCiphersRefused(c.ciphers)
		if !asked || tls13 != c.tls13 || tls12 != c.tls12 {
			t.Fatalf("%q: asked=%v, refused as TLS 1.3 suites=%v and as TLS 1.2 list=%v, want %v and %v",
				c.ciphers, asked, tls13, tls12, c.tls13, c.tls12)
		}
	}

	for _, c := range []struct {
		name    string
		serv    cmn.LbServiceArg
		refused bool
	}{
		{"terminating rule, usable string", cmn.LbServiceArg{Mode: cmn.LBModeFullProxy, Security: cmn.LBServHTTPS, TlsCiphers: good}, false},
		{"terminating rule, unusable string", cmn.LbServiceArg{Mode: cmn.LBModeFullProxy, Security: cmn.LBServHTTPS, TlsCiphers: bad}, true},
		{"end-to-end rule, unusable string", cmn.LbServiceArg{Mode: cmn.LBModeFullProxy, Security: cmn.LBServE2EHTTPS, TlsCiphers: bad}, true},
		{"terminating rule, TLS 1.2 ciphers only", cmn.LbServiceArg{Mode: cmn.LBModeFullProxy, Security: cmn.LBServHTTPS, TlsCiphers: "ECDHE-RSA-AES256-GCM-SHA384"}, true},
		{"terminating rule, no string", cmn.LbServiceArg{Mode: cmn.LBModeFullProxy, Security: cmn.LBServHTTPS}, false},
		{"plain full-proxy rule builds no context", cmn.LbServiceArg{Mode: cmn.LBModeFullProxy, Security: cmn.LBServPlain, TlsCiphers: bad}, false},
		{"a rule that is not full-proxy builds no context", cmn.LbServiceArg{Mode: cmn.LBModeDefault, Security: cmn.LBServHTTPS, TlsCiphers: bad}, false},
	} {
		err := lbTLSCiphersErr(&c.serv)
		if (err != nil) != c.refused {
			t.Errorf("%s: err=%v, want refused=%v", c.name, err, c.refused)
		}
		if err != nil && !strings.Contains(err.Error(), "tls_ciphers") {
			t.Errorf("%s: the refusal does not name the field: %v", c.name, err)
		}
	}
}

// A cipher string that does not fit the data plane's buffer is refused, not cut.
func TestLbTLSCiphersLength(t *testing.T) {
	serv := cmn.LbServiceArg{TlsCiphers: strings.Repeat("A", lbTLSCiphersMaxBytes)}
	if err := validateLBFixedCStringFields(serv); err != nil {
		t.Errorf("a string of %d bytes was refused: %v", lbTLSCiphersMaxBytes, err)
	}
	serv.TlsCiphers += "A"
	err := validateLBFixedCStringFields(serv)
	if err == nil || !strings.Contains(err.Error(), "tls_ciphers") {
		t.Errorf("a string of %d bytes: err=%v, want a refusal naming tls_ciphers", lbTLSCiphersMaxBytes+1, err)
	}
}
