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

package loxinlp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
	opt "github.com/loxilb-io/loxilb/options"
)

type captureLbHook struct {
	cmn.NetHookInterface
	added []cmn.LbRuleMod
}

func (c *captureLbHook) NetLbRuleAdd(m *cmn.LbRuleMod) (int, error) {
	c.added = append(c.added, *m)
	return 0, nil
}

// TestLbConfigReplayDropsRetiredMTLSBackendKeys: an lbconfig.txt written by
// an earlier release still replays, and the rule handed to the rule layer no
// longer carries the retired mtls_backend keys, and its verification request
// is reset: a create request can no longer make one, so a replayed rule must
// read back as one that can be posted again.
func TestLbConfigReplayDropsRetiredMTLSBackendKeys(t *testing.T) {
	prevHooks, prevPath := hooks, opt.Opts.ConfigPath
	defer func() { hooks, opt.Opts.ConfigPath = prevHooks, prevPath }()

	dir := t.TempDir()
	cfg := `{"lbAttr":[{"serviceArguments":{"externalIP":"20.20.20.1","port":8443,"protocol":"tcp",` +
		`"mtls_backend":{"verify_server_cert":true,"backend_ca_path":"/c/SENTINEL-ca.crt",` +
		`"client_cert_path":"/c/SENTINEL-cert.crt","client_key_path":"/c/SENTINEL-key.key",` +
		`"client_cert_data":"SENTINEL-cert-data","client_key_data":"SENTINEL-key-data"}},` +
		`"endpoints":[{"endpointIP":"10.10.10.2","targetPort":9443,"weight":1}]}]}`
	if err := os.WriteFile(filepath.Join(dir, "lbconfig.txt"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	stub := &captureLbHook{}
	hooks, opt.Opts.ConfigPath = stub, dir

	if !applyLoadBalancerConfig() {
		t.Fatal("replay of an earlier release's lbconfig.txt failed")
	}
	if len(stub.added) != 1 {
		t.Fatalf("replayed %d rule(s), want 1", len(stub.added))
	}
	got := stub.added[0]
	if got.Serv.ServIP != "20.20.20.1" || got.Serv.ServPort != 8443 {
		t.Fatalf("replayed rule %s:%d, want 20.20.20.1:8443 -- the fixture keys no longer match the document", got.Serv.ServIP, got.Serv.ServPort)
	}
	enc, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(enc), "SENTINEL") {
		t.Fatalf("replayed rule still carries retired mtls_backend material: %s", enc)
	}
	if got.Serv.MTLSBackend == nil || got.Serv.MTLSBackend.VerifyServerCert {
		t.Fatalf("replayed rule's mtls_backend = %+v, want it present with verify_server_cert reset to false", got.Serv.MTLSBackend)
	}
}
