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
	"errors"
	"os"
	"path/filepath"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
	opt "github.com/loxilb-io/loxilb/options"
)

type refusingLbHook struct {
	cmn.NetHookInterface
	seen []cmn.LbRuleMod
}

func (r *refusingLbHook) NetLbRuleAdd(m *cmn.LbRuleMod) (int, error) {
	r.seen = append(r.seen, *m)
	if m.Serv.ServPort == 8443 {
		return -1, errors.New("refused")
	}
	return 0, nil
}

// TestLbConfigReplayIsMarkedAndGoesOn: every rule of the saved lbconfig.txt
// reaches the rule layer marked as a replay, which is what keeps a rule the
// data plane cannot install yet, and a rule that is refused does not stop
// the rules after it.
func TestLbConfigReplayIsMarkedAndGoesOn(t *testing.T) {
	prevHooks, prevPath := hooks, opt.Opts.ConfigPath
	defer func() { hooks, opt.Opts.ConfigPath = prevHooks, prevPath }()

	dir := t.TempDir()
	cfg := `{"lbAttr":[` +
		`{"serviceArguments":{"externalIP":"20.20.20.1","port":8443,"protocol":"tcp"},` +
		`"endpoints":[{"endpointIP":"10.10.10.2","targetPort":9443,"weight":1}]},` +
		`{"serviceArguments":{"externalIP":"20.20.20.1","port":8444,"protocol":"tcp"},` +
		`"endpoints":[{"endpointIP":"10.10.10.2","targetPort":9444,"weight":1}]}]}`
	if err := os.WriteFile(filepath.Join(dir, "lbconfig.txt"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	stub := &refusingLbHook{}
	hooks, opt.Opts.ConfigPath = stub, dir

	if !applyLoadBalancerConfig() {
		t.Fatal("replay of lbconfig.txt failed")
	}
	if len(stub.seen) != 2 {
		t.Fatalf("%d rule(s) reached the rule layer, want 2: a refused rule stopped the replay", len(stub.seen))
	}
	for _, lb := range stub.seen {
		if !lb.Serv.BootReplay {
			t.Errorf("rule %s:%d reached the rule layer unmarked", lb.Serv.ServIP, lb.Serv.ServPort)
		}
		if lb.Serv.RestoreReplay {
			t.Errorf("rule %s:%d is marked as a snapshot restore", lb.Serv.ServIP, lb.Serv.ServPort)
		}
	}
}
