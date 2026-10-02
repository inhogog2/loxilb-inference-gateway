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

package handler

import (
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/loxilb-io/loxilb/api/models"
	cmn "github.com/loxilb-io/loxilb/common"
	"github.com/loxilb-io/loxilb/pkg/audit"
)

// The snapshot sees every sink as it was configured: the compliance sink
// first under its reserved name, then the secondary ones by name, each
// with its receiver, the paths of its certificate material and its
// selection, and nothing of what the sink has done since.
func TestAuditSinkExportNamesEverySinkAsConfigured(t *testing.T) {
	withAuthMode(t, true)
	f := newGateFixture(t)
	resetAuditSink(t)
	pki := newSinkPKI(t)
	all, some := newSinkReceiver(t, pki), newSinkReceiver(t, pki)

	if got := AuditSinkExport(); len(got) != 0 {
		t.Fatalf("with no sink configured the export is %+v", got)
	}
	if code := putNamedSink(f, "zz", mgmtOnly(some, pki)); code != http.StatusNoContent {
		t.Fatalf("configuring zz answered %d", code)
	}
	if code := putNamedSink(f, "aa", models.AuditNamedSink{
		Address: some.addr, CaBundlePath: pki.caPath, ServerName: "localhost", EnterpriseNumber: testPEN,
		Facility: 10, MaxFrameBytes: 4096,
		Filter: &models.AuditSinkFilter{Streams: []string{"data"}, Services: []string{"svc-a"}, Outcome: "failed", DataSample: 4},
	}); code != http.StatusNoContent {
		t.Fatalf("configuring aa answered %d", code)
	}
	if code := postSink(f, models.AuditSink{Enabled: true, Address: all.addr, CaBundlePath: pki.caPath, Facility: 13}); code != http.StatusNoContent {
		t.Fatalf("enabling the compliance sink answered %d", code)
	}

	want := []cmn.AuditSinkConfig{
		{Name: cmn.AuditSinkCompliance, Address: all.addr, CABundlePath: pki.caPath, Facility: 13},
		{
			Name: "aa", Address: some.addr, CABundlePath: pki.caPath, ServerName: "localhost",
			EnterpriseNumber: testPEN, Facility: 10, MaxFrameBytes: 4096,
			Filter: &cmn.AuditSinkFilter{Streams: []string{"data"}, Services: []string{"svc-a"}, Outcome: "failed", DataSample: 4},
		},
		{
			Name: "zz", Address: some.addr, CABundlePath: pki.caPath, EnterpriseNumber: testPEN,
			Filter: &cmn.AuditSinkFilter{Streams: []string{"mgmt"}},
		},
	}
	if got := AuditSinkExport(); !reflect.DeepEqual(got, want) {
		t.Fatalf("export\n got %+v\nwant %+v", got, want)
	}
}

// A restore stops every sink and configures the document's. A sink that
// comes back under its name continues: the compliance sink sends nothing
// twice and misses nothing, and a secondary sink goes on with the next
// number of its export sequence under the same epoch.
func TestAuditSinkApplyContinuesWhereTheSinkWas(t *testing.T) {
	withAuthMode(t, true)
	f := newGateFixture(t)
	resetAuditSink(t)
	pki := newSinkPKI(t)
	all, some := newSinkReceiver(t, pki), newSinkReceiver(t, pki)

	if code := postSink(f, models.AuditSink{Enabled: true, Address: all.addr, CaBundlePath: pki.caPath}); code != http.StatusNoContent {
		t.Fatalf("enabling the compliance sink answered %d", code)
	}
	all.waitFor("the record of its own session", isEvent("sys.sink.connect"))
	if code := putNamedSink(f, "s", mgmtOnly(some, pki)); code != http.StatusNoContent {
		t.Fatalf("configuring the sink answered %d", code)
	}
	mutate(f, 2)
	some.waitCount(4)

	captured := AuditSinkExport()
	if len(captured) != 2 {
		t.Fatalf("captured %d sinks, want 2", len(captured))
	}
	oldAll, oldSome := currentTailer(), namedTailer("s")
	for _, c := range captured {
		if err := AuditSinkRemove(c.Name); err != nil {
			t.Fatalf("removing %s: %v", c.Name, err)
		}
	}
	if oldAll.Stats().State != audit.SinkStopped || oldSome.Stats().State != audit.SinkStopped {
		t.Fatalf("after the wipe the tailers are %q and %q, want stopped", oldAll.Stats().State, oldSome.Stats().State)
	}
	if got := AuditSinkExport(); len(got) != 0 {
		t.Fatalf("after the wipe the export is %+v", got)
	}
	sentSome := some.drained()
	last := sentSome[len(sentSome)-1]
	_, lastX, epoch := last.export(t)

	// What is written while no sink is configured is sent once they are back.
	mutate(f, 2)
	for i := range captured {
		if err := AuditSinkApply(&captured[i]); err != nil {
			t.Fatalf("applying %s: %v", captured[i].Name, err)
		}
	}
	if got := AuditSinkExport(); !reflect.DeepEqual(got, captured) {
		t.Fatalf("after the apply the export is %+v, captured was %+v", got, captured)
	}
	mutate(f, 1)

	got := some.waitCount(len(sentSome) + 1)[len(sentSome)]
	if _, x, e := got.export(t); x != lastX+1 || e != epoch || got.seq() <= last.seq() {
		t.Fatalf("configured again the sink sends %q at seq %d; it had reached xseq %d under epoch %d at seq %d",
			got.sd, got.seq(), lastX, epoch, last.seq())
	}
	// The compliance receiver holds one unbroken run of the trail.
	f.do("POST", "/netlox/v1/config/loadbalancer", `{"n":"end"}`, "Content-Type", "application/json")
	high := f.w.Stats().SeqHigh
	frames := all.waitFor("the newest record", func(fr sinkFrame) bool { return fr.seq() >= high })
	var prev uint64
	for i, fr := range frames {
		if i > 0 && fr.seq() != prev+1 {
			t.Fatalf("the compliance receiver got seq %d after %d", fr.seq(), prev)
		}
		prev = fr.seq()
	}
}

// Applying a sink goes through the checks a request goes through, and a
// sink that is refused leaves the one running under its name as it was.
func TestAuditSinkApplyRefusesWhatARequestRefuses(t *testing.T) {
	withAuthMode(t, true)
	f := newGateFixture(t)
	resetAuditSink(t)
	pki := newSinkPKI(t)
	rcv := newSinkReceiver(t, pki)

	if code := putNamedSink(f, "s", mgmtOnly(rcv, pki)); code != http.StatusNoContent {
		t.Fatalf("configuring the sink answered %d", code)
	}
	running := namedTailer("s")
	missing := filepath.Join(t.TempDir(), "no-such-ca.pem")

	for _, tc := range []struct {
		what string
		cfg  cmn.AuditSinkConfig
	}{
		{"a CA bundle that cannot be read", cmn.AuditSinkConfig{Name: "s", Address: rcv.addr, CABundlePath: missing, EnterpriseNumber: testPEN}},
		{"no enterprise number", cmn.AuditSinkConfig{Name: "s", Address: rcv.addr, CABundlePath: pki.caPath}},
		{"a facility out of range", cmn.AuditSinkConfig{Name: "s", Address: rcv.addr, CABundlePath: pki.caPath, EnterpriseNumber: testPEN, Facility: 99}},
		{"a name that is not a sink name", cmn.AuditSinkConfig{Name: "No Such", Address: rcv.addr, CABundlePath: pki.caPath, EnterpriseNumber: testPEN}},
		{"a compliance sink with a filter", cmn.AuditSinkConfig{Name: cmn.AuditSinkCompliance, Address: rcv.addr, CABundlePath: pki.caPath,
			Filter: &cmn.AuditSinkFilter{Streams: []string{"mgmt"}}}},
		{"a compliance sink with an enterprise number", cmn.AuditSinkConfig{Name: cmn.AuditSinkCompliance, Address: rcv.addr, CABundlePath: pki.caPath,
			EnterpriseNumber: testPEN}},
		{"a compliance sink whose CA bundle cannot be read", cmn.AuditSinkConfig{Name: cmn.AuditSinkCompliance, Address: rcv.addr, CABundlePath: missing}},
	} {
		cfg := tc.cfg
		err := AuditSinkApply(&cfg)
		if err == nil || !strings.Contains(err.Error(), "refused") {
			t.Errorf("%s: got %v, want it refused", tc.what, err)
		}
	}
	if namedTailer("s") != running || running.Stats().State == audit.SinkStopped {
		t.Fatal("a refused sink disturbed the one running under its name")
	}
	if AuditSink() != nil {
		t.Fatal("a refused compliance sink was installed")
	}
}

// A sink is not held without a trail to feed it. The answer says the trail
// is not running: a restore at start, which can come before the trail is
// up, reads those words as not yet and tries again.
func TestAuditSinkApplyWithoutATrailSaysItIsNotRunning(t *testing.T) {
	withAuthMode(t, true)
	f := newGateFixture(t)
	resetAuditSink(t)
	pki := newSinkPKI(t)

	SetAuditWriter(nil)
	defer SetAuditWriter(f.w)
	for _, cfg := range []cmn.AuditSinkConfig{
		{Name: cmn.AuditSinkCompliance, Address: "127.0.0.1:6514", CABundlePath: pki.caPath},
		{Name: "s", Address: "127.0.0.1:6514", CABundlePath: pki.caPath, EnterpriseNumber: testPEN},
	} {
		cfg := cfg
		err := AuditSinkApply(&cfg)
		if err == nil || !strings.Contains(err.Error(), "not running") {
			t.Errorf("%s: got %v, want the trail named as not running", cfg.Name, err)
		}
	}
	if got := AuditSinkExport(); len(got) != 0 {
		t.Fatalf("a sink was installed with no trail: %+v", got)
	}
}

// Removing a sink that is not configured is not an error: a wipe asks for
// what it found, and a sink gone in between has nothing left to end.
func TestAuditSinkRemoveOfASinkThatIsNotThere(t *testing.T) {
	withAuthMode(t, true)
	newGateFixture(t)
	resetAuditSink(t)
	for _, name := range []string{cmn.AuditSinkCompliance, "s"} {
		if err := AuditSinkRemove(name); err != nil {
			t.Errorf("removing %s: %v", name, err)
		}
	}
}

// A sink change is configuration the persisted document carries, so it
// kicks the write-through like a change under /config/. The policy and the
// rotation are not in the document and do not.
func TestAutoPersistFollowsAuditSinkChanges(t *testing.T) {
	for _, tc := range []struct {
		method, path string
		want         bool
	}{
		{"POST", "/netlox/v1/audit/sink", true},
		{"PUT", "/netlox/v1/audit/sinks/soc", true},
		{"DELETE", "/netlox/v1/audit/sinks/soc", true},
		{"GET", "/netlox/v1/audit/sink", false},
		{"GET", "/netlox/v1/audit/sinks/soc", false},
		{"POST", "/netlox/v1/audit/policy", false},
		{"POST", "/netlox/v1/audit/rotate", false},
		{"POST", "/netlox/v1/config/loadbalancer", true},
		{"POST", "/netlox/v1/config/persist", false},
	} {
		r, _ := http.NewRequest(tc.method, tc.path, nil)
		if got := autoPersistEligible(r); got != tc.want {
			t.Errorf("%s %s: eligible %v, want %v", tc.method, tc.path, got, tc.want)
		}
	}
}
