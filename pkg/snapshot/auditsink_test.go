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

// Unit tests for the auditsink snapshot domain (schema 1.8): list
// get/apply/delete plumbing, what a restore does to the sinks that are
// live, and the boundary that keeps certificate material on the node.

package snapshot

import (
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

func auditSinkFixture() []cmn.AuditSinkConfig {
	return []cmn.AuditSinkConfig{
		{
			Name: cmn.AuditSinkCompliance, Address: "siem.example.net:6514",
			CABundlePath: "/etc/loxilb/audit/ca.pem", ClientCertPath: "/etc/loxilb/audit/client.pem",
			ClientKeyPath: "/etc/loxilb/audit/client.key", Facility: 13,
		},
		{
			Name: "soc", Address: "soc.example.net:6514", CABundlePath: "/etc/loxilb/audit/ca.pem",
			EnterpriseNumber: 32473,
			Filter:           &cmn.AuditSinkFilter{Streams: []string{"mgmt"}, DataSample: 10},
		},
	}
}

// TestAuditSinkDomainRoundTrip: apply two sinks, capture them back
// field-identical, then wipe every one.
func TestAuditSinkDomainRoundTrip(t *testing.T) {
	hooks := newMockHooks()
	doc := NewDocument("v0.9.9", "gw-test", TriggerManual)
	doc.Domains.AuditSink = auditSinkFixture()

	applied, skipped, err := applyAuditSink(hooks, doc, false)
	if err != nil || applied != 2 || skipped != 0 {
		t.Fatalf("apply = (%d,%d,%v), want (2,0,nil)", applied, skipped, err)
	}

	out := NewDocument("v0.9.9", "gw-test", TriggerManual)
	if err := getAuditSink(hooks, out); err != nil {
		t.Fatalf("get: %v", err)
	}
	if !reflect.DeepEqual(out.Domains.AuditSink, doc.Domains.AuditSink) {
		t.Fatalf("the sinks drifted through the round trip: %+v", out.Domains.AuditSink)
	}

	if deleted, err := deleteAuditSink(hooks); err != nil || deleted != 2 {
		t.Fatalf("delete = (%d,%v), want (2,nil)", deleted, err)
	}
	if len(hooks.auditSinks) != 0 {
		t.Fatalf("the wipe left sinks: %+v", hooks.auditSinks)
	}
}

// TestAuditSinkApplyStopsAtTheSinkThatIsRefused: a sink that cannot be
// configured fails the domain and names the sink, and the sinks after it
// are not tried.
func TestAuditSinkApplyStopsAtTheSinkThatIsRefused(t *testing.T) {
	hooks := newMockHooks()
	doc := NewDocument("v0.9.9", "gw-test", TriggerManual)
	doc.Domains.AuditSink = auditSinkFixture()
	hooks.failNext("NetAuditSinkAdd", errors.New("refused: read CA bundle: no such file"))

	applied, _, err := applyAuditSink(hooks, doc, true)
	if err == nil || applied != 0 {
		t.Fatalf("apply = (%d,%v), want the first sink refused", applied, err)
	}
	if !strings.Contains(err.Error(), `"compliance"`) || !strings.Contains(err.Error(), "CA bundle") {
		t.Fatalf("the error does not name the sink and the reason: %v", err)
	}
	if len(hooks.auditSinks) != 0 {
		t.Fatalf("a sink was configured after the refused one: %+v", hooks.auditSinks)
	}
}

// TestRestoreReplacesTheLiveAuditSinks: a restore leaves exactly the
// document's sinks. One that is live under a name the document has is
// replaced by the document's, one the document does not have is stopped.
func TestRestoreReplacesTheLiveAuditSinks(t *testing.T) {
	src := newMockHooks()
	src.auditSinks = auditSinkFixture()
	doc, err := Capture(src, "0.9.8.6-beta", "src-host", TriggerManual, []string{DomainAuditSink})
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	raw := encodeDoc(t, doc)

	hooks := newMockHooks()
	hooks.auditSinks = []cmn.AuditSinkConfig{
		{Name: "soc", Address: "old-soc.example.net:6514", CABundlePath: "/etc/old-ca.pem", EnterpriseNumber: 1},
		{Name: "lab", Address: "lab.example.net:6514", CABundlePath: "/etc/old-ca.pem", EnterpriseNumber: 1},
	}
	e := newTestEngine(hooks, t.TempDir())
	res, err := e.Restore(raw, RestoreOptions{Mode: ModeCommit})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if res.Result != ResultOK {
		t.Fatalf("expected ok, got %+v", res)
	}
	if !reflect.DeepEqual(hooks.auditSinks, auditSinkFixture()) {
		t.Fatalf("live sinks after the restore: %+v", hooks.auditSinks)
	}
}

// TestRestoreRollsBackWhenAnAuditSinkIsRefused: a sink the node cannot
// configure fails the restore, and the sinks that were live come back.
func TestRestoreRollsBackWhenAnAuditSinkIsRefused(t *testing.T) {
	src := newMockHooks()
	src.auditSinks = auditSinkFixture()
	doc, err := Capture(src, "0.9.8.6-beta", "src-host", TriggerManual, []string{DomainAuditSink})
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	raw := encodeDoc(t, doc)

	before := []cmn.AuditSinkConfig{
		{Name: "lab", Address: "lab.example.net:6514", CABundlePath: "/etc/old-ca.pem", EnterpriseNumber: 1},
	}
	hooks := newMockHooks()
	hooks.auditSinks = append([]cmn.AuditSinkConfig(nil), before...)
	hooks.failNext("NetAuditSinkAdd", errors.New("refused: read CA bundle: no such file"))

	e := newTestEngine(hooks, t.TempDir())
	res, err := e.Restore(raw, RestoreOptions{Mode: ModeCommit})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if res.Result != ResultRolledBack {
		t.Fatalf("expected rolled-back, got %+v", res)
	}
	if !reflect.DeepEqual(hooks.auditSinks, before) {
		t.Fatalf("live sinks after the rollback: %+v", hooks.auditSinks)
	}
}

// TestRestoreVerifiesTheAuditSinksItApplied: the sinks read back after the
// apply are compared with the document's, field for field. A sink that
// came up pointing somewhere else fails the restore, and the sinks that
// were live come back.
func TestRestoreVerifiesTheAuditSinksItApplied(t *testing.T) {
	src := newMockHooks()
	src.auditSinks = auditSinkFixture()
	doc, err := Capture(src, "0.9.8.6-beta", "src-host", TriggerManual, []string{DomainAuditSink})
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	raw := encodeDoc(t, doc)

	before := []cmn.AuditSinkConfig{
		{Name: "lab", Address: "lab.example.net:6514", CABundlePath: "/etc/old-ca.pem", EnterpriseNumber: 1},
	}
	hooks := newMockHooks()
	hooks.auditSinks = append([]cmn.AuditSinkConfig(nil), before...)
	// The reads of a commit: the plan, the pre-restore capture, the wipe,
	// then the verification.
	hooks.mutateAtCall("NetAuditSinkGet", 4, func() {
		hooks.auditSinks[1].Address = "elsewhere.example.net:6514"
	})

	e := newTestEngine(hooks, t.TempDir())
	res, err := e.Restore(raw, RestoreOptions{Mode: ModeCommit})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if res.Result != ResultRolledBack {
		t.Fatalf("expected rolled-back, got %+v", res)
	}
	if !strings.Contains(strings.Join(res.Errors, " "), DomainAuditSink) {
		t.Fatalf("the error does not name the domain: %v", res.Errors)
	}
	if !reflect.DeepEqual(hooks.auditSinks, before) {
		t.Fatalf("live sinks after the rollback: %+v", hooks.auditSinks)
	}
}

// TestRestoreOfAnOlderDocumentLeavesTheAuditSinks: a document written
// before the domain existed never captured the sinks, so restoring it
// stops none of the live ones.
func TestRestoreOfAnOlderDocumentLeavesTheAuditSinks(t *testing.T) {
	raw, err := os.ReadFile(goldenPath("1.7"))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	defer SetNodeSecretForTest(goldenNodeSecret)()

	hooks := newMockHooks()
	hooks.auditSinks = auditSinkFixture()
	e := newTestEngine(hooks, t.TempDir())
	res, err := e.Restore(raw, RestoreOptions{Mode: ModeCommit})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if res.Result != ResultOK {
		t.Fatalf("expected ok, got %+v", res)
	}
	if call := containsCallSubstring(hooks.Calls, "NetAuditSinkDel", "NetAuditSinkAdd"); call != "" {
		t.Fatalf("a document that predates the domain touched the sinks: %s", call)
	}
	if !reflect.DeepEqual(hooks.auditSinks, auditSinkFixture()) {
		t.Fatalf("live sinks after the restore: %+v", hooks.auditSinks)
	}
}

// TestCaptureDeclaresTheFilesTheAuditSinksName: every file a captured
// sink names by path is a required entry of the manifest, each once, and a
// capture with no sink declares none.
func TestCaptureDeclaresTheFilesTheAuditSinksName(t *testing.T) {
	hooks := newMockHooks()
	doc, err := Capture(hooks, "v-test", "host", TriggerManual, nil)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	for _, d := range doc.RecoveryDependencies {
		if d.Type == cmn.RecoveryDepAuditSinkFile {
			t.Fatalf("a capture with no sink declares %+v", d)
		}
	}

	hooks.auditSinks = auditSinkFixture()
	doc, err = Capture(hooks, "v-test", "host", TriggerManual, nil)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	var got []string
	for _, d := range doc.RecoveryDependencies {
		if d.Type != cmn.RecoveryDepAuditSinkFile {
			continue
		}
		if !d.Required {
			t.Fatalf("%+v is not required", d)
		}
		got = append(got, d.ID)
	}
	want := []string{"/etc/loxilb/audit/ca.pem", "/etc/loxilb/audit/client.key", "/etc/loxilb/audit/client.pem"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("declared files %v, want %v", got, want)
	}
}

// TestRestoreStopsBeforeTheWipeWhenASinkFileIsMissing: a file a sink of
// the document names cannot be read on this node. The restore ends before
// anything is planned or stopped, so the sinks that are live keep running;
// found at apply instead, they would have been stopped first, and a
// rollback could need the same file.
func TestRestoreStopsBeforeTheWipeWhenASinkFileIsMissing(t *testing.T) {
	src := newMockHooks()
	src.auditSinks = auditSinkFixture()
	doc, err := Capture(src, "0.9.8.6-beta", "src-host", TriggerManual, []string{DomainAuditSink})
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	raw := encodeDoc(t, doc)

	hooks := newMockHooks()
	hooks.auditSinks = auditSinkFixture()
	hooks.depVerifyFail = map[string]error{
		cmn.RecoveryDepAuditSinkFile: errors.New("an audit sink names a file this node cannot read"),
	}
	e := newTestEngine(hooks, t.TempDir())
	for _, mode := range []RestoreMode{ModeDryRun, ModeCommit} {
		res, err := e.Restore(raw, RestoreOptions{Mode: mode})
		if err != nil {
			t.Fatalf("%s: Restore: %v", mode, err)
		}
		if res.Result == ResultOK || len(res.Errors) == 0 || !strings.Contains(strings.Join(res.Errors, " "), "cannot read") {
			t.Fatalf("%s: expected the restore refused for the file, got %+v", mode, res)
		}
	}
	if call := containsCallSubstring(hooks.Calls, "NetAuditSinkDel", "NetAuditSinkAdd"); call != "" {
		t.Fatalf("the restore touched the sinks before it knew the file was missing: %s", call)
	}
}

// TestAuditSinkDocumentCarriesPathsOnly pins the boundary at the schema
// level: every field of a sink that concerns certificate material is a
// path. A field that could carry the material itself forces the
// conversation here.
func TestAuditSinkDocumentCarriesPathsOnly(t *testing.T) {
	typ := reflect.TypeOf(cmn.AuditSinkConfig{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		name := strings.ToLower(f.Name)
		for _, word := range []string{"cert", "key", "bundle", "pem", "secret", "pass"} {
			if strings.Contains(name, word) && !strings.HasSuffix(name, "path") {
				t.Fatalf("AuditSinkConfig gained the field %q -- certificate material must never enter the snapshot document", f.Name)
			}
		}
	}
}
