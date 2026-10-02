/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package handler

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/loxilb-io/loxilb/api/models"
	auditops "github.com/loxilb-io/loxilb/api/restapi/operations/audit"
	"github.com/loxilb-io/loxilb/pkg/audit"
	"github.com/loxilb-io/loxilb/pkg/audit/syslog"
)

// policyRecords returns the mgmt.audit.policy records the run produced.
func recordsOfType(t *testing.T, f *gateFixture, eventType string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, r := range f.records() {
		if r["event_type"] == eventType {
			out = append(out, r)
		}
	}
	return out
}

// An accepted policy change is recorded as its own event type, names the
// fields it changed, and states that the floor did not refuse it.
func TestAuditPolicyChangeIsAuditedWithWhatChanged(t *testing.T) {
	withAuthMode(t, true)
	f := newGateFixture(t)
	f.status = http.StatusNoContent

	body := `{"max_segment_bytes":4096,"retention_max_age_seconds":172800}`
	f.inside = func(r *http.Request) {
		RecordAuditPrincipal(r, "alice|admin")
		var m models.AuditPolicy
		if err := json.Unmarshal([]byte(body), &m); err != nil {
			t.Fatal(err)
		}
		resp := AuditPostPolicy(auditops.PostAuditPolicyParams{HTTPRequest: r, Attr: &m}, "alice|admin")
		if rec := f.serve(resp); rec.Code != http.StatusNoContent {
			t.Fatalf("policy change answered %d: %s", rec.Code, rec.Body.String())
		}
	}
	f.do("POST", "/netlox/v1/audit/policy", body, "Content-Type", "application/json")

	if got := AuditWriter().Policy().MaxSegmentBytes; got != 4096 {
		t.Fatalf("policy not applied: max_segment_bytes = %d", got)
	}

	recs := recordsOfType(t, f, "mgmt.audit.policy")
	if len(recs) == 0 {
		t.Fatal("a policy change produced no mgmt.audit.policy record")
	}
	// The result record is the one carrying what the handler contributed.
	last := detailOf(recs[len(recs)-1])
	if last["floor_rejected"] != false {
		t.Errorf("an accepted change must say the floor did not refuse it: %v", last["floor_rejected"])
	}
	fields, _ := last["changed_fields"].([]any)
	var names []string
	for _, v := range fields {
		names = append(names, v.(string))
	}
	joined := strings.Join(names, ",")
	if !strings.Contains(joined, "max_segment_bytes") {
		t.Errorf("changed_fields did not name the field that changed: %v", names)
	}
}

// A change below the profile floor is refused for the administrator too,
// and the refusal is recorded naming the field — not merely that
// something was refused.
func TestAuditPolicyBelowTheFloorIsRefusedAndRecorded(t *testing.T) {
	withAuthMode(t, true)
	f := newGateFixture(t)
	f.status = http.StatusBadRequest

	SetAuditPolicyFloor(audit.PolicyFloor{MinRetentionAge: 24 * 60 * 60 * 1e9})
	t.Cleanup(func() { SetAuditPolicyFloor(audit.PolicyFloor{}) })

	before := AuditWriter().Policy()
	body := `{"retention_max_age_seconds":60}`
	f.inside = func(r *http.Request) {
		RecordAuditPrincipal(r, "alice|admin")
		var m models.AuditPolicy
		if err := json.Unmarshal([]byte(body), &m); err != nil {
			t.Fatal(err)
		}
		resp := AuditPostPolicy(auditops.PostAuditPolicyParams{HTTPRequest: r, Attr: &m}, "alice|admin")
		// 400, not 403: the caller was authorized and the profile
		// refused the value. A 403 is re-typed by the gate into an
		// authorization denial, which would lose this record entirely.
		if rec := f.serve(resp); rec.Code != http.StatusBadRequest {
			t.Fatalf("a change below the floor answered %d, want 400", rec.Code)
		}
	}
	f.do("POST", "/netlox/v1/audit/policy", body, "Content-Type", "application/json")

	if got := AuditWriter().Policy(); got.Retention.MaxAge != before.Retention.MaxAge {
		t.Fatalf("a refused change was applied anyway: %v", got.Retention.MaxAge)
	}

	recs := recordsOfType(t, f, "mgmt.audit.policy")
	if len(recs) == 0 {
		t.Fatal("a refused policy change produced no record")
	}
	last := detailOf(recs[len(recs)-1])
	if last["floor_rejected"] != true {
		t.Fatalf("the refusal is not marked in the record: %v", last)
	}
	fields, _ := last["changed_fields"].([]any)
	if len(fields) == 0 || fields[0].(string) != "retention.max_age" {
		t.Fatalf("the record does not name the refused field: %v", fields)
	}
}

// The sink refuses a configuration it could not verify a receiver with,
// at configuration time rather than at connect time: a sink that is
// configured but cannot verify reads as working until the day it matters.
func TestAuditSinkWithoutATrustAnchorIsRefused(t *testing.T) {
	withAuthMode(t, true)
	f := newGateFixture(t)
	f.status = http.StatusBadRequest

	f.inside = func(r *http.Request) {
		RecordAuditPrincipal(r, "alice|admin")
		m := models.AuditSink{Enabled: true, Address: "siem.example:6514"}
		resp := AuditPostSink(auditops.PostAuditSinkParams{HTTPRequest: r, Attr: &m}, "alice|admin")
		if rec := f.serve(resp); rec.Code != http.StatusBadRequest {
			t.Fatalf("a sink with no CA bundle answered %d, want 400", rec.Code)
		}
	}
	f.do("POST", "/netlox/v1/audit/sink", `{"enabled":true,"address":"siem.example:6514"}`,
		"Content-Type", "application/json")

	if AuditSink() != nil {
		t.Fatal("a refused sink configuration was installed anyway")
	}
}

// The two numeric knobs arrive as int64 and are used as int. A value that
// does not fit is refused as it arrived: converting first would replace it
// with a different number, and a facility outside RFC 5424 would put the
// PRI outside 0..191, so every frame would be rejected by a strict
// receiver while the sink read as configured.
func TestAuditSinkNumbersOutsideTheirRangeAreRefused(t *testing.T) {
	withAuthMode(t, true)
	ca := writeTestCA(t)

	cases := []struct {
		name string
		attr models.AuditSink
	}{
		{"facility above RFC 5424 table 1", models.AuditSink{
			Enabled: true, Address: "127.0.0.1:6514", CaBundlePath: ca,
			Facility: int64(syslog.MaxFacility) + 1}},
		{"negative facility", models.AuditSink{
			Enabled: true, Address: "127.0.0.1:6514", CaBundlePath: ca, Facility: -1}},
		{"frame cap larger than the framing can carry", models.AuditSink{
			Enabled: true, Address: "127.0.0.1:6514", CaBundlePath: ca,
			MaxFrameBytes: int64(syslog.MaxFrameBytesLimit) + 1}},
		{"frame cap that would not fit an int", models.AuditSink{
			Enabled: true, Address: "127.0.0.1:6514", CaBundlePath: ca,
			MaxFrameBytes: math.MaxInt64}},
		{"negative frame cap", models.AuditSink{
			Enabled: true, Address: "127.0.0.1:6514", CaBundlePath: ca, MaxFrameBytes: -1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newGateFixture(t)
			f.status = http.StatusBadRequest
			attr := tc.attr
			f.inside = func(r *http.Request) {
				RecordAuditPrincipal(r, "alice|admin")
				resp := AuditPostSink(auditops.PostAuditSinkParams{HTTPRequest: r, Attr: &attr}, "alice|admin")
				if rec := f.serve(resp); rec.Code != http.StatusBadRequest {
					t.Fatalf("answered %d, want 400", rec.Code)
				}
			}
			f.do("POST", "/netlox/v1/audit/sink", `{"enabled":true}`,
				"Content-Type", "application/json")
			if AuditSink() != nil {
				t.Fatal("a refused sink configuration was installed anyway")
			}
		})
	}
}

// An accepted sink change records where the trail is being sent and what
// vouches for the receiver, and neither is the material itself.
func TestAuditSinkChangeRecordsTheEndpointAndItsTrustAnchor(t *testing.T) {
	withAuthMode(t, true)
	f := newGateFixture(t)
	f.status = http.StatusNoContent

	ca := writeTestCA(t)
	resetAuditSink(t)

	f.inside = func(r *http.Request) {
		RecordAuditPrincipal(r, "alice|admin")
		m := models.AuditSink{Enabled: true, Address: "127.0.0.1:6514", CaBundlePath: ca}
		resp := AuditPostSink(auditops.PostAuditSinkParams{HTTPRequest: r, Attr: &m}, "alice|admin")
		if rec := f.serve(resp); rec.Code != http.StatusNoContent {
			t.Fatalf("sink change answered %d: %s", rec.Code, rec.Body.String())
		}
	}
	f.do("POST", "/netlox/v1/audit/sink", `{"enabled":true}`, "Content-Type", "application/json")

	if AuditSink() == nil {
		t.Fatal("the sink was not installed")
	}
	recs := recordsOfType(t, f, "mgmt.audit.sink")
	if len(recs) == 0 {
		t.Fatal("a sink change produced no mgmt.audit.sink record")
	}
	last := detailOf(recs[len(recs)-1])
	if last["endpoint"] != "127.0.0.1:6514" {
		t.Errorf("the record does not name the endpoint: %v", last["endpoint"])
	}
	if last["tls_ca_id"] != ca {
		t.Errorf("the record does not name the trust anchor: %v", last["tls_ca_id"])
	}
	// The bundle's contents must not be anywhere in the record.
	blob, _ := json.Marshal(recs[len(recs)-1])
	if strings.Contains(string(blob), "BEGIN CERTIFICATE") {
		t.Error("certificate material reached the trail")
	}
}

// writeTestCA generates a throwaway self-signed anchor. Only the fact
// that it parses as a certificate matters here; the sink's own tests
// cover what verification does with it.
func writeTestCA(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "audit-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
