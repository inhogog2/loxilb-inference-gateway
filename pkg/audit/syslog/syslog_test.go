/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

package syslog

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const sampleRecord = `{"schema_version":1,"event_id":"01a0-e1","ts":"2026-09-27T01:02:03.004Z",` +
	`"instance_id":"gw-1","boot_id":"b-1","seq":42,"stream":"mgmt",` +
	`"event_type":"mgmt.config.mutate","detail":{"path":"/config/loadbalancer"}}`

func fixedNow() time.Time { return time.Date(2026, 9, 27, 1, 2, 3, 0, time.UTC) }

// newSink builds a sink without touching the network. The CA bundle has to
// be real because New verifies it parses.
func newSink(t *testing.T, mutate func(*Config)) *Sink {
	t.Helper()
	dir := t.TempDir()
	_, caPEM := genCA(t)
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Address: "127.0.0.1:6514", CABundlePath: caPath, Now: fixedNow}
	if mutate != nil {
		mutate(&cfg)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

// splitFrame undoes the RFC 5425 octet counting and checks the count is
// the real length of what follows, which is the whole point of the framing.
func splitFrame(t *testing.T, frame []byte) string {
	t.Helper()
	sp := strings.IndexByte(string(frame), ' ')
	if sp <= 0 {
		t.Fatalf("no length prefix in %q", frame)
	}
	n, err := strconv.Atoi(string(frame[:sp]))
	if err != nil {
		t.Fatalf("length prefix %q: %v", frame[:sp], err)
	}
	msg := frame[sp+1:]
	if len(msg) != n {
		t.Fatalf("MSG-LEN says %d, SYSLOG-MSG is %d octets", n, len(msg))
	}
	return string(msg)
}

func TestFrameIsOctetCountedNotNewlineDelimited(t *testing.T) {
	s := newSink(t, nil)
	frame, truncated, err := s.frame([]byte(sampleRecord))
	if err != nil {
		t.Fatal(err)
	}
	if truncated {
		t.Fatal("a record under the cap must not be marked truncated")
	}
	msg := splitFrame(t, frame)
	if strings.Contains(msg, "\n") {
		t.Fatal("the frame must not rely on a newline delimiter")
	}
	// A receiver reading by octet count must land exactly on the end.
	if !strings.HasSuffix(msg, sampleRecord) {
		t.Fatalf("MSG is not the record verbatim: %q", msg)
	}
}

func TestHeaderFieldsAreRFC5424(t *testing.T) {
	s := newSink(t, nil)
	frame, _, err := s.frame([]byte(sampleRecord))
	if err != nil {
		t.Fatal(err)
	}
	msg := splitFrame(t, frame)
	// <PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP
	// MSGID SP STRUCTURED-DATA SP MSG
	head, body, ok := strings.Cut(msg, " "+sampleRecord[:1])
	if !ok {
		t.Fatalf("cannot split header from MSG: %q", msg)
	}
	_ = body
	fields := strings.Split(head, " ")
	if len(fields) != 7 {
		t.Fatalf("expected 7 header fields, got %d: %q", len(fields), fields)
	}
	// facility 13 (log audit) * 8 + notice(5) = 109
	if fields[0] != "<109>1" {
		t.Errorf("PRI/VERSION = %q, want <109>1", fields[0])
	}
	if fields[1] != "2026-09-27T01:02:03.004Z" {
		t.Errorf("TIMESTAMP = %q, want the record's own ts", fields[1])
	}
	if fields[2] != "gw-1" {
		t.Errorf("HOSTNAME = %q, want the instance id", fields[2])
	}
	if fields[3] != DefaultAppName {
		t.Errorf("APP-NAME = %q, want %q", fields[3], DefaultAppName)
	}
	if fields[4] != "-" {
		t.Errorf("PROCID = %q, want NILVALUE", fields[4])
	}
	if fields[5] != "mgmt" {
		t.Errorf("MSGID = %q, want the stream so a receiver can route before parsing", fields[5])
	}
	if fields[6] != "-" {
		t.Errorf("STRUCTURED-DATA = %q, want NILVALUE", fields[6])
	}
}

func TestSecurityEventRaisesSeverity(t *testing.T) {
	s := newSink(t, nil)
	rec := strings.Replace(sampleRecord, `"mgmt.config.mutate"`, `"sec.ai.deny"`, 1)
	frame, _, err := s.frame([]byte(rec))
	if err != nil {
		t.Fatal(err)
	}
	// 13*8 + warning(4) = 108
	if msg := splitFrame(t, frame); !strings.HasPrefix(msg, "<108>1 ") {
		t.Fatalf("a security refusal must not share the ordinary severity: %q", msg[:16])
	}
}

func TestHeaderFieldWithASpaceBecomesNilValue(t *testing.T) {
	s := newSink(t, nil)
	rec := strings.Replace(sampleRecord, `"gw-1"`, `"gw 1"`, 1)
	frame, _, err := s.frame([]byte(rec))
	if err != nil {
		t.Fatal(err)
	}
	// A space inside HOSTNAME would shift every field after it, so the
	// field is dropped rather than allowed to corrupt the header.
	msg := splitFrame(t, frame)
	fields := strings.Split(msg, " ")
	if fields[2] != "-" {
		t.Fatalf("HOSTNAME with a space must become NILVALUE, got %q", fields[2])
	}
	if fields[5] != "mgmt" {
		t.Fatalf("the fields after it must not shift: MSGID = %q", fields[5])
	}
}

func TestOversizeRecordIsTruncatedAtAFieldBoundary(t *testing.T) {
	big := `{"schema_version":1,"event_id":"e","ts":"2026-09-27T01:02:03.004Z",` +
		`"instance_id":"gw-1","boot_id":"b","seq":7,"stream":"data",` +
		`"event_type":"data.ai.complete","detail":{"blob":"` + strings.Repeat("x", 4000) + `"}}`
	s := newSink(t, func(c *Config) { c.MaxFrameBytes = 512 })
	frame, truncated, err := s.frame([]byte(big))
	if err != nil {
		t.Fatal(err)
	}
	if !truncated {
		t.Fatal("an oversized record must be marked truncated")
	}
	msg := splitFrame(t, frame)
	if len(msg) > 512 {
		t.Fatalf("truncated message is still %d octets, cap is 512", len(msg))
	}
	body := msg[strings.Index(msg, "{"):]
	// The decisive property: what is sent is still a complete object, not
	// a JSON document cut in half.
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("truncated record is not valid JSON, so it was cut mid-record: %v", err)
	}
	if m["truncated"] != true {
		t.Errorf("truncated record does not say so: %v", m)
	}
	if _, ok := m["detail"]; ok {
		t.Errorf("the unbounded field should have been the one dropped")
	}
	for _, f := range []string{"event_id", "seq", "stream", "event_type", "instance_id"} {
		if _, ok := m[f]; !ok {
			t.Errorf("identity field %q was dropped; the record can no longer be asked for by replay", f)
		}
	}
}

func TestTruncationFallsBackToIdentityFields(t *testing.T) {
	// Every field is oversized, so dropping detail alone cannot be enough.
	rec := `{"schema_version":1,"event_id":"` + strings.Repeat("e", 300) + `",` +
		`"ts":"2026-09-27T01:02:03.004Z","instance_id":"gw-1","boot_id":"b","seq":7,` +
		`"stream":"data","event_type":"data.ai.complete",` +
		`"extra":"` + strings.Repeat("y", 900) + `","detail":{"a":"` + strings.Repeat("z", 900) + `"}}`
	s := newSink(t, func(c *Config) { c.MaxFrameBytes = 600 })
	frame, truncated, err := s.frame([]byte(rec))
	if err != nil {
		t.Fatal(err)
	}
	if !truncated {
		t.Fatal("must be marked truncated")
	}
	msg := splitFrame(t, frame)
	if len(msg) > 600 {
		t.Fatalf("message is %d octets, cap is 600", len(msg))
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(msg[strings.Index(msg, "{"):]), &m); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
	if _, ok := m["extra"]; ok {
		t.Error("the identity-only fallback should have dropped non-identity fields")
	}
	if m["seq"] == nil || m["event_id"] == nil {
		t.Errorf("identity fields missing: %v", m)
	}
}

func TestMaxFrameBytesTooSmallIsAnErrorNotASilentCut(t *testing.T) {
	s := newSink(t, func(c *Config) { c.MaxFrameBytes = 40 })
	if _, _, err := s.frame([]byte(sampleRecord)); err == nil {
		t.Fatal("a cap below the identity-only record must be refused, never silently cut")
	}
}

// sdField returns the STRUCTURED-DATA field of a SYSLOG-MSG whose MSG is the
// sample record: the seventh space-separated field of the header.
func sdField(t *testing.T, msg string) string {
	t.Helper()
	head, _, ok := strings.Cut(msg, " {")
	if !ok {
		t.Fatalf("no MSG in %q", msg)
	}
	f := strings.SplitN(head, " ", 7)
	if len(f) != 7 {
		t.Fatalf("header has %d fields, want 7: %q", len(f), head)
	}
	return f[6]
}

func TestExportSequenceTravelsInStructuredData(t *testing.T) {
	s := newSink(t, func(c *Config) { c.EnterpriseNumber = 32473 })
	// A receiver that is not there refuses the dial after the frame was
	// built, which is all this needs.
	var built []byte
	orig := frameBuilt
	frameBuilt = func(f []byte) { built = append([]byte(nil), f...) }
	defer func() { frameBuilt = orig }()

	_ = s.Submit([]byte(sampleRecord))
	if built == nil {
		t.Fatal("no frame was built")
	}
	plain := built
	if got := sdField(t, splitFrame(t, plain)); got != "-" {
		t.Fatalf("a plain submission carries STRUCTURED-DATA %q, want NILVALUE", got)
	}

	built = nil
	_ = s.SubmitExport([]byte(sampleRecord), 41, 1700000000)
	if built == nil {
		t.Fatal("no frame was built")
	}
	msg := splitFrame(t, built)
	if got, want := sdField(t, msg), `[audit-export@32473 xseq="41" xseq_epoch="1700000000"]`; got != want {
		t.Fatalf("STRUCTURED-DATA %q, want %q", got, want)
	}
	// The record is the same bytes with or without the element.
	if !strings.HasSuffix(msg, " "+sampleRecord) {
		t.Fatalf("MSG is not the record verbatim: %q", msg)
	}
	if want := strings.Replace(splitFrame(t, plain), " - {", ` [audit-export@32473 xseq="41" xseq_epoch="1700000000"] {`, 1); msg != want {
		t.Fatalf("the element changed more than the STRUCTURED-DATA field:\n got %q\nwant %q", msg, want)
	}
}

func TestExportSequenceNeedsAnEnterpriseNumber(t *testing.T) {
	s := newSink(t, nil)
	err := s.SubmitExport([]byte(sampleRecord), 1, 1)
	if !errors.Is(err, ErrNoEnterpriseNumber) {
		t.Fatalf("got %v, want ErrNoEnterpriseNumber", err)
	}
	// Refused before anything was attempted: no dial, nothing counted.
	if st := s.Stats(); st.Dials != 0 || st.Submitted != 0 {
		t.Fatalf("a refused submission touched the network: %+v", st)
	}
}

func TestSubmitSaysWhetherAnythingWasWritten(t *testing.T) {
	// Nobody listens on the address: the dial fails, so nothing was written.
	s := newSink(t, func(c *Config) { c.Address = "127.0.0.1:1"; c.DialTimeout = time.Second })
	err := s.Submit([]byte(sampleRecord))
	if !errors.Is(err, ErrNotAttempted) || errors.Is(err, ErrRejected) {
		t.Fatalf("an unreachable receiver: %v, want ErrNotAttempted only", err)
	}
	// A record that is not an object can never be framed.
	err = s.Submit([]byte("not json"))
	if !errors.Is(err, ErrRejected) || errors.Is(err, ErrNotAttempted) {
		t.Fatalf("an unframeable record: %v, want ErrRejected only", err)
	}
	if st := s.Stats(); st.Dials != 1 {
		t.Fatalf("the rejected record was dialed for: %+v", st)
	}
}

func TestExportSequenceCountsTowardTheFrameCap(t *testing.T) {
	rec := `{"schema_version":1,"event_id":"e","ts":"2026-09-27T01:02:03.004Z",` +
		`"instance_id":"gw-1","boot_id":"b","seq":7,"stream":"data",` +
		`"event_type":"data.ai.complete","actor":{"user":"u"},"detail":{"blob":"` + strings.Repeat("x", 300) + `"}}`
	s := newSink(t, nil)
	plain, _, err := s.frame([]byte(rec))
	if err != nil {
		t.Fatal(err)
	}
	// A cap the plain message exactly fits: the element is what pushes
	// the message over, so the record must give way, not the cap.
	limit := len(splitFrame(t, plain))
	capped := newSink(t, func(c *Config) { c.MaxFrameBytes = limit })
	if _, truncated, err := capped.frame([]byte(rec)); err != nil || truncated {
		t.Fatalf("the plain message at the cap: truncated %v, err %v", truncated, err)
	}
	sd := []byte(`[audit-export@32473 xseq="7" xseq_epoch="9"]`)
	frame, truncated, err := capped.frameSD([]byte(rec), sd)
	if err != nil {
		t.Fatal(err)
	}
	msg := splitFrame(t, frame)
	if len(msg) > limit {
		t.Fatalf("message with the element is %d octets, cap is %d", len(msg), limit)
	}
	if !truncated {
		t.Fatal("the record was not marked truncated although the element pushed it over the cap")
	}
	if !strings.Contains(msg, " "+string(sd)+" {") {
		t.Fatalf("the element was dropped to make room: %q", msg)
	}
	// Dropping the detail was enough, so that is all that was dropped:
	// the element is weighed at the first step, not discovered at the
	// last one.
	if strings.Contains(msg, `"detail"`) || !strings.Contains(msg, `"actor":{"user":"u"}`) {
		t.Fatalf("want the detail dropped and the rest kept: %q", msg)
	}

	// A cap that only the identity fields fit under: the element is
	// still there, and still counted.
	wide := `{"schema_version":1,"event_id":"e","ts":"2026-09-27T01:02:03.004Z",` +
		`"instance_id":"gw-1","boot_id":"b","seq":7,"stream":"data",` +
		`"event_type":"data.ai.complete","extra":"` + strings.Repeat("y", 600) + `","detail":{}}`
	tight := newSink(t, func(c *Config) { c.MaxFrameBytes = 330 })
	frame, truncated, err = tight.frameSD([]byte(wide), sd)
	if err != nil {
		t.Fatal(err)
	}
	msg = splitFrame(t, frame)
	if len(msg) > 330 || !truncated {
		t.Fatalf("identity-only message is %d octets (cap 330), truncated %v", len(msg), truncated)
	}
	if !strings.Contains(msg, " "+string(sd)+" {") {
		t.Fatalf("the element was dropped from the identity-only message: %q", msg)
	}
	if strings.Contains(msg, `"extra"`) {
		t.Fatalf("the test did not reach the identity-only step: %q", msg)
	}
}

func TestExportSequenceReachesTheReceiver(t *testing.T) {
	caCert, caKey, caPEM := genCAFull(t)
	trusted := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(trusted, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	srv, addr, lines := tlsReceiver(t, serverCert(t, caCert, caKey))
	defer srv.Close()
	s, err := New(Config{Address: addr, CABundlePath: trusted, ServerName: "localhost", Now: fixedNow, EnterpriseNumber: 32473})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for x := uint64(1); x <= 3; x++ {
		if err := s.SubmitExport([]byte(sampleRecord), x, 5); err != nil {
			t.Fatalf("SubmitExport: %v", err)
		}
	}
	for x := 1; x <= 3; x++ {
		select {
		case got := <-lines:
			if want := fmt.Sprintf(`[audit-export@32473 xseq="%d" xseq_epoch="5"]`, x); sdField(t, got) != want {
				t.Fatalf("frame %d carries %q, want %q", x, sdField(t, got), want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("receiver saw %d frames, want 3", x-1)
		}
	}
	if st := s.Stats(); st.Submitted != 3 {
		t.Fatalf("stats %+v, want 3 submitted", st)
	}
}

// ── configuration refusals ────────────────────────────────────────────────

func TestNewRefusesAnUnverifiableReceiver(t *testing.T) {
	if _, err := New(Config{Address: "127.0.0.1:6514"}); err == nil {
		t.Fatal("a sink with no CA bundle must be refused: there is no unverified mode")
	}
}

func TestNewRefusesHalfAClientKeypair(t *testing.T) {
	dir := t.TempDir()
	_, caPEM := genCA(t)
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := New(Config{Address: "127.0.0.1:6514", CABundlePath: caPath, ClientCertPath: "/x"})
	if err == nil {
		t.Fatal("a client certificate without its key must be refused")
	}
}

func TestNewRefusesAMissingAddress(t *testing.T) {
	if _, err := New(Config{}); err != ErrNotConfigured {
		t.Fatalf("want ErrNotConfigured, got %v", err)
	}
}

// A facility outside RFC 5424 table 1 does not produce a frame a strict
// receiver will take: the PRI leaves 0..191 and every record is rejected
// at the far end. It is refused where it is configured, like an
// unverifiable receiver, rather than read as working until it matters.
func TestNewRefusesAFacilityOutsideRFC5424(t *testing.T) {
	dir := t.TempDir()
	_, caPEM := genCA(t)
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	base := Config{Address: "127.0.0.1:6514", CABundlePath: caPath, Now: fixedNow}
	for _, facility := range []int{-1, MaxFacility + 1, math.MaxInt} {
		cfg := base
		cfg.Facility = facility
		if _, err := New(cfg); err == nil {
			t.Errorf("facility %d must be refused", facility)
		}
	}
	for _, facility := range []int{1, MaxFacility, DefaultFacility} {
		cfg := base
		cfg.Facility = facility
		if _, err := New(cfg); err != nil {
			t.Errorf("facility %d is valid, got %v", facility, err)
		}
	}
}

func TestNewRefusesAFrameCapItCannotRepresent(t *testing.T) {
	dir := t.TempDir()
	_, caPEM := genCA(t)
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	base := Config{Address: "127.0.0.1:6514", CABundlePath: caPath, Now: fixedNow}
	for _, cap := range []int{-1, MaxFrameBytesLimit + 1} {
		cfg := base
		cfg.MaxFrameBytes = cap
		if _, err := New(cfg); err == nil {
			t.Errorf("max_frame_bytes %d must be refused", cap)
		}
	}
	// Zero is "no limit" and the ceiling itself is accepted: neither is a
	// number the framing cannot carry.
	for _, cap := range []int{0, 2048, MaxFrameBytesLimit} {
		cfg := base
		cfg.MaxFrameBytes = cap
		if _, err := New(cfg); err != nil {
			t.Errorf("max_frame_bytes %d is valid, got %v", cap, err)
		}
	}
}

// A caller may make Now return a fixed instant — the field exists for it.
// Once real time passes that instant, a socket deadline derived from it is
// in the past and every write fails as a timeout with nothing attempted.
// The record timestamp and the transport deadline are therefore separate
// clocks, and this pins it with an instant long past.
func TestAFixedClockInThePastDoesNotBreakWrites(t *testing.T) {
	caCert, caKey, caPEM := genCAFull(t)
	dir := t.TempDir()
	trusted := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(trusted, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	srv, addr, lines := tlsReceiver(t, serverCert(t, caCert, caKey))
	defer srv.Close()

	past := func() time.Time { return time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC) }
	s, err := New(Config{Address: addr, CABundlePath: trusted, ServerName: "localhost", Now: past})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Submit([]byte(sampleRecord)); err != nil {
		t.Fatalf("a fixed clock must not make the write time out: %v", err)
	}
	select {
	case got := <-lines:
		// The record's own ts still wins for the message timestamp, so the
		// fixed clock is visibly not what stamps a record that has one.
		if !strings.Contains(got, "2026-09-27T01:02:03.004Z") {
			t.Errorf("the record's own timestamp did not reach the receiver: %q", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the receiver saw no frame")
	}
}

// capPlus is a preallocation hint, so the only thing it must never do is
// hand make() a wrapped, negative capacity.
func TestCapPlusGivesUpTheHintRatherThanWrapping(t *testing.T) {
	if got := capPlus(10, 12); got != 22 {
		t.Errorf("capPlus(10, 12) = %d, want 22", got)
	}
	if got := capPlus(math.MaxInt, 12); got != math.MaxInt {
		t.Errorf("capPlus(MaxInt, 12) = %d, want MaxInt", got)
	}
	if got := capPlus(math.MaxInt-12, 12); got != math.MaxInt {
		t.Errorf("capPlus(MaxInt-12, 12) = %d, want MaxInt", got)
	}
	if got := capPlus(math.MaxInt-13, 12); got < 0 {
		t.Errorf("capPlus returned a negative capacity %d", got)
	}
}

// ── the receiver's certificate is actually verified ───────────────────────

func TestSubmitVerifiesTheReceiverCertificate(t *testing.T) {
	caCert, caKey, caPEM := genCAFull(t)
	dir := t.TempDir()
	trusted := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(trusted, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("a receiver signed by the bundle is accepted", func(t *testing.T) {
		srv, addr, lines := tlsReceiver(t, serverCert(t, caCert, caKey))
		defer srv.Close()
		s, err := New(Config{Address: addr, CABundlePath: trusted, ServerName: "localhost", Now: fixedNow})
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		if err := s.Submit([]byte(sampleRecord)); err != nil {
			t.Fatalf("Submit: %v", err)
		}
		select {
		case got := <-lines:
			if !strings.Contains(got, `"event_id":"01a0-e1"`) {
				t.Fatalf("receiver got %q", got)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("receiver saw nothing")
		}
		if st := s.Stats(); st.Submitted != 1 || !st.Connected {
			t.Fatalf("stats %+v", st)
		}
	})

	t.Run("a receiver signed by anything else is refused", func(t *testing.T) {
		// A different CA entirely: the sink must not talk to it.
		otherCert, otherKey, _ := genCAFull(t)
		srv, addr, _ := tlsReceiver(t, serverCert(t, otherCert, otherKey))
		defer srv.Close()
		s, err := New(Config{Address: addr, CABundlePath: trusted, ServerName: "localhost", Now: fixedNow})
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		err = s.Submit([]byte(sampleRecord))
		if err == nil {
			t.Fatal("an unverifiable receiver must be refused")
		}
		if !strings.Contains(err.Error(), "certificate") && !strings.Contains(err.Error(), "authority") {
			t.Fatalf("refusal should name the certificate, got %v", err)
		}
		if st := s.Stats(); st.Connected || st.DialErrors == 0 {
			t.Fatalf("a refused receiver must not read as connected: %+v", st)
		}
	})
}

func TestSubmitReportsAWriteFailureSoTheCursorCannotAdvance(t *testing.T) {
	caCert, caKey, caPEM := genCAFull(t)
	dir := t.TempDir()
	trusted := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(trusted, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	srv, addr, _ := tlsReceiver(t, serverCert(t, caCert, caKey))
	s, err := New(Config{Address: addr, CABundlePath: trusted, ServerName: "localhost", Now: fixedNow})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Submit([]byte(sampleRecord)); err != nil {
		t.Fatalf("first submit: %v", err)
	}
	// Drop the receiver, then keep submitting until the closed socket is
	// observed: the first write after a close often succeeds locally.
	srv.Close()
	var seen error
	for i := 0; i < 50 && seen == nil; i++ {
		seen = s.Submit([]byte(sampleRecord))
		time.Sleep(20 * time.Millisecond)
	}
	if seen == nil {
		t.Fatal("a dead receiver must eventually surface as an error, or a cursor would advance past unsent records")
	}
	if st := s.Stats(); st.Connected {
		t.Fatalf("must not read as connected after the receiver went away: %+v", st)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────

func genCA(t *testing.T) (*x509.Certificate, []byte) {
	t.Helper()
	c, _, p := genCAFull(t)
	return c, p
}

func genCAFull(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "audit-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func serverCert(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() + 1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// receiver is a minimal RFC 5425 receiver: it reads the octet count and
// then exactly that many bytes, which is what proves the framing is right.
// Close drops the accepted connections as well as the listener — closing
// only the listener leaves an established socket happily readable, which
// is not what "the receiver went away" means.
type receiver struct {
	ln    net.Listener
	mu    sync.Mutex
	conns []net.Conn
	done  bool
}

func (r *receiver) track(c net.Conn) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.done {
		_ = c.Close()
		return false
	}
	r.conns = append(r.conns, c)
	return true
}

func (r *receiver) Close() error {
	r.mu.Lock()
	r.done = true
	conns := r.conns
	r.conns = nil
	r.mu.Unlock()
	err := r.ln.Close()
	for _, c := range conns {
		_ = c.Close()
	}
	return err
}

func tlsReceiver(t *testing.T, cert tls.Certificate) (*receiver, string, chan string) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	rcv := &receiver{ln: ln}
	lines := make(chan string, 16)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if !rcv.track(c) {
				continue
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				for {
					n, err := readCount(r)
					if err != nil {
						return
					}
					buf := make([]byte, n)
					if _, err := io.ReadFull(r, buf); err != nil {
						return
					}
					select {
					case lines <- string(buf):
					default:
					}
				}
			}(c)
		}
	}()
	return rcv, ln.Addr().String(), lines
}

func readCount(r *bufio.Reader) (int, error) {
	var digits []byte
	for {
		b, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		if b == ' ' {
			break
		}
		if b < '0' || b > '9' {
			return 0, fmt.Errorf("bad length byte %q", b)
		}
		digits = append(digits, b)
		if len(digits) > 10 {
			return 0, fmt.Errorf("length prefix too long")
		}
	}
	if len(digits) == 0 {
		return 0, fmt.Errorf("empty length prefix")
	}
	return strconv.Atoi(string(digits))
}
