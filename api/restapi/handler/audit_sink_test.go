/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package handler

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/loxilb-io/loxilb/api/models"
	auditops "github.com/loxilb-io/loxilb/api/restapi/operations/audit"
	"github.com/loxilb-io/loxilb/pkg/audit"
	"github.com/loxilb-io/loxilb/pkg/audit/syslog"
)

// sinkPKI is a throwaway anchor and a receiver certificate it signed.
type sinkPKI struct {
	caPath string
	cert   tls.Certificate
}

func newSinkPKI(t *testing.T) sinkPKI {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "audit-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "audit-test-receiver"},
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
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return sinkPKI{caPath: path, cert: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}}
}

// sinkFrame is one message as the receiver read it.
type sinkFrame struct {
	sd     string
	record map[string]any
}

func (f sinkFrame) seq() uint64 {
	n, _ := f.record["seq"].(float64)
	return uint64(n)
}

// sinkReceiver is an RFC 5425 receiver that keeps what it was sent.
type sinkReceiver struct {
	t    *testing.T
	ln   net.Listener
	addr string
	wg   sync.WaitGroup

	mu     sync.Mutex
	frames []sinkFrame
}

func newSinkReceiver(t *testing.T, pki sinkPKI) *sinkReceiver {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pki.cert}})
	if err != nil {
		t.Fatal(err)
	}
	r := &sinkReceiver{t: t, ln: ln, addr: ln.Addr().String()}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			r.wg.Add(1)
			go r.read(c)
		}
	}()
	return r
}

func (r *sinkReceiver) read(c net.Conn) {
	defer r.wg.Done()
	defer c.Close()
	br := bufio.NewReader(c)
	for {
		count, err := br.ReadString(' ')
		if err != nil {
			return
		}
		n, err := strconv.Atoi(strings.TrimSuffix(count, " "))
		if err != nil {
			r.t.Errorf("the receiver read a bad octet count %q", count)
			return
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(br, buf); err != nil {
			return
		}
		// <pri>1 ts host app procid msgid structured-data msg
		parts := strings.SplitN(string(buf), " ", 7)
		if len(parts) != 7 {
			r.t.Errorf("the receiver read a short message %q", buf)
			return
		}
		var fr sinkFrame
		rest := parts[6]
		if strings.HasPrefix(rest, "[") {
			end := strings.Index(rest, "] ")
			fr.sd, rest = rest[:end+1], rest[end+2:]
		} else {
			fr.sd, rest, _ = strings.Cut(rest, " ")
		}
		if err := json.Unmarshal([]byte(rest), &fr.record); err != nil {
			r.t.Errorf("the receiver read a message that is not a record: %q", rest)
			return
		}
		r.mu.Lock()
		r.frames = append(r.frames, fr)
		r.mu.Unlock()
	}
}

func (r *sinkReceiver) got() []sinkFrame {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]sinkFrame(nil), r.frames...)
}

// waitFor waits until a frame satisfies ok and returns what has arrived.
func (r *sinkReceiver) waitFor(what string, ok func(sinkFrame) bool) []sinkFrame {
	r.t.Helper()
	for deadline := time.Now().Add(10 * time.Second); ; {
		frames := r.got()
		for _, fr := range frames {
			if ok(fr) {
				return frames
			}
		}
		if time.Now().After(deadline) {
			r.t.Fatalf("the receiver never saw %s; it has %d frames", what, len(frames))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// drained waits for every session to end, so that everything the sink
// wrote before it dropped the connection has been read.
func (r *sinkReceiver) drained() []sinkFrame {
	r.t.Helper()
	done := make(chan struct{})
	go func() { r.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		r.t.Fatal("the sink's session to the receiver was never closed")
	}
	return r.got()
}

func isEvent(eventType string) func(sinkFrame) bool {
	return func(fr sinkFrame) bool { return fr.record["event_type"] == eventType }
}

// resetAuditSink leaves no sink and no tailer behind for the next test.
func resetAuditSink(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), auditSinkStopTimeout)
		defer cancel()
		auditSink.mu.Lock()
		defer auditSink.mu.Unlock()
		if err := stopAuditSinkLocked(ctx); err != nil {
			t.Errorf("the sink tailer did not stop: %v", err)
		}
		auditSink.sink, auditSink.cfg, auditSink.tailer = nil, syslog.Config{}, nil
	})
}

// postSink sends a sink change through the gate and returns its status.
func postSink(f *gateFixture, m models.AuditSink) int {
	f.t.Helper()
	code := 0
	f.inside = func(r *http.Request) {
		RecordAuditPrincipal(r, "alice|admin")
		resp := AuditPostSink(auditops.PostAuditSinkParams{HTTPRequest: r, Attr: &m}, "alice|admin")
		code = f.serve(resp).Code
		f.status = code
	}
	f.do("POST", "/netlox/v1/audit/sink", `{}`, "Content-Type", "application/json")
	f.inside = nil
	f.status = http.StatusOK
	return code
}

func currentTailer() *audit.SinkTailer {
	auditSink.mu.Lock()
	defer auditSink.mu.Unlock()
	return auditSink.tailer
}

// mutate makes n gated requests, each of which leaves records on the trail.
func mutate(f *gateFixture, n int) {
	for i := 0; i < n; i++ {
		f.do("POST", "/netlox/v1/config/loadbalancer", `{"n":`+strconv.Itoa(i)+`}`, "Content-Type", "application/json")
	}
}

// Enabling the sink is what makes records leave the gateway: the receiver
// gets the trail from its first record, in order, with nothing missing and
// nothing beside the record, and the trail says who the receiver was.
func TestAuditSinkSendsTheTrailToItsReceiver(t *testing.T) {
	withAuthMode(t, true)
	f := newGateFixture(t)
	resetAuditSink(t)
	pki := newSinkPKI(t)
	rcv := newSinkReceiver(t, pki)

	mutate(f, 2)
	if code := postSink(f, models.AuditSink{Enabled: true, Address: rcv.addr, CaBundlePath: pki.caPath}); code != http.StatusNoContent {
		t.Fatalf("enabling the sink answered %d", code)
	}
	mutate(f, 2)

	frames := rcv.waitFor("the record of its own session", isEvent("sys.sink.connect"))
	var connect sinkFrame
	for i, fr := range frames {
		if fr.sd != "-" {
			t.Fatalf("frame %d of the compliance sink carries structured data %q", i, fr.sd)
		}
		if want := frames[0].seq() + uint64(i); fr.seq() != want {
			t.Fatalf("frame %d has seq %d, want %d: the receiver's copy is not the trail in order", i, fr.seq(), want)
		}
		if fr.record["event_type"] == "sys.sink.connect" {
			connect = fr
		}
	}
	// Records written before the sink existed are part of the trail too.
	if frames[0].seq() != 1 {
		t.Errorf("the receiver's first record has seq %d, want 1", frames[0].seq())
	}
	blob, _ := json.Marshal(connect.record)
	if !strings.Contains(string(blob), "audit_sink:"+auditComplianceSink) {
		t.Errorf("the session record does not name the sink: %s", blob)
	}
	d := detailOf(connect.record)
	if subject, _ := d["peer_subject"].(string); !strings.Contains(subject, "audit-test-receiver") {
		t.Errorf("the session record does not name the receiver's certificate: %s", blob)
	}
	if d["cert_not_after"] == nil {
		t.Errorf("the session record does not say when the receiver's certificate expires: %s", blob)
	}
}

// Disabling the sink ends the tailer, not just the connection: nothing
// written afterwards is sent, and the place the sink had reached is kept.
func TestAuditSinkDisabledStopsSending(t *testing.T) {
	withAuthMode(t, true)
	f := newGateFixture(t)
	resetAuditSink(t)
	pki := newSinkPKI(t)
	rcv := newSinkReceiver(t, pki)

	if code := postSink(f, models.AuditSink{Enabled: true, Address: rcv.addr, CaBundlePath: pki.caPath}); code != http.StatusNoContent {
		t.Fatalf("enabling the sink answered %d", code)
	}
	rcv.waitFor("the record of its own session", isEvent("sys.sink.connect"))
	if code := postSink(f, models.AuditSink{}); code != http.StatusNoContent {
		t.Fatalf("disabling the sink answered %d", code)
	}
	if currentTailer() != nil || AuditSink() != nil {
		t.Fatal("a disabled sink still has a tailer or a connection")
	}
	before := len(rcv.drained())

	mutate(f, 3)
	time.Sleep(5 * audit.DefaultSinkIdle)
	if after := len(rcv.got()); after != before {
		t.Fatalf("%d records were sent after the sink was disabled", after-before)
	}
	if _, err := os.Stat(filepath.Join(f.dir, "sink", auditComplianceSink+".cursor")); err != nil {
		t.Fatalf("the sink's cursor did not survive its being disabled: %v", err)
	}
}

// Pointing the sink at another receiver continues the trail there. It is
// one sink with one place in the trail, so the new receiver is not sent
// what the old one has, and nothing between them is lost.
func TestAuditSinkKeepsItsPlaceWhenTheReceiverChanges(t *testing.T) {
	withAuthMode(t, true)
	f := newGateFixture(t)
	resetAuditSink(t)
	pki := newSinkPKI(t)
	first, second := newSinkReceiver(t, pki), newSinkReceiver(t, pki)

	if code := postSink(f, models.AuditSink{Enabled: true, Address: first.addr, CaBundlePath: pki.caPath}); code != http.StatusNoContent {
		t.Fatalf("enabling the sink answered %d", code)
	}
	mutate(f, 2)
	first.waitFor("the record of its own session", isEvent("sys.sink.connect"))
	old := currentTailer()

	if code := postSink(f, models.AuditSink{Enabled: true, Address: second.addr, CaBundlePath: pki.caPath}); code != http.StatusNoContent {
		t.Fatalf("changing the receiver answered %d", code)
	}
	if now := currentTailer(); now == nil || now == old {
		t.Fatal("the change of receiver did not replace the tailer")
	}
	if st := old.Stats(); st.State != audit.SinkStopped {
		t.Fatalf("the old tailer is %q after the change, want stopped", st.State)
	}
	mutate(f, 2)

	sent := first.drained()
	last := sent[len(sent)-1].seq()
	got := second.waitFor("a record", func(sinkFrame) bool { return true })
	if got[0].seq() != last+1 {
		t.Fatalf("the new receiver starts at seq %d; the old one ended at %d", got[0].seq(), last)
	}
}

// A change that is refused leaves the sink that was running as it was.
func TestAuditSinkRefusedChangeLeavesTheRunningSink(t *testing.T) {
	withAuthMode(t, true)
	f := newGateFixture(t)
	resetAuditSink(t)
	pki := newSinkPKI(t)
	rcv := newSinkReceiver(t, pki)

	if code := postSink(f, models.AuditSink{Enabled: true, Address: rcv.addr, CaBundlePath: pki.caPath}); code != http.StatusNoContent {
		t.Fatalf("enabling the sink answered %d", code)
	}
	running := currentTailer()
	if running == nil {
		t.Fatal("enabling the sink started no tailer")
	}
	if code := postSink(f, models.AuditSink{Enabled: true, Address: "siem.example:6514"}); code != http.StatusBadRequest {
		t.Fatalf("a sink with no CA bundle answered %d, want 400", code)
	}
	if currentTailer() != running {
		t.Fatal("a refused change replaced the tailer")
	}
	if st := running.Stats(); st.State == audit.SinkStopped {
		t.Fatal("a refused change stopped the tailer")
	}
	mutate(f, 1)
	rcv.waitFor("a record written after the refusal", isEvent("mgmt.config.mutate"))
}

// With no writer there is no trail to follow: the sink is held as
// configured and nothing is started.
func TestAuditSinkWithoutAWriterStartsNoTailer(t *testing.T) {
	withAuthMode(t, true)
	f := newGateFixture(t)
	resetAuditSink(t)
	pki := newSinkPKI(t)

	f.inside = func(r *http.Request) {
		SetAuditWriter(nil)
		defer SetAuditWriter(f.w)
		m := models.AuditSink{Enabled: true, Address: "127.0.0.1:6514", CaBundlePath: pki.caPath}
		resp := AuditPostSink(auditops.PostAuditSinkParams{HTTPRequest: r, Attr: &m}, "alice|admin")
		if rec := f.serve(resp); rec.Code != http.StatusNoContent {
			t.Fatalf("sink change answered %d", rec.Code)
		}
	}
	f.do("POST", "/netlox/v1/audit/sink", `{}`, "Content-Type", "application/json")
	if AuditSink() == nil {
		t.Fatal("the sink was not installed")
	}
	if currentTailer() != nil {
		t.Fatal("a tailer was started with no trail to follow")
	}
}

// Shutdown ends the tailer before it closes the writer the tailer writes
// its own records through.
func TestCloseAuditWriterStopsTheSinkTailerFirst(t *testing.T) {
	withAuthMode(t, true)
	f := newGateFixture(t)
	resetAuditSink(t)
	pki := newSinkPKI(t)
	rcv := newSinkReceiver(t, pki)

	if code := postSink(f, models.AuditSink{Enabled: true, Address: rcv.addr, CaBundlePath: pki.caPath}); code != http.StatusNoContent {
		t.Fatalf("enabling the sink answered %d", code)
	}
	rcv.waitFor("the record of its own session", isEvent("sys.sink.connect"))
	tailer := currentTailer()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := CloseAuditWriter(ctx); err != nil {
		t.Fatal(err)
	}
	if st := tailer.Stats(); st.State != audit.SinkStopped {
		t.Fatalf("the tailer is %q after shutdown, want stopped", st.State)
	}
	if currentTailer() != nil {
		t.Fatal("shutdown left the tailer installed")
	}
	rcv.drained()
}

// The tailer decides what to do with a record from how its submission
// failed, so the sink's two failure classes must reach it as the tailer's.
func TestSyslogSubmitterSaysHowASubmissionFailed(t *testing.T) {
	pki := newSinkPKI(t)
	const record = `{"seq":7,"stream":"mgmt","event_type":"mgmt.config.mutate","ts":"2026-09-27T01:02:03.004Z"}`

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().String()
	_ = ln.Close()
	down, err := syslog.New(syslog.Config{Address: dead, CABundlePath: pki.caPath})
	if err != nil {
		t.Fatal(err)
	}
	sub := syslogSubmitter{down}
	if err := sub.Submit([]byte(record), 0, 0); !errors.Is(err, audit.ErrSubmitNotAttempted) {
		t.Errorf("an unreachable receiver: %v, want ErrSubmitNotAttempted", err)
	}
	if err := sub.Submit([]byte(`not a record`), 0, 0); !errors.Is(err, audit.ErrSubmitRejected) {
		t.Errorf("a line that cannot be framed: %v, want ErrSubmitRejected", err)
	}
	// No enterprise number is the configuration's fault: the record is
	// kept, never skipped.
	if err := sub.Submit([]byte(record), 3, 1); !errors.Is(err, audit.ErrSubmitNotAttempted) || errors.Is(err, audit.ErrSubmitRejected) {
		t.Errorf("an export sequence without an enterprise number: %v, want ErrSubmitNotAttempted", err)
	}
	if _, _, ok := sub.Peer(); ok {
		t.Error("a sink with no session named a peer")
	}

	rcv := newSinkReceiver(t, pki)
	up, err := syslog.New(syslog.Config{Address: rcv.addr, CABundlePath: pki.caPath, EnterpriseNumber: 32473})
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	sub = syslogSubmitter{up}
	if err := sub.Submit([]byte(record), 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := sub.Submit([]byte(record), 9, 4); err != nil {
		t.Fatal(err)
	}
	subject, notAfter, ok := sub.Peer()
	if !ok || !strings.Contains(subject, "audit-test-receiver") || notAfter.IsZero() {
		t.Errorf("the session's peer is %q until %v (ok=%v)", subject, notAfter, ok)
	}
	_ = up.Close()
	frames := rcv.drained()
	if len(frames) != 2 {
		t.Fatalf("the receiver read %d frames, want 2", len(frames))
	}
	if frames[0].sd != "-" {
		t.Errorf("a submission without an export sequence carries %q", frames[0].sd)
	}
	if want := `[audit-export@32473 xseq="9" xseq_epoch="4"]`; frames[1].sd != want {
		t.Errorf("a numbered submission carries %q, want %q", frames[1].sd, want)
	}
}
