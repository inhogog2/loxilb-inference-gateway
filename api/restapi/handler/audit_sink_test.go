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
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
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

var sinkExportSD = regexp.MustCompile(`^\[audit-export@(\d+) xseq="(\d+)" xseq_epoch="(\d+)"\]$`)

// export returns the frame's export sequence element.
func (f sinkFrame) export(t *testing.T) (pen, xseq, epoch uint64) {
	t.Helper()
	m := sinkExportSD.FindStringSubmatch(f.sd)
	if m == nil {
		t.Fatalf("the frame's structured data is %q, not an export sequence", f.sd)
	}
	pen, _ = strconv.ParseUint(m[1], 10, 64)
	xseq, _ = strconv.ParseUint(m[2], 10, 64)
	epoch, _ = strconv.ParseUint(m[3], 10, 64)
	return pen, xseq, epoch
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
	conns  []net.Conn
}

// stop takes the receiver away: no new session, and the ones it has end.
func (r *sinkReceiver) stop() {
	_ = r.ln.Close()
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.conns {
		_ = c.Close()
	}
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
			r.mu.Lock()
			r.conns = append(r.conns, c)
			r.mu.Unlock()
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
		for name, ns := range auditSink.named {
			if err := ns.stop(ctx); err != nil {
				t.Errorf("the tailer of sink %s did not stop: %v", name, err)
			}
		}
		auditSink.sink, auditSink.cfg, auditSink.tailer, auditSink.named = nil, syslog.Config{}, nil, nil
		publishAuditSinksLocked()
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

// ── secondary sinks ───────────────────────────────────────────────────────

const testPEN = 32473 // the enterprise number RFC 5612 reserves for documentation

// waitCount waits until the receiver holds at least n frames.
func (r *sinkReceiver) waitCount(n int) []sinkFrame {
	r.t.Helper()
	for deadline := time.Now().Add(10 * time.Second); ; {
		frames := r.got()
		if len(frames) >= n {
			return frames
		}
		if time.Now().After(deadline) {
			r.t.Fatalf("the receiver has %d frames, want at least %d", len(frames), n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// putNamedSink sends a secondary sink through the gate and returns its status.
func putNamedSink(f *gateFixture, name string, m models.AuditNamedSink) int {
	f.t.Helper()
	code := 0
	f.inside = func(r *http.Request) {
		RecordAuditPrincipal(r, "alice|admin")
		resp := AuditPutNamedSink(auditops.PutAuditSinksNameParams{HTTPRequest: r, Name: name, Attr: &m}, "alice|admin")
		code = f.serve(resp).Code
	}
	f.do("PUT", "/netlox/v1/audit/sinks/"+name, `{}`, "Content-Type", "application/json")
	f.inside = nil
	f.status = http.StatusOK
	return code
}

func deleteNamedSink(f *gateFixture, name string) int {
	f.t.Helper()
	code := 0
	f.inside = func(r *http.Request) {
		RecordAuditPrincipal(r, "alice|admin")
		resp := AuditDeleteNamedSink(auditops.DeleteAuditSinksNameParams{HTTPRequest: r, Name: name}, "alice|admin")
		code = f.serve(resp).Code
	}
	f.do("DELETE", "/netlox/v1/audit/sinks/"+name, "")
	f.inside = nil
	f.status = http.StatusOK
	return code
}

// getNamedSink reads a secondary sink as GET /audit/sinks/{name} serves it.
func getNamedSink(f *gateFixture, name string) (int, models.AuditNamedSink) {
	f.t.Helper()
	req, _ := http.NewRequest("GET", "/netlox/v1/audit/sinks/"+name, nil)
	rec := f.serve(AuditGetNamedSink(auditops.GetAuditSinksNameParams{HTTPRequest: req, Name: name}, "alice|admin"))
	f.status = http.StatusOK
	var m models.AuditNamedSink
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
			f.t.Fatalf("GET of sink %s is not a sink: %v", name, err)
		}
	}
	return rec.Code, m
}

func namedTailer(name string) *audit.SinkTailer {
	auditSink.mu.Lock()
	defer auditSink.mu.Unlock()
	if ns := auditSink.named[name]; ns != nil {
		return ns.tailer
	}
	return nil
}

func mgmtOnly(rcv *sinkReceiver, pki sinkPKI) models.AuditNamedSink {
	return models.AuditNamedSink{
		Address: rcv.addr, CaBundlePath: pki.caPath, EnterpriseNumber: testPEN,
		Filter: &models.AuditSinkFilter{Streams: []string{"mgmt"}},
	}
}

// A secondary sink receives what its filter selects and nothing else, and
// numbers it: the trail's own seq has holes there by construction, so the
// export sequence beside each record is what is contiguous for that
// receiver. The compliance sink beside it still receives everything, with
// nothing beside the record.
func TestAuditNamedSinkSendsWhatItSelectsUnderItsOwnSequence(t *testing.T) {
	withAuthMode(t, true)
	f := newGateFixture(t)
	resetAuditSink(t)
	pki := newSinkPKI(t)
	all, some := newSinkReceiver(t, pki), newSinkReceiver(t, pki)

	if code := postSink(f, models.AuditSink{Enabled: true, Address: all.addr, CaBundlePath: pki.caPath}); code != http.StatusNoContent {
		t.Fatalf("enabling the compliance sink answered %d", code)
	}
	// Its session record is an audit_system record, now on the trail
	// between the management records either side of it.
	all.waitFor("the record of its own session", isEvent("sys.sink.connect"))
	if code := putNamedSink(f, "mgmt-only", mgmtOnly(some, pki)); code != http.StatusNoContent {
		t.Fatalf("configuring the secondary sink answered %d", code)
	}
	mutate(f, 3)

	// Two sink changes and three mutations, an intent and a result each.
	frames := some.waitCount(10)
	_, _, epoch := frames[0].export(t)
	if epoch == 0 {
		t.Fatal("the export epoch is zero")
	}
	holes := false
	for i, fr := range frames {
		if fr.record["stream"] != "mgmt" {
			t.Fatalf("frame %d is a %v record; the filter selects mgmt", i, fr.record["stream"])
		}
		pen, xseq, e := fr.export(t)
		if pen != testPEN || xseq != uint64(i+1) || e != epoch {
			t.Fatalf("frame %d carries %q, want xseq %d under epoch %d and number %d", i, fr.sd, i+1, epoch, testPEN)
		}
		if i > 0 {
			if fr.seq() <= frames[i-1].seq() {
				t.Fatalf("frame %d has seq %d after %d", i, fr.seq(), frames[i-1].seq())
			}
			holes = holes || fr.seq() != frames[i-1].seq()+1
		}
	}
	if !holes {
		t.Error("seq is contiguous at the filtered receiver: the test did not filter anything out")
	}
	for i, fr := range all.waitFor("an audit_system record", func(fr sinkFrame) bool { return fr.record["stream"] == "audit_system" }) {
		if fr.sd != "-" {
			t.Fatalf("frame %d of the compliance sink carries %q", i, fr.sd)
		}
	}

	// The cursor is published when it is saved, which the tailer does once
	// it finds the trail idle.
	var got models.AuditNamedSink
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		var code int
		if code, got = getNamedSink(f, "mgmt-only"); code != http.StatusOK {
			t.Fatalf("GET of the sink answered %d", code)
		}
		if got.XseqHigh >= int64(len(frames)) || time.Now().After(deadline) {
			break
		}
	}
	if got.Name != "mgmt-only" || got.State != audit.SinkConnected || got.EnterpriseNumber != testPEN ||
		got.XseqEpoch != int64(epoch) || got.XseqHigh < int64(len(frames)) || got.Cursor == nil || got.Cursor.Seq == 0 {
		t.Errorf("GET reports %+v (cursor %+v)", got, got.Cursor)
	}
	if got.Filter == nil || len(got.Filter.Streams) != 1 || got.Filter.Streams[0] != "mgmt" {
		t.Errorf("GET does not report the filter: %+v", got.Filter)
	}
	if got.Filtered == 0 {
		t.Error("GET reports no record kept from the sink, and some were")
	}

	st := auditStatusModel(f.w, time.Now())
	if !st.ComplianceSink || len(st.Sinks) != 2 {
		t.Fatalf("status reports compliance_sink=%v and %d sinks, want true and 2", st.ComplianceSink, len(st.Sinks))
	}
	if c, s := st.Sinks[0], st.Sinks[1]; c.Name != auditComplianceSink || !c.Compliance || s.Name != "mgmt-only" || s.Compliance {
		t.Errorf("status lists %s (compliance=%v) then %s (compliance=%v)", c.Name, c.Compliance, s.Name, s.Compliance)
	}
	if s := st.Sinks[1]; !s.InActiveSegment || s.Cursor.SegmentUUID != st.Segment.UUID || s.LagRecords < 0 || s.LagRecords > st.SeqHigh {
		t.Errorf("status places the secondary sink at %+v (in_active_segment=%v, lag %d of %d)", s.Cursor, s.InActiveSegment, s.LagRecords, st.SeqHigh)
	}
}

// Status without any sink says so: no compliance sink is what "the trail
// is local only" looks like to a monitor.
func TestAuditStatusWithoutSinks(t *testing.T) {
	f := newGateFixture(t)
	resetAuditSink(t)
	if st := auditStatusModel(f.w, time.Now()); st.ComplianceSink || len(st.Sinks) != 0 {
		t.Fatalf("status reports compliance_sink=%v and %d sinks with none configured", st.ComplianceSink, len(st.Sinks))
	}
}

// What a secondary sink cannot be is refused when it is configured, and a
// refusal installs nothing and disturbs nothing.
func TestAuditNamedSinkRefusals(t *testing.T) {
	withAuthMode(t, true)
	f := newGateFixture(t)
	resetAuditSink(t)
	pki := newSinkPKI(t)
	rcv := newSinkReceiver(t, pki)
	ok := func() models.AuditNamedSink {
		return models.AuditNamedSink{Address: rcv.addr, CaBundlePath: pki.caPath, EnterpriseNumber: testPEN}
	}
	with := func(edit func(*models.AuditNamedSink)) models.AuditNamedSink { m := ok(); edit(&m); return m }

	for _, tt := range []struct {
		what, name string
		m          models.AuditNamedSink
	}{
		{"the compliance sink's name", auditComplianceSink, ok()},
		{"a name that is not a file name", "Bad.Name", ok()},
		{"no enterprise number", "a", with(func(m *models.AuditNamedSink) { m.EnterpriseNumber = 0 })},
		{"an enterprise number past 32 bits", "a", with(func(m *models.AuditNamedSink) { m.EnterpriseNumber = 1 << 32 })},
		{"a negative enterprise number", "a", with(func(m *models.AuditNamedSink) { m.EnterpriseNumber = -1 })},
		{"an unknown stream", "a", with(func(m *models.AuditNamedSink) { m.Filter = &models.AuditSinkFilter{Streams: []string{"nope"}} })},
		{"an unknown outcome", "a", with(func(m *models.AuditNamedSink) { m.Filter = &models.AuditSinkFilter{Outcome: "maybe"} })},
		{"a negative sample", "a", with(func(m *models.AuditNamedSink) { m.Filter = &models.AuditSinkFilter{DataSample: -1} })},
		{"no trust anchor", "a", with(func(m *models.AuditNamedSink) { m.CaBundlePath = "" })},
		{"a facility outside RFC 5424", "a", with(func(m *models.AuditNamedSink) { m.Facility = 24 })},
	} {
		if code := putNamedSink(f, tt.name, tt.m); code != http.StatusBadRequest {
			t.Errorf("%s answered %d, want 400", tt.what, code)
		}
		if namedTailer(tt.name) != nil {
			t.Errorf("%s was refused and installed anyway", tt.what)
		}
	}

	if code := putNamedSink(f, "a", ok()); code != http.StatusNoContent {
		t.Fatalf("a valid sink answered %d", code)
	}
	running := namedTailer("a")
	if running == nil {
		t.Fatal("a valid sink started no tailer")
	}
	// A secondary sink that selects everything is a secondary sink still:
	// what it sends is numbered.
	if _, xseq, _ := rcv.waitCount(1)[0].export(t); xseq != 1 {
		t.Fatalf("the first record of an unfiltered secondary sink carries xseq %d", xseq)
	}
	if code := putNamedSink(f, "a", with(func(m *models.AuditNamedSink) { m.EnterpriseNumber = 0 })); code != http.StatusBadRequest {
		t.Fatalf("a refused replacement answered %d", code)
	}
	if namedTailer("a") != running || running.Stats().State == audit.SinkStopped {
		t.Fatal("a refused replacement disturbed the running sink")
	}
	if code, _ := getNamedSink(f, "b"); code != http.StatusNotFound {
		t.Errorf("GET of a sink that does not exist answered %d", code)
	}
	if code := deleteNamedSink(f, "b"); code != http.StatusNotFound {
		t.Errorf("DELETE of a sink that does not exist answered %d", code)
	}
}

// A secondary sink that is replaced, or removed and configured again,
// continues its export sequence: the next number under the same epoch,
// and the trail from where it was.
func TestAuditNamedSinkContinuesItsSequence(t *testing.T) {
	withAuthMode(t, true)
	f := newGateFixture(t)
	resetAuditSink(t)
	pki := newSinkPKI(t)
	first, second, third := newSinkReceiver(t, pki), newSinkReceiver(t, pki), newSinkReceiver(t, pki)

	if code := putNamedSink(f, "s", mgmtOnly(first, pki)); code != http.StatusNoContent {
		t.Fatalf("configuring the sink answered %d", code)
	}
	mutate(f, 2)
	first.waitCount(4)
	old := namedTailer("s")

	// Replaced.
	if code := putNamedSink(f, "s", mgmtOnly(second, pki)); code != http.StatusNoContent {
		t.Fatalf("replacing the sink answered %d", code)
	}
	if old.Stats().State != audit.SinkStopped {
		t.Fatalf("the replaced tailer is %q, want stopped", old.Stats().State)
	}
	sent := first.drained()
	last := sent[len(sent)-1]
	_, lastX, epoch := last.export(t)
	got := second.waitCount(1)[0]
	if _, x, e := got.export(t); x != lastX+1 || e != epoch || got.seq() <= last.seq() {
		t.Fatalf("after the replacement the sink sends %q at seq %d; it had reached xseq %d under epoch %d at seq %d",
			got.sd, got.seq(), lastX, epoch, last.seq())
	}

	// Removed: nothing more is sent, and what the sink kept is still there.
	if code := deleteNamedSink(f, "s"); code != http.StatusNoContent {
		t.Fatalf("removing the sink answered %d", code)
	}
	if code, _ := getNamedSink(f, "s"); code != http.StatusNotFound {
		t.Fatalf("GET of the removed sink answered %d", code)
	}
	sent = second.drained()
	mutate(f, 2)
	time.Sleep(5 * audit.DefaultSinkIdle)
	if n := len(second.got()); n != len(sent) {
		t.Fatalf("%d records were sent after the sink was removed", n-len(sent))
	}
	last = sent[len(sent)-1]
	_, lastX, _ = last.export(t)

	// Configured again under its name.
	if code := putNamedSink(f, "s", mgmtOnly(third, pki)); code != http.StatusNoContent {
		t.Fatalf("configuring the sink again answered %d", code)
	}
	got = third.waitCount(1)[0]
	if _, x, e := got.export(t); x != lastX+1 || e != epoch || got.seq() <= last.seq() {
		t.Fatalf("configured again the sink sends %q at seq %d; it had reached xseq %d under epoch %d at seq %d",
			got.sd, got.seq(), lastX, epoch, last.seq())
	}
}

// A change to a secondary sink is recorded as a sink change that names
// which sink, where it sends and what vouches for the receiver.
func TestAuditNamedSinkChangeIsRecordedUnderItsName(t *testing.T) {
	withAuthMode(t, true)
	f := newGateFixture(t)
	resetAuditSink(t)
	pki := newSinkPKI(t)
	rcv := newSinkReceiver(t, pki)

	if code := putNamedSink(f, "siem-b", mgmtOnly(rcv, pki)); code != http.StatusNoContent {
		t.Fatalf("configuring the sink answered %d", code)
	}
	if code := deleteNamedSink(f, "siem-b"); code != http.StatusNoContent {
		t.Fatalf("removing the sink answered %d", code)
	}
	recs := recordsOfType(t, f, "mgmt.audit.sink")
	if len(recs) != 4 {
		t.Fatalf("%d mgmt.audit.sink records, want an intent and a result for each of the two changes", len(recs))
	}
	for i, r := range recs {
		blob, _ := json.Marshal(r)
		if !strings.Contains(string(blob), `"audit_sink:siem-b"`) {
			t.Errorf("record %d does not name the sink: %s", i, blob)
		}
	}
	put := detailOf(recs[1])
	if put["endpoint"] != rcv.addr || put["tls_ca_id"] != pki.caPath {
		t.Errorf("the result of the PUT names endpoint %v and anchor %v", put["endpoint"], put["tls_ca_id"])
	}
}

// Shutdown ends the secondary sinks' tailers too.
func TestCloseAuditWriterStopsTheSecondarySinks(t *testing.T) {
	withAuthMode(t, true)
	f := newGateFixture(t)
	resetAuditSink(t)
	pki := newSinkPKI(t)
	rcv := newSinkReceiver(t, pki)

	if code := putNamedSink(f, "s", mgmtOnly(rcv, pki)); code != http.StatusNoContent {
		t.Fatalf("configuring the sink answered %d", code)
	}
	rcv.waitCount(1)
	tailer := namedTailer("s")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := CloseAuditWriter(ctx); err != nil {
		t.Fatal(err)
	}
	if st := tailer.Stats(); st.State != audit.SinkStopped {
		t.Fatalf("the tailer is %q after shutdown, want stopped", st.State)
	}
}

// The sinks the handlers run are the sinks the pruner asks about. A
// segment pruned while one of them has not been sent it is put on record
// as lost to that sink, and the sinks that do have it are named on the
// prune.
func TestAuditSinksStandInThePruneRecords(t *testing.T) {
	withAuthMode(t, true)
	f := newGateFixtureWith(t, func(c *audit.Config) { c.HeartbeatInterval = 50 * time.Millisecond })
	resetAuditSink(t)
	pki := newSinkPKI(t)
	rcv := newSinkReceiver(t, pki)

	// A receiver that is not there: this sink never gets past anything.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().String()
	_ = ln.Close()
	if code := putNamedSink(f, "unreachable", models.AuditNamedSink{Address: dead, CaBundlePath: pki.caPath, EnterpriseNumber: testPEN}); code != http.StatusNoContent {
		t.Fatalf("configuring the unreachable sink answered %d", code)
	}
	if code := postSink(f, models.AuditSink{Enabled: true, Address: rcv.addr, CaBundlePath: pki.caPath}); code != http.StatusNoContent {
		t.Fatalf("enabling the compliance sink answered %d", code)
	}
	mutate(f, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sealed, _, err := f.w.RotateNow(ctx)
	if err != nil {
		t.Fatal(err)
	}
	mutate(f, 1)
	// The compliance sink is past the sealed segment once it reads the
	// one being written.
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		st := auditStatusModel(f.w, time.Now())
		if len(st.Sinks) == 2 && st.Sinks[0].InActiveSegment {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the compliance sink never reached the active segment")
		}
	}
	f.w.SetRetention(audit.Retention{MaxBytes: 1})

	frames := rcv.waitFor("the prune of the sealed segment", isEvent("sys.segment.prune"))
	var lost, prune map[string]any
	for _, fr := range frames {
		switch fr.record["event_type"] {
		case "sys.segment.lost_to_retention":
			lost = detailOf(fr.record)
		case "sys.segment.prune":
			prune = detailOf(fr.record)
		}
	}
	if lost == nil {
		t.Fatal("the segment was pruned without a record of what the unreachable sink lost")
	}
	if lost["resource"] != "audit_segment:"+sealed || lost["seq_from"] != float64(1) {
		t.Errorf("the loss is %v, want segment %s from seq 1", lost, sealed)
	}
	if got := fmt.Sprint(lost["sinks_pending"]); got != "[unreachable]" {
		t.Errorf("sinks pending %s, want [unreachable]", got)
	}
	if got := fmt.Sprint(prune["exported_to"]); got != "["+auditComplianceSink+"]" {
		t.Errorf("exported to %s, want [%s]", got, auditComplianceSink)
	}
}
