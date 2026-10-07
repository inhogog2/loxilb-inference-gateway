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

// Package syslog submits audit records to a remote receiver as RFC 5424
// messages framed per RFC 5425 over TCP with TLS.
//
// It is transport only. It takes a record line that is already durable in
// the local JSONL — the system of record — and hands it to the receiver.
// It owns no spool, no queue and no retry schedule: a failed submission is
// reported to the caller, which is what stops a cursor from advancing.
//
// What the caller may claim from a successful Submit is deliberately
// narrow. RFC 5425 has no application-level acknowledgement, so a write
// that returns without error means the bytes reached the socket, not that
// the receiver indexed them. Nothing here is at-least-once, and the
// delivery contract is not decided in this package.
package syslog

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Facility 13 is "log audit" in RFC 5424 table 1, which is what this
// stream is. Severity is notice for an ordinary record and warning for a
// security event, so a receiver can route on the header before it parses
// any JSON.
const (
	DefaultFacility = 13
	severityNotice  = 5
	severityWarning = 4
)

// MaxFacility is the highest facility RFC 5424 table 1 defines. A value
// above it produces a PRI outside 0..191, which is not a valid header: a
// strict receiver rejects every frame, so the trail stops arriving because
// of one number. It is refused where it is configured instead.
const MaxFacility = 23

// MaxFrameBytesLimit bounds the configurable frame cap. One frame carries
// one record, so a cap this large is not a receiver's limit; accepting a
// larger number would only let the octet count and the buffer sizes
// derived from it stop being representable.
const MaxFrameBytesLimit = 1 << 30

// DefaultAppName is the RFC 5424 APP-NAME every frame carries.
const DefaultAppName = "loxilb-igw"

// nilValue is RFC 5424's NILVALUE, used for every header field this sink
// does not populate.
const nilValue = "-"

// Defaults for the transport timeouts.
const (
	DefaultDialTimeout  = 10 * time.Second
	DefaultWriteTimeout = 10 * time.Second
)

// Config describes one receiver.
type Config struct {
	// Address is the receiver's host:port.
	Address string
	// CABundlePath is the PEM bundle the receiver's certificate is
	// verified against. It is required: this sink has no unverified mode.
	CABundlePath string
	// ServerName is the name expected in the receiver's certificate. It
	// defaults to the host part of Address.
	ServerName string
	// ClientCertPath and ClientKeyPath enable mutual TLS when both are
	// set. A receiver that does not ask for a client certificate ignores
	// them.
	ClientCertPath string
	ClientKeyPath  string
	// Facility is the RFC 5424 facility. Default DefaultFacility.
	Facility int
	// AppName is the RFC 5424 APP-NAME. Default DefaultAppName.
	AppName string
	// MaxFrameBytes is the largest SYSLOG-MSG this receiver accepts, not
	// counting the RFC 5425 length prefix. Zero means no limit. A record
	// that does not fit is truncated at a field boundary and marked, never
	// cut mid-JSON.
	MaxFrameBytes int
	// EnterpriseNumber is the IANA private enterprise number that
	// qualifies this sink's STRUCTURED-DATA identifiers. RFC 5424 reserves
	// unqualified SD-IDs for IANA, so an element of our own needs one. Zero
	// means none is configured: plain submissions are unaffected, and a
	// submission that needs an element is refused. No number is built in.
	EnterpriseNumber uint32
	// DialTimeout and WriteTimeout bound the two blocking operations.
	DialTimeout  time.Duration
	WriteTimeout time.Duration

	// Now and Logf are injection points for tests. Now supplies the
	// message timestamp for a record that carries no usable ts of its own
	// and nothing else — in particular no socket deadline is derived from
	// it, so a fixed instant here cannot turn a write into a timeout.
	Now  func() time.Time
	Logf func(format string, args ...any)
}

func (c Config) withDefaults() Config {
	if c.Facility == 0 {
		c.Facility = DefaultFacility
	}
	if c.AppName == "" {
		c.AppName = DefaultAppName
	}
	if c.DialTimeout <= 0 {
		c.DialTimeout = DefaultDialTimeout
	}
	if c.WriteTimeout <= 0 {
		c.WriteTimeout = DefaultWriteTimeout
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Logf == nil {
		c.Logf = func(string, ...any) {}
	}
	return c
}

// Stats are the sink's counters since it was created.
type Stats struct {
	Submitted   uint64
	Bytes       uint64
	Truncated   uint64
	WriteErrors uint64
	Dials       uint64
	DialErrors  uint64
	Connected   bool
	LastError   string
}

// ErrNoEnterpriseNumber is returned by SubmitExport on a sink that has no
// private enterprise number to qualify the element with.
var ErrNoEnterpriseNumber = errors.New("syslog: an export sequence needs a private enterprise number")

// ErrNotAttempted marks a failed submission of which no octet was written:
// the receiver could not be reached. A caller that numbers its submissions
// may use the same number again after it, and after no other failure.
var ErrNotAttempted = errors.New("syslog: nothing was written")

// ErrPeerClosed is why a submission was not attempted on a session the
// receiver had already closed.
var ErrPeerClosed = errors.New("syslog: the receiver closed the session")

// ErrRejected marks a record this sink can never submit, whatever the
// receiver does: it is not an object, or its identity fields alone exceed
// the frame cap. Retrying it cannot succeed.
var ErrRejected = errors.New("syslog: the record cannot be framed")

// ErrNotConfigured is returned by New when no receiver is configured.
var ErrNotConfigured = errors.New("syslog: no receiver address")

// Sink is one receiver connection. It is safe for concurrent use, though
// a cursor tailer submits from a single goroutine.
type Sink struct {
	cfg Config
	tls *tls.Config

	mu   sync.Mutex
	conn net.Conn
	// raw is the connection under the TLS session, counting what is
	// handed to it. ends holds, oldest first, where each accepted frame
	// that the receiver's transport has not acknowledged ended in that
	// count. left is what Unconfirmed reported when the last session
	// ended, kept for a caller that asks after it.
	raw    *countingConn
	ends   []uint64
	left   int
	leftOK bool

	submitted   atomic.Uint64
	bytes       atomic.Uint64
	truncated   atomic.Uint64
	writeErrors atomic.Uint64
	dials       atomic.Uint64
	dialErrors  atomic.Uint64

	errMu    sync.Mutex
	lastErr  string
	isDialed atomic.Bool
}

// New validates the configuration and builds the TLS material. It does not
// connect: a receiver that is down must not stop the gateway from starting,
// because the local trail is the system of record and the sink is a
// follower of it.
func New(cfg Config) (*Sink, error) {
	cfg = cfg.withDefaults()
	if cfg.Address == "" {
		return nil, ErrNotConfigured
	}
	if _, _, err := net.SplitHostPort(cfg.Address); err != nil {
		return nil, fmt.Errorf("syslog: address %q: %w", cfg.Address, err)
	}
	if cfg.Facility < 0 || cfg.Facility > MaxFacility {
		return nil, fmt.Errorf("syslog: facility %d outside 0..%d", cfg.Facility, MaxFacility)
	}
	if cfg.MaxFrameBytes < 0 || cfg.MaxFrameBytes > MaxFrameBytesLimit {
		return nil, fmt.Errorf("syslog: max_frame_bytes %d outside 0..%d",
			cfg.MaxFrameBytes, MaxFrameBytesLimit)
	}
	tc, err := buildTLS(cfg)
	if err != nil {
		return nil, err
	}
	return &Sink{cfg: cfg, tls: tc}, nil
}

// buildTLS refuses anything that would leave the receiver unverified. There
// is no switch here that turns verification off: an audit trail crossing a
// network to an unauthenticated peer is not an audit trail.
func buildTLS(cfg Config) (*tls.Config, error) {
	if cfg.CABundlePath == "" {
		return nil, errors.New("syslog: a CA bundle is required to verify the receiver")
	}
	pem, err := os.ReadFile(cfg.CABundlePath)
	if err != nil {
		return nil, fmt.Errorf("syslog: ca bundle: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("syslog: ca bundle %s: no certificate found", cfg.CABundlePath)
	}
	name := cfg.ServerName
	if name == "" {
		host, _, err := net.SplitHostPort(cfg.Address)
		if err != nil {
			return nil, fmt.Errorf("syslog: address %q: %w", cfg.Address, err)
		}
		name = host
	}
	tc := &tls.Config{
		RootCAs:    pool,
		ServerName: name,
		MinVersion: tls.VersionTLS12,
	}
	switch {
	case cfg.ClientCertPath != "" && cfg.ClientKeyPath != "":
		pair, err := tls.LoadX509KeyPair(cfg.ClientCertPath, cfg.ClientKeyPath)
		if err != nil {
			return nil, fmt.Errorf("syslog: client keypair: %w", err)
		}
		tc.Certificates = []tls.Certificate{pair}
	case cfg.ClientCertPath != "" || cfg.ClientKeyPath != "":
		return nil, errors.New("syslog: a client certificate needs both a cert and a key")
	}
	return tc, nil
}

// Submit formats one audit record line as an RFC 5424 message, frames it
// per RFC 5425 and writes it. An error means the caller must not treat the
// record as submitted; the connection is dropped so the next call redials.
func (s *Sink) Submit(line []byte) error {
	return s.submit(line, nil)
}

// SubmitExport is Submit with the sink's export sequence carried beside the
// record, in STRUCTURED-DATA as [audit-export@<PEN> xseq="…" xseq_epoch="…"].
// xseq counts what was sent to this sink and epoch changes whenever that
// count starts again: a sink that receives a filtered subset of the trail
// sees holes in seq by construction, and this pair is what is contiguous
// for it. The record itself is the same bytes either way, so its identity
// and any hash over it are the same at every receiver.
func (s *Sink) SubmitExport(line []byte, xseq, epoch uint64) error {
	if s.cfg.EnterpriseNumber == 0 {
		return ErrNoEnterpriseNumber
	}
	sd := make([]byte, 0, 72)
	sd = append(sd, "[audit-export@"...)
	sd = strconv.AppendUint(sd, uint64(s.cfg.EnterpriseNumber), 10)
	sd = append(sd, ` xseq="`...)
	sd = strconv.AppendUint(sd, xseq, 10)
	sd = append(sd, `" xseq_epoch="`...)
	sd = strconv.AppendUint(sd, epoch, 10)
	sd = append(sd, '"', ']')
	return s.submit(line, sd)
}

// frameBuilt sees every frame before it is written. The tests read the
// frame a submission built there without needing a receiver.
var frameBuilt = func([]byte) {}

func (s *Sink) submit(line, sd []byte) error {
	frame, truncated, err := s.frameSD(line, sd)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrRejected, err)
	}
	frameBuilt(frame)
	if truncated {
		s.truncated.Add(1)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	conn, err := s.connLocked()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNotAttempted, err)
	}
	// A receiver that has closed its side takes nothing more, and a write
	// to it still succeeds until its refusal comes back, or for as long as
	// nothing comes back at all. The session is ended here, before the
	// frame is written into it.
	if _, closed, ok := transportState(s.raw.Conn); ok && closed {
		s.writeErrors.Add(1)
		s.dropLocked(ErrPeerClosed)
		return fmt.Errorf("%w: %w", ErrNotAttempted, ErrPeerClosed)
	}
	// The deadline comes from the real clock, never from cfg.Now: that one
	// stamps a record when the record carries no timestamp of its own, and
	// a caller is free to make it return a fixed instant. A socket deadline
	// built from a fixed instant is in the past as soon as real time passes
	// it, and then every write fails as a timeout without one byte being
	// attempted.
	if err := conn.SetWriteDeadline(time.Now().Add(s.cfg.WriteTimeout)); err != nil {
		s.dropLocked(err)
		return err
	}
	if _, err := conn.Write(frame); err != nil {
		s.writeErrors.Add(1)
		s.dropLocked(err)
		return fmt.Errorf("syslog: write: %w", err)
	}
	s.submitted.Add(1)
	s.bytes.Add(uint64(len(frame)))
	s.ends = append(s.ends, s.raw.written)
	return nil
}

// countingConn counts the bytes handed to the connection it wraps.
type countingConn struct {
	net.Conn
	written uint64
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.written += uint64(n)
	return n, err
}

// Unconfirmed reports how many of the most recent accepted submissions the
// receiver's transport has not acknowledged. A write that returned without
// error put its bytes in the socket; the acknowledgement is the first sign
// that they left this host and arrived at the other. It says nothing about
// what the receiver did with them. ok is false where the transport cannot
// be asked, and then nothing is known either way.
//
// After a session has ended the answer is the one it ended with, until the
// next session accepts a submission.
func (s *Sink) Unconfirmed() (n int, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return s.left, s.leftOK
	}
	return s.unconfirmedLocked()
}

// Broken reports that the receiver has closed the session the last
// submission went out on, and ends that session. Nothing is written to
// find out, so a sink with nothing to send learns of it as well. A session
// that failed on a submission is not reported here again: that submission
// returned the error.
func (s *Sink) Broken() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return false
	}
	if _, closed, ok := transportState(s.raw.Conn); !ok || !closed {
		return false
	}
	s.dropLocked(ErrPeerClosed)
	return true
}

// unconfirmedLocked forgets the frames that have been acknowledged and
// counts the rest.
func (s *Sink) unconfirmedLocked() (int, bool) {
	unacked, _, ok := transportState(s.raw.Conn)
	if !ok {
		s.ends = s.ends[:0]
		return 0, false
	}
	// Everything written is in the count, the handshake included, and
	// what is not acknowledged is the end of it.
	var acked uint64
	if unacked < s.raw.written {
		acked = s.raw.written - unacked
	}
	i := 0
	for i < len(s.ends) && s.ends[i] <= acked {
		i++
	}
	if i > 0 {
		s.ends = append(s.ends[:0], s.ends[i:]...)
	}
	return len(s.ends), true
}

// connLocked returns the live connection, dialing if there is none.
func (s *Sink) connLocked() (net.Conn, error) {
	if s.conn != nil {
		return s.conn, nil
	}
	s.dials.Add(1)
	failed := func(err error) (net.Conn, error) {
		s.dialErrors.Add(1)
		s.setErr(err)
		s.isDialed.Store(false)
		return nil, fmt.Errorf("syslog: dial %s: %w", s.cfg.Address, err)
	}
	d := &net.Dialer{Timeout: s.cfg.DialTimeout}
	tcp, err := d.Dial("tcp", s.cfg.Address)
	if err != nil {
		return failed(err)
	}
	boundSilence(tcp, s.cfg.WriteTimeout)
	raw := &countingConn{Conn: tcp}
	conn := tls.Client(raw, s.tls)
	// One limit over the connection and the handshake together, as the
	// dial had when it made both.
	_ = tcp.SetDeadline(time.Now().Add(s.cfg.DialTimeout))
	if err := conn.Handshake(); err != nil {
		_ = tcp.Close()
		return failed(err)
	}
	_ = tcp.SetDeadline(time.Time{})
	s.conn, s.raw, s.ends = conn, raw, s.ends[:0]
	s.left, s.leftOK = 0, false
	s.isDialed.Store(true)
	s.setErr(nil)
	return conn, nil
}

// endSessionLocked closes the session and keeps what it left
// unacknowledged.
func (s *Sink) endSessionLocked() error {
	if s.conn == nil {
		return nil
	}
	s.left, s.leftOK = s.unconfirmedLocked()
	err := s.conn.Close()
	s.conn, s.raw, s.ends = nil, nil, s.ends[:0]
	s.isDialed.Store(false)
	return err
}

func (s *Sink) dropLocked(err error) {
	s.setErr(err)
	_ = s.endSessionLocked()
	s.isDialed.Store(false)
}

func (s *Sink) setErr(err error) {
	s.errMu.Lock()
	if err == nil {
		s.lastErr = ""
	} else {
		s.lastErr = err.Error()
	}
	s.errMu.Unlock()
}

// Close drops the connection. The sink stays usable and redials on the
// next Submit.
func (s *Sink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.endSessionLocked()
}

// Peer names the receiver of the current session: the subject of the
// certificate it presented and when that certificate expires. ok is false
// when there is no session.
func (s *Sink) Peer() (subject string, notAfter time.Time, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tc, isTLS := s.conn.(*tls.Conn)
	if !isTLS {
		return "", time.Time{}, false
	}
	certs := tc.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", time.Time{}, false
	}
	return certs[0].Subject.String(), certs[0].NotAfter, true
}

// Stats reports the counters a status endpoint reads.
func (s *Sink) Stats() Stats {
	s.errMu.Lock()
	last := s.lastErr
	s.errMu.Unlock()
	return Stats{
		Submitted:   s.submitted.Load(),
		Bytes:       s.bytes.Load(),
		Truncated:   s.truncated.Load(),
		WriteErrors: s.writeErrors.Load(),
		Dials:       s.dials.Load(),
		DialErrors:  s.dialErrors.Load(),
		Connected:   s.isDialed.Load(),
		LastError:   last,
	}
}

// header carries the RFC 5424 fields this sink reads out of the record.
type header struct {
	TS         string `json:"ts"`
	InstanceID string `json:"instance_id"`
	Stream     string `json:"stream"`
	EventType  string `json:"event_type"`
}

// frame builds the complete RFC 5425 octet-counted frame for one record
// line: MSG-LEN SP SYSLOG-MSG, where MSG-LEN counts the octets of
// SYSLOG-MSG. Newline-delimited framing is what a permissive receiver
// tolerates and a strict one fragments on, so it is not used.
func (s *Sink) frame(line []byte) ([]byte, bool, error) {
	return s.frameSD(line, nil)
}

// frameSD is frame with a STRUCTURED-DATA element; nil keeps NILVALUE. The
// element counts toward the frame cap like every other octet of the
// message.
func (s *Sink) frameSD(line, sd []byte) ([]byte, bool, error) {
	var h header
	if err := json.Unmarshal(line, &h); err != nil {
		return nil, false, fmt.Errorf("syslog: record is not an object: %w", err)
	}
	msg := line
	truncated := false
	if s.cfg.MaxFrameBytes > 0 {
		if over := s.overBy(h, sd, msg); over > 0 {
			shorter, err := truncateRecord(line)
			if err != nil {
				return nil, false, err
			}
			msg, truncated = shorter, true
		}
	}
	syslogMsg := s.syslogMessage(h, sd, msg)
	// A truncated record must still fit. If dropping the detail was not
	// enough, fall back to the identity fields alone, which is the least a
	// receiver needs to see that a record exists and to ask for it by
	// replay from the local segment.
	if s.cfg.MaxFrameBytes > 0 && len(syslogMsg) > s.cfg.MaxFrameBytes {
		minimal, err := minimalRecord(line)
		if err != nil {
			return nil, false, err
		}
		syslogMsg = s.syslogMessage(h, sd, minimal)
		truncated = true
		if len(syslogMsg) > s.cfg.MaxFrameBytes {
			return nil, false, fmt.Errorf(
				"syslog: max_frame_bytes %d is too small for an identity-only record (%d)",
				s.cfg.MaxFrameBytes, len(syslogMsg))
		}
	}
	out := make([]byte, 0, capPlus(len(syslogMsg), framePrefixHint))
	out = strconv.AppendInt(out, int64(len(syslogMsg)), 10)
	out = append(out, ' ')
	out = append(out, syslogMsg...)
	return out, truncated, nil
}

// framePrefixHint covers the RFC 5425 length prefix: the decimal octet
// count and the space after it. msgHeaderHint covers the RFC 5424 HEADER
// ahead of the JSON. Both are preallocation hints, not limits — a longer
// hostname or app name simply grows the slice once.
const (
	framePrefixHint = 12
	msgHeaderHint   = 128
)

// capPlus returns n+extra for use as a preallocation hint, giving up the
// extra rather than wrapping when the sum would not fit in an int. A
// wrapped sum would reach make() as a negative capacity; the hint only
// ever saves a reallocation, so losing it costs nothing that matters.
func capPlus(n, extra int) int {
	if n > math.MaxInt-extra {
		return n
	}
	return n + extra
}

// overBy reports how many octets the assembled message exceeds the cap by.
func (s *Sink) overBy(h header, sd, msg []byte) int {
	return len(s.syslogMessage(h, sd, msg)) - s.cfg.MaxFrameBytes
}

// syslogMessage assembles the RFC 5424 SYSLOG-MSG. STRUCTURED-DATA is
// NILVALUE unless the caller supplies an element: the receiver parses the
// JSON, and splitting envelope fields across SD-IDs would duplicate the
// schema. What does belong there is what is true of one submission and not
// of the record, such as a sink's export sequence.
func (s *Sink) syslogMessage(h header, sd, msg []byte) []byte {
	pri := s.cfg.Facility*8 + severityFor(h.EventType)
	hostname := valueOr(h.InstanceID)
	msgID := valueOr(h.Stream)
	ts := timestampOr(h.TS, s.cfg.Now)

	out := make([]byte, 0, capPlus(capPlus(len(msg), len(sd)), msgHeaderHint))
	out = append(out, '<')
	out = strconv.AppendInt(out, int64(pri), 10)
	out = append(out, '>', '1', ' ')
	out = append(out, ts...)
	out = append(out, ' ')
	out = append(out, hostname...)
	out = append(out, ' ')
	out = append(out, s.cfg.AppName...)
	out = append(out, ' ')
	out = append(out, nilValue...) // PROCID
	out = append(out, ' ')
	out = append(out, msgID...)
	out = append(out, ' ')
	if len(sd) == 0 {
		out = append(out, nilValue...) // STRUCTURED-DATA
	} else {
		out = append(out, sd...)
	}
	out = append(out, ' ')
	out = append(out, msg...)
	return out
}

// severityFor keeps a security refusal visibly different from an ordinary
// record in the header, before anything parses the body.
func severityFor(eventType string) int {
	if len(eventType) >= 4 && eventType[:4] == "sec." {
		return severityWarning
	}
	return severityNotice
}

// valueOr replaces an empty or space-bearing header field with NILVALUE: a
// space inside a header field would shift every field after it.
func valueOr(v string) string {
	if v == "" {
		return nilValue
	}
	for i := 0; i < len(v); i++ {
		if v[i] <= ' ' || v[i] > '~' {
			return nilValue
		}
	}
	return v
}

// timestampOr passes the record's own timestamp through when it is a valid
// RFC 3339 stamp, so the receiver sees the time the event happened rather
// than the time it was submitted.
func timestampOr(ts string, now func() time.Time) string {
	if ts != "" {
		if _, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			return ts
		}
	}
	return now().UTC().Format("2006-01-02T15:04:05.000Z")
}

// identityFields are the envelope fields a record is never truncated below:
// without them a receiver cannot say which record it holds, nor ask for it
// back by replay.
var identityFields = []string{
	"schema_version", "event_id", "ts", "instance_id", "boot_id",
	"segment_uuid", "seq", "stream", "event_type",
}

// truncateRecord drops the detail object, which is the only unbounded part
// of the envelope, and marks the record. It never cuts mid-JSON: the result
// is a complete object that happens to carry less.
func truncateRecord(line []byte) ([]byte, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(line, &m); err != nil {
		return nil, fmt.Errorf("syslog: record is not an object: %w", err)
	}
	delete(m, "detail")
	m["truncated"] = json.RawMessage("true")
	return json.Marshal(m)
}

// minimalRecord keeps the identity fields and the truncation marker and
// nothing else.
func minimalRecord(line []byte) ([]byte, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(line, &m); err != nil {
		return nil, fmt.Errorf("syslog: record is not an object: %w", err)
	}
	out := make(map[string]json.RawMessage, len(identityFields)+1)
	for _, f := range identityFields {
		if v, ok := m[f]; ok {
			out[f] = v
		}
	}
	out["truncated"] = json.RawMessage("true")
	return json.Marshal(out)
}
