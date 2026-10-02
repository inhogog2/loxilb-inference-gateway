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

package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Submitter is the receiving end of a sink: something that takes one
// record line and hands it to a receiver.
type Submitter interface {
	// Submit sends line. A non-zero xseq is the sink's export sequence
	// number for this submission, with its epoch, and travels beside the
	// record; zero sends the record alone.
	//
	// A nil error means the receiver's side of the contract was met,
	// whatever that is for the sink: for syslog over TLS, that the bytes
	// were written. An error wrapping ErrSubmitNotAttempted means nothing
	// was sent; one wrapping ErrSubmitRejected means this record can
	// never be sent; any other error leaves it unknown how much arrived.
	Submit(line []byte, xseq, epoch uint64) error
}

// SinkPeer is implemented by a Submitter that can name the peer of its
// current session.
type SinkPeer interface {
	Peer() (subject string, notAfter time.Time, ok bool)
}

var (
	// ErrSubmitNotAttempted: the submission failed before anything was
	// sent.
	ErrSubmitNotAttempted = errors.New("audit: nothing was submitted")
	// ErrSubmitRejected: the record cannot be submitted to this sink at
	// all.
	ErrSubmitRejected = errors.New("audit: the sink cannot carry this record")
)

// Outcome values a filter can select.
const (
	FilterOutcomeOK     = "ok"
	FilterOutcomeFailed = "failed"
)

// SinkFilter selects the records a secondary sink receives. Each field
// that is set narrows the selection, and a field only judges records that
// have what it looks at: Services looks at the service of a data record
// and lets every other stream through, so "the chat service's data and
// nothing else" is Streams data plus Services chat.
type SinkFilter struct {
	// Streams keeps records of these streams. Empty keeps all.
	Streams []Stream
	// Services keeps data records of these services.
	Services []string
	// Outcome keeps records whose outcome is ok, or failed.
	Outcome string
	// DataSample keeps one data record in this many. Zero and one keep
	// all. Only the data stream can be sampled: a sampled management or
	// system stream would be a trail with records missing by design.
	DataSample uint64
}

func (f SinkFilter) empty() bool {
	return len(f.Streams) == 0 && len(f.Services) == 0 && f.Outcome == "" && f.DataSample <= 1
}

func (f SinkFilter) validate() error {
	for _, s := range f.Streams {
		if !s.valid() {
			return fmt.Errorf("audit: sink filter: unknown stream %q", s)
		}
	}
	for _, s := range f.Services {
		if s == "" {
			return errors.New("audit: sink filter: empty service name")
		}
	}
	switch f.Outcome {
	case "", FilterOutcomeOK, FilterOutcomeFailed:
	default:
		return fmt.Errorf("audit: sink filter: outcome %q is neither %q nor %q",
			f.Outcome, FilterOutcomeOK, FilterOutcomeFailed)
	}
	return nil
}

// filterFields is the part of a record a filter looks at.
type filterFields struct {
	Seq       uint64 `json:"seq"`
	Stream    Stream `json:"stream"`
	EventType string `json:"event_type"`
	Outcome   *struct {
		OK bool `json:"ok"`
	} `json:"outcome"`
	Detail struct {
		Service string `json:"service"`
	} `json:"detail"`
}

func (f SinkFilter) match(r *filterFields) bool {
	if len(f.Streams) > 0 {
		in := false
		for _, s := range f.Streams {
			if s == r.Stream {
				in = true
				break
			}
		}
		if !in {
			return false
		}
	}
	if len(f.Services) > 0 && r.Stream == StreamData {
		in := false
		for _, s := range f.Services {
			if s == r.Detail.Service {
				in = true
				break
			}
		}
		if !in {
			return false
		}
	}
	if f.Outcome != "" && r.Outcome != nil && r.Outcome.OK != (f.Outcome == FilterOutcomeOK) {
		return false
	}
	// The sample is taken on seq, so that sending a range again selects
	// the same records it selected the first time.
	if f.DataSample > 1 && r.Stream == StreamData && r.Seq%f.DataSample != 0 {
		return false
	}
	return true
}

// Sink states, as Stats reports them.
const (
	SinkStarting     = "starting"
	SinkConnected    = "connected"
	SinkDisconnected = "disconnected"
	SinkStalled      = "stalled"
	SinkStopped      = "stopped"
)

// Defaults of a sink tailer.
const (
	DefaultSinkBatch           = 256
	DefaultSinkIdle            = 200 * time.Millisecond
	DefaultSinkRetry           = time.Second
	DefaultSinkRetryMax        = 30 * time.Second
	DefaultSinkReconnectWindow = 64
)

// SinkTailerConfig describes one sink that follows the trail.
type SinkTailerConfig struct {
	// Name identifies the sink in its state files, its records and the
	// status. It becomes part of a file name.
	Name string
	// Dir is the audit directory.
	Dir       string
	Submitter Submitter
	// Compliance marks the one sink that receives every record. It takes
	// no filter, and its submissions carry no export sequence: seq is
	// contiguous there, and that is the sequence a reader checks.
	Compliance bool
	Filter     SinkFilter
	// Batch is how many records pass between two saves of the cursor.
	Batch int
	// Idle is how long the tailer waits when the trail has nothing new.
	Idle time.Duration
	// Retry is the first wait after a failed submission; it doubles up
	// to RetryMax.
	Retry    time.Duration
	RetryMax time.Duration
	// ReconnectWindow is how many of the most recently submitted records
	// are sent again after a submission failed part-way. A write that
	// returned without error says the bytes reached the socket, not the
	// receiver, so the records just before a failure are the ones most
	// likely to be missing there. Negative disables it.
	ReconnectWindow int
	// Reserve is the export sequence block size; zero takes the default.
	Reserve uint64
	// Emit writes an audit_system record; durable waits until it is on
	// stable storage. Nil discards them.
	Emit func(ctx context.Context, r *Record, durable bool) error
	Now  func() time.Time
	Logf func(format string, args ...any)
	// Fault reports whether a named fault point is armed.
	Fault func(point string) bool
}

// ValidSinkName reports whether name can identify a sink: 1 to 64 of a-z,
// 0-9, '-' and '_'. The name becomes part of a file name.
func ValidSinkName(name string) bool { return validSinkName(name) }

func validSinkName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// SinkTailerStats is what a status endpoint reads.
type SinkTailerStats struct {
	Name       string
	Compliance bool
	State      string
	// Cursor is the sink's state as it was last saved.
	Cursor SinkCursor
	// Submitted counts accepted submissions, records sent again included.
	Submitted uint64
	// Filtered counts records the filter kept from this sink.
	Filtered uint64
	// Resent counts submissions that repeated an earlier one.
	Resent uint64
	// Poison counts records skipped because the sink cannot carry them.
	Poison        uint64
	SubmitErrors  uint64
	CursorErrors  uint64
	ReserveErrors uint64
	ReadErrors    uint64
	// LagDrops counts the times the tailer's segment was removed before
	// it had been read out.
	LagDrops  uint64
	LastError string
}

// SinkTailer follows the trail for one sink: it reads each record after
// the sink's cursor, sends the ones the sink is to receive and saves the
// cursor behind them. The local trail is the system of record and the
// tailer is a follower of it, so nothing the tailer does or fails to do
// reaches the writer: a receiver that is down is a cursor that does not
// move.
type SinkTailer struct {
	cfg   SinkTailerConfig
	store *cursorStore
	die   func(string)

	stop     chan struct{}
	done     chan struct{}
	stopOnce sync.Once

	submitted     atomic.Uint64
	filtered      atomic.Uint64
	resent        atomic.Uint64
	poison        atomic.Uint64
	submitErrors  atomic.Uint64
	cursorErrors  atomic.Uint64
	reserveErrors atomic.Uint64
	readErrors    atomic.Uint64
	lagDrops      atomic.Uint64

	mu      sync.Mutex
	state   string
	cursor  SinkCursor
	reached Position
	lastErr string
}

// NewSinkTailer validates the configuration. Nothing is read or sent
// until Start.
func NewSinkTailer(cfg SinkTailerConfig) (*SinkTailer, error) {
	if !validSinkName(cfg.Name) {
		return nil, fmt.Errorf("audit: sink name %q: 1 to 64 of a-z, 0-9, '-' and '_'", cfg.Name)
	}
	if cfg.Submitter == nil {
		return nil, errors.New("audit: sink " + cfg.Name + ": no submitter")
	}
	if err := cfg.Filter.validate(); err != nil {
		return nil, err
	}
	if cfg.Compliance && !cfg.Filter.empty() {
		return nil, errors.New("audit: sink " + cfg.Name +
			": the compliance sink receives every record and takes no filter")
	}
	if cfg.Batch <= 0 {
		cfg.Batch = DefaultSinkBatch
	}
	if cfg.Idle <= 0 {
		cfg.Idle = DefaultSinkIdle
	}
	if cfg.Retry <= 0 {
		cfg.Retry = DefaultSinkRetry
	}
	if cfg.RetryMax < cfg.Retry {
		cfg.RetryMax = DefaultSinkRetryMax
		if cfg.RetryMax < cfg.Retry {
			cfg.RetryMax = cfg.Retry
		}
	}
	if cfg.ReconnectWindow == 0 {
		cfg.ReconnectWindow = DefaultSinkReconnectWindow
	}
	if cfg.ReconnectWindow < 0 {
		cfg.ReconnectWindow = 0
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.Fault == nil {
		cfg.Fault = func(string) bool { return false }
	}
	t := &SinkTailer{
		cfg:   cfg,
		store: newCursorStore(cfg.Dir, cfg.Name, cfg.Fault),
		stop:  make(chan struct{}),
		done:  make(chan struct{}),
		state: SinkStarting,
	}
	t.die = func(point string) {
		fmt.Fprintf(os.Stderr, "audit: fault point %s: exiting\n", point)
		os.Exit(86)
	}
	return t, nil
}

// Start runs the tailer on its own goroutine.
func (t *SinkTailer) Start() { go t.run() }

// Stop asks the tailer to save its cursor and end, and waits for it.
func (t *SinkTailer) Stop(ctx context.Context) error {
	t.stopOnce.Do(func() { close(t.stop) })
	select {
	case <-t.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Stats reports the tailer's counters and state.
func (t *SinkTailer) Stats() SinkTailerStats {
	t.mu.Lock()
	state, cur, last := t.state, t.cursor, t.lastErr
	t.mu.Unlock()
	return SinkTailerStats{
		Name: t.cfg.Name, Compliance: t.cfg.Compliance, State: state, Cursor: cur,
		Submitted: t.submitted.Load(), Filtered: t.filtered.Load(), Resent: t.resent.Load(),
		Poison: t.poison.Load(), SubmitErrors: t.submitErrors.Load(),
		CursorErrors: t.cursorErrors.Load(), ReserveErrors: t.reserveErrors.Load(),
		ReadErrors: t.readErrors.Load(), LagDrops: t.lagDrops.Load(), LastError: last,
	}
}

// Progress reports the last record the sink is past, whether or not the
// cursor that says so has been saved yet. It is what the pruner asks: a
// record already sent is not lost to the sink because the save that
// follows it is still to come.
func (t *SinkTailer) Progress() SinkProgress {
	t.mu.Lock()
	defer t.mu.Unlock()
	return SinkProgress{Name: t.cfg.Name, Position: t.reached}
}

func (t *SinkTailer) resource() string { return "audit_sink:" + t.cfg.Name }

func (t *SinkTailer) emit(r *Record, durable bool) error {
	if t.cfg.Emit == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := t.cfg.Emit(ctx, r, durable)
	if err != nil {
		t.cfg.Logf("audit: sink %s: %s not recorded: %v", t.cfg.Name, r.EventType, err)
	}
	return err
}

// setState moves the state and reports whether it changed.
func (t *SinkTailer) setState(state string, err error) (changed bool, from string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	from = t.state
	t.state = state
	if err != nil {
		t.lastErr = err.Error()
	} else if state == SinkConnected {
		t.lastErr = ""
	}
	return from != state, from
}

func (t *SinkTailer) setCursor(c SinkCursor) {
	t.mu.Lock()
	t.cursor, t.reached = c, c.Position
	t.mu.Unlock()
}

func (t *SinkTailer) setReached(p Position) {
	t.mu.Lock()
	t.reached = p
	t.mu.Unlock()
}

// wait sleeps for d and reports false when the tailer was asked to stop.
func (t *SinkTailer) wait(d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-t.stop:
		return false
	case <-timer.C:
		return true
	}
}

func (t *SinkTailer) stopping() bool {
	select {
	case <-t.stop:
		return true
	default:
		return false
	}
}

// reportRecovery records how the cursor came back, when it did not simply
// resume. The record is made durable before the first submission that
// acts on the rebuilt cursor: what follows is a re-send or a new epoch,
// and a reader of the trail must be able to find why.
func (t *SinkTailer) reportRecovery(rec CursorRecovery) {
	if rec.Method == CursorResumed && !rec.EpochChanged {
		return
	}
	if rec.Method == CursorFresh {
		return
	}
	old, start := rec.Old, rec.Start
	t.cfg.Logf("audit: sink %s: cursor reset (%s): continues at %s seq %d, export epoch %d",
		t.cfg.Name, rec.Method, start.SegmentUUID, start.Seq, start.XseqEpoch)
	_ = t.emit(sysRecord("sys.sink.cursor_reset", t.resource(), &SysDetail{
		OldCursor: &old, NewCursor: &start, Method: rec.Method,
	}), true)
}

// recentPositions remembers the places of the last submitted records.
type recentPositions struct {
	buf  []Position
	next int
	n    int
}

func (r *recentPositions) push(p Position) {
	if len(r.buf) == 0 {
		return
	}
	r.buf[r.next] = p
	r.next = (r.next + 1) % len(r.buf)
	if r.n < len(r.buf) {
		r.n++
	}
}

// oldest returns the earliest place remembered.
func (r *recentPositions) oldest() (Position, bool) {
	if r.n == 0 {
		return Position{}, false
	}
	return r.buf[(r.next-r.n+len(r.buf))%len(r.buf)], true
}

func (r *recentPositions) clear() { r.next, r.n = 0, 0 }

func (t *SinkTailer) run() {
	defer close(t.done)
	seq, rec := openExportSeq(t.store, t.cfg.Reserve, t.cfg.Now)
	t.setCursor(seq.cursor())
	t.reportRecovery(rec)

	rd := NewTrailReader(t.cfg.Dir, seq.cursor().Position)
	defer rd.Close()

	var (
		// pos is the last record the sink is past; dirty says it moved
		// since the cursor was last saved.
		pos     = seq.cursor().Position
		dirty   bool
		inBatch int
		// cur is a record that was read and not yet dealt with. It is
		// kept across a failed submission, so the same record is tried
		// again.
		cur  TrailLine
		have bool
		// number is an export sequence number that was taken and not
		// used.
		number uint64
		// While resending, the tailer is going over records at or before
		// pos again; pos does not move until it is reached.
		resending bool
		backoff   = t.cfg.Retry
		// One place more than the window: sending the window again means
		// continuing after the record before it.
		recent = recentPositions{}
	)
	if t.cfg.ReconnectWindow > 0 {
		recent.buf = make([]Position, t.cfg.ReconnectWindow+1)
	}
	commit := func() {
		if !dirty {
			return
		}
		if t.cfg.Fault(FaultSinkBeforeCursorWrite) {
			t.die(FaultSinkBeforeCursorWrite)
		}
		if err := seq.commit(pos); err != nil {
			t.cursorErrors.Add(1)
			t.cfg.Logf("audit: sink %s: cursor not saved: %v", t.cfg.Name, err)
		}
		dirty, inBatch = false, 0
		t.setCursor(seq.cursor())
	}
	finish := func() {
		commit()
		if err := seq.close(); err != nil {
			t.cursorErrors.Add(1)
			t.cfg.Logf("audit: sink %s: cursor not saved at stop: %v", t.cfg.Name, err)
		}
		t.setCursor(seq.cursor())
		t.setState(SinkStopped, nil)
	}
	// passed moves the sink past the record in hand.
	passed := func() {
		if resending {
			if cur.Pos == pos {
				resending = false
			}
		} else {
			pos, dirty = cur.Pos, true
			inBatch++
			t.setReached(pos)
		}
		have = false
		if inBatch >= t.cfg.Batch {
			commit()
		}
	}

	for {
		if t.stopping() {
			finish()
			return
		}
		if !have {
			l, err := rd.Next()
			switch {
			case err == nil:
				cur, have = l, true
			case errors.Is(err, ErrTrailIdle):
				commit()
				if !t.wait(t.cfg.Idle) {
					finish()
					return
				}
				continue
			case errors.Is(err, ErrPositionLost):
				if resending {
					// The window reached back into a segment that is
					// gone. The window is a courtesy; the place is not.
					resending = false
					recent.clear()
					rd.Seek(pos)
					continue
				}
				// The segment was removed before it was read out. What
				// was in it never reached this sink; the trail's oldest
				// record is where the sink can still continue.
				t.lagDrops.Add(1)
				t.cfg.Logf("audit: sink %s: segment %s was removed before it was sent; continuing from the oldest segment",
					t.cfg.Name, pos.SegmentUUID)
				recent.clear()
				rd.Seek(Position{})
				continue
			default:
				t.readErrors.Add(1)
				// Reported when the sink stalls, not on every attempt
				// that finds it still stalled.
				if changed, _ := t.setState(SinkStalled, err); changed {
					t.cfg.Logf("audit: sink %s: %v", t.cfg.Name, err)
					at := pos
					_ = t.emit(sysRecord("sys.sink.cursor_recovery_failed", t.resource(), &SysDetail{
						ErrnoClass: errnoClass(err), Cursor: &at,
					}), false)
				}
				rd.Close()
				commit()
				if !t.wait(backoff) {
					finish()
					return
				}
				backoff = nextBackoff(backoff, t.cfg.RetryMax)
				continue
			}
		}

		var ff filterFields
		decoded := json.Unmarshal(cur.Raw, &ff) == nil
		// The compliance sink has no filter: one is refused when the
		// sink is built.
		if !t.cfg.Filter.empty() && decoded && !t.cfg.Filter.match(&ff) {
			if !resending {
				t.filtered.Add(1)
			}
			passed()
			continue
		}

		if number == 0 {
			x, err := seq.next()
			if err != nil {
				// Without a reserved number nothing may be sent. The
				// record stays in hand.
				t.reserveErrors.Add(1)
				if changed, _ := t.setState(SinkStalled, err); changed {
					t.cfg.Logf("audit: %v", err)
				}
				if !t.wait(backoff) {
					finish()
					return
				}
				backoff = nextBackoff(backoff, t.cfg.RetryMax)
				continue
			}
			number = x
		}
		var xseq, epoch uint64
		if !t.cfg.Compliance {
			xseq, epoch = number, seq.cursor().XseqEpoch
		}
		err := t.cfg.Submitter.Submit(cur.Raw, xseq, epoch)
		switch {
		case err == nil:
			number = 0
			backoff = t.cfg.Retry
			t.submitted.Add(1)
			if resending {
				t.resent.Add(1)
			}
			recent.push(cur.Pos)
			if changed, _ := t.setState(SinkConnected, nil); changed {
				d := &SysDetail{Cursor: &Position{SegmentUUID: cur.Pos.SegmentUUID, Seq: cur.Pos.Seq}}
				if p, ok := t.cfg.Submitter.(SinkPeer); ok {
					if subject, notAfter, ok := p.Peer(); ok {
						d.PeerSubject, d.CertNotAfter = subject, formatTS(notAfter)
					}
				}
				_ = t.emit(sysRecord("sys.sink.connect", t.resource(), d), false)
			}
			passed()

		case errors.Is(err, ErrSubmitRejected):
			// The number stays in hand for the next record: nothing went
			// out under it.
			t.poison.Add(1)
			t.cfg.Logf("audit: sink %s: record seq %d skipped: %v", t.cfg.Name, cur.Pos.Seq, err)
			// A record about this sink that the sink cannot carry is not
			// answered with another record about it: that one would be
			// skipped for the same reason, and so on without end.
			if !decoded || !strings.HasPrefix(ff.EventType, "sys.sink.") {
				_ = t.emit(sysRecord("sys.sink.poison", t.resource(), &SysDetail{
					PoisonSeq: cur.Pos.Seq, Reason: "rejected", Cursor: &Position{SegmentUUID: cur.Pos.SegmentUUID, Seq: cur.Pos.Seq},
				}), false)
			}
			passed()

		default:
			t.submitErrors.Add(1)
			attempted := !errors.Is(err, ErrSubmitNotAttempted)
			if attempted {
				// Some of the frame may have arrived, with its number.
				number = 0
			}
			changed, from := t.setState(SinkDisconnected, err)
			if changed {
				t.cfg.Logf("audit: sink %s: %v", t.cfg.Name, err)
				w := uint64(t.cfg.ReconnectWindow)
				reason := "write_failed"
				if !attempted {
					reason = "unreachable"
				}
				_ = t.emit(sysRecord("sys.sink.disconnect", t.resource(), &SysDetail{
					Reason: reason, Cursor: &Position{SegmentUUID: pos.SegmentUUID, Seq: pos.Seq},
					ReconnectWindowRecords: &w,
				}), false)
			}
			commit()
			// A session that was up and then failed may have lost what
			// was written just before the failure. Go back over the
			// window; the record in hand is read again after it.
			if from == SinkConnected && !resending {
				if start, ok := recent.oldest(); ok && start != pos {
					resending = true
					have = false
					recent.clear()
					rd.Seek(start)
				}
			}
			if !t.wait(backoff) {
				finish()
				return
			}
			backoff = nextBackoff(backoff, t.cfg.RetryMax)
		}
	}
}

func nextBackoff(d, limit time.Duration) time.Duration {
	d *= 2
	if d > limit {
		return limit
	}
	return d
}
