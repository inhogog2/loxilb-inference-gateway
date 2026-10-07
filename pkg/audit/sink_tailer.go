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

// SinkConfirmer is implemented by a Submitter that can say how far the
// receiver's transport has acknowledged what was submitted.
type SinkConfirmer interface {
	// Unconfirmed reports how many of the most recent accepted
	// submissions have not been acknowledged. ok is false when that
	// cannot be told.
	Unconfirmed() (n int, ok bool)
	// Broken reports that the session the last submission went out on
	// has been ended from the other side. It is reported once.
	Broken() bool
}

var (
	// errSinkSessionEnded is the error of a session the receiver ended
	// while nothing was being submitted.
	errSinkSessionEnded = errors.New("audit: the receiver ended the session")
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
	TS        string `json:"ts"`
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
	// maxSinkWindow bounds how many submitted records a tailer keeps the
	// places of. An unacknowledged run is as long as the socket's buffer
	// lets it be, which is far below this.
	maxSinkWindow = 1 << 16
	// sinkSettle is how long a stopping tailer gives the acknowledgements
	// of its last submissions to arrive before it calls them owed.
	sinkSettle = 300 * time.Millisecond
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
	//
	// With a Submitter that is a SinkConfirmer the window is never
	// shorter than the run of submissions the receiver's transport has
	// not acknowledged, and that run is saved with the cursor: a tailer
	// stopped with submissions unacknowledged, for whatever reason,
	// starts its next run by sending them again.
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
	// readOff is the offset in reached's segment file behind the record
	// reached names; -1 when it is not known.
	readOff int64
	// pendingTS is the time of the record in hand, the oldest one the
	// sink has not been sent; empty when none is in hand.
	pendingTS string
	// idle is set while the sink has been through everything the trail
	// held when it last asked.
	idle    bool
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
	t.readOff = -1
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
	return SinkProgress{Name: t.cfg.Name, Position: t.reached, Connected: t.state == SinkConnected}
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

// setReached moves the sink past the record at p, which ends at off in its
// segment's file.
func (t *SinkTailer) setReached(p Position, off int64) {
	t.mu.Lock()
	t.reached, t.readOff, t.pendingTS = p, off, ""
	t.mu.Unlock()
}

// setPending notes the time of the record in hand.
func (t *SinkTailer) setPending(ts string) {
	t.mu.Lock()
	t.pendingTS, t.idle = ts, false
	t.mu.Unlock()
}

// pending reports whether a record in hand has been noted.
func (t *SinkTailer) pending() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.pendingTS != ""
}

func (t *SinkTailer) setIdle(idle bool) {
	t.mu.Lock()
	t.idle = idle
	t.mu.Unlock()
}

// SinkPlace is where a sink stands, for measuring how far behind it is.
type SinkPlace struct {
	// Position is the last record the sink is past.
	Position Position
	// Offset is where that record ends in its segment's file; -1 when it
	// is not known, which is the case before the first record of a run
	// and inside a compressed segment.
	Offset int64
	// Idle says the sink had been through every record the trail held
	// when it last asked.
	Idle bool
	// Oldest is the time of the oldest record the sink has read and not
	// been able to send; zero when it holds none.
	Oldest time.Time
}

// Place reports where the sink stands.
func (t *SinkTailer) Place() SinkPlace {
	t.mu.Lock()
	p := SinkPlace{Position: t.reached, Offset: t.readOff, Idle: t.idle}
	ts := t.pendingTS
	t.mu.Unlock()
	if ts != "" {
		if at, err := time.Parse(tsLayout, ts); err == nil {
			p.Oldest = at
		}
	}
	return p
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

// recentPositions remembers the places of the last submitted records,
// oldest first, and in front of them the place the first of them was
// submitted after. Sending the last n again means continuing after the
// place n back from the end.
type recentPositions struct {
	buf []Position
	// head is where the remembered places begin in buf; what is before
	// it has been dropped and is cleared out when it is the larger part.
	head int
}

func (r *recentPositions) empty() bool { return r.head == len(r.buf) }

func (r *recentPositions) push(p Position) { r.buf = append(r.buf, p) }

// keep drops all but the last n submissions and the place before them.
func (r *recentPositions) keep(n int) {
	if over := len(r.buf) - r.head - (n + 1); over > 0 {
		r.head += over
	}
	if r.head > len(r.buf)/2 {
		r.buf = append(r.buf[:0], r.buf[r.head:]...)
		r.head = 0
	}
}

// before returns the place the last n submissions were submitted after,
// or the oldest place remembered when fewer are.
func (r *recentPositions) before(n int) (Position, bool) {
	if r.empty() {
		return Position{}, false
	}
	i := len(r.buf) - 1 - n
	if i < r.head {
		i = r.head
	}
	return r.buf[i], true
}

func (r *recentPositions) clear() { r.buf, r.head = r.buf[:0], 0 }

func (t *SinkTailer) run() {
	defer close(t.done)
	seq, rec := openExportSeq(t.store, t.cfg.Reserve, t.cfg.Now)
	t.setCursor(seq.cursor())
	t.reportRecovery(rec)

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
		// last is the place of the record read before cur.
		last = pos
		// number is an export sequence number that was taken and not
		// used.
		number uint64
		// While resending, the tailer is going over records at or before
		// pos again; pos does not move until it is reached.
		resending bool
		// resendSeg is the segment the resend was last seen in.
		resendSeg string
		backoff   = t.cfg.Retry
		recent    = recentPositions{}
		// settled says the save has already waited a turn for the
		// acknowledgement of what was last written.
		settled bool
	)
	confirmer, _ := t.cfg.Submitter.(SinkConfirmer)
	// unconfirmed is how many of the last submissions the receiver's
	// transport has not acknowledged, as far as that can be told.
	unconfirmed := func() int {
		if confirmer == nil {
			return 0
		}
		n, ok := confirmer.Unconfirmed()
		if !ok || n < 0 {
			return 0
		}
		if n > maxSinkWindow {
			n = maxSinkWindow
		}
		return n
	}
	// window is how many of the last submissions a failure sends again.
	window := func() int {
		if n := unconfirmed(); n > t.cfg.ReconnectWindow {
			return n
		}
		return t.cfg.ReconnectWindow
	}
	remember := t.cfg.ReconnectWindow > 0 || confirmer != nil

	// The run before this one ended with submissions the receiver's
	// transport had not acknowledged. They are owed again, and this run
	// begins with them.
	if from := seq.resendFrom(); from != (Position{}) && from != pos {
		t.cfg.Logf("audit: sink %s: not acknowledged when the last run ended: sending again from %s seq %d to %s seq %d",
			t.cfg.Name, from.SegmentUUID, from.Seq, pos.SegmentUUID, pos.Seq)
		resending, last = true, from
	}
	rd := NewTrailReader(t.cfg.Dir, last)
	defer rd.Close()

	// owed is the place the next run would have to send again from: the
	// place before the oldest submission that is not acknowledged. A
	// resend still under way is owed from where it began.
	owed := func() Position {
		if resending {
			return seq.resendFrom()
		}
		n := unconfirmed()
		if n == 0 {
			return Position{}
		}
		if from, ok := recent.before(n); ok && from != pos {
			return from
		}
		return Position{}
	}
	commit := func() {
		from := owed()
		if !dirty && from == seq.resendFrom() {
			return
		}
		if t.cfg.Fault(FaultSinkBeforeCursorWrite) {
			t.die(FaultSinkBeforeCursorWrite)
		}
		if err := seq.commit(pos, from); err != nil {
			t.cursorErrors.Add(1)
			t.cfg.Logf("audit: sink %s: cursor not saved: %v", t.cfg.Name, err)
		}
		dirty, inBatch = false, 0
		t.setCursor(seq.cursor())
	}
	// rewind saves the cursor at an earlier place than pos: the start of a
	// resend. The resend is owed to the receiver whether or not this
	// process lives to make it, and the saved cursor is all a later one
	// has to go by. pos itself, and what the pruner is told, stay where
	// they are.
	rewind := func(to Position) {
		if err := seq.commit(to, Position{}); err != nil {
			t.cursorErrors.Add(1)
			t.cfg.Logf("audit: sink %s: cursor not saved: %v", t.cfg.Name, err)
		}
		dirty, inBatch = false, 0
		c := seq.cursor()
		t.mu.Lock()
		t.cursor = c
		t.mu.Unlock()
	}
	// lost is what follows a session that ended: the state, the record of
	// it, and the window. A session that was up and then failed may have
	// lost what was written just before the failure. The tailer goes back
	// over the window; the record in hand is read again after it. The
	// cursor is saved at the start of the window, not at pos: a restart
	// before the receiver is back must begin there too.
	lost := func(err error, attempted bool) {
		changed, from := t.setState(SinkDisconnected, err)
		if changed {
			t.cfg.Logf("audit: sink %s: %v", t.cfg.Name, err)
			w := uint64(window())
			reason := "write_failed"
			if !attempted {
				reason = "unreachable"
			}
			_ = t.emit(sysRecord("sys.sink.disconnect", t.resource(), &SysDetail{
				Reason: reason, Cursor: &Position{SegmentUUID: pos.SegmentUUID, Seq: pos.Seq},
				ReconnectWindowRecords: &w,
			}), false)
		}
		// A resend that was under way goes back as well: what this
		// session took of it is no more received than anything else it
		// took.
		rewound := false
		if from == SinkConnected {
			if start, ok := recent.before(window()); ok && (resending || start != pos) {
				resending, resendSeg = true, ""
				have = false
				// The sink is behind by the window from here, whether or
				// not a new record is waiting behind it.
				t.setIdle(false)
				recent.clear()
				rd.Seek(start)
				last = start
				rewind(start)
				rewound = true
			}
		}
		if !rewound && !resending {
			commit()
		}
	}
	// ended asks, without writing anything, whether the receiver has ended
	// the session, and treats that as the failed write it would have been
	// for the next record.
	ended := func() bool {
		if confirmer == nil || !confirmer.Broken() {
			return false
		}
		lost(errSinkSessionEnded, false)
		return true
	}
	finish := func() {
		// What was just written is acknowledged within moments by a
		// receiver that is there. It is given those moments, so that a
		// stop with the receiver up leaves nothing owed.
		for deadline := time.Now().Add(sinkSettle); !resending && unconfirmed() > 0 && time.Now().Before(deadline); {
			time.Sleep(sinkSettle / 30)
		}
		// A receiver that closed while the sink had nothing to send is
		// found out here at the latest.
		if !ended() {
			commit()
		}
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
				// Everything the sink was past it is past again, and
				// holds nothing unsent.
				resending = false
				t.setReached(pos, rd.offset())
			}
		} else {
			pos, dirty = cur.Pos, true
			inBatch++
			t.setReached(pos, rd.offset())
		}
		last = cur.Pos
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
				t.setIdle(!resending)
				switch {
				case ended():
				case !settled && !resending && unconfirmed() > 0:
					// What was just written is acknowledged within
					// moments by a receiver that is there. The save
					// waits one turn for that, so that it is made once
					// and says nothing is owed, and not twice.
					settled = true
				default:
					commit()
					settled = false
				}
				if !t.wait(t.cfg.Idle) {
					finish()
					return
				}
				continue
			case errors.Is(err, ErrPositionLost):
				t.setIdle(false)
				if resending {
					// The window reached back into a segment that is
					// gone. The window is a courtesy; the place is not.
					resending = false
					recent.clear()
					rd.Seek(pos)
					last = pos
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
				last = Position{}
				continue
			default:
				t.setIdle(false)
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

		// A resend ends at the record pos names. When retention has taken
		// the segment that record was in, it will never be met, and a
		// resend left waiting for it would send every later record as a
		// repeat and never move the cursor again. The directory is asked
		// once for each segment the resend enters.
		if resending && cur.Pos.SegmentUUID != resendSeg {
			resendSeg = cur.Pos.SegmentUUID
			if held, err := rd.Holds(pos.SegmentUUID); err == nil && !held && pos.SegmentUUID != "" {
				t.lagDrops.Add(1)
				t.cfg.Logf("audit: sink %s: segment %s was removed before it was sent; continuing from %s",
					t.cfg.Name, pos.SegmentUUID, cur.Pos.SegmentUUID)
				resending = false
			}
		}

		var ff filterFields
		decoded := json.Unmarshal(cur.Raw, &ff) == nil
		// The oldest record the sink holds unsent is the one in hand, or
		// the first of a resend: what is being gone over again is as
		// unsent as what was never tried.
		if !resending || !t.pending() {
			t.setPending(ff.TS)
		}
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
			if remember {
				if recent.empty() {
					recent.push(last)
				}
				recent.push(cur.Pos)
				recent.keep(window())
			}
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
			lost(err, attempted)
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
