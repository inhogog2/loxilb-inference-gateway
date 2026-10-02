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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// frame is one submission as the receiver saw it.
type frame struct {
	raw   []byte
	xseq  uint64
	epoch uint64
}

func (f frame) field(t *testing.T, name string) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(f.raw, &m); err != nil {
		t.Fatalf("frame is not a record: %s", f.raw)
	}
	switch v := m[name].(type) {
	case string:
		return v
	case float64:
		return fmt.Sprint(uint64(v))
	}
	return ""
}

// fakeSink is a receiver. verdict, when set, decides each attempt before
// anything is recorded: it sees the attempt's number, counted from 1, and
// the record.
type fakeSink struct {
	mu       sync.Mutex
	frames   []frame
	attempts int
	verdict  func(attempt int, line []byte) error
}

func (f *fakeSink) Submit(line []byte, xseq, epoch uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attempts++
	if f.verdict != nil {
		if err := f.verdict(f.attempts, line); err != nil {
			return err
		}
	}
	f.frames = append(f.frames, frame{raw: append([]byte(nil), line...), xseq: xseq, epoch: epoch})
	return nil
}

func (f *fakeSink) got() []frame {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]frame(nil), f.frames...)
}

func (f *fakeSink) setVerdict(v func(int, []byte) error) {
	f.mu.Lock()
	f.verdict = v
	f.mu.Unlock()
}

func tailerConfig(dir, name string, sink Submitter, w *Writer) SinkTailerConfig {
	cfg := SinkTailerConfig{
		Name: name, Dir: dir, Submitter: sink,
		Idle: 2 * time.Millisecond, Retry: 2 * time.Millisecond, RetryMax: 4 * time.Millisecond,
		Reserve: 16, Batch: 4,
	}
	if w != nil {
		cfg.Emit = w.EmitSystem
	}
	return cfg
}

func startTailer(t *testing.T, cfg SinkTailerConfig) *SinkTailer {
	t.Helper()
	cfg.Logf = func(format string, args ...any) { t.Logf(format, args...) }
	tl, err := NewSinkTailer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	tl.Start()
	t.Cleanup(func() { stopTailer(t, tl) })
	return tl
}

func stopTailer(t *testing.T, tl *SinkTailer) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := tl.Stop(ctx); err != nil {
		t.Fatalf("stop: %v", err)
	}
}

// settled waits until the sink has received as many frames as the
// directory holds records, twice in a row: the tailer's own records are
// in the trail too, and are followed like any other.
func settled(t *testing.T, dir string, sink *fakeSink, extra int) {
	t.Helper()
	stable := 0
	waitFor(t, "the sink to catch up with the trail", func() bool {
		if len(sink.got()) == len(rawRecords(t, dir))+extra {
			stable++
		} else {
			stable = 0
		}
		return stable >= 3
	})
}

func eventsOf(t *testing.T, dir, eventType string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, raw := range rawRecords(t, dir) {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		if m["event_type"] == eventType {
			out = append(out, m)
		}
	}
	return out
}

func writeData(t *testing.T, w *Writer, n int) {
	t.Helper()
	p := w.Producer("", StreamData)
	for i := 0; i < n; i++ {
		r := dataRecord()
		r.Data.Service = []string{"chat", "embed"}[i%2]
		if !p.Emit(r) {
			t.Fatal("data record refused")
		}
	}
	// A durable write behind them puts every queued record on disk.
	writeN(t, w, 1, "flush")
}

func TestSinkTailerComplianceSinkReceivesEveryRecordUnchanged(t *testing.T) {
	cfg := testConfig(t)
	w := startWriter(t, cfg)
	writeN(t, w, 5, "one")
	sealNow(t, w)
	writeData(t, w, 6)

	sink := &fakeSink{}
	tc := tailerConfig(cfg.Dir, "siem", sink, w)
	tc.Compliance = true
	tl := startTailer(t, tc)
	settled(t, cfg.Dir, sink, 0)

	want := rawRecords(t, cfg.Dir)
	got := sink.got()
	for i := range want {
		if !bytes.Equal(got[i].raw, want[i]) {
			t.Fatalf("frame %d is not record %d of the trail:\n got %s\nwant %s", i, i, got[i].raw, want[i])
		}
		if got[i].xseq != 0 {
			t.Fatalf("frame %d of the compliance sink carries export sequence %d", i, got[i].xseq)
		}
	}
	if n := len(eventsOf(t, cfg.Dir, "sys.sink.connect")); n != 1 {
		t.Fatalf("%d sys.sink.connect records, want 1", n)
	}
	st := tl.Stats()
	if st.State != SinkConnected || st.Submitted != uint64(len(want)) || st.Filtered != 0 {
		t.Fatalf("stats %+v, want connected with %d submitted", st, len(want))
	}

	// A restart continues behind the last record and sends nothing again.
	stopTailer(t, tl)
	before := len(sink.got())
	writeN(t, w, 2, "later")
	tl2 := startTailer(t, tc)
	settled(t, cfg.Dir, sink, 0)
	after := sink.got()
	seen := map[string]bool{}
	for _, f := range after {
		id := f.field(t, "boot_id") + "/" + f.field(t, "seq")
		if seen[id] {
			t.Fatalf("record %s was sent twice across a clean restart", id)
		}
		seen[id] = true
	}
	if len(after) <= before {
		t.Fatal("nothing arrived after the restart")
	}
	if got := tl2.Stats().Cursor.Seq; got == 0 {
		t.Fatal("the cursor did not move")
	}
}

// Progress is where the sink is, not where its saved cursor is: a record
// that was sent is behind the sink at once, and the save follows a batch
// later. The pruner judges a segment by the first of the two.
func TestSinkTailerProgressRunsAheadOfTheSavedCursor(t *testing.T) {
	cfg := testConfig(t)
	w := startWriter(t, cfg)
	writeN(t, w, 6, "one")
	all := rawRecords(t, cfg.Dir)
	third := frame{raw: all[2]}

	// The fourth submission does not return until the test lets it, so
	// the tailer is held between two saves with three records behind it.
	hold := make(chan struct{})
	sink := &fakeSink{verdict: func(attempt int, _ []byte) error {
		if attempt == 4 {
			<-hold
		}
		return nil
	}}
	tc := tailerConfig(cfg.Dir, "held", sink, nil)
	tc.Batch = 100
	tl := startTailer(t, tc)
	defer close(hold)

	waitFor(t, "the third record to be behind the sink", func() bool {
		p := tl.Progress()
		return fmt.Sprint(p.Position.Seq) == third.field(t, "seq") && p.Position.SegmentUUID == third.field(t, "segment_uuid")
	})
	if p := tl.Progress(); p.Name != "held" {
		t.Errorf("progress is reported for %q", p.Name)
	}
	if c := tl.Stats().Cursor; c.Seq != 0 {
		t.Fatalf("the cursor was saved at seq %d; the test needs the tailer between two saves", c.Seq)
	}
}

// The pruner gives a pass to a sink that is connected, so Progress says
// whether this one is: after a record was accepted, and not once a
// submission has failed.
func TestSinkTailerProgressSaysWhetherTheSinkIsConnected(t *testing.T) {
	cfg := testConfig(t)
	w := startWriter(t, cfg)
	var down atomic.Bool
	sink := &fakeSink{verdict: func(int, []byte) error {
		if down.Load() {
			return errors.New("receiver is down")
		}
		return nil
	}}
	tl := startTailer(t, tailerConfig(cfg.Dir, "follower", sink, nil))
	if tl.Progress().Connected && tl.Stats().Submitted == 0 {
		t.Fatal("a sink that has sent nothing is reported connected")
	}
	writeN(t, w, 2, "one")
	waitFor(t, "the sink to be connected", func() bool { return tl.Progress().Connected })
	down.Store(true)
	writeN(t, w, 1, "two")
	waitFor(t, "the sink to be disconnected", func() bool { return !tl.Progress().Connected })
}

// A sink that keeps up is, at any moment, a few records short of the end.
// When its segment is sealed and the quota is small, the pass that follows
// finds it there. It is given that pass: nothing is recorded as lost, the
// sink is sent the rest, and the segment goes at the next pass as one the
// sink has in full.
func TestPruneGivesAFollowingTailerOnePassToFinishItsSegment(t *testing.T) {
	cfg := testConfig(t)
	w := startWriter(t, cfg)
	writeN(t, w, 6, "one")

	hold := make(chan struct{})
	var held atomic.Bool
	sink := &fakeSink{verdict: func(attempt int, _ []byte) error {
		if attempt == 4 {
			held.Store(true)
			<-hold
		}
		return nil
	}}
	tl := startTailer(t, tailerConfig(cfg.Dir, "follower", sink, nil))
	released := false
	release := func() {
		if !released {
			released = true
			close(hold)
		}
	}
	defer release()
	waitFor(t, "the tailer to stand inside the segment", func() bool { return held.Load() && tl.Progress().Connected })

	sealNow(t, w)
	waitCompressed(t, cfg.Dir)
	w.SetSinkProgress(func() []SinkProgress { return []SinkProgress{tl.Progress()} })
	w.SetRetention(Retention{MaxBytes: 1})
	w.prunePassNow(t)
	if left, _ := w.seg.listSealed(); len(left) != 1 {
		t.Fatalf("%d sealed segments after the pass, want the one the sink is inside", len(left))
	}
	if got := w.Stats().LostToRetention; got != 0 {
		t.Fatalf("%d records counted as lost to a sink that is connected and inside the segment", got)
	}

	release()
	settled(t, cfg.Dir, sink, 0)
	w.prunePassNow(t)
	if left, _ := w.seg.listSealed(); len(left) != 0 {
		t.Fatalf("%d sealed segments after the second pass, want none", len(left))
	}
	closeWriter(t, w)
	ls := readDir(t, cfg.Dir)
	if lost := ofType(ls, "sys.segment.lost_to_retention"); len(lost) != 0 {
		t.Fatalf("a loss is recorded against a sink that was sent the segment: %v", lost[0].detail())
	}
	prunes := ofType(ls, "sys.segment.prune")
	if len(prunes) != 1 {
		t.Fatalf("%d prune records, want 1", len(prunes))
	}
	if got, want := stringsOf(prunes[0].detail()["exported_to"]), []string{"follower"}; !reflect.DeepEqual(got, want) {
		t.Errorf("exported to %v, want %v", got, want)
	}
}

func TestSinkTailerFilteredSinkHasItsOwnContiguousSequence(t *testing.T) {
	cfg := testConfig(t)
	w := startWriter(t, cfg)
	writeN(t, w, 3, "one")
	writeData(t, w, 8)
	writeN(t, w, 2, "two")

	sink := &fakeSink{}
	tc := tailerConfig(cfg.Dir, "mgmt-only", sink, w)
	tc.Filter = SinkFilter{Streams: []Stream{StreamMgmt}}
	tl := startTailer(t, tc)

	wantMgmt := 0
	for _, raw := range rawRecords(t, cfg.Dir) {
		if bytes.Contains(raw, []byte(`"stream":"mgmt"`)) {
			wantMgmt++
		}
	}
	waitFor(t, "the management records", func() bool { return len(sink.got()) == wantMgmt })
	// The cursor passes the records that were filtered too: the trail
	// ends in records this sink does not receive, and the cursor ends
	// behind the last of them, so a restart does not read them again.
	p := w.Producer("", StreamData)
	for i := 0; i < 4; i++ {
		if !p.Emit(dataRecord()) {
			t.Fatal("data record refused")
		}
	}
	sealNow(t, w)
	all := rawRecords(t, cfg.Dir)
	last := frame{raw: all[len(all)-1]}
	if last.field(t, "stream") == "mgmt" {
		t.Fatal("the trail ends in a management record; the test needs it to end in a filtered one")
	}
	waitFor(t, "the cursor to pass the filtered records", func() bool {
		c := tl.Stats().Cursor
		return fmt.Sprint(c.Seq) == last.field(t, "seq") && c.SegmentUUID == last.field(t, "segment_uuid")
	})
	if len(sink.got()) != wantMgmt {
		t.Fatalf("%d frames, want the %d management records", len(sink.got()), wantMgmt)
	}
	got := sink.got()
	var lastSeq uint64
	holes := 0
	for i, f := range got {
		if f.field(t, "stream") != "mgmt" {
			t.Fatalf("frame %d is a %s record", i, f.field(t, "stream"))
		}
		if f.xseq != uint64(i+1) {
			t.Fatalf("frame %d carries xseq %d, want %d", i, f.xseq, i+1)
		}
		if f.epoch == 0 || f.epoch != got[0].epoch {
			t.Fatalf("frame %d carries epoch %d, first frame %d", i, f.epoch, got[0].epoch)
		}
		var seq uint64
		fmt.Sscan(f.field(t, "seq"), &seq)
		if lastSeq != 0 && seq != lastSeq+1 {
			holes++
		}
		lastSeq = seq
	}
	if holes == 0 {
		t.Fatal("seq is contiguous at the filtered sink: the filter kept nothing out and the test proves nothing")
	}
}

func TestSinkTailerFilterDimensions(t *testing.T) {
	rec := func(stream Stream, service string, ok bool, seq uint64) *filterFields {
		f := &filterFields{Seq: seq, Stream: stream}
		f.Outcome = &struct {
			OK bool `json:"ok"`
		}{OK: ok}
		f.Detail.Service = service
		return f
	}
	cases := []struct {
		name string
		f    SinkFilter
		r    *filterFields
		want bool
	}{
		{"no filter keeps everything", SinkFilter{}, rec(StreamData, "chat", true, 1), true},
		{"stream kept", SinkFilter{Streams: []Stream{StreamMgmt, StreamSystem}}, rec(StreamSystem, "", true, 1), true},
		{"stream dropped", SinkFilter{Streams: []Stream{StreamMgmt}}, rec(StreamData, "chat", true, 1), false},
		{"service kept", SinkFilter{Services: []string{"chat"}}, rec(StreamData, "chat", true, 1), true},
		{"service dropped", SinkFilter{Services: []string{"chat"}}, rec(StreamData, "embed", true, 1), false},
		{"service does not judge a management record", SinkFilter{Services: []string{"chat"}}, rec(StreamMgmt, "", true, 1), true},
		{"outcome ok kept", SinkFilter{Outcome: FilterOutcomeOK}, rec(StreamData, "chat", true, 1), true},
		{"outcome ok dropped", SinkFilter{Outcome: FilterOutcomeOK}, rec(StreamData, "chat", false, 1), false},
		{"outcome failed kept", SinkFilter{Outcome: FilterOutcomeFailed}, rec(StreamMgmt, "", false, 1), true},
		{"outcome failed dropped", SinkFilter{Outcome: FilterOutcomeFailed}, rec(StreamMgmt, "", true, 1), false},
		{"sample keeps the multiple", SinkFilter{DataSample: 4}, rec(StreamData, "chat", true, 8), true},
		{"sample drops the rest", SinkFilter{DataSample: 4}, rec(StreamData, "chat", true, 9), false},
		{"sample never drops a management record", SinkFilter{DataSample: 4}, rec(StreamMgmt, "", true, 9), true},
		{"sample never drops a system record", SinkFilter{DataSample: 4}, rec(StreamSystem, "", true, 9), true},
		{"fields combine", SinkFilter{Streams: []Stream{StreamData}, Services: []string{"chat"}, Outcome: FilterOutcomeFailed},
			rec(StreamData, "chat", true, 1), false},
	}
	for _, c := range cases {
		if got := c.f.match(c.r); got != c.want {
			t.Errorf("%s: match = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestSinkTailerConfigurationRefusals(t *testing.T) {
	sink := &fakeSink{}
	dir := t.TempDir()
	cases := []struct {
		name string
		mut  func(*SinkTailerConfig)
	}{
		{"a filter on the compliance sink", func(c *SinkTailerConfig) {
			c.Compliance = true
			c.Filter = SinkFilter{Streams: []Stream{StreamMgmt}}
		}},
		{"sampling on the compliance sink", func(c *SinkTailerConfig) { c.Compliance = true; c.Filter = SinkFilter{DataSample: 10} }},
		{"an unknown stream", func(c *SinkTailerConfig) { c.Filter = SinkFilter{Streams: []Stream{"everything"}} }},
		{"an unknown outcome", func(c *SinkTailerConfig) { c.Filter = SinkFilter{Outcome: "maybe"} }},
		{"an empty service", func(c *SinkTailerConfig) { c.Filter = SinkFilter{Services: []string{""}} }},
		{"a name that leaves the state directory", func(c *SinkTailerConfig) { c.Name = "../siem" }},
		{"an empty name", func(c *SinkTailerConfig) { c.Name = "" }},
		{"no submitter", func(c *SinkTailerConfig) { c.Submitter = nil }},
	}
	for _, c := range cases {
		cfg := tailerConfig(dir, "siem", sink, nil)
		c.mut(&cfg)
		if _, err := NewSinkTailer(cfg); err == nil {
			t.Errorf("%s was accepted", c.name)
		}
	}
	if _, err := NewSinkTailer(tailerConfig(dir, "siem", sink, nil)); err != nil {
		t.Fatalf("the unmodified configuration was refused: %v", err)
	}
}

func TestSinkTailerOutageIsACursorThatDoesNotMove(t *testing.T) {
	cfg := testConfig(t)
	w := startWriter(t, cfg)
	writeN(t, w, 3, "before")

	sink := &fakeSink{}
	tc := tailerConfig(cfg.Dir, "second", sink, w)
	tc.Filter = SinkFilter{Streams: []Stream{StreamMgmt}}
	// No window: this test is about what an outage alone does.
	tc.ReconnectWindow = -1
	tl := startTailer(t, tc)
	waitFor(t, "the first records", func() bool { return len(sink.got()) == 3 })

	// The receiver goes away: nothing can be written to it.
	sink.setVerdict(func(int, []byte) error { return fmt.Errorf("dial: %w", ErrSubmitNotAttempted) })
	writeN(t, w, 4, "during")
	sealNow(t, w)
	writeN(t, w, 2, "after-rotation")
	waitFor(t, "the sink to report the outage", func() bool { return tl.Stats().State == SinkDisconnected })
	at := tl.Stats().Cursor
	time.Sleep(20 * time.Millisecond)
	if tl.Stats().Cursor != at {
		t.Fatalf("the cursor moved during the outage: %+v then %+v", at, tl.Stats().Cursor)
	}
	if n := len(sink.got()); n != 3 {
		t.Fatalf("%d frames arrived during the outage", n-3)
	}

	sink.setVerdict(nil)
	waitFor(t, "the records written during the outage", func() bool { return len(sink.got()) == 9 })
	got := sink.got()
	for i, f := range got {
		// Nothing was written while the receiver was away, so no number
		// was used: the sequence has no hole.
		if f.xseq != uint64(i+1) {
			t.Fatalf("frame %d carries xseq %d, want %d", i, f.xseq, i+1)
		}
	}
	if d := eventsOf(t, cfg.Dir, "sys.sink.disconnect"); len(d) != 1 {
		t.Fatalf("%d sys.sink.disconnect records, want 1", len(d))
	} else if detail := d[0]["detail"].(map[string]any); detail["reason"] != "unreachable" || detail["resource"] != "audit_sink:second" {
		t.Fatalf("disconnect detail %v", detail)
	}
	if c := eventsOf(t, cfg.Dir, "sys.sink.connect"); len(c) != 2 {
		t.Fatalf("%d sys.sink.connect records, want 2: one per session", len(c))
	}
}

func TestSinkTailerFailedWriteBurnsItsNumberAndResendsTheWindow(t *testing.T) {
	cfg := testConfig(t)
	w := startWriter(t, cfg)
	writeN(t, w, 10, "r")

	sink := &fakeSink{}
	// The seventh attempt fails after bytes went out.
	sink.setVerdict(func(n int, _ []byte) error {
		if n == 7 {
			return errors.New("write: broken pipe")
		}
		return nil
	})
	tc := tailerConfig(cfg.Dir, "second", sink, w)
	tc.Filter = SinkFilter{Streams: []Stream{StreamMgmt}}
	tc.ReconnectWindow = 3
	tl := startTailer(t, tc)

	// Ten records, and the three before the failure once more.
	waitFor(t, "ten records and the window", func() bool { return len(sink.got()) == 13 })
	time.Sleep(20 * time.Millisecond)
	got := sink.got()
	if len(got) != 13 {
		t.Fatalf("%d frames, want 13", len(got))
	}
	var seqs []string
	type key struct{ epoch, xseq uint64 }
	used := map[key]bool{}
	for _, f := range got {
		seqs = append(seqs, f.field(t, "seq"))
		k := key{f.epoch, f.xseq}
		if used[k] {
			t.Fatalf("xseq %d was used twice", f.xseq)
		}
		used[k] = true
	}
	first := 0
	fmt.Sscan(seqs[0], &first)
	want := []int{0, 1, 2, 3, 4, 5 /* failure at the 7th */, 3, 4, 5, 6, 7, 8, 9}
	for i := range want {
		if seqs[i] != fmt.Sprint(first+want[i]) {
			t.Fatalf("order of arrival %v, want offsets %v from %d", seqs, want, first)
		}
	}
	// The number the failed write went out under is not used again.
	if got[6].xseq != 8 {
		t.Fatalf("the first frame after the failure carries xseq %d, want 8 (7 was burnt)", got[6].xseq)
	}
	if st := tl.Stats(); st.Resent != 3 || st.SubmitErrors != 1 {
		t.Fatalf("stats %+v, want 3 resent and 1 submit error", st)
	}
	d := eventsOf(t, cfg.Dir, "sys.sink.disconnect")
	if len(d) != 1 {
		t.Fatalf("%d disconnect records, want 1", len(d))
	}
	detail := d[0]["detail"].(map[string]any)
	if detail["reason"] != "write_failed" || detail["reconnect_window_records"] != float64(3) {
		t.Fatalf("disconnect detail %v", detail)
	}
}

// The window is owed to the receiver whether or not the process that
// noticed the failure lives to send it: a sink stopped while its receiver
// is away starts again at the window, not after it.
func TestSinkTailerWindowSurvivesARestartDuringTheOutage(t *testing.T) {
	cfg := testConfig(t)
	w := startWriter(t, cfg)
	writeN(t, w, 6, "r")

	sink := &fakeSink{}
	tc := tailerConfig(cfg.Dir, "second", sink, w)
	tc.Filter = SinkFilter{Streams: []Stream{StreamMgmt}}
	tc.ReconnectWindow = 3
	tl := startTailer(t, tc)
	waitFor(t, "the first records", func() bool { return len(sink.got()) == 6 })
	// The record of the sink's own connect is written behind the records
	// that caused it. This sink is not sent it and moves past it, so its
	// place is taken once it has: the two records a writer starts with
	// and that one are what the filter has kept from it by then, and it
	// is the last record written.
	waitFor(t, "the sink to be past the record of its connect", func() bool {
		return tl.Stats().Filtered == 3 && tl.Progress().Position.Seq == w.SeqHigh()
	})
	waitFor(t, "the cursor to be saved behind them", func() bool {
		return tl.Stats().Cursor.Position == tl.Progress().Position
	})
	at := tl.Progress().Position

	// The receiver dies with the session up: a write fails after bytes
	// went out, and every attempt after it.
	sink.setVerdict(func(int, []byte) error { return errors.New("write: broken pipe") })
	writeN(t, w, 1, "during")
	waitFor(t, "the sink to report the outage", func() bool { return tl.Stats().State == SinkDisconnected })
	// The state changes before the cursor is saved; the save is what a
	// restart goes by.
	waitFor(t, "the saved cursor to go back to the start of the window", func() bool {
		saved := tl.Stats().Cursor.Position
		return saved.SegmentUUID == at.SegmentUUID && saved.Seq < at.Seq
	})
	if reached := tl.Progress().Position; reached != at {
		t.Fatalf("the sink reports itself at %+v, want %+v: what it sent it is still past", reached, at)
	}
	stopTailer(t, tl)

	sink.setVerdict(nil)
	startTailer(t, tc)
	waitFor(t, "the window and the record of the outage", func() bool { return len(sink.got()) == 10 })
	time.Sleep(20 * time.Millisecond)
	got := sink.got()
	if len(got) != 10 {
		t.Fatalf("%d frames, want 10", len(got))
	}
	type key struct{ epoch, xseq uint64 }
	used := map[key]bool{}
	for i, f := range got {
		k := key{f.epoch, f.xseq}
		if used[k] {
			t.Fatalf("xseq %d was used twice", f.xseq)
		}
		used[k] = true
		if i >= 6 && i < 9 && f.field(t, "seq") != got[i-3].field(t, "seq") {
			t.Fatalf("frame %d is seq %s, want the window's %s again", i, f.field(t, "seq"), got[i-3].field(t, "seq"))
		}
	}
	if !strings.Contains(string(got[9].raw), `"/during/0"`) {
		t.Fatalf("the record written during the outage did not follow the window: %s", got[9].raw)
	}
}

// A resend ends at the record the sink had reached. Retention can take the
// segment that record is in while the receiver is away; the resend must
// end all the same, or the cursor never moves again.
func TestSinkTailerResendEndsWhenItsPlaceWasRemoved(t *testing.T) {
	cfg := testConfig(t)
	w := startWriter(t, cfg)
	writeN(t, w, 4, "one")
	sink := &fakeSink{}
	tc := tailerConfig(cfg.Dir, "siem", sink, w)
	tc.Compliance = true
	// Wide enough that the window begins in the first segment.
	tc.ReconnectWindow = 32
	tl := startTailer(t, tc)
	settled(t, cfg.Dir, sink, 0)
	sealNow(t, w)
	writeN(t, w, 3, "two")
	settled(t, cfg.Dir, sink, 0)
	place := tl.Progress().Position.SegmentUUID
	if place != w.seg.currentUUID() {
		t.Fatalf("the sink is in %s, want the second segment %s", place, w.seg.currentUUID())
	}

	sink.setVerdict(func(int, []byte) error { return errors.New("write: broken pipe") })
	writeN(t, w, 1, "lost")
	waitFor(t, "the sink to report the outage", func() bool { return tl.Stats().State == SinkDisconnected })

	// While the receiver is away the second segment is sealed and removed.
	sealNow(t, w)
	writeN(t, w, 2, "three")
	waitCompressed(t, cfg.Dir)
	removed := 0
	entries, _ := os.ReadDir(cfg.Dir)
	for _, e := range entries {
		path := filepath.Join(cfg.Dir, e.Name())
		if _, _, ok := parseSegmentName(e.Name()); ok && readHeaderUUID(path) == place {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			removed++
		}
	}
	if removed != 1 {
		t.Fatalf("%d files held the second segment, want 1", removed)
	}

	sink.setVerdict(nil)
	waitFor(t, "the cursor to reach the segment being written", func() bool {
		return tl.Stats().Cursor.SegmentUUID == w.seg.currentUUID()
	})
	st := tl.Stats()
	if st.LagDrops != 1 {
		t.Fatalf("lag drops %d, want 1: the segment was removed before it was sent", st.LagDrops)
	}
	before := st.Resent
	writeN(t, w, 2, "four")
	waitFor(t, "the records written afterwards", func() bool {
		got := sink.got()
		return strings.Contains(string(got[len(got)-1].raw), `"/four/1"`) || strings.Contains(string(got[len(got)-2].raw), `"/four/1"`)
	})
	if after := tl.Stats().Resent; after != before {
		t.Fatalf("%d records written after the resend were sent as repeats", after-before)
	}
}

func TestSinkTailerPoisonRecordIsSkippedAndNamed(t *testing.T) {
	cfg := testConfig(t)
	w := startWriter(t, cfg)
	writeN(t, w, 6, "r")

	sink := &fakeSink{}
	sink.setVerdict(func(_ int, line []byte) error {
		if bytes.Contains(line, []byte(`"/r/2"`)) {
			return fmt.Errorf("too large: %w", ErrSubmitRejected)
		}
		return nil
	})
	tc := tailerConfig(cfg.Dir, "second", sink, w)
	tc.Filter = SinkFilter{Streams: []Stream{StreamMgmt}}
	tl := startTailer(t, tc)
	waitFor(t, "the other five records", func() bool { return len(sink.got()) == 5 })
	got := sink.got()
	for i, f := range got {
		if bytes.Contains(f.raw, []byte(`"/r/2"`)) {
			t.Fatal("the rejected record arrived")
		}
		// Nothing went out under the skipped record's number, so the
		// next record takes it.
		if f.xseq != uint64(i+1) {
			t.Fatalf("frame %d carries xseq %d, want %d", i, f.xseq, i+1)
		}
	}
	waitFor(t, "the poison record", func() bool { return len(eventsOf(t, cfg.Dir, "sys.sink.poison")) == 1 })
	detail := eventsOf(t, cfg.Dir, "sys.sink.poison")[0]["detail"].(map[string]any)
	var skipped string
	for _, raw := range rawRecords(t, cfg.Dir) {
		if bytes.Contains(raw, []byte(`"/r/2"`)) {
			skipped = frame{raw: raw}.field(t, "seq")
		}
	}
	if fmt.Sprint(detail["poison_seq"]) != skipped {
		t.Fatalf("the poison record names seq %v, the skipped record is seq %s", detail["poison_seq"], skipped)
	}
	if st := tl.Stats(); st.Poison != 1 || st.State != SinkConnected {
		t.Fatalf("stats %+v, want one poison record and a connected sink", st)
	}
}

func TestSinkTailerRejectingEverythingDoesNotFeedOnItself(t *testing.T) {
	cfg := testConfig(t)
	w := startWriter(t, cfg)
	writeN(t, w, 3, "r")
	sink := &fakeSink{}
	sink.setVerdict(func(int, []byte) error { return ErrSubmitRejected })
	tc := tailerConfig(cfg.Dir, "siem", sink, w)
	tc.Compliance = true
	tl := startTailer(t, tc)
	waitFor(t, "the sink to pass the trail", func() bool {
		return tl.Stats().Poison >= uint64(len(rawRecords(t, cfg.Dir)))
	})
	time.Sleep(50 * time.Millisecond)
	// Every record that is not about the sink is named once. The records
	// naming them are rejected too, and those are not named in turn.
	other := 0
	for _, raw := range rawRecords(t, cfg.Dir) {
		if !bytes.Contains(raw, []byte(`"event_type":"sys.sink.`)) {
			other++
		}
	}
	if n := len(eventsOf(t, cfg.Dir, "sys.sink.poison")); n != other {
		t.Fatalf("%d poison records for %d records that are not about the sink", n, other)
	}
}

func TestSinkTailerCrashBetweenSubmitAndCursorWrite(t *testing.T) {
	cfg := testConfig(t)
	w := startWriter(t, cfg)
	writeN(t, w, 6, "r")

	sink := &fakeSink{}
	tc := tailerConfig(cfg.Dir, "second", sink, w)
	tc.Filter = SinkFilter{Streams: []Stream{StreamMgmt}}
	tc.Batch = 100
	var armed atomic.Bool
	armed.Store(true)
	tc.Fault = func(p string) bool { return armed.Load() && p == FaultSinkBeforeCursorWrite }
	tc.Logf = func(format string, args ...any) { t.Logf(format, args...) }
	tl, err := NewSinkTailer(tc)
	if err != nil {
		t.Fatal(err)
	}
	// The process ends at the fault point: the goroutine stops there and
	// nothing after it runs, the clean stop included.
	died := make(chan struct{})
	tl.die = func(string) { close(died); runtime.Goexit() }
	tl.Start()
	select {
	case <-died:
	case <-time.After(5 * time.Second):
		t.Fatal("the fault point never fired")
	}
	first := sink.got()
	if len(first) != 6 {
		t.Fatalf("%d frames before the crash, want 6", len(first))
	}
	if _, ok, _ := tl.store.read(tl.store.cursorPath()); ok {
		t.Fatal("the cursor was saved although the process ended before the write")
	}

	// The next process finds no cursor and a reservation. It sends the
	// six again, and under numbers above every one the first could have
	// used.
	armed.Store(false)
	tc.Fault = nil
	tl2 := startTailer(t, tc)
	waitFor(t, "the records again", func() bool { return len(sink.got()) >= 12 })
	got := sink.got()
	type key struct{ epoch, xseq uint64 }
	used := map[key]bool{}
	for _, f := range got {
		k := key{f.epoch, f.xseq}
		if used[k] {
			t.Fatalf("xseq %d of epoch %d was used twice across the crash", f.xseq, f.epoch)
		}
		used[k] = true
	}
	if got[6].epoch != got[0].epoch {
		t.Fatalf("the epoch changed across the crash: %d then %d", got[0].epoch, got[6].epoch)
	}
	if got[6].xseq != 17 {
		t.Fatalf("the first number after the crash is %d, want 17: above the block of 16 reserved before it", got[6].xseq)
	}
	_ = tl2
}

func TestSinkTailerReportsACursorResetBeforeActingOnIt(t *testing.T) {
	cfg := testConfig(t)
	w := startWriter(t, cfg)
	writeN(t, w, 5, "r")
	sink := &fakeSink{}
	tc := tailerConfig(cfg.Dir, "second", sink, w)
	tc.Filter = SinkFilter{Streams: []Stream{StreamMgmt}}
	tc.Batch = 2
	tc.Reserve = 4
	var crash atomic.Bool
	tc.Fault = func(p string) bool { return crash.Load() && p == FaultSinkBeforeCursorWrite }
	tc.Logf = func(format string, args ...any) { t.Logf(format, args...) }
	tl, err := NewSinkTailer(tc)
	if err != nil {
		t.Fatal(err)
	}
	tl.die = func(string) { runtime.Goexit() }
	tl.Start()
	waitFor(t, "the records", func() bool { return len(sink.got()) == 5 })
	waitFor(t, "the cursor behind them", func() bool { return tl.Stats().Cursor.XseqHigh == 5 })
	if n := len(eventsOf(t, cfg.Dir, "sys.sink.cursor_reset")); n != 0 {
		t.Fatalf("%d cursor_reset records on a sink that never lost its cursor", n)
	}

	// The process is lost without a clean stop and its cursor file is
	// damaged. What is left is the reservation written when the second
	// block of four was opened: the place behind the fourth record.
	crash.Store(true)
	writeN(t, w, 1, "trigger")
	waitFor(t, "the tailer to end", func() bool {
		select {
		case <-tl.done:
			return true
		default:
			return false
		}
	})
	cursor := filepath.Join(cfg.Dir, SinkStateDirName, "second.cursor")
	if err := os.WriteFile(cursor, []byte("{"), fileMode); err != nil {
		t.Fatal(err)
	}
	before := len(sink.got())

	// The receiver notes how many reset records the trail held when the
	// first frame of the new process arrived.
	resetsAtFirstFrame := -1
	sink.setVerdict(func(int, []byte) error {
		if resetsAtFirstFrame < 0 {
			resetsAtFirstFrame = len(eventsOf(t, cfg.Dir, "sys.sink.cursor_reset"))
		}
		return nil
	})
	tc.Fault = nil
	// The reset is announced through the durable path: it has to be on
	// stable storage before the sink acts on the rebuilt cursor.
	var resetDurable atomic.Int32
	tc.Emit = func(ctx context.Context, r *Record, durable bool) error {
		if r.EventType == "sys.sink.cursor_reset" {
			if durable {
				resetDurable.Store(1)
			} else {
				resetDurable.Store(-1)
			}
		}
		return w.EmitSystem(ctx, r, durable)
	}
	startTailer(t, tc)
	waitFor(t, "the records after the reservation's place, again", func() bool { return len(sink.got()) >= before+2 })
	if resetDurable.Load() != 1 {
		t.Fatalf("the cursor_reset record was not written through the durable path (%d)", resetDurable.Load())
	}
	if resetsAtFirstFrame != 1 {
		t.Fatalf("the trail held %d cursor_reset records when the first frame after the reset arrived, want 1", resetsAtFirstFrame)
	}
	detail := eventsOf(t, cfg.Dir, "sys.sink.cursor_reset")[0]["detail"].(map[string]any)
	if detail["method"] != CursorFromReservation || detail["new_cursor"] == nil {
		t.Fatalf("cursor_reset detail %v", detail)
	}
	// The same epoch, and numbers above the reserved block of the lost
	// process.
	got := sink.got()
	if got[before].epoch != got[0].epoch || got[before].xseq != 9 {
		t.Fatalf("after the reset: epoch %d xseq %d, want epoch %d and xseq 9", got[before].epoch, got[before].xseq, got[0].epoch)
	}
	if !bytes.Contains(got[before].raw, []byte(`"/r/4"`)) {
		t.Fatalf("the first frame after the reset is %s, want the fifth record: the one after the reservation's place", got[before].raw)
	}
}

func TestSinkTailerSegmentRemovedBeforeItWasSent(t *testing.T) {
	cfg := testConfig(t)
	w := startWriter(t, cfg)
	writeN(t, w, 3, "one")
	sink := &fakeSink{}
	tc := tailerConfig(cfg.Dir, "siem", sink, w)
	tc.Compliance = true
	tl := startTailer(t, tc)
	settled(t, cfg.Dir, sink, 0)
	stopTailer(t, tl)

	// While the sink is away the trail rotates twice and retention takes
	// every sealed segment, the one the cursor is in among them.
	sealNow(t, w)
	writeN(t, w, 3, "two")
	sealNow(t, w)
	writeN(t, w, 2, "three")
	// Compression renames a sealed segment; the directory is listed once
	// it has finished, so that every name listed is still there to remove
	// and none appears afterwards.
	waitCompressed(t, cfg.Dir)
	entries, _ := os.ReadDir(cfg.Dir)
	for _, e := range entries {
		if _, _, ok := parseSegmentName(e.Name()); ok {
			if err := os.Remove(filepath.Join(cfg.Dir, e.Name())); err != nil {
				t.Fatal(err)
			}
		}
	}
	before := len(sink.got())
	tl2 := startTailer(t, tc)
	waitFor(t, "the sink to continue from what is left", func() bool {
		return len(sink.got()) >= before+len(rawRecords(t, cfg.Dir))
	})
	if tl2.Stats().LagDrops != 1 {
		t.Fatalf("lag drops %d, want 1", tl2.Stats().LagDrops)
	}
	var arrived []string
	for _, f := range sink.got()[before:] {
		arrived = append(arrived, string(f.raw))
	}
	if !strings.Contains(strings.Join(arrived, "\n"), `"/three/1"`) {
		t.Fatal("the records still in the trail did not arrive")
	}
	if strings.Contains(strings.Join(arrived, "\n"), `"/two/`) {
		t.Fatal("a record of a removed segment arrived")
	}
}

func TestSinkTailerReportsASegmentItCannotRead(t *testing.T) {
	cfg := testConfig(t)
	w := startWriter(t, cfg)
	writeN(t, w, 3, "one")
	sink := &fakeSink{}
	tc := tailerConfig(cfg.Dir, "siem", sink, w)
	tc.Compliance = true
	tl := startTailer(t, tc)
	settled(t, cfg.Dir, sink, 0)
	stopTailer(t, tl)

	// While the sink is away the trail rotates twice, and the newer of
	// the two sealed segments is damaged where it lies: it is cut short,
	// so that it still says which segment it is and cannot be read out.
	sealNow(t, w)
	writeN(t, w, 3, "two")
	sealNow(t, w)
	writeN(t, w, 2, "three")
	waitCompressed(t, cfg.Dir)
	var damaged string
	entries, _ := os.ReadDir(cfg.Dir)
	for _, e := range entries {
		if _, gz, ok := parseSegmentName(e.Name()); ok && gz {
			damaged = filepath.Join(cfg.Dir, e.Name())
		}
	}
	if damaged == "" {
		t.Fatal("no compressed segment to damage")
	}
	whole, err := os.ReadFile(damaged)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(damaged, whole[:len(whole)*3/4], fileMode); err != nil {
		t.Fatal(err)
	}
	if hdr, ok := readSegmentHeader(damaged); !ok || hdr.SegmentUUID == "" {
		t.Fatal("the cut took the segment's header with it; the test needs a segment that is still listed")
	}

	before := len(sink.got())
	tl2 := startTailer(t, tc)
	waitFor(t, "the sink to stall", func() bool { return tl2.Stats().State == SinkStalled })
	waitFor(t, "further attempts on the same segment", func() bool { return tl2.Stats().ReadErrors >= 4 })
	failed := eventsOf(t, cfg.Dir, "sys.sink.cursor_recovery_failed")
	if len(failed) != 1 {
		t.Fatalf("%d cursor_recovery_failed records for one stall, want 1", len(failed))
	}
	detail, _ := failed[0]["detail"].(map[string]any)
	if detail["resource"] != "audit_sink:siem" || detail["errno_class"] != "other" {
		t.Fatalf("the record does not name the sink and the class of the failure: %v", detail)
	}
	if at, _ := detail["cursor"].(map[string]any); at["segment_uuid"] == nil || at["segment_uuid"] == "" {
		t.Fatalf("the record does not name the place the sink stands at: %v", detail)
	}
	for _, f := range sink.got()[before:] {
		if strings.Contains(string(f.raw), `"/three/`) {
			t.Fatal("the sink went past a segment it could not read")
		}
	}

	// The segment is taken away. What was in it is lost to this sink; the
	// records behind it are not.
	if err := os.Remove(damaged); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the records behind the damaged segment", func() bool {
		var arrived []string
		for _, f := range sink.got()[before:] {
			arrived = append(arrived, string(f.raw))
		}
		return strings.Contains(strings.Join(arrived, "\n"), `"/three/1"`)
	})
	if tl2.Stats().State == SinkStalled {
		t.Fatal("the sink still reports itself stalled after it continued")
	}
}

func TestSinkTailerDoesNotPassOverASegmentWithoutAHeader(t *testing.T) {
	cfg := testConfig(t)
	w := startWriter(t, cfg)
	writeN(t, w, 3, "one")
	sink := &fakeSink{}
	tc := tailerConfig(cfg.Dir, "siem", sink, w)
	tc.Compliance = true
	tl := startTailer(t, tc)
	settled(t, cfg.Dir, sink, 0)
	stopTailer(t, tl)

	// The newer of two sealed segments no longer says which segment it
	// is: nothing in it can be read, not even its first line.
	sealNow(t, w)
	writeN(t, w, 3, "two")
	sealNow(t, w)
	writeN(t, w, 2, "three")
	waitCompressed(t, cfg.Dir)
	var damaged string
	entries, _ := os.ReadDir(cfg.Dir)
	for _, e := range entries {
		if _, gz, ok := parseSegmentName(e.Name()); ok && gz {
			damaged = filepath.Join(cfg.Dir, e.Name())
		}
	}
	if damaged == "" {
		t.Fatal("no compressed segment to damage")
	}
	if err := os.WriteFile(damaged, []byte("not a compressed segment\n"), fileMode); err != nil {
		t.Fatal(err)
	}

	before := len(sink.got())
	arrived := func() string {
		var out []string
		for _, f := range sink.got()[before:] {
			out = append(out, string(f.raw))
		}
		return strings.Join(out, "\n")
	}
	tl2 := startTailer(t, tc)
	waitFor(t, "the sink to stall", func() bool { return tl2.Stats().State == SinkStalled })
	waitFor(t, "further attempts on the same segment", func() bool { return tl2.Stats().ReadErrors >= 4 })
	if strings.Contains(arrived(), `"/three/`) {
		t.Fatal("the sink went past a segment it could not read")
	}
	if last := tl2.Stats().LastError; !strings.Contains(last, filepath.Base(damaged)) {
		t.Fatalf("the sink does not name the segment it stands before: %q", last)
	}

	// The damaged file cannot be parsed by the helpers that read the
	// whole directory, so the trail is looked at once it is gone.
	if err := os.Remove(damaged); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the records behind the damaged segment", func() bool {
		return strings.Contains(arrived(), `"/three/1"`)
	})
	if n := len(eventsOf(t, cfg.Dir, "sys.sink.cursor_recovery_failed")); n != 1 {
		t.Fatalf("%d cursor_recovery_failed records for one stall, want 1", n)
	}
}

func TestSinkTailerStallsWithoutAReservedNumber(t *testing.T) {
	cfg := testConfig(t)
	w := startWriter(t, cfg)
	writeN(t, w, 3, "r")
	// The state directory's place is taken by a file before the sink
	// starts: no number can be reserved, so nothing may be sent.
	state := filepath.Join(cfg.Dir, SinkStateDirName)
	if err := os.WriteFile(state, nil, fileMode); err != nil {
		t.Fatal(err)
	}
	sink := &fakeSink{}
	tc := tailerConfig(cfg.Dir, "second", sink, w)
	tc.Filter = SinkFilter{Streams: []Stream{StreamMgmt}}
	tl := startTailer(t, tc)
	waitFor(t, "the sink to stall", func() bool { return tl.Stats().State == SinkStalled })
	time.Sleep(20 * time.Millisecond)
	if n := len(sink.got()); n != 0 {
		t.Fatalf("%d frames were sent without a reserved number", n)
	}
	if err := os.Remove(state); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the records once a number can be reserved", func() bool { return len(sink.got()) == 3 })
	if got := sink.got(); got[0].xseq != 1 {
		t.Fatalf("the first frame carries xseq %d, want 1", got[0].xseq)
	}
}
