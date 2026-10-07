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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// modelFS is a filesystem that can lose power. It keeps what a real one
// keeps apart: the content of a file is durable once the file was flushed,
// and a name (a create or a rename) is durable once its directory was
// flushed. crash() throws away everything that was not.
type modelFS struct {
	live    map[string]*modelFile
	durable map[string]*modelFile
	// ops counts calls; crashAt makes the call with that number panic
	// instead of running, which is a power loss between two calls.
	ops     int
	crashAt int
}

type modelFile struct {
	data   []byte
	synced []byte
}

type powerLoss struct{}

func newModelFS() *modelFS {
	return &modelFS{live: map[string]*modelFile{}, durable: map[string]*modelFile{}, crashAt: -1}
}

func (m *modelFS) step() {
	if m.ops == m.crashAt {
		m.ops++
		panic(powerLoss{})
	}
	m.ops++
}

func (m *modelFS) WriteFile(path string, data []byte, sync bool) error {
	m.step()
	f := &modelFile{data: append([]byte(nil), data...)}
	if sync {
		f.synced = f.data
	}
	m.live[path] = f
	return nil
}

func (m *modelFS) Rename(oldpath, newpath string) error {
	m.step()
	f, ok := m.live[oldpath]
	if !ok {
		return fs.ErrNotExist
	}
	m.live[newpath] = f
	delete(m.live, oldpath)
	return nil
}

func (m *modelFS) SyncDir(string) error {
	m.step()
	m.durable = make(map[string]*modelFile, len(m.live))
	for k, v := range m.live {
		m.durable[k] = v
	}
	return nil
}

func (m *modelFS) ReadFile(path string) ([]byte, error) {
	f, ok := m.live[path]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return append([]byte(nil), f.data...), nil
}

func (m *modelFS) MkdirAll(string) error { return nil }

func (m *modelFS) crash() {
	m.live = make(map[string]*modelFile, len(m.durable))
	for k, v := range m.durable {
		v.data = v.synced
		m.live[k] = v
	}
}

func modelStore(m *modelFS) *cursorStore {
	return &cursorStore{fs: m, dir: "/audit/sink", name: "siem",
		fault: func(string) bool { return false }, die: func(string) {}}
}

// sent is one frame as the receiver saw it.
type sent struct {
	rec   int
	xseq  uint64
	epoch uint64
}

// exportRun drives an export sequence the way a sink does, over records
// numbered 1..total: a number is taken, the record is "sent", and the
// cursor is committed after every batch. A power loss is injected before
// the filesystem call numbered crashAt of each process; after it the sink
// starts again from what the filesystem kept. clock moves forward by one
// second per start.
func exportRun(t *testing.T, m *modelFS, total, batch int, reserve uint64, crashes []int) (out []sent, recs []CursorRecovery) {
	t.Helper()
	clock := time.Unix(1_700_000_000, 0)
	for run := 0; ; run++ {
		m.ops, m.crashAt = 0, -1
		if run < len(crashes) {
			m.crashAt = crashes[run]
		}
		done := func() (finished bool) {
			defer func() {
				if r := recover(); r != nil {
					if _, ok := r.(powerLoss); !ok {
						panic(r)
					}
					m.crash()
				}
			}()
			clock = clock.Add(time.Second)
			e, rec := openExportSeq(modelStore(m), reserve, func() time.Time { return clock })
			recs = append(recs, rec)
			// The position's seq is the record number; the segment is
			// one and the same throughout.
			at := int(e.cursor().Seq)
			for at < total {
				end := at + batch
				if end > total {
					end = total
				}
				for i := at + 1; i <= end; i++ {
					x, err := e.next()
					if err != nil {
						t.Fatalf("next: %v", err)
					}
					out = append(out, sent{rec: i, xseq: x, epoch: e.cursor().XseqEpoch})
				}
				if err := e.commit(Position{SegmentUUID: "u1", Seq: uint64(end)}, Position{}); err != nil {
					t.Fatalf("commit: %v", err)
				}
				at = end
			}
			if err := e.close(); err != nil {
				t.Fatalf("close: %v", err)
			}
			return true
		}()
		if done {
			return out, recs
		}
		if run > len(crashes)+1 {
			t.Fatal("the run did not finish after its last crash")
		}
	}
}

// checkExport asserts the two properties a receiver relies on: no export
// sequence number appears twice in one epoch, and every record arrived.
func checkExport(t *testing.T, what string, out []sent, total int) {
	t.Helper()
	type key struct{ epoch, xseq uint64 }
	seen := map[key]int{}
	got := map[int]bool{}
	for _, s := range out {
		k := key{s.epoch, s.xseq}
		if prev, dup := seen[k]; dup {
			t.Fatalf("%s: xseq %d of epoch %d was used for record %d and again for record %d",
				what, s.xseq, s.epoch, prev, s.rec)
		}
		seen[k] = s.rec
		got[s.rec] = true
	}
	for i := 1; i <= total; i++ {
		if !got[i] {
			t.Fatalf("%s: record %d never reached the receiver", what, i)
		}
	}
}

func TestExportSeqIsContiguousWithoutACrash(t *testing.T) {
	m := newModelFS()
	out, recs := exportRun(t, m, 50, 7, 16, nil)
	checkExport(t, "no crash", out, 50)
	if len(out) != 50 {
		t.Fatalf("%d frames for 50 records: something was sent twice", len(out))
	}
	for i, s := range out {
		if s.xseq != uint64(i+1) {
			t.Fatalf("frame %d carries xseq %d, want %d", i, s.xseq, i+1)
		}
	}
	if recs[0].Method != CursorFresh || recs[0].EpochChanged {
		t.Fatalf("first start: %+v, want fresh and no epoch change", recs[0])
	}
}

func TestExportSeqCleanRestartContinuesWithTheNextNumber(t *testing.T) {
	m := newModelFS()
	out1, _ := exportRun(t, m, 20, 6, 16, nil)
	// A second process over the same state, 20 more records.
	clock := time.Unix(1_800_000_000, 0)
	e, rec := openExportSeq(modelStore(m), 16, func() time.Time { return clock })
	if rec.Method != CursorResumed || rec.EpochChanged {
		t.Fatalf("restart: %+v, want resumed and the same epoch", rec)
	}
	if got := e.cursor(); got.Seq != 20 || got.XseqHigh != 20 || got.XseqEpoch != out1[0].epoch {
		t.Fatalf("restart at %+v, want seq 20, xseq_high 20, epoch %d", got, out1[0].epoch)
	}
	x, err := e.next()
	if err != nil || x != 21 {
		t.Fatalf("first number after a clean restart: %d (%v), want 21", x, err)
	}
}

// TestExportSeqNeverReusesANumberAcrossAPowerLoss cuts the power before
// every filesystem call of a run in turn, and once more in the run that
// follows each of those.
func TestExportSeqNeverReusesANumberAcrossAPowerLoss(t *testing.T) {
	const total, batch, reserve = 40, 5, 8
	ref := newModelFS()
	exportRun(t, ref, total, batch, reserve, nil)
	calls := ref.ops
	if calls < 30 {
		t.Fatalf("the reference run made %d filesystem calls; the sweep would prove little", calls)
	}
	holes := 0
	for k := 0; k < calls; k++ {
		for _, second := range []int{-1, 0, 1, 2, 3, 5, 8} {
			crashes := []int{k}
			if second >= 0 {
				crashes = append(crashes, second)
			}
			m := newModelFS()
			out, recs := exportRun(t, m, total, batch, reserve, crashes)
			what := fmt.Sprintf("power loss before calls %v", crashes)
			checkExport(t, what, out, total)
			var high uint64
			for _, s := range out {
				if s.xseq > high {
					high = s.xseq
				}
			}
			if high > uint64(total) {
				holes++
			}
			// A hole is bounded by one block per crash, plus the
			// records re-sent after it.
			if limit := uint64(total + len(crashes)*(reserve+batch+reserve)); high > limit {
				t.Fatalf("%s: xseq reached %d, want at most %d", what, high, limit)
			}
			for _, r := range recs[1:] {
				if r.EpochChanged && r.Method != CursorFresh {
					t.Fatalf("%s: the epoch changed although the reservation was never lost: %+v", what, r)
				}
			}
		}
	}
	if holes == 0 {
		t.Fatal("no run left a hole in xseq: the crashes never landed inside a reserved block")
	}
}

func realStore(t *testing.T) *cursorStore {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "audit")
	if err := os.MkdirAll(dir, dirMode); err != nil {
		t.Fatal(err)
	}
	return newCursorStore(dir, "siem", nil)
}

func fixedClock(sec int64) func() time.Time {
	return func() time.Time { return time.Unix(sec, 0) }
}

// usedExportSeq leaves a sink that sent 10 records and then lost its
// process without a clean stop.
func usedExportSeq(t *testing.T, s *cursorStore) SinkCursor {
	t.Helper()
	e, _ := openExportSeq(s, 16, fixedClock(1000))
	for i := 1; i <= 10; i++ {
		if _, err := e.next(); err != nil {
			t.Fatal(err)
		}
		if i == 4 {
			if err := e.commit(Position{SegmentUUID: "u1", Seq: 4}, Position{}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := e.commit(Position{SegmentUUID: "u2", Seq: 10}, Position{}); err != nil {
		t.Fatal(err)
	}
	return e.cursor()
}

func TestCursorFilesOnARealFilesystem(t *testing.T) {
	s := realStore(t)
	last := usedExportSeq(t, s)
	for _, p := range []string{s.cursorPath(), s.reservationPath()} {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != fileMode {
			t.Fatalf("%s mode %04o, want %04o", p, st.Mode().Perm(), fileMode)
		}
		if _, err := os.Stat(p + ".tmp"); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("%s.tmp was left behind", p)
		}
	}
	st, err := os.Stat(s.dir)
	if err != nil || st.Mode().Perm() != dirMode {
		t.Fatalf("state directory: %v mode %v, want %04o", err, st.Mode().Perm(), dirMode)
	}
	got, ok, _ := s.read(s.cursorPath())
	if !ok || got != last {
		t.Fatalf("cursor file holds %+v (readable %v), want %+v", got, ok, last)
	}
	resv, ok, _ := s.read(s.reservationPath())
	if !ok || resv.XseqHigh != 16 || resv.XseqEpoch != 1000 {
		t.Fatalf("reservation holds %+v (readable %v), want xseq_high 16 in epoch 1000", resv, ok)
	}
}

func TestExportSeqAfterAnUncleanStop(t *testing.T) {
	s := realStore(t)
	last := usedExportSeq(t, s)
	e, rec := openExportSeq(s, 16, fixedClock(2000))
	if rec.Method != CursorResumed || rec.EpochChanged || e.cursor().Position != last.Position {
		t.Fatalf("recovery %+v at %+v, want resumed at %+v", rec, e.cursor(), last.Position)
	}
	// Ten numbers were used and sixteen were reserved. Which of the
	// reserved ones went out is not knowable, so none is handed out again.
	if x, err := e.next(); err != nil || x != 17 {
		t.Fatalf("first number: %d (%v), want 17", x, err)
	}
	if e.cursor().XseqEpoch != 1000 {
		t.Fatalf("epoch %d, want the same 1000", e.cursor().XseqEpoch)
	}
}

func TestExportSeqCursorFileCutShort(t *testing.T) {
	s := realStore(t)
	usedExportSeq(t, s)
	data, err := os.ReadFile(s.cursorPath())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.cursorPath(), data[:len(data)/2], fileMode); err != nil {
		t.Fatal(err)
	}
	e, rec := openExportSeq(s, 16, fixedClock(2000))
	// The place comes from the reservation, which was written when the
	// block was opened: before the first record. Everything is re-sent,
	// under new numbers of the same epoch.
	if rec.Method != CursorFromReservation || rec.EpochChanged {
		t.Fatalf("recovery %+v, want the place from the reservation and the same epoch", rec)
	}
	if got := e.cursor(); got.Position != (Position{}) || got.XseqEpoch != 1000 {
		t.Fatalf("continues at %+v, want the reservation's place and epoch 1000", got)
	}
	if x, _ := e.next(); x != 17 {
		t.Fatalf("first number: %d, want 17", x)
	}
}

func TestExportSeqPlaceFromALaterReservation(t *testing.T) {
	s := realStore(t)
	e, _ := openExportSeq(s, 4, fixedClock(1000))
	for i := 1; i <= 6; i++ {
		if _, err := e.next(); err != nil {
			t.Fatal(err)
		}
		// The fifth number opens the second block, and the reservation
		// written for it carries the place committed just before.
		if i == 4 {
			if err := e.commit(Position{SegmentUUID: "u1", Seq: 4}, Position{}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := e.commit(Position{SegmentUUID: "u1", Seq: 6}, Position{}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.cursorPath(), []byte("{"), fileMode); err != nil {
		t.Fatal(err)
	}
	e2, rec := openExportSeq(s, 4, fixedClock(2000))
	want := Position{SegmentUUID: "u1", Seq: 4}
	if rec.Method != CursorFromReservation || e2.cursor().Position != want {
		t.Fatalf("recovery %+v at %+v, want the reservation's place %+v", rec, e2.cursor().Position, want)
	}
	if x, _ := e2.next(); x != 9 {
		t.Fatalf("first number: %d, want 9", x)
	}
}

func TestExportSeqCursorFileAltered(t *testing.T) {
	s := realStore(t)
	usedExportSeq(t, s)
	data, err := os.ReadFile(s.cursorPath())
	if err != nil {
		t.Fatal(err)
	}
	// One digit of the record changes; the line is still valid JSON.
	i := len(`{"segment_uuid":"u2","seq":1`)
	if data[i] != '0' {
		t.Fatalf("the test's offset is off: byte %d is %q in %s", i, data[i], data)
	}
	data[i] = '9'
	if err := os.WriteFile(s.cursorPath(), data, fileMode); err != nil {
		t.Fatal(err)
	}
	if _, rec := openExportSeq(s, 16, fixedClock(2000)); rec.Method != CursorFromReservation {
		t.Fatalf("recovery %+v: an altered cursor was believed", rec)
	}
}

func TestExportSeqReservationLost(t *testing.T) {
	s := realStore(t)
	last := usedExportSeq(t, s)
	if err := os.Remove(s.reservationPath()); err != nil {
		t.Fatal(err)
	}
	e, rec := openExportSeq(s, 16, fixedClock(2000))
	// The place is intact. Which numbers were used is not, so the count
	// starts again under an epoch a receiver has not seen.
	if !rec.EpochChanged || e.cursor().Position != last.Position {
		t.Fatalf("recovery %+v at %+v, want a new epoch at the same place", rec, e.cursor())
	}
	if e.cursor().XseqEpoch != 2000 {
		t.Fatalf("epoch %d, want 2000", e.cursor().XseqEpoch)
	}
	if x, _ := e.next(); x != 1 {
		t.Fatalf("first number of the new epoch: %d, want 1", x)
	}
}

func TestExportSeqAllStateLost(t *testing.T) {
	s := realStore(t)
	usedExportSeq(t, s)
	// One file removed, the other unreadable: not the state of a sink
	// that never ran.
	if err := os.Remove(s.cursorPath()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.reservationPath(), nil, fileMode); err != nil {
		t.Fatal(err)
	}
	e, rec := openExportSeq(s, 16, fixedClock(2000))
	if rec.Method != CursorFromOldest || !rec.EpochChanged {
		t.Fatalf("recovery %+v, want a start from the oldest segment under a new epoch", rec)
	}
	if got := e.cursor(); got.Position != (Position{}) || got.XseqEpoch != 2000 || got.XseqHigh != 0 {
		t.Fatalf("continues at %+v, want the zero position, epoch 2000, no number used", got)
	}
}

func TestExportSeqEpochWithAClockSetBack(t *testing.T) {
	s := realStore(t)
	usedExportSeq(t, s) // epoch 1000
	if err := os.Remove(s.reservationPath()); err != nil {
		t.Fatal(err)
	}
	// The clock now reads earlier than the epoch in use. The cursor
	// still names that epoch, and the new one must be above it.
	e, _ := openExportSeq(s, 16, fixedClock(500))
	if e.cursor().XseqEpoch != 1001 {
		t.Fatalf("epoch %d, want 1001", e.cursor().XseqEpoch)
	}
}

func TestExportSeqReservationThatCannotBeWritten(t *testing.T) {
	s := realStore(t)
	e, _ := openExportSeq(s, 4, fixedClock(1000))
	for i := 0; i < 4; i++ {
		if _, err := e.next(); err != nil {
			t.Fatal(err)
		}
	}
	// The state directory is replaced by a file: the next block cannot
	// be reserved.
	if err := os.RemoveAll(s.dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.dir, nil, fileMode); err != nil {
		t.Fatal(err)
	}
	if x, err := e.next(); err == nil {
		t.Fatalf("number %d was handed out although its block could not be reserved", x)
	}
	if e.cursor().XseqHigh != 4 {
		t.Fatalf("xseq_high moved to %d on a refused number", e.cursor().XseqHigh)
	}
	// Once the directory is back the same number is handed out: a
	// refused number was never used.
	if err := os.Remove(s.dir); err != nil {
		t.Fatal(err)
	}
	if x, err := e.next(); err != nil || x != 5 {
		t.Fatalf("after the directory came back: %d (%v), want 5", x, err)
	}
}

func TestCursorFaultPointStopsBeforeTheDirectoryFlush(t *testing.T) {
	m := newModelFS()
	s := modelStore(m)
	died := ""
	s.fault = func(p string) bool { return p == FaultSinkCursorAfterRename }
	s.die = func(p string) { died = p; panic(powerLoss{}) }
	func() {
		defer func() { _ = recover() }()
		_ = s.save(s.cursorPath(), SinkCursor{XseqHigh: 1})
	}()
	if died != FaultSinkCursorAfterRename {
		t.Fatalf("the point did not fire (died at %q)", died)
	}
	if _, ok := m.live[s.cursorPath()]; !ok {
		t.Fatal("the rename had not happened when the point fired")
	}
	if _, ok := m.durable[s.cursorPath()]; ok {
		t.Fatal("the directory had been flushed when the point fired")
	}
}

// The resend a run left owed is in the cursor file and is what the next
// run finds. It is carried to a clean stop unchanged, cleared by a save
// that owes nothing, and a file written before there was such a thing
// reads as owing nothing.
func TestExportSeqKeepsTheResendThatIsOwed(t *testing.T) {
	store := realStore(t)
	now := func() time.Time { return time.Unix(1_800_000_000, 0) }
	at, from := Position{SegmentUUID: "u2", Seq: 30}, Position{SegmentUUID: "u1", Seq: 21}

	e, _ := openExportSeq(store, 16, now)
	if got := e.resendFrom(); got != (Position{}) {
		t.Fatalf("a sink with no state owes a resend from %+v", got)
	}
	if err := e.commit(at, from); err != nil {
		t.Fatal(err)
	}
	if err := e.close(); err != nil {
		t.Fatal(err)
	}

	e, rec := openExportSeq(store, 16, now)
	if rec.Method != CursorResumed || e.cursor().Position != at || e.resendFrom() != from {
		t.Fatalf("reopened at %+v owing from %+v (%s), want %+v owing from %+v", e.cursor().Position, e.resendFrom(), rec.Method, at, from)
	}
	// What a reader of the cursor alone sees has not changed.
	data, err := os.ReadFile(store.cursorPath())
	if err != nil {
		t.Fatal(err)
	}
	if c, err := decodeCursor(data); err != nil || c.Position != at {
		t.Fatalf("the cursor reads as %+v (%v), want %+v", c, err, at)
	}

	if err := e.commit(at, Position{}); err != nil {
		t.Fatal(err)
	}
	if e, _ = openExportSeq(store, 16, now); e.resendFrom() != (Position{}) {
		t.Fatalf("a save that owed nothing left a resend from %+v", e.resendFrom())
	}

	// A file of the form without the field.
	if err := os.WriteFile(store.cursorPath(), encodeCursor(SinkCursor{Position: at, XseqHigh: 3, XseqEpoch: 9}), fileMode); err != nil {
		t.Fatal(err)
	}
	if e, _ = openExportSeq(store, 16, now); e.cursor().Position != at || e.resendFrom() != (Position{}) {
		t.Fatalf("an earlier file reads as %+v owing from %+v", e.cursor().Position, e.resendFrom())
	}
}
