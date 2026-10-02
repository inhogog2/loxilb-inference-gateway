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
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// SinkStateDirName is the directory, inside the audit directory, that
// holds what each sink must remember across restarts.
const SinkStateDirName = "sink"

// DefaultExportReserve is how many export sequence numbers are set aside
// by one durable write. It is also the largest hole a crash can leave in a
// sink's export sequence.
const DefaultExportReserve = 1024

// SinkCursor is what a sink remembers: the last record it is past, and
// where its export sequence stands.
//
// The export sequence exists because a sink that receives a filtered
// subset of the trail sees holes in seq by construction and cannot tell a
// filtered record from a lost one. Xseq counts what was sent to that one
// sink, so it is contiguous there. XseqEpoch changes whenever the count
// has to start again, so a receiver sees a new epoch and never a sequence
// that went backwards.
type SinkCursor struct {
	Position
	XseqHigh  uint64 `json:"xseq_high"`
	XseqEpoch uint64 `json:"xseq_epoch"`
}

// cursorFS is the set of file operations the cursor's durability rests
// on. It is an interface so that the tests can put a model of a
// filesystem that loses power in its place: what a crash leaves behind is
// decided by which of these calls had returned, and no real filesystem
// lets a test choose that.
type cursorFS interface {
	// WriteFile creates or replaces path with data. With sync set the
	// data is flushed to stable storage before it returns.
	WriteFile(path string, data []byte, sync bool) error
	Rename(oldpath, newpath string) error
	// SyncDir flushes the directory itself, which is what makes a
	// rename or a newly created name survive a power loss.
	SyncDir(dir string) error
	ReadFile(path string) ([]byte, error)
	MkdirAll(dir string) error
}

type osCursorFS struct{}

func (osCursorFS) WriteFile(path string, data []byte, sync bool) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, fileMode)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil && sync {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

func (osCursorFS) Rename(oldpath, newpath string) error { return os.Rename(oldpath, newpath) }

func (osCursorFS) SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}

func (osCursorFS) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) }

func (o osCursorFS) MkdirAll(dir string) error {
	if st, err := os.Stat(dir); err == nil && st.IsDir() {
		return nil
	}
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return err
	}
	// MkdirAll honours the umask; make the mode explicit.
	if err := os.Chmod(dir, dirMode); err != nil {
		return err
	}
	// A new directory is a new name in its parent, and is no more
	// durable than any other name until the parent is flushed.
	return o.SyncDir(filepath.Dir(dir))
}

// cursorStore keeps two small files for one sink.
//
// <name>.cursor is the cursor itself, rewritten after every batch the sink
// accepted. <name>.xseq is the reservation: the highest export sequence
// number the sink is allowed to have used, written before the first number
// of each block is handed out, together with the position at that time.
//
// They are two files because they answer two questions that fail
// differently. Losing the cursor only loses the place, and a place can be
// taken again from further back: records are then sent twice, which a
// receiver removes by (instance_id, boot_id, seq). Losing the reservation
// loses the proof of which numbers were used, and no number may be used
// twice, so that loss can only be answered with a new epoch.
type cursorStore struct {
	fs   cursorFS
	dir  string
	name string
	// fault and die serve the fault-enabled build: a point that is armed
	// ends the process at that exact step, which is how a harness puts a
	// crash between two steps of the protocol.
	fault func(string) bool
	die   func(string)
}

func newCursorStore(auditDir, sink string, fault func(string) bool) *cursorStore {
	if fault == nil {
		fault = func(string) bool { return false }
	}
	return &cursorStore{
		fs:    osCursorFS{},
		dir:   filepath.Join(auditDir, SinkStateDirName),
		name:  sink,
		fault: fault,
		die: func(point string) {
			fmt.Fprintf(os.Stderr, "audit: fault point %s: exiting\n", point)
			os.Exit(86)
		},
	}
}

func (s *cursorStore) cursorPath() string      { return filepath.Join(s.dir, s.name+".cursor") }
func (s *cursorStore) reservationPath() string { return filepath.Join(s.dir, s.name+".xseq") }

// encodeCursor is the file's content: the record as one JSON line and a
// checksum of that line on the next. A file cut short, emptied or altered
// fails one of the two and is treated as unreadable, never half-believed.
func encodeCursor(c SinkCursor) []byte {
	body, _ := json.Marshal(c)
	out := make([]byte, 0, len(body)+12)
	out = append(out, body...)
	out = append(out, '\n')
	out = strconv.AppendUint(out, uint64(crc32.ChecksumIEEE(body)), 16)
	return append(out, '\n')
}

var errCursorCorrupt = errors.New("audit: sink cursor file is not readable")

func decodeCursor(data []byte) (SinkCursor, error) {
	var c SinkCursor
	body, rest, ok := bytes.Cut(data, []byte{'\n'})
	if !ok {
		return c, errCursorCorrupt
	}
	sum, tail, ok := bytes.Cut(rest, []byte{'\n'})
	if !ok || len(tail) != 0 {
		return c, errCursorCorrupt
	}
	want, err := strconv.ParseUint(string(sum), 16, 32)
	if err != nil || uint32(want) != crc32.ChecksumIEEE(body) {
		return c, errCursorCorrupt
	}
	if err := json.Unmarshal(body, &c); err != nil {
		return c, errCursorCorrupt
	}
	return c, nil
}

// save replaces path with c so that a crash at any point leaves either the
// old content or the new one, and so that once save has returned the new
// one survives a power loss. Each step is there for one of those two: the
// temporary file and the rename make the replacement atomic; flushing the
// file before the rename keeps a name from pointing at data that was never
// written; flushing the directory after it makes the rename itself
// durable. Without the last step the rename is visible and can still be
// undone by a power loss, which would bring the previous content back
// after the caller has acted on the new one.
func (s *cursorStore) save(path string, c SinkCursor) error {
	if err := s.fs.MkdirAll(s.dir); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := s.fs.WriteFile(tmp, encodeCursor(c), true); err != nil {
		return err
	}
	if err := s.fs.Rename(tmp, path); err != nil {
		return err
	}
	if s.fault(FaultSinkCursorAfterRename) {
		s.die(FaultSinkCursorAfterRename)
	}
	return s.fs.SyncDir(s.dir)
}

// read returns the file's cursor. missing is true when there is no file,
// which is a different fact from a file that cannot be read.
func (s *cursorStore) read(path string) (c SinkCursor, ok bool, missing bool) {
	data, err := s.fs.ReadFile(path)
	if err != nil {
		return c, false, errors.Is(err, fs.ErrNotExist)
	}
	c, err = decodeCursor(data)
	return c, err == nil, false
}

// Ways an export sequence came back at start. Anything but resumed or
// fresh is a reset and is reported, never applied silently.
const (
	// CursorResumed: both files were readable.
	CursorResumed = "resumed"
	// CursorFresh: the sink has no state, which is how a sink starts.
	CursorFresh = "fresh"
	// CursorFromReservation: the cursor was unreadable and the place was
	// taken from the reservation, which is older. Records are re-sent.
	CursorFromReservation = "reservation"
	// CursorFromOldest: no place was readable at all; the sink starts at
	// the oldest segment the directory holds.
	CursorFromOldest = "oldest_segment"
)

// CursorRecovery describes how an export sequence was opened.
type CursorRecovery struct {
	// Method is one of the Cursor* constants.
	Method string
	// EpochChanged is set when the numbers already used could not be
	// established, so the count starts again at 1 under a new epoch.
	EpochChanged bool
	// Old is what the cursor file held, when it was readable.
	Old SinkCursor
	// Start is where the sink continues.
	Start SinkCursor
}

// exportSeq hands out a sink's export sequence numbers and keeps its
// cursor, in an order that never lets a number be used twice in an epoch.
//
// A number is used the moment a record carrying it is written to the
// socket, and the cursor is saved after that, so a crash in between would
// find the old cursor and hand the same number out again. The reservation
// closes that: before the first number of a block is handed out, the end
// of the block is made durable. After a crash the count continues above
// the reserved end. The numbers of the block that were not used become a
// hole, at most one block long, and none is repeated. A clean stop writes
// the reservation back to the exact count, so a restart continues with the
// very next number.
type exportSeq struct {
	store    *cursorStore
	cur      SinkCursor
	reserved uint64
	reserve  uint64
}

// openExportSeq loads a sink's state. now supplies the clock a new epoch
// is taken from.
func openExportSeq(store *cursorStore, reserve uint64, now func() time.Time) (*exportSeq, CursorRecovery) {
	if reserve == 0 {
		reserve = DefaultExportReserve
	}
	cur, curOK, curMissing := store.read(store.cursorPath())
	resv, resvOK, resvMissing := store.read(store.reservationPath())
	e := &exportSeq{store: store, reserve: reserve}
	rec := CursorRecovery{Method: CursorResumed}
	if curOK {
		rec.Old = cur
	}

	// The place. A cursor that names another epoch than the reservation
	// was written under a count that no longer exists; its place is still
	// a true statement about the trail and is kept.
	switch {
	case curOK:
		e.cur.Position = cur.Position
	case resvOK:
		e.cur.Position = resv.Position
		rec.Method = CursorFromReservation
	case curMissing && resvMissing:
		rec.Method = CursorFresh
	default:
		rec.Method = CursorFromOldest
	}

	// The count. Only the reservation proves which numbers were used.
	if resvOK {
		e.cur.XseqEpoch = resv.XseqEpoch
		e.cur.XseqHigh = resv.XseqHigh
		e.reserved = resv.XseqHigh
	} else {
		// An epoch has to be greater than every one this sink has used,
		// and the file that would say which that was is the one that is
		// gone. The clock is the only source left that moves forward
		// across the loss of all state. A readable cursor still bounds
		// it from below, for a clock that was set back.
		epoch := uint64(now().Unix())
		if curOK && epoch <= cur.XseqEpoch {
			epoch = cur.XseqEpoch + 1
		}
		if epoch == 0 {
			epoch = 1
		}
		e.cur.XseqEpoch = epoch
		e.cur.XseqHigh = 0
		e.reserved = 0
		rec.EpochChanged = rec.Method != CursorFresh
	}
	rec.Start = e.cur
	return e, rec
}

// next returns the next export sequence number. An error means no number
// was handed out: the block it would have come from could not be reserved,
// and sending under an unreserved number is what must not happen.
func (e *exportSeq) next() (uint64, error) {
	x := e.cur.XseqHigh + 1
	if x > e.reserved {
		r := SinkCursor{Position: e.cur.Position, XseqHigh: e.cur.XseqHigh + e.reserve, XseqEpoch: e.cur.XseqEpoch}
		if err := e.store.save(e.store.reservationPath(), r); err != nil {
			return 0, fmt.Errorf("audit: sink %s: reserve export sequence: %w", e.store.name, err)
		}
		e.reserved = r.XseqHigh
	}
	e.cur.XseqHigh = x
	return x, nil
}

// commit records that the sink is past pos. A failure is returned for
// counting and does not stop the sink: an unsaved cursor costs a re-send
// after a restart and nothing else.
func (e *exportSeq) commit(pos Position) error {
	e.cur.Position = pos
	return e.store.save(e.store.cursorPath(), e.cur)
}

// cursor returns the current state.
func (e *exportSeq) cursor() SinkCursor { return e.cur }

// close is the clean stop: the cursor is saved and the reservation is
// brought back to the exact count.
func (e *exportSeq) close() error {
	err := e.store.save(e.store.cursorPath(), e.cur)
	if rerr := e.store.save(e.store.reservationPath(), e.cur); rerr != nil {
		if err == nil {
			err = rerr
		}
	} else {
		e.reserved = e.cur.XseqHigh
	}
	return err
}
