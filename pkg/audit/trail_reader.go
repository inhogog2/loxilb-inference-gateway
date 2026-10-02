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
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Position names one record of the trail by the segment that holds it and
// its sequence number. It is not a file name or an offset: sealing renames
// a segment and compression replaces the file, while the UUID in the
// segment's header survives both. The zero Position is the place before
// the oldest record the directory still holds.
type Position struct {
	SegmentUUID string `json:"segment_uuid"`
	Seq         uint64 `json:"seq"`
}

// TrailLine is one record as it sits on disk.
type TrailLine struct {
	Pos Position
	// Raw is the record's line without its newline, byte for byte what
	// the writer appended. It aliases the reader's buffer and is valid
	// until the next call to Next.
	Raw []byte
}

var (
	// ErrTrailIdle is returned by Next when every record written so far
	// has been returned. It is not a failure: the caller waits and asks
	// again.
	ErrTrailIdle = errors.New("audit: no further record in the trail yet")
	// ErrPositionLost is returned when the segment a Position names is no
	// longer in the directory, which is what retention does to a segment
	// a reader was too far behind to finish. The reader is left unopened;
	// Seek to the zero Position continues from the oldest segment left.
	ErrPositionLost = errors.New("audit: the position's segment is no longer in the trail")
)

// trailChunk is the first read size. A line longer than the chunk doubles
// it, up to maxTrailChunk.
const (
	trailChunk    = 64 << 10
	maxTrailChunk = 2 * maxLineBytes
)

// trailBeforeScan runs between a read that found nothing more and the
// directory scan that follows it, which is where the writer can append,
// seal and open the next segment unseen. The tests put exactly that there.
var trailBeforeScan = func() {}

// trailSegment is one segment file as a directory scan found it.
type trailSegment struct {
	path   string
	name   string
	uuid   string
	prev   string
	gz     bool
	active bool
}

// TrailReader returns the records of an audit directory in the order they
// were written, across sealing, compression and restarts of the writer,
// and keeps up with the active segment as it grows. It reads; it never
// writes to the directory. It is not safe for concurrent use.
type TrailReader struct {
	dir string
	// hdrs caches the header of every sealed file by name. A sealed name
	// is never reused, so the entry cannot go stale; the active segment's
	// name is reused by every segment and is never cached.
	hdrs map[string]segmentHeader

	start  Position
	opened bool
	cur    *openSegment
}

// openSegment is the segment being read.
type openSegment struct {
	seg trailSegment
	f   *os.File

	// A plain file is read by offset, because it can still be growing.
	// off is the offset of the first line not yet returned; buf holds
	// what was read from there and rd is how much of it was returned.
	off   int64
	buf   []byte
	rd    int
	chunk int

	// A compressed file is complete by construction and is read as a
	// stream.
	zr *gzip.Reader
	br *bufio.Reader

	// skip is the seq up to which records are passed over after a resume
	// inside this segment.
	skip uint64
	// last is the seq of the last record returned from this segment.
	last uint64
	// done is set by the footer, or by the end of a compressed stream.
	done bool
}

// NewTrailReader returns a reader that continues after pos. Nothing is
// opened until the first Next.
func NewTrailReader(dir string, after Position) *TrailReader {
	return &TrailReader{dir: dir, hdrs: make(map[string]segmentHeader), start: after}
}

// Seek repositions the reader to continue after pos.
func (r *TrailReader) Seek(after Position) {
	r.closeCur()
	r.start, r.opened = after, false
}

// Close releases the open segment. The reader can be used again: the next
// call to Next continues after the last record returned.
func (r *TrailReader) Close() {
	if r.cur != nil {
		r.start = Position{SegmentUUID: r.cur.seg.uuid, Seq: r.cur.last}
	}
	r.closeCur()
	r.opened = false
}

func (r *TrailReader) closeCur() {
	if r.cur != nil {
		r.cur.close()
		r.cur = nil
	}
}

func (o *openSegment) close() {
	if o.zr != nil {
		_ = o.zr.Close()
	}
	if o.f != nil {
		_ = o.f.Close()
	}
}

// Next returns the next record. ErrTrailIdle means there is none yet.
func (r *TrailReader) Next() (TrailLine, error) {
	if !r.opened {
		if err := r.openStart(); err != nil {
			return TrailLine{}, err
		}
	}
	for {
		line, err := r.cur.readLine()
		if err == nil {
			var lk lineKind
			if jerr := json.Unmarshal(line, &lk); jerr != nil {
				// A complete line that is not an object cannot be a
				// record. In a segment still being written it is what
				// a read racing the writer's cut-back of a short write
				// can see, and the next read sees the real line; a
				// sealed segment has no such excuse.
				if !r.cur.done && r.isActive(r.cur) {
					r.cur.rewind(len(line) + 1)
					return TrailLine{}, ErrTrailIdle
				}
				return TrailLine{}, fmt.Errorf("audit: %s: unreadable line at offset %d: %w",
					r.cur.seg.name, r.cur.off-int64(len(line)+1), jerr)
			}
			switch lk.Kind {
			case kindHeader:
				continue
			case kindFooter:
				r.cur.done = true
				continue
			case "":
				if lk.Seq <= r.cur.skip {
					continue
				}
				r.cur.last = lk.Seq
				return TrailLine{Pos: Position{SegmentUUID: r.cur.seg.uuid, Seq: lk.Seq}, Raw: line}, nil
			default:
				continue
			}
		}
		if !errors.Is(err, ErrTrailIdle) && !errors.Is(err, io.EOF) {
			return TrailLine{}, err
		}
		if errors.Is(err, io.EOF) {
			r.cur.done = true
		}
		moved, merr := r.advance()
		if merr != nil {
			return TrailLine{}, merr
		}
		if !moved {
			return TrailLine{}, ErrTrailIdle
		}
	}
}

// advance moves to the segment that follows the open one, when there is
// one and the open one has nothing more to give.
func (r *TrailReader) advance() (bool, error) {
	trailBeforeScan()
	segs, err := r.scan()
	if err != nil {
		return false, err
	}
	var next *trailSegment
	at := -1
	for i := range segs {
		if segs[i].uuid == r.cur.seg.uuid {
			at = i
			continue
		}
		if segs[i].prev == r.cur.seg.uuid && next == nil {
			next = &segs[i]
		}
	}
	if next == nil {
		if r.isActive(r.cur) {
			return false, nil
		}
		switch {
		case at >= 0 && at+1 < len(segs):
			// No segment names this one as its predecessor, yet a
			// later one exists: the link was lost, which is what a
			// segment recovered without a readable header leaves
			// behind. The directory order is the only order left, and
			// a reader that stayed here would never move again.
			next = &segs[at+1]
		case at < 0:
			// The segment was removed while it was being read and
			// nothing follows it by name. Where to continue is the
			// caller's decision, as it is for any lost position.
			r.Close()
			return false, ErrPositionLost
		default:
			return false, nil
		}
	}
	if !r.cur.done {
		// Another segment exists, so the writer has finished with this
		// one: the footer is written before the next segment is opened.
		// Whatever is still unread was there before the scan. Read it
		// out before leaving; a segment whose footer could not be
		// written simply ends.
		if r.cur.hasMore() {
			return true, nil
		}
	}
	o, err := openTrailSegment(*next)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Compressed between the scan and the open; the next call
			// finds it under its new name.
			return false, nil
		}
		return false, err
	}
	r.closeCur()
	r.cur = o
	return true, nil
}

// openStart opens the segment the start position names, or the oldest one
// for the zero Position.
func (r *TrailReader) openStart() error {
	for attempt := 0; ; attempt++ {
		segs, err := r.scan()
		if err != nil {
			return err
		}
		var pick *trailSegment
		if r.start.SegmentUUID == "" {
			pick = oldestSegment(segs)
			if pick == nil {
				return ErrTrailIdle
			}
		} else {
			for i := range segs {
				if segs[i].uuid == r.start.SegmentUUID {
					pick = &segs[i]
					break
				}
			}
			if pick == nil {
				return ErrPositionLost
			}
		}
		o, err := openTrailSegment(*pick)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) && attempt == 0 {
				continue
			}
			return err
		}
		if r.start.SegmentUUID != "" {
			o.skip, o.last = r.start.Seq, r.start.Seq
		}
		r.cur, r.opened = o, true
		return nil
	}
}

// oldestSegment is the first segment of the chain the directory still
// holds: one whose predecessor is not there. A directory can hold more
// than one such segment after a link was lost; the scan order, sealed
// segments by name and the active one last, then picks the earliest.
func oldestSegment(segs []trailSegment) *trailSegment {
	have := make(map[string]bool, len(segs))
	for i := range segs {
		have[segs[i].uuid] = true
	}
	for i := range segs {
		if segs[i].prev == "" || !have[segs[i].prev] {
			return &segs[i]
		}
	}
	if len(segs) > 0 {
		return &segs[0]
	}
	return nil
}

// scan lists the segments in the directory with their identities, sealed
// segments oldest first and the active segment last.
func (r *TrailReader) scan() ([]trailSegment, error) {
	entries, err := os.ReadDir(r.dir)
	if err != nil {
		return nil, err
	}
	var out []trailSegment
	present := make(map[string]bool, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		present[name] = true
		seg := trailSegment{name: name, path: filepath.Join(r.dir, name)}
		if name == ActiveSegmentName {
			seg.active = true
		} else {
			_, gz, ok := parseSegmentName(name)
			if !ok {
				continue
			}
			seg.gz = gz
		}
		hdr, ok := r.hdrs[name]
		if !ok || seg.active {
			// A file that vanished since ReadDir, or whose header is
			// not written yet, is simply not listed this time.
			if hdr, ok = readSegmentHeader(seg.path); !ok || hdr.SegmentUUID == "" {
				continue
			}
			if !seg.active {
				r.hdrs[name] = hdr
			}
		}
		seg.uuid, seg.prev = hdr.SegmentUUID, hdr.PrevSegmentUUID
		// While a segment is being compressed it is listed in both
		// forms. They carry one UUID and sort together, and a reader
		// asks for a segment by UUID or for the one after it, so either
		// form serves and neither is read twice.
		out = append(out, seg)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].active != out[j].active {
			return !out[i].active
		}
		return strings.TrimSuffix(out[i].name, gzipExt) < strings.TrimSuffix(out[j].name, gzipExt)
	})
	for name := range r.hdrs {
		if !present[name] {
			delete(r.hdrs, name)
		}
	}
	return out, nil
}

// isActive reports whether the open file is still the one behind the
// active segment's name.
func (r *TrailReader) isActive(o *openSegment) bool {
	if o.zr != nil {
		return false
	}
	a, err := os.Stat(filepath.Join(r.dir, ActiveSegmentName))
	if err != nil {
		return false
	}
	b, err := o.f.Stat()
	if err != nil {
		return false
	}
	return os.SameFile(a, b)
}

func openTrailSegment(seg trailSegment) (*openSegment, error) {
	f, err := os.Open(seg.path)
	if err != nil {
		return nil, err
	}
	o := &openSegment{seg: seg, f: f, chunk: trailChunk}
	if seg.gz {
		zr, err := gzip.NewReader(f)
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("audit: %s: %w", seg.name, err)
		}
		o.zr = zr
		o.br = bufio.NewReaderSize(zr, trailChunk)
	}
	return o, nil
}

// readLine returns the next complete line without its newline.
// ErrTrailIdle means a plain file has no further complete line; io.EOF
// means a compressed one has ended.
func (o *openSegment) readLine() ([]byte, error) {
	if o.zr != nil {
		line, err := o.br.ReadBytes('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				// A final line without a newline was torn before the
				// segment was sealed; it is not a record.
				return nil, io.EOF
			}
			return nil, fmt.Errorf("audit: %s: %w", o.seg.name, err)
		}
		return line[:len(line)-1], nil
	}
	for {
		if i := bytes.IndexByte(o.buf[o.rd:], '\n'); i >= 0 {
			line := o.buf[o.rd : o.rd+i]
			o.rd += i + 1
			o.off += int64(i + 1)
			return line, nil
		}
		// Nothing complete is buffered. Read again from the start of
		// the first line not returned, rather than appending to what
		// is held: the writer cuts a short write back to the last
		// complete line, so held bytes without a newline may no longer
		// be in the file.
		if cap(o.buf) < o.chunk {
			o.buf = make([]byte, o.chunk)
		}
		n, err := o.f.ReadAt(o.buf[:o.chunk], o.off)
		o.buf, o.rd = o.buf[:n], 0
		if bytes.IndexByte(o.buf, '\n') >= 0 {
			continue
		}
		o.buf = o.buf[:0]
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("audit: %s: %w", o.seg.name, err)
		}
		if n < o.chunk {
			return nil, ErrTrailIdle
		}
		if o.chunk >= maxTrailChunk {
			return nil, fmt.Errorf("audit: %s: a line at offset %d is longer than %d bytes",
				o.seg.name, o.off, maxTrailChunk)
		}
		o.chunk *= 2
	}
}

// rewind gives back the last n bytes returned, so that the next readLine
// reads them from the file again.
func (o *openSegment) rewind(n int) {
	o.off -= int64(n)
	o.buf, o.rd = o.buf[:0], 0
}

// hasMore reports whether a plain file holds a complete line that has not
// been returned.
func (o *openSegment) hasMore() bool {
	if o.zr != nil {
		return false
	}
	line, err := o.readLine()
	if err != nil {
		return false
	}
	o.rewind(len(line) + 1)
	return true
}
