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
	"io"
	"os"
	"sort"
	"strings"
)

// SinkProgress is how far one sink has got through the trail.
type SinkProgress struct {
	Name string
	// Position is the last record the sink is past; the zero Position is a
	// sink that has not passed any.
	Position Position
	// Connected says the sink's receiver took the last record it was
	// offered.
	Connected bool
}

// SetSinkProgress tells the writer how to ask where the sinks are. The
// pruner asks before it deletes a segment, so that a segment a sink never
// received is recorded as lost and not merely as pruned. fn is called on
// the writer goroutine and must not wait for the writer; nil means no sink
// follows the trail.
func (w *Writer) SetSinkProgress(fn func() []SinkProgress) {
	if fn == nil {
		w.sinkProgress.Store(nil)
		return
	}
	w.sinkProgress.Store(&fn)
}

// segRange is the sequence numbers a sealed segment holds.
type segRange struct {
	first, last uint64
	// empty is a segment with no record in it.
	empty bool
	// unknown is a segment that could not be read; it is pruned without
	// its range being stated.
	unknown bool
}

func (s *segmenter) cacheRange(uuid string, r segRange) {
	if uuid == "" {
		return
	}
	s.uuidMu.Lock()
	s.ranges[uuid] = r
	delete(s.resolving, uuid)
	s.uuidMu.Unlock()
}

func (s *segmenter) forgetRange(uuid string) {
	s.uuidMu.Lock()
	delete(s.ranges, uuid)
	s.uuidMu.Unlock()
}

// rangeOf returns the range of a sealed segment. A segment this process
// sealed is known from the seal. One it found on disk has to be read to
// its footer, which for a compressed segment means reading all of it, and
// the writer goroutine is not where that may happen: the read is started
// on its own goroutine and ok is false until it has finished.
func (s *segmenter) rangeOf(seg SegmentInfo, uuid string) (r segRange, ok bool) {
	if uuid == "" {
		// The header could not be read, so there is no identity to keep
		// a range under and no reason to expect the rest to read. A pass
		// that waited for this range would wait at every pass.
		return segRange{unknown: true}, true
	}
	s.uuidMu.Lock()
	r, ok = s.ranges[uuid]
	start := !ok && !s.resolving[uuid]
	if start {
		s.resolving[uuid] = true
	}
	s.uuidMu.Unlock()
	if start {
		go func() { s.cacheRange(uuid, readSegmentRange(seg.Path)) }()
	}
	return r, ok
}

// readSegmentRange reads a sealed segment's range from its first and last
// record. The footer states the same two numbers, and is not relied on: a
// segment recovered after a crash may have none, and reaching the footer
// means reading past every record anyway.
func readSegmentRange(path string) segRange {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		// Compressed, or not yet: the other name.
		if strings.HasSuffix(path, gzipExt) {
			path = strings.TrimSuffix(path, gzipExt)
		} else {
			path += gzipExt
		}
		f, err = os.Open(path)
	}
	if err != nil {
		return segRange{unknown: true}
	}
	defer f.Close()
	var rd io.Reader = f
	if strings.HasSuffix(path, gzipExt) {
		zr, err := gzip.NewReader(f)
		if err != nil {
			return segRange{unknown: true}
		}
		defer zr.Close()
		rd = zr
	}
	var first, last []byte
	sc := bufio.NewScanner(rd)
	sc.Buffer(make([]byte, 64*1024), maxLineBytes)
	for sc.Scan() {
		line := sc.Bytes()
		// Only the two framing lines begin with a kind; a record is told
		// apart without decoding it.
		if bytes.HasPrefix(line, []byte(`{"kind":`)) {
			continue
		}
		if first == nil {
			first = append([]byte(nil), line...)
		}
		last = append(last[:0], line...)
	}
	if first == nil {
		return segRange{empty: sc.Err() == nil, unknown: sc.Err() != nil}
	}
	var a, b struct {
		Seq uint64 `json:"seq"`
	}
	if json.Unmarshal(first, &a) != nil || json.Unmarshal(last, &b) != nil || a.Seq == 0 || b.Seq < a.Seq {
		return segRange{unknown: true}
	}
	return segRange{first: a.Seq, last: b.Seq}
}

// sinkStandings sorts the sinks into those that have been sent all of the
// sealed segment segs[at] and those that have not. connected says that one
// of those that have not is connected. ready is false when that cannot be
// decided yet: the segment's range is still being read.
//
// A sink is past the segment when its place is in a later one. One whose
// place is in the segment itself is past it only at the segment's last
// record. One whose place is in no segment the directory holds has lost
// its place already and will continue from the oldest segment, which is
// this one or a later one, so it has not been sent this one either.
func (w *Writer) sinkStandings(segs []SegmentInfo, at int, uuid string) (exported, pending []string, connected bool, rng segRange, ready bool) {
	fn := w.sinkProgress.Load()
	if fn == nil {
		return nil, nil, false, segRange{}, true
	}
	sinks := (*fn)()
	if len(sinks) == 0 {
		return nil, nil, false, segRange{}, true
	}
	active := w.seg.currentUUID()
	// order is the place of each sealed segment in the directory, read
	// only as far as a sink's place makes necessary.
	order := map[string]int{}
	scanned := 0
	indexOf := func(u string) (int, bool) {
		if i, ok := order[u]; ok {
			return i, true
		}
		for ; scanned < len(segs); scanned++ {
			su := w.seg.uuidOf(segs[scanned].Path)
			order[su] = scanned
			if su == u {
				scanned++
				return scanned - 1, true
			}
		}
		return 0, false
	}
	// segs was listed when the pass began, and the records the pass writes
	// can seal the active segment under it. A place in a segment sealed
	// since then is in none of segs and is not the active one either; it is
	// later than all of them, and not a place that was lost.
	var sealedNow map[string]bool
	sealedSince := func(u string) bool {
		if sealedNow == nil {
			sealedNow = map[string]bool{}
			if fresh, err := w.seg.listSealed(); err == nil {
				for _, s := range fresh {
					sealedNow[w.seg.uuidOf(s.Path)] = true
				}
			}
		}
		return sealedNow[u]
	}
	var inside []SinkProgress
	behind := func(s SinkProgress) {
		pending = append(pending, s.Name)
		connected = connected || s.Connected
	}
	for _, s := range sinks {
		p := s.Position
		switch {
		case p.SegmentUUID == "":
			behind(s)
		case p.SegmentUUID == active:
			exported = append(exported, s.Name)
		case p.SegmentUUID == uuid:
			inside = append(inside, s)
		default:
			i, ok := indexOf(p.SegmentUUID)
			switch {
			case ok && i > at:
				exported = append(exported, s.Name)
			case !ok && sealedSince(p.SegmentUUID):
				exported = append(exported, s.Name)
			default:
				behind(s)
			}
		}
	}
	if len(pending) == 0 && len(inside) == 0 {
		sort.Strings(exported)
		return exported, nil, false, segRange{}, true
	}
	rng, ok := w.seg.rangeOf(segs[at], uuid)
	if !ok {
		return nil, nil, false, segRange{}, false
	}
	for _, s := range inside {
		if rng.empty || (!rng.unknown && s.Position.Seq >= rng.last) {
			exported = append(exported, s.Name)
		} else {
			behind(s)
		}
	}
	// By name, so that the same standing is always the same record.
	sort.Strings(exported)
	sort.Strings(pending)
	return exported, pending, connected, rng, true
}
