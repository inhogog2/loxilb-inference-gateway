/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

package audit

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
)

// sealedTrail is a trail of two sealed segments and an active one, with
// the range of each sealed segment taken from the records themselves.
type sealedTrail struct {
	cfg    Config
	w      *Writer
	uuids  []string // sealed segments, oldest first
	ranges map[string][2]uint64
}

func newSealedTrail(t *testing.T) *sealedTrail {
	t.Helper()
	st := &sealedTrail{cfg: testConfig(t), ranges: map[string][2]uint64{}}
	st.w = startWriter(t, st.cfg)
	writeN(t, st.w, 3, "one")
	sealNow(t, st.w)
	writeN(t, st.w, 3, "two")
	sealNow(t, st.w)
	writeN(t, st.w, 2, "three")
	waitCompressed(t, st.cfg.Dir)
	st.index(t)
	return st
}

// index reads the sealed segments' ranges the plain way.
func (st *sealedTrail) index(t *testing.T) {
	t.Helper()
	for _, raw := range rawRecords(t, st.cfg.Dir) {
		f := frame{raw: raw}
		u := f.field(t, "segment_uuid")
		seq, err := strconv.ParseUint(f.field(t, "seq"), 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		r, ok := st.ranges[u]
		if !ok || seq < r[0] {
			r[0] = seq
		}
		if seq > r[1] {
			r[1] = seq
		}
		st.ranges[u] = r
	}
	segs, err := st.w.seg.listSealed()
	if err != nil {
		t.Fatal(err)
	}
	st.uuids = nil
	for _, s := range segs {
		st.uuids = append(st.uuids, st.w.seg.uuidOf(s.Path))
	}
	if len(st.uuids) < 2 {
		t.Fatalf("%d sealed segments, want at least 2", len(st.uuids))
	}
}

func (st *sealedTrail) sinks(ps ...SinkProgress) {
	st.w.SetSinkProgress(func() []SinkProgress { return ps })
}

// pruneOldest lowers the quota so that one pass takes the oldest segment.
func (st *sealedTrail) pruneOldest(t *testing.T) {
	t.Helper()
	st.w.SetRetention(Retention{MaxBytes: 1})
	st.w.prunePassNow(t)
}

func stringsOf(v any) []string {
	var out []string
	list, _ := v.([]any)
	for _, x := range list {
		out = append(out, fmt.Sprint(x))
	}
	return out
}

// Retention wins over a sink that is behind, and says so before it acts:
// the range of numbers the sink will never be sent, and which sinks, are
// on the trail ahead of the record of the prune itself.
func TestPruneRecordsWhatASinkWasNeverSent(t *testing.T) {
	st := newSealedTrail(t)
	oldest, second := st.uuids[0], st.uuids[1]
	rng := st.ranges[oldest]
	st.sinks(
		SinkProgress{Name: "ahead", Position: Position{SegmentUUID: second, Seq: st.ranges[second][0]}},
		SinkProgress{Name: "active", Position: Position{SegmentUUID: st.w.seg.currentUUID(), Seq: 1}},
		SinkProgress{Name: "at-the-end", Position: Position{SegmentUUID: oldest, Seq: rng[1]}},
		SinkProgress{Name: "one-short", Position: Position{SegmentUUID: oldest, Seq: rng[1] - 1}},
		SinkProgress{Name: "never-started", Position: Position{}},
		SinkProgress{Name: "place-gone", Position: Position{SegmentUUID: "0190a000-0000-7000-8000-000000000000", Seq: 4}},
	)
	st.pruneOldest(t)
	if got := st.w.Stats().LostToRetention; got != rng[1]-rng[0]+1 {
		t.Errorf("%d records counted as lost, want %d", got, rng[1]-rng[0]+1)
	}
	closeWriter(t, st.w)

	ls := readDir(t, st.cfg.Dir)
	lost, prunes := ofType(ls, "sys.segment.lost_to_retention"), ofType(ls, "sys.segment.prune")
	if len(lost) != 1 || len(prunes) != 1 {
		t.Fatalf("%d loss records and %d prune records, want one of each", len(lost), len(prunes))
	}
	d := lost[0].detail()
	if d["resource"] != "audit_segment:"+oldest {
		t.Errorf("the loss names %v, want the oldest segment %s", d["resource"], oldest)
	}
	if d["seq_from"] != float64(rng[0]) || d["seq_to"] != float64(rng[1]) {
		t.Errorf("the loss covers %v..%v, want %d..%d", d["seq_from"], d["seq_to"], rng[0], rng[1])
	}
	if got, want := stringsOf(d["sinks_pending"]), []string{"never-started", "one-short", "place-gone"}; !reflect.DeepEqual(got, want) {
		t.Errorf("sinks pending %v, want %v", got, want)
	}
	if got, want := stringsOf(prunes[0].detail()["exported_to"]), []string{"active", "ahead", "at-the-end"}; !reflect.DeepEqual(got, want) {
		t.Errorf("exported to %v, want %v", got, want)
	}
	if lost[0].num("seq") >= prunes[0].num("seq") {
		t.Errorf("the loss (seq %v) is recorded after the prune (seq %v)", lost[0].num("seq"), prunes[0].num("seq"))
	}
}

// A segment every sink has been sent is pruned as before, with the sinks
// that have it named, and nothing is called lost.
func TestPruneOfAnExportedSegmentLosesNothing(t *testing.T) {
	st := newSealedTrail(t)
	oldest := st.uuids[0]
	st.sinks(
		SinkProgress{Name: "a", Position: Position{SegmentUUID: oldest, Seq: st.ranges[oldest][1]}},
		SinkProgress{Name: "b", Position: Position{SegmentUUID: st.uuids[1], Seq: 1}},
	)
	st.pruneOldest(t)
	if got := st.w.Stats().LostToRetention; got != 0 {
		t.Errorf("%d records counted as lost", got)
	}
	closeWriter(t, st.w)
	ls := readDir(t, st.cfg.Dir)
	if n := len(ofType(ls, "sys.segment.lost_to_retention")); n != 0 {
		t.Fatalf("%d loss records for a segment every sink had", n)
	}
	prunes := ofType(ls, "sys.segment.prune")
	if len(prunes) != 1 {
		t.Fatalf("%d prune records, want 1", len(prunes))
	}
	if got, want := stringsOf(prunes[0].detail()["exported_to"]), []string{"a", "b"}; !reflect.DeepEqual(got, want) {
		t.Errorf("exported to %v, want %v", got, want)
	}
}

// With no sink there is nothing to be behind: the prune record is the one
// it always was.
func TestPruneWithoutSinksSaysNothingAboutSinks(t *testing.T) {
	for _, tt := range []struct {
		name string
		set  func(*sealedTrail)
	}{
		{"no progress source", func(*sealedTrail) {}},
		{"a source with no sinks", func(st *sealedTrail) { st.sinks() }},
		{"a source taken away", func(st *sealedTrail) {
			st.sinks(SinkProgress{Name: "gone"})
			st.w.SetSinkProgress(nil)
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			st := newSealedTrail(t)
			tt.set(st)
			st.pruneOldest(t)
			closeWriter(t, st.w)
			ls := readDir(t, st.cfg.Dir)
			if n := len(ofType(ls, "sys.segment.lost_to_retention")); n != 0 {
				t.Fatalf("%d loss records with no sink", n)
			}
			prunes := ofType(ls, "sys.segment.prune")
			if len(prunes) != 1 {
				t.Fatalf("%d prune records, want 1", len(prunes))
			}
			if _, has := prunes[0].detail()["exported_to"]; has {
				t.Errorf("the prune record names sinks: %v", prunes[0].detail())
			}
		})
	}
}

// A segment sealed by an earlier process has to be read to learn its
// range, and a compressed one has to be read whole. That is not done on
// the writer goroutine: the pass that needs the range starts the read and
// prunes nothing, and a later pass prunes with the range in hand.
func TestPruneWaitsForTheRangeOfASegmentItDidNotSeal(t *testing.T) {
	st := newSealedTrail(t)
	oldest, rng := st.uuids[0], st.ranges[st.uuids[0]]
	closeWriter(t, st.w)

	st.w = startWriter(t, st.cfg)
	// A segment this process seals is one whose range it knows. The pass
	// must still not take it ahead of the older one it cannot judge yet.
	writeN(t, st.w, 2, "four")
	sealNow(t, st.w)
	waitCompressed(t, st.cfg.Dir)
	st.sinks(SinkProgress{Name: "behind"})
	before, _ := st.w.seg.listSealed()
	st.pruneOldest(t)
	if after, _ := st.w.seg.listSealed(); len(after) != len(before) {
		t.Fatalf("the pass that started the read pruned %d segments", len(before)-len(after))
	}
	waitFor(t, "the range of the oldest segment", func() bool {
		st.w.seg.uuidMu.Lock()
		defer st.w.seg.uuidMu.Unlock()
		_, ok := st.w.seg.ranges[oldest]
		return ok
	})
	st.w.prunePassNow(t)
	after, _ := st.w.seg.listSealed()
	if len(after) != len(before)-1 {
		t.Fatalf("with the range in hand the pass pruned %d segments, want 1", len(before)-len(after))
	}
	if got := st.w.seg.uuidOf(after[0].Path); got != st.uuids[1] {
		t.Fatalf("the oldest segment left is %s, want the second-oldest %s", got, st.uuids[1])
	}
	closeWriter(t, st.w)

	lost := ofType(readDir(t, st.cfg.Dir), "sys.segment.lost_to_retention")
	if len(lost) != 1 {
		t.Fatalf("%d loss records, want 1", len(lost))
	}
	d := lost[0].detail()
	if d["resource"] != "audit_segment:"+oldest || d["seq_from"] != float64(rng[0]) || d["seq_to"] != float64(rng[1]) {
		t.Errorf("the loss is %v, want %s %d..%d", d, oldest, rng[0], rng[1])
	}
}

// With every sink in a later segment the range is never needed, so a
// segment from an earlier process is pruned in the pass that finds it and
// is not read.
func TestPruneDoesNotReadASegmentNoSinkIsBehind(t *testing.T) {
	st := newSealedTrail(t)
	oldest := st.uuids[0]
	closeWriter(t, st.w)

	st.w = startWriter(t, st.cfg)
	st.sinks(SinkProgress{Name: "ahead", Position: Position{SegmentUUID: st.uuids[1], Seq: 1}})
	before, _ := st.w.seg.listSealed()
	st.pruneOldest(t)
	if after, _ := st.w.seg.listSealed(); len(after) != len(before)-1 {
		t.Fatalf("the pass pruned %d segments, want 1", len(before)-len(after))
	}
	st.w.seg.uuidMu.Lock()
	_, read := st.w.seg.ranges[oldest]
	reading := st.w.seg.resolving[oldest]
	st.w.seg.uuidMu.Unlock()
	if read || reading {
		t.Error("the segment was read although no sink was behind it")
	}
}

func TestReadSegmentRange(t *testing.T) {
	const header = `{"kind":"segment_header","segment_uuid":"u","first_seq":5}` + "\n"
	const recs = `{"seq":5,"stream":"mgmt"}` + "\n" + `{"seq":6,"stream":"mgmt"}` + "\n" + `{"seq":9,"stream":"mgmt"}` + "\n"
	const footer = `{"kind":"segment_footer","segment_uuid":"u","record_count":3,"first_seq":5,"last_seq":9}` + "\n"
	dir := t.TempDir()
	write := func(name, body string, gz bool) string {
		t.Helper()
		data := []byte(body)
		if gz {
			var buf bytes.Buffer
			zw := gzip.NewWriter(&buf)
			_, _ = zw.Write(data)
			_ = zw.Close()
			data = buf.Bytes()
		}
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, tt := range []struct {
		name string
		path string
		want segRange
	}{
		{"sealed", write("a.jsonl", header+recs+footer, false), segRange{first: 5, last: 9}},
		{"sealed, compressed", write("b.jsonl.gz", header+recs+footer, true), segRange{first: 5, last: 9}},
		// A segment recovered without a footer still holds its records.
		{"no footer", write("c.jsonl", header+recs, false), segRange{first: 5, last: 9}},
		{"no footer, compressed", write("d.jsonl.gz", header+recs, true), segRange{first: 5, last: 9}},
		{"no record", write("e.jsonl", header+`{"kind":"segment_footer","segment_uuid":"u","record_count":0}`+"\n", false), segRange{empty: true}},
		{"header alone", write("f.jsonl", header, false), segRange{empty: true}},
		{"not a segment", write("g.jsonl.gz", "not gzip", false), segRange{unknown: true}},
		{"records that are not records", write("h.jsonl", header+"garbage\n", false), segRange{unknown: true}},
		{"missing", filepath.Join(dir, "nothing.jsonl"), segRange{unknown: true}},
		// Compressed between the listing and the read.
		{"renamed by compression", filepath.Join(dir, "b.jsonl"), segRange{first: 5, last: 9}},
	} {
		if got := readSegmentRange(tt.path); got != tt.want {
			t.Errorf("%s: %+v, want %+v", tt.name, got, tt.want)
		}
	}
}
