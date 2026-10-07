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
	"compress/gzip"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/loxilb-io/loxilb/pkg/logrotate"
)

// plainTwin writes the plain form of a compressed sealed segment beside
// it and returns both paths. With keep false the compressed form is
// removed, which leaves the segment as it was before its compression.
func plainTwin(t *testing.T, gz string, keep bool) (plain string) {
	t.Helper()
	plain = strings.TrimSuffix(gz, gzipExt)
	in, err := os.Open(gz)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	zr, err := gzip.NewReader(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := os.OpenFile(plain, os.O_CREATE|os.O_EXCL|os.O_WRONLY, fileMode)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, zr); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	if !keep {
		if err := os.Remove(gz); err != nil {
			t.Fatal(err)
		}
	}
	return plain
}

func oldestSealed(t *testing.T, w *Writer) SegmentInfo {
	t.Helper()
	segs, err := w.seg.listSealed()
	if err != nil || len(segs) == 0 {
		t.Fatalf("no sealed segment: %v", err)
	}
	return segs[0]
}

// formsOf lists the files a sealed segment is held in.
func formsOf(t *testing.T, w *Writer, uuid string) []string {
	t.Helper()
	segs, err := w.seg.listSealed()
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, s := range segs {
		if readHeaderUUID(s.Path) == uuid {
			out = append(out, s.Name)
		}
	}
	return out
}

// pruneUntilGone runs passes under a quota no pass can meet until no file
// of the segment is left. A pass takes one segment, the oldest, so the
// passes that run before the segment is gone are all about it.
func pruneUntilGone(t *testing.T, st *sealedTrail, uuid string) {
	t.Helper()
	st.w.SetRetention(Retention{MaxBytes: 1})
	waitFor(t, "the segment to be pruned in every form", func() bool {
		st.w.prunePassNow(t)
		return len(formsOf(t, st.w, uuid)) == 0
	})
	st.w.SetRetention(Retention{})
}

// oneLossOnePrune checks that a segment went once: one record of the loss,
// one of the prune, its range counted once and no file of it left.
func oneLossOnePrune(t *testing.T, st *sealedTrail, uuid string) {
	t.Helper()
	rng := st.ranges[uuid]
	if left := formsOf(t, st.w, uuid); len(left) != 0 {
		t.Errorf("the pruned segment is still held in %v", left)
	}
	if got, want := st.w.Stats().LostToRetention, rng[1]-rng[0]+1; got != want {
		t.Errorf("%d records counted as lost, want %d: the range %d..%d once", got, want, rng[0], rng[1])
	}
	if got := st.w.Stats().Pruned; got != 1 {
		t.Errorf("%d segments counted as pruned, want 1", got)
	}
	closeWriter(t, st.w)
	ls := readDir(t, st.cfg.Dir)
	var lost, prunes int
	for _, l := range ofType(ls, "sys.segment.lost_to_retention") {
		if l.detail()["resource"] == "audit_segment:"+uuid {
			lost++
		}
	}
	for _, l := range ofType(ls, "sys.segment.prune") {
		if l.detail()["resource"] == "audit_segment:"+uuid {
			prunes++
		}
	}
	if lost != 1 || prunes != 1 {
		t.Errorf("%d loss records and %d prune records name the segment, want one of each", lost, prunes)
	}
}

// While a segment is being compressed the directory holds it in both
// forms. They are one segment: it is lost once and pruned once.
func TestPruneTakesASegmentHeldInBothFormsOnce(t *testing.T) {
	st := newSealedTrail(t)
	oldest := st.uuids[0]
	plainTwin(t, oldestSealed(t, st.w).Path, true)
	if forms := formsOf(t, st.w, oldest); len(forms) != 2 {
		t.Fatalf("the oldest segment is held in %v, want both forms", forms)
	}
	st.sinks(SinkProgress{Name: "behind", Position: Position{}})
	pruneUntilGone(t, st, oldest)
	oneLossOnePrune(t, st, oldest)
}

// Compression replaces the plain file a pass has listed with the
// compressed one. The pass that announced the segment is the one that
// removes it, under whichever name it then has.
func TestPruneFollowsASegmentCompressedUnderThePass(t *testing.T) {
	st := newSealedTrail(t)
	oldest := st.uuids[0]
	plain := plainTwin(t, oldestSealed(t, st.w).Path, false)
	var once sync.Once
	st.w.SetSinkProgress(func() []SinkProgress {
		// The pruner asks after it has listed the directory and before
		// it removes anything, which is where the compression lands.
		once.Do(func() {
			if err := logrotate.GzipFile(plain, fileMode); err != nil {
				t.Errorf("compress: %v", err)
			}
		})
		return []SinkProgress{{Name: "behind", Position: Position{}}}
	})
	pruneUntilGone(t, st, oldest)
	oneLossOnePrune(t, st, oldest)
}

// A segment pruned while its archive is being written does not come back
// under the archive's name.
func TestPruneOfASegmentBeingCompressedIsNotUndone(t *testing.T) {
	st := newSealedTrail(t)
	oldest := st.uuids[0]
	plain := plainTwin(t, oldestSealed(t, st.w).Path, false)

	// Held as the pruner holds it while it removes a segment. The worker
	// reads the plain file and writes its archive beside it meanwhile,
	// and must wait here before it puts the archive in place.
	st.w.seg.formMu.Lock()
	st.w.seg.enqueueCompress(plain)
	waitFor(t, "the worker to have the plain file open", func() bool {
		_, err := os.Stat(plain + gzipExt + ".tmp")
		return err == nil
	})
	if err := os.Remove(plain); err != nil {
		t.Fatal(err)
	}
	st.w.seg.formMu.Unlock()

	waitFor(t, "the worker to drop its archive", func() bool {
		_, err := os.Stat(plain + gzipExt + ".tmp")
		return errors.Is(err, os.ErrNotExist)
	})
	if left := formsOf(t, st.w, oldest); len(left) != 0 {
		t.Fatalf("the pruned segment came back as %v", left)
	}
	if n := st.w.Stats().CompressFailed; n != 0 {
		t.Errorf("%d compression failures counted for a segment that was pruned", n)
	}
}

// A removal that fails leaves the prune on the trail and the segment on
// the disk. That is said once; the pass does not go on to a newer segment;
// and the pass that does remove it announces and counts nothing again.
func TestPruneThatCannotRemoveIsSaidOnceAndTriedAgain(t *testing.T) {
	st := newSealedTrail(t)
	oldest, second := st.uuids[0], st.uuids[1]
	st.sinks(SinkProgress{Name: "behind", Position: Position{}})

	var refuse atomic.Bool
	refuse.Store(true)
	remove := removeFile
	removeFile = func(path string) error {
		if refuse.Load() {
			return &os.PathError{Op: "remove", Path: path, Err: syscall.EROFS}
		}
		return remove(path)
	}
	t.Cleanup(func() { removeFile = remove })

	st.w.SetRetention(Retention{MaxBytes: 1, MaxPrunePerPass: 2})
	st.w.prunePassNow(t)
	st.w.prunePassNow(t)
	if got := formsOf(t, st.w, oldest); len(got) != 1 {
		t.Fatalf("the segment that could not be removed is held in %v", got)
	}
	if got := formsOf(t, st.w, second); len(got) != 1 {
		t.Fatalf("a newer segment was taken ahead of the one that could not be removed: %v", got)
	}
	if s := st.w.Stats(); s.Pruned != 0 || s.PruneFailed != 1 {
		t.Fatalf("%d pruned and %d failed after two refused passes, want 0 and 1", s.Pruned, s.PruneFailed)
	}

	// The policy no longer asks for it; the prune that is on the trail is
	// carried out all the same, and nothing else is.
	refuse.Store(false)
	st.w.SetRetention(Retention{})
	st.w.prunePassNow(t)
	if got := formsOf(t, st.w, second); len(got) != 1 {
		t.Fatalf("a segment the policy keeps was pruned: %v", got)
	}
	oneLossOnePrune(t, st, oldest)

	failed := 0
	for _, l := range ofType(readDir(t, st.cfg.Dir), "sys.segment.prune_failed") {
		d := l.detail()
		if d["resource"] != "audit_segment:"+oldest || d["errno_class"] == "" {
			t.Errorf("prune_failed detail %v", d)
		}
		failed++
	}
	if failed != 1 {
		t.Errorf("%d sys.segment.prune_failed records, want 1", failed)
	}
}
