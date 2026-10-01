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
	"io/fs"
	"os"
	"strings"
)

// NewEventID mints the identifier an intent and its result share. The
// gate mints it before the intent is written so the result can name it
// after the record itself has gone back to the pool.
func NewEventID() string { return newUUID() }

// intentLine is the minimal decode of a management record used by the
// orphan scan.
type intentLine struct {
	Kind    string `json:"kind"`
	Stream  Stream `json:"stream"`
	Phase   Phase  `json:"phase"`
	EventID string `json:"event_id"`
	BootID  string `json:"boot_id"`
}

// maxOrphanScanSegments bounds how many of the previous boot's segments
// the start-time scan reads. An intent's result follows it, so a pair can
// straddle a rotation but never run backwards; the newest segments are
// where a crash leaves its orphans.
const maxOrphanScanSegments = 8

// scanOrphans reconciles the previous boot: a management intent is durable
// and its result is best-effort, so a crash between the two leaves an
// intent with no result. That is information, not a defect, and it is
// reported rather than left for an investigator to notice. The scan reads
// the previous boot's newest segments — the segment that boot left
// unsealed is among them once recovery has sealed it — and writes one
// sys.intent.orphaned record per intent without a result, carrying the
// intent's event_id and the configuration generation observed at this
// boot. Nothing guesses whether the mutation landed.
func (w *Writer) scanOrphans() {
	sealed, err := w.seg.listSealed()
	if err != nil {
		w.logf("audit: orphan scan: %v", err)
		return
	}
	var files []string
	prevBoot, newer := "", ""
	for i := len(sealed) - 1; i >= 0 && len(files) < maxOrphanScanSegments; i-- {
		// Between its rename and its remove, a segment being compressed
		// is listed twice, as X.jsonl.gz and X.jsonl. It is one segment.
		name := sealed[i].Name
		if name+gzipExt == newer {
			continue
		}
		newer = name
		hdr, ok := readSegmentHeader(sealed[i].Path)
		if !ok || hdr.BootID == w.bootID {
			continue
		}
		if prevBoot == "" {
			prevBoot = hdr.BootID
		}
		if hdr.BootID != prevBoot {
			break
		}
		files = append([]string{sealed[i].Path}, files...)
	}
	if len(files) == 0 {
		return
	}
	open := map[string]struct{}{}
	var order []string
	for _, path := range files {
		w.scanOrphanFile(path, open, &order)
	}
	gen := uint64(0)
	if w.cfg.ConfigGeneration != nil {
		gen = w.cfg.ConfigGeneration()
	}
	for _, id := range order {
		if _, still := open[id]; !still {
			continue
		}
		w.stats.orphanedIntents.Add(1)
		orphan := id
		w.lastOrphan.Store(&orphan)
		w.writeSystem(sysRecord("sys.intent.orphaned", "mgmt_intent", &SysDetail{
			IntentEventID: id, ConfigGenerationAtBoot: gen,
		}))
	}
}

// openSealed opens a sealed segment for reading, decompressing a .gz one.
// The scan lists the directory before it reads, and the compression
// worker starts at the same time: it writes X.jsonl.gz and then removes
// X.jsonl, so a plain segment listed a moment ago can be gone by the time
// it is opened. It is then read under its .gz name, not skipped.
func openSealed(path string) (io.Reader, func(), error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) && !strings.HasSuffix(path, gzipExt) {
		path += gzipExt
		f, err = os.Open(path)
	}
	if err != nil {
		return nil, nil, err
	}
	if !strings.HasSuffix(path, gzipExt) {
		return f, func() { f.Close() }, nil
	}
	zr, err := gzip.NewReader(f)
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return zr, func() { zr.Close(); f.Close() }, nil
}

// readSegmentHeader decodes the first line of a sealed segment.
func readSegmentHeader(path string) (segmentHeader, bool) {
	r, done, err := openSealed(path)
	if err != nil {
		return segmentHeader{}, false
	}
	defer done()
	line, err := bufio.NewReaderSize(r, 4096).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return segmentHeader{}, false
	}
	var hdr segmentHeader
	if json.Unmarshal(bytes.TrimSpace(line), &hdr) != nil || hdr.Kind != kindHeader {
		return segmentHeader{}, false
	}
	return hdr, true
}

// scanOrphanFile adds every management intent in the file to open and
// removes every one that has its result. Records of the current boot are
// skipped so a restart of the writer goroutine never reports its own
// in-flight pairs. A line the decoder cannot read ends the scan of that
// file: a torn tail was already truncated at recovery, so anything after
// an unreadable line is not evidence.
func (w *Writer) scanOrphanFile(path string, open map[string]struct{}, order *[]string) {
	r, done, err := openSealed(path)
	if err != nil {
		w.logf("audit: orphan scan %s: %v", path, err)
		return
	}
	defer done()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), maxLineBytes)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var il intentLine
		if err := json.Unmarshal(line, &il); err != nil {
			return
		}
		if il.Kind != "" || il.Stream != StreamMgmt || il.BootID == w.bootID {
			continue
		}
		switch il.Phase {
		case PhaseIntent:
			if _, seen := open[il.EventID]; !seen {
				open[il.EventID] = struct{}{}
				*order = append(*order, il.EventID)
			}
		case PhaseResult:
			delete(open, il.EventID)
		}
	}
}
