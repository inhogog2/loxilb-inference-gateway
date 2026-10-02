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
package handler

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/loxilb-io/loxilb/pkg/audit"
	"github.com/loxilb-io/loxilb/pkg/audit/syslog"
	tk "github.com/loxilb-io/loxilib"
)

// auditComplianceSink names the sink /audit/sink configures: the one that
// receives every record. Its cursor is kept under this name whatever the
// receiver's address is, so pointing the sink at another receiver continues
// where the trail was left and does not send it again from the start.
const auditComplianceSink = "compliance"

// auditSinkStopTimeout bounds the wait for a tailer to end. A tailer that
// is asked to stop finishes the submission it is in first, and that is at
// most one dial and one write.
const auditSinkStopTimeout = syslog.DefaultDialTimeout + syslog.DefaultWriteTimeout + 5*time.Second

// auditSinkCloseShare is how much of a shutdown's time the tailer may take
// before the writer is closed regardless. A tailer cut off here has not
// saved its cursor, which costs a re-send of at most one batch at the next
// start; a writer cut off loses records.
const auditSinkCloseShare = 2 * time.Second

// syslogSubmitter puts a syslog sink behind the tailer's Submitter, and
// says in the tailer's terms how a submission failed.
type syslogSubmitter struct{ s *syslog.Sink }

func (a syslogSubmitter) Submit(line []byte, xseq, epoch uint64) error {
	var err error
	if xseq == 0 {
		err = a.s.Submit(line)
	} else {
		err = a.s.SubmitExport(line, xseq, epoch)
	}
	switch {
	case err == nil:
		return nil
	case errors.Is(err, syslog.ErrRejected):
		return fmt.Errorf("%w: %w", audit.ErrSubmitRejected, err)
	case errors.Is(err, syslog.ErrNotAttempted), errors.Is(err, syslog.ErrNoEnterpriseNumber):
		// A sink with no enterprise number refuses before it frames
		// anything. That is a fault of the configuration and not of the
		// record, so the record is kept and tried again rather than
		// skipped.
		return fmt.Errorf("%w: %w", audit.ErrSubmitNotAttempted, err)
	}
	return err
}

func (a syslogSubmitter) Peer() (string, time.Time, bool) { return a.s.Peer() }

// startAuditSinkTailer starts the compliance tailer for s over w's trail.
func startAuditSinkTailer(w *audit.Writer, s *syslog.Sink) (*audit.SinkTailer, error) {
	t, err := audit.NewSinkTailer(audit.SinkTailerConfig{
		Name:       auditComplianceSink,
		Dir:        w.Dir(),
		Submitter:  syslogSubmitter{s},
		Compliance: true,
		Emit:       w.EmitSystem,
		Logf:       func(f string, v ...any) { tk.LogIt(tk.LogInfo, f+"\n", v...) },
		Fault:      audit.FaultArmed,
	})
	if err != nil {
		return nil, err
	}
	t.Start()
	return t, nil
}

// stopAuditSinkLocked ends the tailer, waits for it and drops the sink's
// connection. The tailer is forgotten only once it has ended: two tailers
// over one cursor would each send what the other already sent. The caller
// holds auditSink.mu.
func stopAuditSinkLocked(ctx context.Context) error {
	if auditSink.tailer != nil {
		if err := auditSink.tailer.Stop(ctx); err != nil {
			return err
		}
		auditSink.tailer = nil
	}
	if auditSink.sink != nil {
		_ = auditSink.sink.Close()
	}
	return nil
}
