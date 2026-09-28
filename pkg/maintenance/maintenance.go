/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Package maintenance holds the operator-owned maintenance state of the
// gateway's management plane. It is deliberately distinct from the two
// internal write-freezes (boot-replay settling and restore-in-progress in
// the snapshot domain): those gates are taken by the gateway itself and
// clear themselves, while this one is entered and left only by an
// operator through PUT /maintenance.
//
// The package is pure state machinery: no I/O, no cgo, no knowledge of
// what is being refused. The REST middleware consults Active() to refuse
// mutating configuration calls; the read-back handler combines Status()
// with live counters it fetches elsewhere. Refusal of new *inference*
// requests happens on the data path (sockproxy): it installs a drain
// (SetDataPathDrain) that Enter turns on and Leave turns off, and the
// read-back reports whether such a drain is installed.
package maintenance

import (
	"fmt"
	"sync"
	"time"
)

// State is the operator maintenance state of the management plane.
type State string

const (
	// StateActive - normal operation, no operator maintenance in effect.
	StateActive State = "active"
	// StateMaintenance - an operator holds the gateway in maintenance;
	// mutating configuration calls are refused until Leave.
	StateMaintenance State = "maintenance"
)

// Status is a point-in-time snapshot of the maintenance state. Elapsed
// and DeadlineExceeded are computed against the clock at snapshot time,
// so two Status calls in the same episode agree on identity fields
// (OperationID, EnteredAt, DrainTimeout) but not necessarily on Elapsed.
type Status struct {
	State State
	// OperationID identifies the maintenance episode. Stable across
	// repeated idempotent Enter calls within one episode; empty when no
	// episode is in effect. A Leave response carries the ID of the
	// episode it ended (empty when Leave was a no-op).
	OperationID string
	// RefusingInference reports that the data path refuses new inference
	// requests for this episode: true while in maintenance once the data
	// path has installed its drain (SetDataPathDrain); false for a
	// management plane with no data path behind it.
	RefusingInference bool
	// EnteredAt is when the current episode began (zero when active).
	EnteredAt time.Time
	// DrainTimeout is the operator-declared drain window for the current
	// episode (0 = no deadline declared).
	DrainTimeout time.Duration
	// Elapsed is time spent in the current episode at snapshot time.
	Elapsed time.Duration
	// DeadlineExceeded reports Elapsed > DrainTimeout for a nonzero
	// DrainTimeout. The state machine does NOT leave maintenance on its
	// own when the deadline passes -- it only reports the fact; the
	// operator decides what an overrun means.
	DeadlineExceeded bool
}

// Manager is a maintenance state machine. The zero value is not usable;
// construct with NewManager. A process normally uses the package-level
// default manager via the package functions below.
type Manager struct {
	mu sync.Mutex
	// applyMu orders the data path's drain calls: each applies the state
	// as it stands when its turn comes, so the last one to run is the
	// current state however two transitions overlapped.
	applyMu      sync.Mutex
	state        State
	opSeq        uint64
	opID         string
	enteredAt    time.Time
	drainTimeout time.Duration
	now          func() time.Time
}

// DataPathDrain is what the data path does when maintenance is entered
// (on = true) or left (on = false): refuse new inference requests, end the
// ones waiting for capacity, and let the executing ones finish. Installed
// once by the data path at start; nil means no data path is attached and
// maintenance refuses configuration writes only.
type DataPathDrain func(on bool)

var (
	drainMu   sync.Mutex
	drainHook DataPathDrain
)

// SetDataPathDrain installs the data path's drain. Entering maintenance
// after this call drains the data path; leaving it restores admission.
func SetDataPathDrain(fn DataPathDrain) {
	drainMu.Lock()
	drainHook = fn
	drainMu.Unlock()
}

func dataPathDrain() DataPathDrain {
	drainMu.Lock()
	defer drainMu.Unlock()
	return drainHook
}

// NewManager returns a Manager in the active state. A nil clock means
// time.Now; tests inject a fake clock.
func NewManager(clock func() time.Time) *Manager {
	if clock == nil {
		clock = time.Now
	}
	return &Manager{state: StateActive, now: clock}
}

// Enter puts the manager into maintenance. Idempotent: entering while
// already in maintenance changes nothing -- not the operation ID, not
// EnteredAt, not the drain timeout (changing the window requires
// Leave+Enter, so one episode has one immutable identity). Returns the
// resulting status.
func (m *Manager) Enter(drainTimeout time.Duration) Status {
	m.mu.Lock()
	entered := false
	if m.state != StateMaintenance {
		m.opSeq++
		m.enteredAt = m.now()
		m.drainTimeout = drainTimeout
		m.opID = fmt.Sprintf("maint-%d-%d", m.enteredAt.Unix(), m.opSeq)
		m.state = StateMaintenance
		entered = true
	}
	st := m.statusLocked()
	m.mu.Unlock()
	if entered {
		m.applyDrain()
	}
	return st
}

// Leave returns the manager to the active state. Idempotent: leaving
// while active changes nothing. The returned status carries the ID of
// the episode that was ended, so the transition is receipt-able; a
// no-op Leave carries an empty OperationID.
func (m *Manager) Leave() Status {
	m.mu.Lock()
	endedID := ""
	if m.state == StateMaintenance {
		endedID = m.opID
		m.state = StateActive
		m.opID = ""
		m.enteredAt = time.Time{}
		m.drainTimeout = 0
	}
	st := m.statusLocked()
	st.OperationID = endedID
	m.mu.Unlock()
	if endedID != "" {
		m.applyDrain()
	}
	return st
}

// applyDrain brings the data path to the manager's state. It runs outside
// m.mu (the data path walks its pools and ends waiting requests, and a
// status read must not wait for that) but under applyMu, and it reads the
// state after taking its turn: an Enter and a Leave that overlap each apply
// whatever the state is by then, so the data path can never be left
// draining behind a manager that reports active, or open behind one that
// reports maintenance.
func (m *Manager) applyDrain() {
	fn := dataPathDrain()
	if fn == nil {
		return
	}
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	m.mu.Lock()
	on := m.state == StateMaintenance
	m.mu.Unlock()
	fn(on)
}

// Status returns the current state snapshot.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.statusLocked()
}

// Active reports whether operator maintenance is in effect (the
// middleware's cheap gate check).
func (m *Manager) Active() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state == StateMaintenance
}

func (m *Manager) statusLocked() Status {
	st := Status{
		State:        m.state,
		OperationID:  m.opID,
		EnteredAt:    m.enteredAt,
		DrainTimeout: m.drainTimeout,
	}
	if m.state == StateMaintenance {
		st.Elapsed = m.now().Sub(m.enteredAt)
		st.DeadlineExceeded = m.drainTimeout > 0 && st.Elapsed > m.drainTimeout
		st.RefusingInference = dataPathDrain() != nil
	}
	return st
}

// defaultManager is the process-wide maintenance state consulted by the
// REST middleware and handlers.
var defaultManager = NewManager(nil)

// Enter enters maintenance on the process-wide manager.
func Enter(drainTimeout time.Duration) Status { return defaultManager.Enter(drainTimeout) }

// Leave leaves maintenance on the process-wide manager.
func Leave() Status { return defaultManager.Leave() }

// Get returns the process-wide maintenance status.
func Get() Status { return defaultManager.Status() }

// Active reports whether the process-wide manager is in maintenance.
func Active() bool { return defaultManager.Active() }
