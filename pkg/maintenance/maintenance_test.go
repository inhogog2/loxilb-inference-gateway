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

package maintenance

import (
	"sync"
	"testing"
	"time"
)

// fakeClock is a settable clock for deterministic elapsed/deadline tests.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newFixture() (*Manager, *fakeClock) {
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	return NewManager(clk.now), clk
}

func TestInitialStateIsActive(t *testing.T) {
	m, _ := newFixture()
	st := m.Status()
	if st.State != StateActive {
		t.Fatalf("initial state = %q, want %q", st.State, StateActive)
	}
	if st.OperationID != "" {
		t.Fatalf("initial OperationID = %q, want empty", st.OperationID)
	}
	if m.Active() {
		t.Fatal("Active() = true before any Enter")
	}
}

func TestEnterTransitionsAndReportsIdentity(t *testing.T) {
	m, clk := newFixture()
	st := m.Enter(5 * time.Minute)
	if st.State != StateMaintenance {
		t.Fatalf("state after Enter = %q, want %q", st.State, StateMaintenance)
	}
	if st.OperationID == "" {
		t.Fatal("Enter returned empty OperationID")
	}
	if !st.EnteredAt.Equal(clk.now()) {
		t.Fatalf("EnteredAt = %v, want clock time %v", st.EnteredAt, clk.now())
	}
	if st.DrainTimeout != 5*time.Minute {
		t.Fatalf("DrainTimeout = %v, want 5m", st.DrainTimeout)
	}
	if !m.Active() {
		t.Fatal("Active() = false after Enter")
	}
}

// Repeated Enter within one episode is a pure no-op: same operation ID,
// same EnteredAt, and -- deliberately -- the drain timeout does NOT get
// rewritten by the repeat call.
func TestEnterIsIdempotentIncludingTimeout(t *testing.T) {
	m, clk := newFixture()
	first := m.Enter(5 * time.Minute)
	clk.advance(30 * time.Second)
	second := m.Enter(1 * time.Hour) // different timeout must be ignored
	if second.OperationID != first.OperationID {
		t.Fatalf("repeat Enter changed OperationID: %q -> %q", first.OperationID, second.OperationID)
	}
	if !second.EnteredAt.Equal(first.EnteredAt) {
		t.Fatalf("repeat Enter changed EnteredAt: %v -> %v", first.EnteredAt, second.EnteredAt)
	}
	if second.DrainTimeout != 5*time.Minute {
		t.Fatalf("repeat Enter rewrote DrainTimeout to %v, want original 5m", second.DrainTimeout)
	}
	if second.Elapsed != 30*time.Second {
		t.Fatalf("Elapsed = %v, want 30s", second.Elapsed)
	}
}

func TestLeaveReturnsEndedEpisodeID(t *testing.T) {
	m, _ := newFixture()
	entered := m.Enter(0)
	left := m.Leave()
	if left.State != StateActive {
		t.Fatalf("state after Leave = %q, want %q", left.State, StateActive)
	}
	if left.OperationID != entered.OperationID {
		t.Fatalf("Leave receipt ID = %q, want ended episode %q", left.OperationID, entered.OperationID)
	}
	// The stored state must not keep the ended episode's identity.
	if st := m.Status(); st.OperationID != "" || st.State != StateActive {
		t.Fatalf("post-Leave Status = %+v, want active with empty ID", st)
	}
}

func TestLeaveIsIdempotent(t *testing.T) {
	m, _ := newFixture()
	m.Enter(0)
	m.Leave()
	again := m.Leave()
	if again.State != StateActive {
		t.Fatalf("state after repeat Leave = %q, want %q", again.State, StateActive)
	}
	if again.OperationID != "" {
		t.Fatalf("no-op Leave carried OperationID %q, want empty", again.OperationID)
	}
}

// A new episode must get a NEW operation ID even when the clock has not
// moved between episodes (the sequence number, not the timestamp, is the
// uniqueness guarantee).
func TestNewEpisodeGetsFreshOperationID(t *testing.T) {
	m, _ := newFixture()
	first := m.Enter(0)
	m.Leave()
	second := m.Enter(0)
	if second.OperationID == first.OperationID {
		t.Fatalf("second episode reused OperationID %q", first.OperationID)
	}
}

func TestDeadlineExceededReporting(t *testing.T) {
	m, clk := newFixture()
	m.Enter(1 * time.Minute)

	if st := m.Status(); st.DeadlineExceeded {
		t.Fatal("DeadlineExceeded = true immediately after Enter")
	}
	clk.advance(59 * time.Second)
	if st := m.Status(); st.DeadlineExceeded {
		t.Fatal("DeadlineExceeded = true before the window elapsed")
	}
	clk.advance(2 * time.Second)
	st := m.Status()
	if !st.DeadlineExceeded {
		t.Fatal("DeadlineExceeded = false after the window elapsed")
	}
	// Passing the deadline must NOT flip the state by itself.
	if st.State != StateMaintenance {
		t.Fatalf("state flipped to %q on deadline; the operator owns the transition", st.State)
	}
}

func TestZeroTimeoutNeverExceedsDeadline(t *testing.T) {
	m, clk := newFixture()
	m.Enter(0)
	clk.advance(24 * time.Hour)
	if st := m.Status(); st.DeadlineExceeded {
		t.Fatal("DeadlineExceeded = true with no declared drain window")
	}
}

func TestConcurrentEnterYieldsOneEpisode(t *testing.T) {
	m, _ := newFixture()
	const n = 32
	ids := make([]string, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ids[i] = m.Enter(time.Minute).OperationID
		}(i)
	}
	wg.Wait()
	for i := 1; i < n; i++ {
		if ids[i] != ids[0] {
			t.Fatalf("concurrent Enter produced divergent episode IDs: %q vs %q", ids[0], ids[i])
		}
	}
}

// withDrainHook installs a recording data-path drain for one test and
// removes it afterwards so no other test sees a data path attached.
func withDrainHook(t *testing.T) *[]bool {
	t.Helper()
	calls := &[]bool{}
	SetDataPathDrain(func(on bool) { *calls = append(*calls, on) })
	t.Cleanup(func() { SetDataPathDrain(nil) })
	return calls
}

func TestNoDataPathNeverClaimsInferenceRefusal(t *testing.T) {
	m, _ := newFixture()
	m.Enter(0)
	if st := m.Status(); st.RefusingInference {
		t.Fatal("RefusingInference = true with no data path drain installed")
	}
}

func TestDataPathDrainFollowsTheEpisode(t *testing.T) {
	m, _ := newFixture()
	calls := withDrainHook(t)

	st := m.Enter(time.Minute)
	if !st.RefusingInference {
		t.Fatal("Enter with a drain installed reported RefusingInference = false")
	}
	if got := *calls; len(got) != 1 || !got[0] {
		t.Fatalf("Enter drained %v, want [true]", got)
	}
	// A repeated Enter is the same episode: the data path is not drained
	// twice.
	m.Enter(time.Hour)
	if got := *calls; len(got) != 1 {
		t.Fatalf("idempotent Enter drained again: %v", got)
	}
	st = m.Leave()
	if st.RefusingInference {
		t.Fatal("Leave reported RefusingInference = true")
	}
	if got := *calls; len(got) != 2 || got[1] {
		t.Fatalf("Leave drained %v, want [true false]", got)
	}
	// A no-op Leave ends nothing and touches no data path.
	m.Leave()
	if got := *calls; len(got) != 2 {
		t.Fatalf("no-op Leave drained again: %v", got)
	}
}

func TestDataPathDrainRunsOutsideTheLock(t *testing.T) {
	m, _ := newFixture()
	// A drain that reads the status back must not deadlock: the manager
	// releases its lock before calling the data path.
	var seen []State
	SetDataPathDrain(func(on bool) { seen = append(seen, m.Status().State) })
	t.Cleanup(func() { SetDataPathDrain(nil) })

	done := make(chan struct{})
	go func() {
		m.Enter(0)
		m.Leave()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Enter/Leave with a status-reading drain did not return: hook called under the lock")
	}
	if len(seen) != 2 || seen[0] != StateMaintenance || seen[1] != StateActive {
		t.Fatalf("drain saw states %v, want [maintenance active]", seen)
	}
}
