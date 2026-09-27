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
	"context"
	"errors"
	"fmt"
	"sort"
	"time"
)

// Policy is the part of the audit configuration that may be changed while
// the gateway runs. Everything outside it — the audit root directory, the
// mandatory-audit mode and the instance identity — is startup-only,
// because changing where the trail is written while it is being written
// would break the one thing the trail is for.
type Policy struct {
	// MaxSegmentBytes seals the active segment before it exceeds this.
	MaxSegmentBytes int64
	// MaxSegmentAge seals the active segment once it is this old.
	MaxSegmentAge time.Duration
	// Retention is the local prune policy.
	Retention Retention
}

// PolicyFloor is the minimum a deployment profile accepts. A change that
// would go below it is refused for every caller, the gateway administrator
// included: the floor exists so that the operator who is being audited
// cannot quietly shorten the evidence.
//
// The zero floor imposes nothing. A profile supplies the numbers; none are
// invented here, because a floor that the plan has not decided would be a
// policy claim dressed as a default.
type PolicyFloor struct {
	// MinRetentionAge refuses a retention target shorter than this.
	MinRetentionAge time.Duration
	// MinRetentionBytes refuses a local byte quota smaller than this. A
	// quota of zero means "no quota" and is never below the floor.
	MinRetentionBytes int64
	// MinReserveBytes refuses a smaller free-space reserve.
	MinReserveBytes int64
	// MaxSegmentAgeCeiling refuses leaving a segment open longer than
	// this: an unsealed segment is the part of the trail that is not yet
	// protected by a seal.
	MaxSegmentAgeCeiling time.Duration
}

// IsZero reports whether the floor constrains anything.
func (f PolicyFloor) IsZero() bool { return f == PolicyFloor{} }

// ErrPolicyFloor is returned when a change would go below the profile's
// floor. The violated field names travel with it.
type ErrPolicyFloor struct{ Fields []string }

func (e *ErrPolicyFloor) Error() string {
	return "audit: policy below the profile floor: " + joinFields(e.Fields)
}

func joinFields(f []string) string {
	out := ""
	for i, s := range f {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}

// Validate rejects a policy that is internally impossible, before any
// question of the floor.
func (p Policy) Validate() error {
	if p.MaxSegmentBytes < 0 {
		return errors.New("audit: max_segment_bytes must not be negative")
	}
	if p.MaxSegmentAge < 0 {
		return errors.New("audit: max_segment_age must not be negative")
	}
	if p.Retention.MaxAge < 0 {
		return errors.New("audit: retention.max_age must not be negative")
	}
	if p.Retention.MaxBytes < 0 {
		return errors.New("audit: retention.max_bytes must not be negative")
	}
	if p.Retention.ReserveBytes < 0 {
		return errors.New("audit: retention.reserve_bytes must not be negative")
	}
	if p.Retention.MaxPrunePerPass < 0 {
		return errors.New("audit: retention.max_prune_per_pass must not be negative")
	}
	// A quota smaller than one segment cannot be satisfied by pruning: the
	// writer would delete everything and still be over.
	if p.Retention.MaxBytes > 0 && p.MaxSegmentBytes > 0 && p.Retention.MaxBytes < p.MaxSegmentBytes {
		return fmt.Errorf("audit: retention.max_bytes %d is below one segment (%d)",
			p.Retention.MaxBytes, p.MaxSegmentBytes)
	}
	return nil
}

// FloorViolations names the fields that fall below the floor. An empty
// result means the policy is acceptable.
func (p Policy) FloorViolations(f PolicyFloor) []string {
	var bad []string
	if f.MinRetentionAge > 0 {
		// Zero means "keep forever", which is never below a floor.
		if p.Retention.MaxAge > 0 && p.Retention.MaxAge < f.MinRetentionAge {
			bad = append(bad, "retention.max_age")
		}
	}
	if f.MinRetentionBytes > 0 && p.Retention.MaxBytes > 0 && p.Retention.MaxBytes < f.MinRetentionBytes {
		bad = append(bad, "retention.max_bytes")
	}
	if f.MinReserveBytes > 0 && p.Retention.ReserveBytes < f.MinReserveBytes {
		bad = append(bad, "retention.reserve_bytes")
	}
	if f.MaxSegmentAgeCeiling > 0 {
		// Zero here means "never seal by age", which is the weakest
		// setting and so always violates a ceiling.
		if p.MaxSegmentAge == 0 || p.MaxSegmentAge > f.MaxSegmentAgeCeiling {
			bad = append(bad, "max_segment_age")
		}
	}
	sort.Strings(bad)
	return bad
}

// ChangedFields names what differs between two policies, in the dotted
// form the audit record's changed_fields carries.
func ChangedFields(old, next Policy) []string {
	var out []string
	if old.MaxSegmentBytes != next.MaxSegmentBytes {
		out = append(out, "max_segment_bytes")
	}
	if old.MaxSegmentAge != next.MaxSegmentAge {
		out = append(out, "max_segment_age")
	}
	if old.Retention.MaxAge != next.Retention.MaxAge {
		out = append(out, "retention.max_age")
	}
	if old.Retention.MaxBytes != next.Retention.MaxBytes {
		out = append(out, "retention.max_bytes")
	}
	if old.Retention.ReserveBytes != next.Retention.ReserveBytes {
		out = append(out, "retention.reserve_bytes")
	}
	if old.Retention.MaxPrunePerPass != next.Retention.MaxPrunePerPass {
		out = append(out, "retention.max_prune_per_pass")
	}
	sort.Strings(out)
	return out
}

// Policy returns the policy in force.
func (w *Writer) Policy() Policy {
	return Policy{
		MaxSegmentBytes: w.segMaxBytes.Load(),
		MaxSegmentAge:   time.Duration(w.segMaxAge.Load()),
		Retention:       w.RetentionPolicy(),
	}
}

// SetPolicy validates a policy, checks it against the floor and applies it
// on the writer goroutine so the change is ordered with the writes around
// it. It reports the fields that changed.
//
// Lowering a retention target never deletes what is already on disk. The
// segments sealed at the moment of the reduction keep the terms they were
// written under; only what is sealed afterwards is subject to the shorter
// one. A reduced target is an instruction about the future, not an
// instruction to destroy existing evidence — and an operator who could
// shorten retention and have yesterday's segments disappear in the same
// call would have a deletion tool, not a policy knob. A free-space breach
// still prunes them, because a full disk stops the trail altogether.
func (w *Writer) SetPolicy(ctx context.Context, p Policy, floor PolicyFloor) ([]string, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if bad := p.FloorViolations(floor); len(bad) > 0 {
		return nil, &ErrPolicyFloor{Fields: bad}
	}
	old := w.Policy()
	changed := ChangedFields(old, p)
	if len(changed) == 0 {
		return nil, nil
	}
	p.Retention = p.Retention.withDefaults()
	err := w.onLoop(ctx, func() {
		w.grandfatherLocked(old, p)
		w.segMaxBytes.Store(p.MaxSegmentBytes)
		w.segMaxAge.Store(int64(p.MaxSegmentAge))
		w.seg.maxBytes = p.MaxSegmentBytes
		w.seg.maxAge = p.MaxSegmentAge
		r := p.Retention
		w.retention.Store(&r)
	})
	if err != nil {
		return nil, err
	}
	return changed, nil
}

// grandfatherLocked records the terms the already-sealed segments were
// written under, when the new policy is stricter than the old one. It runs
// on the writer goroutine.
func (w *Writer) grandfatherLocked(old, next Policy) {
	tighterAge := next.Retention.MaxAge > 0 &&
		(old.Retention.MaxAge == 0 || next.Retention.MaxAge < old.Retention.MaxAge)
	tighterBytes := next.Retention.MaxBytes > 0 &&
		(old.Retention.MaxBytes == 0 || next.Retention.MaxBytes < old.Retention.MaxBytes)
	if !tighterAge && !tighterBytes {
		return
	}
	segs, err := w.seg.listSealed()
	if err != nil {
		w.logf("audit: policy change: cannot list sealed segments, nothing grandfathered: %v", err)
		return
	}
	w.grandMu.Lock()
	defer w.grandMu.Unlock()
	if w.grandfathered == nil {
		w.grandfathered = make(map[string]time.Time)
	}
	for _, s := range segs {
		uuid := w.seg.uuidOf(s.Path)
		if uuid == "" {
			continue
		}
		if _, ok := w.grandfathered[uuid]; ok {
			// Already carrying earlier terms; a second reduction must not
			// shorten them.
			continue
		}
		// The zero time means the old policy would have kept this segment
		// indefinitely, so the new age rule never reaches it.
		var notBefore time.Time
		if old.Retention.MaxAge > 0 {
			notBefore = s.SealedAt.Add(old.Retention.MaxAge)
		}
		w.grandfathered[uuid] = notBefore
	}
}

// grandfatherHolds reports whether a segment is still protected by the
// terms it was sealed under. A breach of the free-space reserve overrides
// it: a trail that cannot write is worse than one that pruned early.
func (w *Writer) grandfatherHolds(uuid string, now time.Time) bool {
	if uuid == "" {
		return false
	}
	w.grandMu.Lock()
	defer w.grandMu.Unlock()
	notBefore, ok := w.grandfathered[uuid]
	if !ok {
		return false
	}
	if notBefore.IsZero() {
		return true
	}
	if now.Before(notBefore) {
		return true
	}
	delete(w.grandfathered, uuid)
	return false
}

// forgetGrandfather drops a segment's protection once it is gone.
func (w *Writer) forgetGrandfather(uuid string) {
	if uuid == "" {
		return
	}
	w.grandMu.Lock()
	delete(w.grandfathered, uuid)
	w.grandMu.Unlock()
}

// RotateNow seals the active segment and opens the next one, as the
// operator action of the same name. It returns the sealed segment's UUID
// and the one now active.
func (w *Writer) RotateNow(ctx context.Context) (sealed, opened string, err error) {
	rerr := w.onLoop(ctx, func() {
		sealed = w.seg.currentUUID()
		if e := w.rotate(); e != nil {
			err = e
			return
		}
		opened = w.seg.currentUUID()
	})
	if rerr != nil {
		return "", "", rerr
	}
	return sealed, opened, err
}
