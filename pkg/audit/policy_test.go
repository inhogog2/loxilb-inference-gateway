/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

package audit

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func basePolicy() Policy {
	return Policy{
		MaxSegmentBytes: 1 << 20,
		MaxSegmentAge:   time.Hour,
		Retention:       Retention{MaxAge: 48 * time.Hour, MaxPrunePerPass: 1},
	}
}

func TestPolicyValidateRejectsTheImpossible(t *testing.T) {
	cases := map[string]func(*Policy){
		"negative segment bytes": func(p *Policy) { p.MaxSegmentBytes = -1 },
		"negative segment age":   func(p *Policy) { p.MaxSegmentAge = -time.Second },
		"negative retention age": func(p *Policy) { p.Retention.MaxAge = -time.Second },
		"negative quota":         func(p *Policy) { p.Retention.MaxBytes = -1 },
		"negative reserve":       func(p *Policy) { p.Retention.ReserveBytes = -1 },
		// A quota below one segment can never be satisfied: the writer
		// would delete every segment and still be over it.
		"quota below one segment": func(p *Policy) { p.Retention.MaxBytes = 1024 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := basePolicy()
			mutate(&p)
			if err := p.Validate(); err == nil {
				t.Fatalf("%s was accepted", name)
			}
		})
	}
	if err := basePolicy().Validate(); err != nil {
		t.Fatalf("a sane policy was refused: %v", err)
	}
}

func TestPolicyFloorNamesTheViolatedFields(t *testing.T) {
	floor := PolicyFloor{
		MinRetentionAge:      24 * time.Hour,
		MinReserveBytes:      1 << 20,
		MaxSegmentAgeCeiling: 2 * time.Hour,
	}
	p := basePolicy()
	p.Retention.MaxAge = time.Hour  // below the floor
	p.Retention.ReserveBytes = 1024 // below the floor
	p.MaxSegmentAge = 6 * time.Hour // above the ceiling
	got := p.FloorViolations(floor)
	want := []string{"max_segment_age", "retention.max_age", "retention.reserve_bytes"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("violations %v, want %v", got, want)
	}
}

func TestPolicyFloorTreatsKeepForeverAsAboveTheFloor(t *testing.T) {
	floor := PolicyFloor{MinRetentionAge: 24 * time.Hour, MinRetentionBytes: 1 << 30}
	p := basePolicy()
	// Zero means keep forever, which is the strongest setting there is.
	p.Retention.MaxAge = 0
	p.Retention.MaxBytes = 0
	if got := p.FloorViolations(floor); len(got) != 0 {
		t.Fatalf("keeping forever was read as below the floor: %v", got)
	}
}

func TestPolicyFloorTreatsNeverSealingAsBelowACeiling(t *testing.T) {
	// A segment that is never sealed by age is the part of the trail with
	// no seal over it, so "never" is the weakest setting, not the
	// strongest.
	floor := PolicyFloor{MaxSegmentAgeCeiling: time.Hour}
	p := basePolicy()
	p.MaxSegmentAge = 0
	if got := p.FloorViolations(floor); len(got) != 1 || got[0] != "max_segment_age" {
		t.Fatalf("violations %v, want max_segment_age", got)
	}
}

func TestZeroFloorConstrainsNothing(t *testing.T) {
	p := basePolicy()
	p.Retention = Retention{}
	p.MaxSegmentAge = 0
	if got := p.FloorViolations(PolicyFloor{}); len(got) != 0 {
		t.Fatalf("the zero floor refused something: %v", got)
	}
}

func TestChangedFields(t *testing.T) {
	old := basePolicy()
	next := old
	next.Retention.MaxAge = 72 * time.Hour
	next.MaxSegmentBytes = 1 << 21
	got := ChangedFields(old, next)
	want := []string{"max_segment_bytes", "retention.max_age"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("changed %v, want %v", got, want)
	}
	if got := ChangedFields(old, old); len(got) != 0 {
		t.Fatalf("an unchanged policy reported %v", got)
	}
}

func TestSetPolicyAppliesAndReportsWhatChanged(t *testing.T) {
	cfg := testConfig(t)
	cfg.Retention = Retention{MaxAge: 48 * time.Hour}
	w := startWriter(t, cfg)
	ctx := context.Background()

	next := w.Policy()
	next.MaxSegmentBytes = 4096
	next.Retention.MaxAge = 72 * time.Hour
	changed, err := w.SetPolicy(ctx, next, PolicyFloor{})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"max_segment_bytes", "retention.max_age"}
	if !reflect.DeepEqual(changed, want) {
		t.Fatalf("changed %v, want %v", changed, want)
	}
	got := w.Policy()
	if got.MaxSegmentBytes != 4096 || got.Retention.MaxAge != 72*time.Hour {
		t.Fatalf("policy not applied: %+v", got)
	}
	// The segmenter is what actually seals, so the change has to reach it
	// and not only the mirror the status endpoint reads.
	if w.seg.maxBytes != 4096 {
		t.Fatalf("segmenter still sealing at %d", w.seg.maxBytes)
	}
	if again, err := w.SetPolicy(ctx, got, PolicyFloor{}); err != nil || len(again) != 0 {
		t.Fatalf("re-applying the same policy reported %v, %v", again, err)
	}
}

func TestSetPolicyRefusesBelowTheFloorForEveryCaller(t *testing.T) {
	cfg := testConfig(t)
	cfg.Retention = Retention{MaxAge: 48 * time.Hour}
	w := startWriter(t, cfg)

	next := w.Policy()
	next.Retention.MaxAge = time.Minute
	_, err := w.SetPolicy(context.Background(), next, PolicyFloor{MinRetentionAge: 24 * time.Hour})
	var fe *ErrPolicyFloor
	if !errors.As(err, &fe) {
		t.Fatalf("want a floor refusal, got %v", err)
	}
	if len(fe.Fields) != 1 || fe.Fields[0] != "retention.max_age" {
		t.Fatalf("refusal named %v", fe.Fields)
	}
	// Refused means unchanged, not partially applied.
	if w.Policy().Retention.MaxAge != 48*time.Hour {
		t.Fatalf("a refused change was applied anyway: %v", w.Policy().Retention.MaxAge)
	}
}

// TestLoweringRetentionDoesNotDeleteWhatIsAlreadySealed is the rule that
// separates a policy knob from a deletion tool. An operator who shortens
// retention is saying something about what to keep from now on; if
// yesterday's segments vanished in the same call, the endpoint would be a
// way to destroy evidence with one request.
func TestLoweringRetentionDoesNotDeleteWhatIsAlreadySealed(t *testing.T) {
	cfg := testConfig(t)
	cfg.Retention = Retention{MaxAge: time.Hour, MaxPrunePerPass: 10}
	w := startWriter(t, cfg)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if err := w.Write(ctx, mgmtIntent("/seg")); err != nil {
			t.Fatal(err)
		}
		if err := w.SealNow(ctx); err != nil {
			t.Fatal(err)
		}
	}
	// Wait for compression too: the worker renames a sealed file, and a
	// prune pass holding the pre-rename listing would fail on a path that
	// no longer exists.
	waitFor(t, "three compressed segments", func() bool { return compressedCount(w) == 3 })
	before, _ := w.seg.listSealed()

	// Cut retention to effectively nothing.
	next := w.Policy()
	next.Retention.MaxAge = time.Nanosecond
	if _, err := w.SetPolicy(ctx, next, PolicyFloor{}); err != nil {
		t.Fatal(err)
	}
	w.prunePassNow(t)

	after, _ := w.seg.listSealed()
	if len(after) != len(before) {
		t.Fatalf("lowering retention deleted %d segments that were already on disk",
			len(before)-len(after))
	}

	// What is sealed after the change is subject to the new terms, or the
	// reduction would never take effect at all.
	if err := w.Write(ctx, mgmtIntent("/after")); err != nil {
		t.Fatal(err)
	}
	if err := w.SealNow(ctx); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "a fourth compressed segment", func() bool { return compressedCount(w) == 4 })
	time.Sleep(10 * time.Millisecond) // older than a nanosecond
	w.prunePassNow(t)
	final, _ := w.seg.listSealed()
	if len(final) != 3 {
		t.Fatalf("after the new segment aged out there are %d segments, want the 3 grandfathered ones", len(final))
	}
	kept := map[string]bool{}
	for _, s := range final {
		kept[s.Name] = true
	}
	for _, s := range before {
		if !kept[s.Name] {
			t.Fatalf("grandfathered segment %s was pruned", s.Name)
		}
	}
}

// TestAFreeSpaceBreachOverridesTheGrandfather: keeping old segments must
// not be able to wedge the trail. A disk that cannot be written to stops
// the audit altogether, which is worse than pruning early.
func TestAFreeSpaceBreachOverridesTheGrandfather(t *testing.T) {
	cfg := testConfig(t)
	cfg.Retention = Retention{MaxAge: time.Hour, MaxPrunePerPass: 10}
	w := startWriter(t, cfg)
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		if err := w.Write(ctx, mgmtIntent("/seg")); err != nil {
			t.Fatal(err)
		}
		if err := w.SealNow(ctx); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "two compressed segments", func() bool { return compressedCount(w) == 2 })

	next := w.Policy()
	next.Retention.MaxAge = time.Nanosecond
	if _, err := w.SetPolicy(ctx, next, PolicyFloor{}); err != nil {
		t.Fatal(err)
	}
	// A reserve no filesystem can satisfy, so the pass sees a breach.
	next = w.Policy()
	next.Retention.ReserveBytes = 1 << 62
	if _, err := w.SetPolicy(ctx, next, PolicyFloor{}); err != nil {
		t.Fatal(err)
	}
	w.prunePassNow(t)

	after, _ := w.seg.listSealed()
	if len(after) != 0 {
		t.Fatalf("%d segments survived a reserve breach; the grandfather must not outrank a full disk", len(after))
	}
}

func TestRotateNowSealsAndOpens(t *testing.T) {
	w := startWriter(t, testConfig(t))
	ctx := context.Background()
	if err := w.Write(ctx, mgmtIntent("/x")); err != nil {
		t.Fatal(err)
	}
	sealed, opened, err := w.RotateNow(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if sealed == "" || opened == "" {
		t.Fatalf("rotate reported sealed %q opened %q", sealed, opened)
	}
	if sealed == opened {
		t.Fatal("rotate must open a different segment from the one it sealed")
	}
	if w.seg.currentUUID() != opened {
		t.Fatalf("active segment is %s, rotate said %s", w.seg.currentUUID(), opened)
	}
}

// compressedCount reports how many sealed segments the compression worker
// has finished with. A prune pass taken before it finishes races the
// rename.
func compressedCount(w *Writer) int {
	segs, _ := w.seg.listSealed()
	n := 0
	for _, s := range segs {
		if s.Compressed {
			n++
		}
	}
	return n
}
