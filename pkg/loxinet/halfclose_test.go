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

package loxinet

import (
	"errors"
	"sync"
	"testing"
	"time"

	cmn "github.com/loxilb-io/loxilb/common"
)

// The settings read as nil until set, are stored as set, refuse a bound out
// of range without changing what is stored, and reset back to nil.
func TestHalfCloseSettingsHolder(t *testing.T) {
	na := &NetAPIStruct{}
	if _, err := na.NetHalfCloseReset(); err != nil {
		t.Fatal(err)
	}
	if cfg, err := na.NetHalfCloseGet(); err != nil || cfg != nil {
		t.Fatalf("unset settings read as %+v, %v; want nil", cfg, err)
	}

	set := cmn.HalfCloseConfig{Allow: false, CapSeconds: 30}
	if _, err := na.NetHalfCloseSet(&set); err != nil {
		t.Fatalf("set refused: %v", err)
	}
	set.CapSeconds = 99 // the holder keeps its own copy
	if cfg, _ := na.NetHalfCloseGet(); cfg == nil || cfg.Allow || cfg.CapSeconds != 30 {
		t.Fatalf("read back %+v, want allow=false cap=30", cfg)
	}

	for _, capSec := range []uint32{0, 3601} {
		_, err := na.NetHalfCloseSet(&cmn.HalfCloseConfig{Allow: true, CapSeconds: capSec})
		var invalid *cmn.ValidationError
		if !errors.As(err, &invalid) {
			t.Fatalf("bound %d: err=%v, want a validation refusal", capSec, err)
		}
	}
	if cfg, _ := na.NetHalfCloseGet(); cfg == nil || cfg.CapSeconds != 30 {
		t.Fatalf("a refused set changed the settings: %+v", cfg)
	}
	if _, err := na.NetHalfCloseSet(nil); err == nil {
		t.Fatal("a nil set was accepted")
	}

	if _, err := na.NetHalfCloseReset(); err != nil {
		t.Fatal(err)
	}
	if cfg, _ := na.NetHalfCloseGet(); cfg != nil {
		t.Fatalf("reset left %+v", cfg)
	}
}

// Partial updates arriving together cannot undo each other: an operator
// blocking holds while others change the bound must find holds blocked
// afterwards, and every answer is a state that update itself left in force.
func TestHalfCloseUpdateConcurrent(t *testing.T) {
	na := &NetAPIStruct{}
	if _, err := na.NetHalfCloseReset(); err != nil {
		t.Fatal(err)
	}
	defer na.NetHalfCloseReset()

	block := false
	var wg sync.WaitGroup
	errs := make(chan string, 400)
	for i := 0; i < 200; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			got, err := na.NetHalfCloseUpdate(&cmn.HalfCloseUpdate{Allow: &block})
			if err != nil || got.Allow {
				errs <- "a block answered allowed"
			}
		}()
		go func(capSec uint32) {
			defer wg.Done()
			got, err := na.NetHalfCloseUpdate(&cmn.HalfCloseUpdate{CapSeconds: &capSec})
			if err != nil || got.CapSeconds != capSec {
				errs <- "a new bound answered another bound"
			}
		}(uint32(10 + i))
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
	cfg, _ := na.NetHalfCloseGet()
	if cfg == nil || cfg.Allow {
		t.Fatalf("after concurrent updates the settings are %+v: the block was undone", cfg)
	}

	// Neither field is a refusal, and a bound out of range changes nothing.
	if _, err := na.NetHalfCloseUpdate(&cmn.HalfCloseUpdate{}); err == nil {
		t.Fatal("an empty update was accepted")
	}
	before, _ := na.NetHalfCloseGet()
	tooLong := uint32(3601)
	if _, err := na.NetHalfCloseUpdate(&cmn.HalfCloseUpdate{CapSeconds: &tooLong}); err == nil {
		t.Fatal("a bound over an hour was accepted")
	}
	if after, _ := na.NetHalfCloseGet(); *after != *before {
		t.Fatalf("a refused update changed %+v into %+v", *before, *after)
	}
}

// The window itself: a block arriving while a bound change has read the
// settings and not yet stored its merge must wait for it, and land on top of
// it - not be overwritten by the stale allow the bound change read.
func TestHalfCloseUpdateWindow(t *testing.T) {
	na := &NetAPIStruct{}
	if _, err := na.NetHalfCloseReset(); err != nil {
		t.Fatal(err)
	}
	defer na.NetHalfCloseReset()
	defer func() { halfCloseMergedHook = nil }()

	block := false
	blocked := make(chan cmn.HalfCloseConfig, 1) // the block's answer
	done := make(chan struct{})                  // closed once the block returned
	halfCloseMergedHook = func() {
		halfCloseMergedHook = nil
		go func() {
			got, _ := na.NetHalfCloseUpdate(&cmn.HalfCloseUpdate{Allow: &block})
			blocked <- got
			close(done)
		}()
		// Give the block every chance to slip into the window.
		select {
		case <-done:
			t.Error("a block completed inside another update's merge window")
		case <-time.After(100 * time.Millisecond):
		}
	}
	capSec := uint32(30)
	if got, err := na.NetHalfCloseUpdate(&cmn.HalfCloseUpdate{CapSeconds: &capSec}); err != nil ||
		!got.Allow || got.CapSeconds != 30 {
		t.Fatalf("the bound change answered %+v, %v", got, err)
	}
	if got := <-blocked; got.Allow || got.CapSeconds != 30 {
		t.Fatalf("the block answered %+v: it did not land on the bound change", got)
	}
	if cfg, _ := na.NetHalfCloseGet(); cfg == nil || cfg.Allow || cfg.CapSeconds != 30 {
		t.Fatalf("the settings are %+v, want blocked with a 30 s bound", cfg)
	}
}
