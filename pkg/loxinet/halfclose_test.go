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
	"testing"

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
