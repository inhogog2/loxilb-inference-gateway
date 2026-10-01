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

// halfclose.go — NetHookInterface surface over the process-wide half-close
// hold settings (cmn.HalfCloseConfig): whether new holds may be taken and the
// idle bound on a hold, both handed to the data path, and the one-shot
// release of every held client. The settings are desired state, captured and
// replayed by the config snapshot like any other domain; the defaults are
// not configuration and are captured as absent. No BgpPeerMode guard: the
// settings hold nothing that needs the data path to be up to be stored.

package loxinet

import (
	"errors"
	"sync"

	cmn "github.com/loxilb-io/loxilb/common"
	tk "github.com/loxilb-io/loxilib"
)

var halfClose struct {
	mtx sync.Mutex
	cfg *cmn.HalfCloseConfig // nil: the defaults are in force
}

// halfCloseApply hands the settings to the data path, when there is one.
func halfCloseApply(c cmn.HalfCloseConfig) {
	if mh.dpEbpf == nil {
		return
	}
	mh.dpEbpf.DpHalfCloseConfig(c.Allow, c.CapSeconds)
}

// NetHalfCloseGet - the settings as set; nil while the defaults are in force.
func (na *NetAPIStruct) NetHalfCloseGet() (*cmn.HalfCloseConfig, error) {
	halfClose.mtx.Lock()
	defer halfClose.mtx.Unlock()
	if halfClose.cfg == nil {
		return nil, nil
	}
	c := *halfClose.cfg
	return &c, nil
}

// NetHalfCloseSet - replace the settings (overwrite semantics).
func (na *NetAPIStruct) NetHalfCloseSet(cfg *cmn.HalfCloseConfig) (int, error) {
	if cfg == nil {
		return RuleArgsErr, cmn.NewValidationError("", "half-close settings missing")
	}
	if err := cfg.Validate(); err != nil {
		return RuleArgsErr, err
	}
	halfClose.mtx.Lock()
	defer halfClose.mtx.Unlock()
	c := *cfg
	halfCloseApply(c)
	halfClose.cfg = &c
	tk.LogIt(tk.LogInfo, "half-close holds %s, bound %d s\n",
		map[bool]string{true: "allowed", false: "blocked"}[c.Allow], c.CapSeconds)
	return 0, nil
}

// NetHalfCloseReset - back to the defaults.
func (na *NetAPIStruct) NetHalfCloseReset() (int, error) {
	halfClose.mtx.Lock()
	defer halfClose.mtx.Unlock()
	halfCloseApply(cmn.DefaultHalfCloseConfig())
	halfClose.cfg = nil
	return 0, nil
}

// NetHalfCloseRelease - close every held client at the data path's next pass.
func (na *NetAPIStruct) NetHalfCloseRelease() (int, error) {
	if mh.dpEbpf == nil {
		return RuleErrBase, errors.New("half-close release: the data path is not running")
	}
	mh.dpEbpf.DpHalfCloseRelease()
	tk.LogIt(tk.LogInfo, "half-close: release of every held client requested\n")
	return 0, nil
}
