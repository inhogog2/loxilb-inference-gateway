/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-openapi/swag"
	"github.com/loxilb-io/loxilb/api/models"
	"github.com/loxilb-io/loxilb/api/restapi/operations"
	cmn "github.com/loxilb-io/loxilb/common"
)

// stubHalfCloseHook keeps the settings the way the loxinet holder does:
// nil while the defaults are in force, and a set validated on the way in.
type stubHalfCloseHook struct {
	cmn.NetHookInterface
	cfg      *cmn.HalfCloseConfig
	sets     int
	released int
}

func (s *stubHalfCloseHook) NetHalfCloseGet() (*cmn.HalfCloseConfig, error) {
	if s.cfg == nil {
		return nil, nil
	}
	c := *s.cfg
	return &c, nil
}

func (s *stubHalfCloseHook) NetHalfCloseSet(cfg *cmn.HalfCloseConfig) (int, error) {
	if err := cfg.Validate(); err != nil {
		return -1, err
	}
	c := *cfg
	s.cfg = &c
	s.sets++
	return 0, nil
}

func (s *stubHalfCloseHook) NetHalfCloseUpdate(u *cmn.HalfCloseUpdate) (cmn.HalfCloseConfig, error) {
	c := cmn.DefaultHalfCloseConfig()
	if s.cfg != nil {
		c = *s.cfg
	}
	if u.Allow != nil {
		c.Allow = *u.Allow
	}
	if u.CapSeconds != nil {
		c.CapSeconds = *u.CapSeconds
	}
	if _, err := s.NetHalfCloseSet(&c); err != nil {
		return cmn.HalfCloseConfig{}, err
	}
	return c, nil
}

func (s *stubHalfCloseHook) NetHalfCloseRelease() (int, error) {
	s.released++
	return 0, nil
}

func halfCloseGet(t *testing.T) (bool, int32) {
	t.Helper()
	res := ConfigGetHalfClose(operations.GetConfigHalfcloseParams{
		HTTPRequest: httptest.NewRequest(http.MethodGet, "/netlox/v1/config/halfclose", nil),
	}, nil)
	ok, isOK := res.(*operations.GetConfigHalfcloseOK)
	if !isOK {
		t.Fatalf("GET answered %T", res)
	}
	return *ok.Payload.Allow, *ok.Payload.CapSeconds
}

func halfClosePost(attr *models.HalfCloseConfig) interface{} {
	return halfClosePostRaw(attr, "")
}

// halfClosePostRaw posts attr with raw as the body the middleware captured.
func halfClosePostRaw(attr *models.HalfCloseConfig, raw string) interface{} {
	req := httptest.NewRequest(http.MethodPost, "/netlox/v1/config/halfclose", nil)
	req = req.WithContext(WithRawLoadbalancerBody(req.Context(), []byte(raw)))
	return ConfigPostHalfClose(operations.PostConfigHalfcloseParams{HTTPRequest: req, Attr: attr}, nil)
}

// applied returns the settings a POST answered with.
func applied(t *testing.T, res interface{}) (bool, int32) {
	t.Helper()
	ok, isOK := res.(*operations.PostConfigHalfcloseOK)
	if !isOK {
		t.Fatalf("POST answered %T", res)
	}
	return *ok.Payload.Allow, *ok.Payload.CapSeconds
}

// GET answers the defaults until the settings are set; a POST that names one
// field keeps the other as in force.
func TestHalfCloseSettingsRoundTrip(t *testing.T) {
	prev := ApiHooks
	defer func() { ApiHooks = prev }()
	stub := &stubHalfCloseHook{}
	ApiHooks = stub

	if allow, capSec := halfCloseGet(t); !allow || capSec != 240 {
		t.Fatalf("defaults read back as allow=%v cap=%d, want true 240", allow, capSec)
	}

	// The answer is the settings in force once applied, and GET agrees.
	if allow, capSec := applied(t, halfClosePostRaw(&models.HalfCloseConfig{Allow: swag.Bool(false)},
		`{"allow":false}`)); allow || capSec != 240 {
		t.Fatalf("blocking answered allow=%v cap=%d, want false 240", allow, capSec)
	}
	if allow, capSec := halfCloseGet(t); allow || capSec != 240 {
		t.Fatalf("after blocking: allow=%v cap=%d, want false 240", allow, capSec)
	}

	// A new bound alone keeps the block in force.
	if allow, capSec := applied(t, halfClosePost(&models.HalfCloseConfig{CapSeconds: swag.Int32(30)})); allow || capSec != 30 {
		t.Fatalf("a new bound answered allow=%v cap=%d, want false 30", allow, capSec)
	}
	if allow, capSec := halfCloseGet(t); allow || capSec != 30 {
		t.Fatalf("after a new bound: allow=%v cap=%d, want false 30", allow, capSec)
	}
}

func TestHalfCloseSettingsRefused(t *testing.T) {
	prev := ApiHooks
	defer func() { ApiHooks = prev }()

	for _, c := range []struct {
		name string
		attr *models.HalfCloseConfig
		raw  string
	}{
		{"neither field", &models.HalfCloseConfig{}, `{}`},
		{"no body", nil, ""},
		{"a bound of zero", &models.HalfCloseConfig{CapSeconds: swag.Int32(0)}, ""},
		{"a negative bound", &models.HalfCloseConfig{CapSeconds: swag.Int32(-1)}, ""},
		{"a bound over an hour", &models.HalfCloseConfig{CapSeconds: swag.Int32(3601)}, ""},
		// A misspelt field must not pass for "omitted": the operator would
		// believe holds were blocked.
		{"a misspelt field alone", &models.HalfCloseConfig{}, `{"alow":false}`},
		{"a misspelt field beside a known one", &models.HalfCloseConfig{CapSeconds: swag.Int32(240)},
			`{"alow":false,"capSeconds":240}`},
		{"a field from another API", &models.HalfCloseConfig{Allow: swag.Bool(false)},
			`{"allow":false,"max_idle_sec":240}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			stub := &stubHalfCloseHook{}
			ApiHooks = stub
			res := halfClosePostRaw(c.attr, c.raw)
			er, ok := res.(*ErrorResponse)
			if !ok {
				t.Fatalf("answered %T, want an error", res)
			}
			if er.Payload.Code != http.StatusBadRequest {
				t.Fatalf("answered %d, want 400: %s", er.Payload.Code, er.Payload.Result)
			}
			if stub.cfg != nil {
				t.Fatalf("stored %+v", *stub.cfg)
			}
		})
	}
}

// With no body captured a misspelt field could not be told from an omitted
// one, so the POST fails rather than skipping that check.
func TestHalfCloseSettingsWithoutCapture(t *testing.T) {
	prev := ApiHooks
	defer func() { ApiHooks = prev }()
	stub := &stubHalfCloseHook{}
	ApiHooks = stub

	res := ConfigPostHalfClose(operations.PostConfigHalfcloseParams{
		HTTPRequest: httptest.NewRequest(http.MethodPost, "/netlox/v1/config/halfclose", nil),
		Attr:        &models.HalfCloseConfig{Allow: swag.Bool(false)},
	}, nil)
	er, ok := res.(*ErrorResponse)
	if !ok || er.Payload.Code != http.StatusInternalServerError {
		t.Fatalf("answered %T %+v, want 500", res, res)
	}
	if stub.cfg != nil {
		t.Fatalf("stored %+v", *stub.cfg)
	}
}

func TestHalfCloseRelease(t *testing.T) {
	prev := ApiHooks
	defer func() { ApiHooks = prev }()
	stub := &stubHalfCloseHook{}
	ApiHooks = stub

	res := ConfigPostHalfCloseRelease(operations.PostConfigHalfcloseReleaseParams{
		HTTPRequest: httptest.NewRequest(http.MethodPost, "/netlox/v1/config/halfclose/release", nil),
	}, nil)
	if _, ok := res.(*ResultResponse); !ok {
		t.Fatalf("answered %T", res)
	}
	if stub.released != 1 || stub.sets != 0 {
		t.Fatalf("released %d times, set %d times; want 1 and 0", stub.released, stub.sets)
	}
}
