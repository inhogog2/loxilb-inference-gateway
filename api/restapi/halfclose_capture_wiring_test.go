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

package restapi

// halfclose_capture_wiring_test.go — POST /config/halfclose refuses a field
// the settings do not have only if setupGlobalMiddleware captured the raw
// body for that route; the handler alone cannot see past the generated
// model. This drives the middleware as registered and the handler behind it.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-openapi/runtime"
	"github.com/loxilb-io/loxilb/api/models"
	"github.com/loxilb-io/loxilb/api/restapi/handler"
	"github.com/loxilb-io/loxilb/api/restapi/operations"
	cmn "github.com/loxilb-io/loxilb/common"
	opts "github.com/loxilb-io/loxilb/options"
	"github.com/loxilb-io/loxilb/pkg/audit"
)

type halfCloseWiringHook struct {
	cmn.NetHookInterface
	updates int
}

func (h *halfCloseWiringHook) NetHalfCloseUpdate(u *cmn.HalfCloseUpdate) (cmn.HalfCloseConfig, error) {
	h.updates++
	c := cmn.DefaultHalfCloseConfig()
	if u.Allow != nil {
		c.Allow = *u.Allow
	}
	if u.CapSeconds != nil {
		c.CapSeconds = *u.CapSeconds
	}
	return c, nil
}

func TestGlobalMiddlewareCapturesHalfCloseBody(t *testing.T) {
	prevAuth := opts.Opts.UserServiceEnable
	opts.Opts.UserServiceEnable = false
	prevHooks := handler.ApiHooks
	hook := &halfCloseWiringHook{}
	handler.ApiHooks = hook
	t.Cleanup(func() {
		opts.Opts.UserServiceEnable = prevAuth
		handler.ApiHooks = prevHooks
		handler.SetAuditWriter(nil)
	})
	dir := filepath.Join(t.TempDir(), "audit")
	w, err := audit.New(audit.Config{Dir: dir, CreateDir: true, InstanceID: "gw-test"})
	if err != nil {
		t.Fatal(err)
	}
	w.Start()
	for deadline := time.Now().Add(5 * time.Second); !w.Running(); {
		if time.Now().After(deadline) {
			t.Fatal("writer did not start")
		}
		time.Sleep(5 * time.Millisecond)
	}
	handler.SetAuditWriter(w)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = w.Close(ctx)
	})
	handler.SetAuditRouteLookup("/netlox/v1", nil)

	// The generated chain stands in as the binder would: it drains the body
	// into the model, then runs the handler with the request it was given.
	h := setupGlobalMiddleware(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		attr := &models.HalfCloseConfig{}
		_ = json.Unmarshal(body, attr)
		res := handler.ConfigPostHalfClose(operations.PostConfigHalfcloseParams{HTTPRequest: r, Attr: attr}, nil)
		res.WriteResponse(rw, runtime.JSONProducer())
	}))
	post := func(body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/netlox/v1/config/halfclose", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		h.ServeHTTP(rec, req)
		return rec
	}

	if rec := post(`{"alow":false,"capSeconds":240}`); rec.Code != http.StatusBadRequest ||
		!strings.Contains(rec.Body.String(), "alow") || hook.updates != 0 {
		t.Fatalf("a misspelt field: %d %s, %d updates", rec.Code, rec.Body.String(), hook.updates)
	}
	if rec := post(`{"allow":false}`); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), `"allow":false`) || hook.updates != 1 {
		t.Fatalf("a block: %d %s, %d updates", rec.Code, rec.Body.String(), hook.updates)
	}
}
