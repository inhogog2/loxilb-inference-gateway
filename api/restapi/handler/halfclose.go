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

	"github.com/go-openapi/runtime/middleware"
	"github.com/loxilb-io/loxilb/api/models"
	"github.com/loxilb-io/loxilb/api/restapi/operations"
	cmn "github.com/loxilb-io/loxilb/common"
	tk "github.com/loxilb-io/loxilib"
)

// The process-wide half-close hold settings and the release of every held
// client (/config/halfclose). A service's half_close_mode decides whether it
// holds at all; these decide whether new holds may be taken anywhere, and for
// how long a hold may go without an answer byte.

// halfCloseInForce returns the settings in force: as set, else the defaults.
func halfCloseInForce() (cmn.HalfCloseConfig, error) {
	cfg, err := ApiHooks.NetHalfCloseGet()
	if err != nil {
		return cmn.HalfCloseConfig{}, err
	}
	if cfg == nil {
		return cmn.DefaultHalfCloseConfig(), nil
	}
	return *cfg, nil
}

// ConfigGetHalfClose - GET /config/halfclose
func ConfigGetHalfClose(params operations.GetConfigHalfcloseParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: half-close %s API called. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.URL)

	cfg, err := halfCloseInForce()
	if err != nil {
		return &ErrorResponse{Payload: ResultErrorResponseError(err)}
	}
	allow := cfg.Allow
	capSec := int32(cfg.CapSeconds)
	return operations.NewGetConfigHalfcloseOK().WithPayload(
		&models.HalfCloseConfig{Allow: &allow, CapSeconds: &capSec})
}

// ConfigPostHalfClose - POST /config/halfclose. A field omitted keeps the
// value in force, so blocking new holds in an incident needs no other value.
func ConfigPostHalfClose(params operations.PostConfigHalfcloseParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: half-close %s API called. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.URL)

	attr := params.Attr
	if attr == nil || (attr.Allow == nil && attr.CapSeconds == nil) {
		return errorResponseWithCode(http.StatusBadRequest, "give allow, capSeconds or both")
	}
	cfg, err := halfCloseInForce()
	if err != nil {
		return &ErrorResponse{Payload: ResultErrorResponseError(err)}
	}
	if attr.Allow != nil {
		cfg.Allow = *attr.Allow
	}
	if attr.CapSeconds != nil {
		if *attr.CapSeconds < 0 {
			return errorResponseWithCode(http.StatusBadRequest, "capSeconds must not be negative")
		}
		cfg.CapSeconds = uint32(*attr.CapSeconds)
	}
	if _, err := ApiHooks.NetHalfCloseSet(&cfg); err != nil {
		return &ErrorResponse{Payload: ResultErrorResponseError(err)}
	}
	return &ResultResponse{Result: "Success"}
}

// ConfigPostHalfCloseRelease - POST /config/halfclose/release
func ConfigPostHalfCloseRelease(params operations.PostConfigHalfcloseReleaseParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: half-close %s API called. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.URL)

	if _, err := ApiHooks.NetHalfCloseRelease(); err != nil {
		return &ErrorResponse{Payload: ResultErrorResponseError(err)}
	}
	return &ResultResponse{Result: "Success"}
}
