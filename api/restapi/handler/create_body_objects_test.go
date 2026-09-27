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

package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-openapi/runtime/middleware"

	"github.com/loxilb-io/loxilb/api/models"
	"github.com/loxilb-io/loxilb/api/restapi/operations"
)

// The create bodies below make the object each rule is built from
// optional in the schema, so a body without it passes validation and
// reaches the handler. The handler must refuse it as a bad request; it
// used to dereference the missing object and panic, which dropped the
// connection without an answer.
func TestCreateBodiesWithoutTheirObjectAreBadRequests(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/netlox/v1/config", nil)
	cases := []struct {
		name, field string
		call        func() middleware.Responder
	}{
		{"loadbalancer", "serviceArguments", func() middleware.Responder {
			return ConfigPostLoadbalancer(operations.PostConfigLoadbalancerParams{HTTPRequest: req, Attr: &models.LoadbalanceEntry{}}, nil)
		}},
		{"session without either tunnel", "accessNetworkTunnel", func() middleware.Responder {
			return ConfigPostSession(operations.PostConfigSessionParams{HTTPRequest: req, Attr: &models.SessionEntry{}}, nil)
		}},
		{"session without the core tunnel", "coreNetworkTunnel", func() middleware.Responder {
			return ConfigPostSession(operations.PostConfigSessionParams{HTTPRequest: req, Attr: &models.SessionEntry{
				AccessNetworkTunnel: &models.SessionEntryAccessNetworkTunnel{},
			}}, nil)
		}},
		{"session ulcl", "ulclArgument", func() middleware.Responder {
			return ConfigPostSessionUlCl(operations.PostConfigSessionulclParams{HTTPRequest: req, Attr: &models.SessionUlClEntry{}}, nil)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var res middleware.Responder
			func() {
				defer func() {
					if p := recover(); p != nil {
						t.Fatalf("the handler panicked: %v", p)
					}
				}()
				res = c.call()
			}()
			er, ok := res.(*ErrorResponse)
			if !ok {
				t.Fatalf("answered %T, want an error response", res)
			}
			if er.Payload.Code != http.StatusBadRequest || er.Payload.Message != c.field+" is required" {
				t.Fatalf("answered %d %q", er.Payload.Code, er.Payload.Message)
			}
		})
	}
}
