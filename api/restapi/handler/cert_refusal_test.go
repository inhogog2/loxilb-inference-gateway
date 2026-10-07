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
	"strings"
	"testing"

	"github.com/loxilb-io/loxilb/api/models"
	"github.com/loxilb-io/loxilb/api/restapi/operations"
	cmn "github.com/loxilb-io/loxilb/common"
)

// A request the certificate handlers refuse is answered with the reason: the
// body is a 400 that carries the handler's own sentence, not the reference
// to a log line that an unclassified internal error gets.
func TestCertRefusalCarriesTheReason(t *testing.T) {
	const caPEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	const keyPEM = "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n"

	sp := func(v string) *string { return &v }

	check := func(name string, got *models.Error, want string) {
		t.Helper()
		if got == nil {
			t.Fatalf("%s: no body", name)
		}
		if got.Code != 400 {
			t.Errorf("%s: body code %d, want 400", name, got.Code)
		}
		if !strings.Contains(got.Result, want) {
			t.Errorf("%s: body says %q, want the reason %q", name, got.Result, want)
		}
	}

	post := func(attr *models.Cert) *models.Error {
		t.Helper()
		resp := ConfigPostCert(operations.PostConfigCertParams{
			HTTPRequest: httptest.NewRequest(http.MethodPost, "/netlox/v1/config/cert", nil),
			Attr:        attr,
		}, nil)
		bad, ok := resp.(*operations.PostConfigCertBadRequest)
		if !ok {
			t.Fatalf("POST answered %T, want a 400", resp)
		}
		return bad.Payload
	}

	check("no body", post(nil), "empty body")
	check("a CA bundle sent with a key", post(&models.Cert{
		CertID: sp("refusal-ca"), Usage: sp("ca"), CertPem: sp(caPEM), KeyPem: sp(keyPEM),
	}), "keyPem must be empty")
	check("a usage nothing defines", post(&models.Cert{
		CertID: sp("refusal-usage"), Usage: sp("peer"), CertPem: sp(caPEM), KeyPem: sp(keyPEM),
	}), "usage must be one of")
	check("a client pair that does not parse", post(&models.Cert{
		CertID: sp("refusal-client"), Usage: sp("client"), CertPem: sp(caPEM), KeyPem: sp(keyPEM),
	}), "not a usable pair")

	// A rotation is refused through the same body. The entry exists, so the
	// request gets as far as the check that it does not change the usage.
	certStoreMu.Lock()
	certStore["refusal-rotate"] = &cmn.CertArg{CertId: "refusal-rotate", Usage: cmn.CertUsageClient}
	certStoreMu.Unlock()
	defer func() {
		certStoreMu.Lock()
		delete(certStore, "refusal-rotate")
		certStoreMu.Unlock()
	}()
	put := ConfigPutCert(operations.PutConfigCertCertIDParams{
		HTTPRequest: httptest.NewRequest(http.MethodPut, "/netlox/v1/config/cert/refusal-rotate", nil),
		CertID:      "refusal-rotate",
		Attr:        &models.Cert{Usage: sp("ca"), CertPem: sp(caPEM), KeyPem: sp("")},
	}, nil)
	badPut, ok := put.(*operations.PutConfigCertCertIDBadRequest)
	if !ok {
		t.Fatalf("PUT that changes the usage answered %T, want a 400", put)
	}
	check("a rotation that changes the usage", badPut.Payload, "a rotation cannot change it")

	del := ConfigDeleteCert(operations.DeleteConfigCertCertIDParams{
		HTTPRequest: httptest.NewRequest(http.MethodDelete, "/netlox/v1/config/cert/x", nil),
		CertID:      "../x",
	}, nil)
	bad, ok := del.(*operations.DeleteConfigCertCertIDBadRequest)
	if !ok {
		t.Fatalf("DELETE of an ID that is a path answered %T, want a 400", del)
	}
	check("an ID that is a path", bad.Payload, "certId")
}
