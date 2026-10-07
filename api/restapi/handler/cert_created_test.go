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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/loxilb-io/loxilb/api/models"
	"github.com/loxilb-io/loxilb/api/restapi/operations"
	cmn "github.com/loxilb-io/loxilb/common"
)

func testCABundlePEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "cert-created-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// A certificate that was created is answered with the ID it is stored under:
// the one the request named, and the one the server minted when it named none.
func TestCertCreateAnswersWithTheCertID(t *testing.T) {
	dir := t.TempDir()
	prevCmn, prevHandler := cmn.CertManagedDir, certManagedDir
	cmn.CertManagedDir, certManagedDir = dir, dir
	t.Cleanup(func() { cmn.CertManagedDir, certManagedDir = prevCmn, prevHandler })

	sp := func(v string) *string { return &v }
	bundle := testCABundlePEM(t)

	post := func(certID *string) string {
		t.Helper()
		resp := ConfigPostCert(operations.PostConfigCertParams{
			HTTPRequest: httptest.NewRequest(http.MethodPost, "/netlox/v1/config/cert", nil),
			Attr:        &models.Cert{CertID: certID, Usage: sp("ca"), CertPem: sp(bundle), KeyPem: sp("")},
		}, nil)
		created, ok := resp.(*operations.PostConfigCertCreated)
		if !ok {
			if bad, isBad := resp.(*operations.PostConfigCertBadRequest); isBad && bad.Payload != nil {
				t.Fatalf("POST answered 400: %s", bad.Payload.Result)
			}
			t.Fatalf("POST answered %T, want a 201", resp)
		}
		if created.Payload == nil || created.Payload.CertID == nil {
			t.Fatal("the 201 carries no certId")
		}
		id := *created.Payload.CertID
		t.Cleanup(func() {
			certStoreMu.Lock()
			delete(certStore, id)
			certStoreMu.Unlock()
		})
		return id
	}

	if got := post(sp("created-named")); got != "created-named" {
		t.Errorf("a named certificate was answered with certId %q", got)
	}

	minted := post(nil)
	if minted == "" || minted == "created-named" {
		t.Fatalf("the minted certId is %q", minted)
	}
	if got := cmn.CertDiskUsage(minted); got != cmn.CertUsageCA {
		t.Errorf("the answered certId %q holds usage %q on disk, want %q", minted, got, cmn.CertUsageCA)
	}
	certStoreMu.Lock()
	_, stored := certStore[minted]
	certStoreMu.Unlock()
	if !stored {
		t.Errorf("the answered certId %q is not in the registry", minted)
	}
}
