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
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/loxilb-io/loxilb/api/models"
	"github.com/loxilb-io/loxilb/api/restapi/operations"
	cmn "github.com/loxilb-io/loxilb/common"
)

// stubCertHook answers the two hooks the certificate handlers consult about
// load-balancer rules. Any other method of the embedded (nil) interface
// panics, which is how a test learns that a handler reached past them.
type stubCertHook struct {
	cmn.NetHookInterface
	rules      []cmn.LbRuleMod
	getErr     error
	pushed     int
	kept       []string
	refreshErr error
	refreshed  []string
}

func (s *stubCertHook) NetLbRuleGet() ([]cmn.LbRuleMod, error) {
	return s.rules, s.getErr
}

func (s *stubCertHook) NetLbBackendCertRefresh(certID string) (int, []string, error) {
	s.refreshed = append(s.refreshed, certID)
	return s.pushed, s.kept, s.refreshErr
}

// certHookEnv points the handlers at a stub and at a managed directory of the
// test's own, with one stored CA entry whose material is on disk.
func certHookEnv(t *testing.T, hook *stubCertHook, certID string) string {
	t.Helper()
	prevHooks, prevDir := ApiHooks, certManagedDir
	ApiHooks = hook
	certManagedDir = t.TempDir()
	dir := filepath.Join(certManagedDir, certID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), []byte("previous material"), 0o600); err != nil {
		t.Fatal(err)
	}
	certStoreMu.Lock()
	certStore[certID] = &cmn.CertArg{CertId: certID, Usage: cmn.CertUsageCA}
	certStoreMu.Unlock()
	t.Cleanup(func() {
		ApiHooks, certManagedDir = prevHooks, prevDir
		certStoreMu.Lock()
		delete(certStore, certID)
		certStoreMu.Unlock()
	})
	return dir
}

func certStored(certID string) bool {
	certStoreMu.RLock()
	defer certStoreMu.RUnlock()
	_, ok := certStore[certID]
	return ok
}

func certHookCAPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "cert hook test CA"},
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

func certHookDelete(certID string) interface{} {
	return ConfigDeleteCert(operations.DeleteConfigCertCertIDParams{
		HTTPRequest: httptest.NewRequest(http.MethodDelete, "/netlox/v1/config/cert/"+certID, nil),
		CertID:      certID,
	}, nil)
}

func certHookRotate(t *testing.T, certID string) (interface{}, string) {
	t.Helper()
	ca := certHookCAPEM(t)
	usage, empty := cmn.CertUsageCA, ""
	return ConfigPutCert(operations.PutConfigCertCertIDParams{
		HTTPRequest: httptest.NewRequest(http.MethodPut, "/netlox/v1/config/cert/"+certID, nil),
		CertID:      certID,
		Attr:        &models.Cert{Usage: &usage, CertPem: &ca, KeyPem: &empty},
	}, nil), ca
}

func certHookBody(t *testing.T, name string, got *models.Error, code int32, want string) {
	t.Helper()
	if got == nil {
		t.Fatalf("%s: no body", name)
	}
	if got.Code != code {
		t.Errorf("%s: body code %d, want %d", name, got.Code, code)
	}
	if !strings.Contains(got.Result, want) {
		t.Errorf("%s: body says %q, want %q", name, got.Result, want)
	}
}

// A certificate is not deleted when the rules that might refer to it cannot
// be read: "no rule refers to it" is not known, and the delete is not undone.
func TestCertDeleteRefusedWhenRulesUnreadable(t *testing.T) {
	const id = "hook-del-unreadable"
	cause := errors.New("rule table walk failed at slot 7")
	dir := certHookEnv(t, &stubCertHook{getErr: cause}, id)

	resp := certHookDelete(id)
	fail, ok := resp.(*operations.DeleteConfigCertCertIDInternalServerError)
	if !ok {
		t.Fatalf("DELETE with unreadable rules answered %T, want a 500", resp)
	}
	certHookBody(t, "unreadable rules", fail.Payload, 500, "nothing was deleted")
	if strings.Contains(fail.Payload.Result, cause.Error()) {
		t.Errorf("the body carries the internal cause %q", cause)
	}
	if !certStored(id) {
		t.Error("the entry left the store although the delete was refused")
	}
	if _, err := os.Stat(filepath.Join(dir, "ca.crt")); err != nil {
		t.Errorf("the material left the disk although the delete was refused: %v", err)
	}
}

// A rule that refers to the certificate refuses the delete and is named.
func TestCertDeleteRefusedWhenARuleRefers(t *testing.T) {
	const id = "hook-del-inuse"
	for _, tc := range []struct {
		name string
		serv cmn.LbServiceArg
	}{
		{"as its CA", cmn.LbServiceArg{ServIP: "20.20.20.1", ServPort: 8443, Proto: "tcp", BackendCaCertId: id}},
		{"as its client certificate", cmn.LbServiceArg{ServIP: "20.20.20.2", ServPort: 9443, Proto: "tcp", BackendClientCertId: id}},
	} {
		certHookEnv(t, &stubCertHook{rules: []cmn.LbRuleMod{
			{Serv: cmn.LbServiceArg{ServIP: "20.20.20.9", ServPort: 80, Proto: "tcp", BackendCaCertId: "another"}},
			{Serv: tc.serv},
		}}, id)
		resp := certHookDelete(id)
		bad, ok := resp.(*operations.DeleteConfigCertCertIDBadRequest)
		if !ok {
			t.Fatalf("%s: DELETE answered %T, want a 400", tc.name, resp)
		}
		certHookBody(t, tc.name, bad.Payload, 400, "20.20.20.")
		if !strings.Contains(bad.Payload.Result, tc.serv.ServIP) {
			t.Errorf("%s: body %q does not name the rule that refers to it", tc.name, bad.Payload.Result)
		}
		if !certStored(id) {
			t.Errorf("%s: the entry left the store although the delete was refused", tc.name)
		}
	}
}

// An instance that runs goBGP only has no rules, so nothing refers to a
// certificate there: the answer is "no rule", as it is when the rules were
// read and none refers to it, and not the failure every other error is. The
// delete that follows this answer ends in the data plane's registry, which a
// unit test does not have, so the answer is checked where it is produced.
func TestCertInUseAnswers(t *testing.T) {
	const id = "hook-inuse"
	other := cmn.LbRuleMod{Serv: cmn.LbServiceArg{ServIP: "20.20.20.9", ServPort: 80, Proto: "tcp", BackendCaCertId: "another"}}
	mine := cmn.LbRuleMod{Serv: cmn.LbServiceArg{ServIP: "20.20.20.1", ServPort: 8443, Proto: "tcp", BackendClientCertId: id}}
	cause := errors.New("rule table walk failed at slot 7")

	for _, tc := range []struct {
		name     string
		hook     *stubCertHook
		wantRule string
		wantErr  error
	}{
		{"goBGP only", &stubCertHook{getErr: cmn.ErrBgpOnlyMode}, "", nil},
		{"goBGP only, wrapped", &stubCertHook{getErr: fmt.Errorf("get rules: %w", cmn.ErrBgpOnlyMode)}, "", nil},
		{"no rules", &stubCertHook{}, "", nil},
		{"no rule refers to it", &stubCertHook{rules: []cmn.LbRuleMod{other}}, "", nil},
		{"a rule refers to it", &stubCertHook{rules: []cmn.LbRuleMod{other, mine}}, "20.20.20.1:8443/tcp", nil},
		{"the rules cannot be read", &stubCertHook{getErr: cause}, "", cause},
		// An error that only reads like the sentinel is not the sentinel.
		{"same words, another error", &stubCertHook{getErr: errors.New(cmn.ErrBgpOnlyMode.Error())}, "", errAny},
	} {
		certHookEnv(t, tc.hook, id)
		rule, err := certInUse(id)
		if rule != tc.wantRule {
			t.Errorf("%s: rule %q, want %q", tc.name, rule, tc.wantRule)
		}
		switch {
		case tc.wantErr == nil && err != nil:
			t.Errorf("%s: error %v, want none", tc.name, err)
		case tc.wantErr == errAny && err == nil:
			t.Errorf("%s: no error, want one", tc.name)
		case tc.wantErr != nil && tc.wantErr != errAny && !errors.Is(err, tc.wantErr):
			t.Errorf("%s: error %v, want %v", tc.name, err, tc.wantErr)
		}
	}

	// No hooks at all (a handler test without a stub): nothing refers to it.
	prev := ApiHooks
	ApiHooks = nil
	defer func() { ApiHooks = prev }()
	if rule, err := certInUse(id); rule != "" || err != nil {
		t.Errorf("no hooks: (%q, %v), want (\"\", nil)", rule, err)
	}
}

// errAny stands for "an error, whichever" in the table above.
var errAny = errors.New("any error")

// A rotation whose rules could not be pushed again says so: the new material
// is stored, and the rules may still be serving the replaced one.
func TestCertRotateReportsRuleRefreshFailure(t *testing.T) {
	const id = "hook-rot-failed"
	cause := errors.New("rule table locked by a restore")
	hook := &stubCertHook{refreshErr: cause}
	dir := certHookEnv(t, hook, id)

	resp, ca := certHookRotate(t, id)
	fail, ok := resp.(*operations.PutConfigCertCertIDInternalServerError)
	if !ok {
		t.Fatalf("PUT whose rule refresh failed answered %T, want a 500", resp)
	}
	certHookBody(t, "failed refresh", fail.Payload, 500, "is stored, but the rules that refer to it could not be pushed again")
	if strings.Contains(fail.Payload.Result, cause.Error()) {
		t.Errorf("the body carries the internal cause %q", cause)
	}
	if len(hook.refreshed) != 1 || hook.refreshed[0] != id {
		t.Errorf("refresh asked for %v, want one call for %q", hook.refreshed, id)
	}
	// The body says the material is stored; it is.
	if got, err := os.ReadFile(filepath.Join(dir, "ca.crt")); err != nil || string(got) != ca {
		t.Errorf("the new material is not on disk (err %v)", err)
	}
}

// The answers a rotation already had are kept: 200 when every rule took the
// material, 200 on an instance that has no rules, 400 naming the rules that
// kept the previous context.
func TestCertRotateAnswersWithoutHookFailure(t *testing.T) {
	t.Run("every rule pushed", func(t *testing.T) {
		hook := &stubCertHook{pushed: 2}
		certHookEnv(t, hook, "hook-rot-ok")
		resp, _ := certHookRotate(t, "hook-rot-ok")
		if _, ok := resp.(*operations.PutConfigCertCertIDOK); !ok {
			t.Fatalf("PUT answered %T, want a 200", resp)
		}
		if len(hook.refreshed) != 1 {
			t.Errorf("refresh was called %d time(s), want 1", len(hook.refreshed))
		}
	})
	t.Run("goBGP only", func(t *testing.T) {
		certHookEnv(t, &stubCertHook{refreshErr: cmn.ErrBgpOnlyMode}, "hook-rot-bgp")
		resp, _ := certHookRotate(t, "hook-rot-bgp")
		if _, ok := resp.(*operations.PutConfigCertCertIDOK); !ok {
			t.Fatalf("PUT answered %T, want a 200", resp)
		}
	})
	t.Run("a rule kept its previous context", func(t *testing.T) {
		certHookEnv(t, &stubCertHook{pushed: 1, kept: []string{"20.20.20.1:8443/tcp"}}, "hook-rot-kept")
		resp, _ := certHookRotate(t, "hook-rot-kept")
		bad, ok := resp.(*operations.PutConfigCertCertIDBadRequest)
		if !ok {
			t.Fatalf("PUT answered %T, want a 400", resp)
		}
		certHookBody(t, "kept", bad.Payload, 400, "20.20.20.1:8443/tcp")
	})
}
