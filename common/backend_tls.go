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

package common

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// CertManagedDir is where the certificate registry keeps its material, one
// directory per certificate ID. The data plane reads the same directory.
var CertManagedDir = "/etc/loxilb/certs"

// CertIDMax is the size of the data plane's certificate ID buffer; an ID is
// at most CertIDMax-1 bytes.
const CertIDMax = 64

// What a certificate registry entry is for. The usage decides which files the
// entry holds and who may refer to it.
const (
	// CertUsageServer is a listener certificate and key, selected by SNI.
	CertUsageServer = "server"
	// CertUsageCA is a bundle of CA certificates backends are verified against.
	// It holds no key.
	CertUsageCA = "ca"
	// CertUsageClient is the certificate and key the gateway presents to
	// backends.
	CertUsageClient = "client"
)

// CertUsageFiles returns the certificate and key file names of a usage. A CA
// entry has no key file. An unknown usage returns two empty names.
func CertUsageFiles(usage string) (crt, key string) {
	switch usage {
	case CertUsageServer:
		return "server.crt", "server.key"
	case CertUsageCA:
		return "ca.crt", ""
	case CertUsageClient:
		return "client.crt", "client.key"
	}
	return "", ""
}

// ValidateCertID checks a certificate ID wherever one reaches a filesystem
// path: present, within the data plane's buffer, and unable to leave the
// managed directory.
func ValidateCertID(id string) error {
	if strings.TrimSpace(id) == "" {
		return fmt.Errorf("cert: certId is required")
	}
	if len(id) >= CertIDMax {
		return fmt.Errorf("cert: certId too long (%d >= %d)", len(id), CertIDMax)
	}
	if strings.ContainsAny(id, "/\\\x00") || id == "." || id == ".." ||
		strings.Contains(id, "..") {
		return fmt.Errorf("cert: certId %q contains illegal path characters", id)
	}
	return nil
}

// CertDiskUsage reports what the managed material under a certificate ID is
// for, from the files that are there. It returns "" when the ID holds no
// complete entry.
func CertDiskUsage(id string) string {
	if ValidateCertID(id) != nil {
		return ""
	}
	dir := filepath.Join(CertManagedDir, id)
	has := func(name string) bool {
		fi, err := os.Stat(filepath.Join(dir, name))
		return err == nil && fi.Mode().IsRegular()
	}
	for _, usage := range []string{CertUsageServer, CertUsageClient, CertUsageCA} {
		crt, key := CertUsageFiles(usage)
		if has(crt) && (key == "" || has(key)) {
			return usage
		}
	}
	return ""
}

// BackendTLSPolicy is what a rule asks of the TLS leg to its endpoints.
type BackendTLSPolicy struct {
	// Verify asks for the endpoint's certificate to be verified.
	Verify bool
	// CACertID names the CA bundle the endpoint's certificate must chain to.
	CACertID string
	// ClientCertID names the certificate and key presented to the endpoint.
	ClientCertID string
	// ServerName is sent as SNI and, when Verify is set, must be a DNS name
	// of the endpoint's certificate. Empty: no SNI, and a verified endpoint
	// must carry the address it was dialled at.
	ServerName string
}

// BackendTLSPolicyOf collects the backend TLS request of a rule.
func BackendTLSPolicyOf(serv *LbServiceArg) BackendTLSPolicy {
	p := BackendTLSPolicy{
		CACertID:     serv.BackendCaCertId,
		ClientCertID: serv.BackendClientCertId,
		ServerName:   serv.BackendTLSServerName,
	}
	if serv.MTLSBackend != nil {
		p.Verify = serv.MTLSBackend.VerifyServerCert
	}
	return p
}

// Requested reports whether the policy asks for anything beyond an
// unauthenticated TLS leg.
func (p BackendTLSPolicy) Requested() bool {
	return p.Verify || p.CACertID != "" || p.ClientCertID != "" || p.ServerName != ""
}

// ValidateBackendTLS checks the backend TLS request of a rule against the
// rule's mode, the build and the certificate registry. It runs on the final
// state of a rule, whichever way the rule arrived, so a rule that asks for
// verification is either installed verifying or not installed. An error
// names the argument and never a certificate.
func ValidateBackendTLS(serv *LbServiceArg) error {
	p := BackendTLSPolicyOf(serv)
	if !p.Requested() {
		return nil
	}
	if !MTLSBuild {
		return fmt.Errorf("backend TLS verification and client certificates need a build with client-certificate support")
	}
	if serv.Mode != LBModeFullProxy || serv.Security != LBServE2EHTTPS {
		return fmt.Errorf("backend TLS verification and client certificates need mode fullproxy with security e2ehttps")
	}
	if p.CACertID != "" && !p.Verify {
		return fmt.Errorf("backend_ca_cert_id: set mtls_backend.verify_server_cert, a CA without verification has no effect")
	}
	if p.Verify {
		if p.CACertID == "" {
			return fmt.Errorf("mtls_backend.verify_server_cert: backend_ca_cert_id is required, there is no default trust store")
		}
		if err := ValidateCertID(p.CACertID); err != nil {
			return fmt.Errorf("backend_ca_cert_id: %v", err)
		}
		if usage := CertDiskUsage(p.CACertID); usage != CertUsageCA {
			return fmt.Errorf("backend_ca_cert_id: %s", certUsageMismatch(usage, CertUsageCA))
		}
	}
	if p.ClientCertID != "" {
		if err := ValidateCertID(p.ClientCertID); err != nil {
			return fmt.Errorf("backend_client_cert_id: %v", err)
		}
		if usage := CertDiskUsage(p.ClientCertID); usage != CertUsageClient {
			return fmt.Errorf("backend_client_cert_id: %s", certUsageMismatch(usage, CertUsageClient))
		}
	}
	if p.ServerName != "" {
		if err := validateBackendServerName(p.ServerName); err != nil {
			return fmt.Errorf("backend_tls_server_name: %v", err)
		}
	}
	return nil
}

func certUsageMismatch(have, want string) string {
	if have == "" {
		return fmt.Sprintf("no certificate with usage %q is registered under this ID", want)
	}
	return fmt.Sprintf("the certificate under this ID has usage %q, usage %q is required", have, want)
}

// validateBackendServerName accepts a DNS host name: it is sent as SNI, which
// carries no address, and matched against the DNS names of a certificate.
func validateBackendServerName(name string) error {
	if len(name) > 253 {
		return fmt.Errorf("longer than 253 bytes")
	}
	if net.ParseIP(name) != nil {
		return fmt.Errorf("an address is not a server name, leave it empty to match the endpoint address")
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return fmt.Errorf("not a DNS host name")
		}
		for i, c := range label {
			ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
				(c == '-' && i > 0 && i < len(label)-1)
			if !ok {
				return fmt.Errorf("not a DNS host name")
			}
		}
	}
	return nil
}
