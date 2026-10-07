/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package epptest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"time"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// ListenAndServe serves f on addr outside a test (cmd/epp-fake): plaintext,
// or TLS with a fresh self-signed certificate when serverTLS. It returns
// the bound address and a stop function.
func ListenAndServe(addr string, f *Fake, serverTLS bool) (string, func(), error) {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return "", nil, err
	}
	var opts []grpc.ServerOption
	if serverTLS {
		cert, err := selfSigned()
		if err != nil {
			lis.Close()
			return "", nil, err
		}
		opts = append(opts, grpc.Creds(credentials.NewServerTLSFromCert(cert)))
	}
	srv := grpc.NewServer(opts...)
	extprocv3.RegisterExternalProcessorServer(srv, f)
	go srv.Serve(lis)
	return lis.Addr().String(), srv.Stop, nil
}

func selfSigned() (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "epp-fake"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * 365 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
