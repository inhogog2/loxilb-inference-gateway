/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package epp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/structpb"
)

// fakeEpp is an ExternalProcessor that behaves like the llm-d EPP: it
// waits for the whole request body, answers with a headers response and
// streamed body chunks, then expects the response-phase reports.
type fakeEpp struct {
	extprocv3.UnimplementedExternalProcessorServer
	mode string // "ok", "echo", "immediate", "hang", "metadata-only", "disagree"

	mu           sync.Mutex
	reqHeaders   map[string]string
	subset       []string
	body         []byte
	respStatus   map[string]string
	served       string
	respEOS      bool
	streamClosed chan struct{}
}

func newFakeEpp(mode string) *fakeEpp {
	return &fakeEpp{mode: mode, streamClosed: make(chan struct{}, 1)}
}

func hv(k, v string) *corev3.HeaderValueOption {
	return &corev3.HeaderValueOption{Header: &corev3.HeaderValue{Key: k, RawValue: []byte(v)}}
}

func (f *fakeEpp) Process(st extprocv3.ExternalProcessor_ProcessServer) error {
	defer func() { f.streamClosed <- struct{}{} }()
	var body []byte
	headersEOS := false
	// Request phase.
	for {
		msg, err := st.Recv()
		if err != nil {
			return err
		}
		switch r := msg.Request.(type) {
		case *extprocv3.ProcessingRequest_RequestHeaders:
			f.mu.Lock()
			f.reqHeaders = make(map[string]string)
			for _, h := range r.RequestHeaders.GetHeaders().GetHeaders() {
				f.reqHeaders[h.Key] = string(h.RawValue)
			}
			if hint := msg.GetMetadataContext().GetFilterMetadata()[MetadataSubsetNamespace]; hint != nil {
				for _, v := range hint.GetFields()[HeaderSubset].GetListValue().GetValues() {
					f.subset = append(f.subset, v.GetStringValue())
				}
			}
			f.mu.Unlock()
			headersEOS = r.RequestHeaders.GetEndOfStream()
		case *extprocv3.ProcessingRequest_RequestBody:
			body = append(body, r.RequestBody.GetBody()...)
			headersEOS = r.RequestBody.GetEndOfStream()
		}
		if headersEOS {
			break
		}
	}
	f.mu.Lock()
	f.body = body
	f.mu.Unlock()

	switch f.mode {
	case "hang":
		<-st.Context().Done()
		return st.Context().Err()
	case "immediate":
		return st.Send(&extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ImmediateResponse{
			ImmediateResponse: &extprocv3.ImmediateResponse{
				Status:  &typev3.HttpStatus{Code: typev3.StatusCode_TooManyRequests},
				Body:    []byte(`{"error":"shed"}`),
				Headers: &extprocv3.HeaderMutation{SetHeaders: []*corev3.HeaderValueOption{hv("Retry-After", "1")}},
			}}})
	}

	// Headers response: destination (five entries, the client keeps four),
	// a prefill hint, a content-length the client must drop, a removal.
	hm := &extprocv3.HeaderMutation{RemoveHeaders: []string{"X-Drop"}}
	dest := "10.0.0.1:8000,10.0.0.2:8000, 10.0.0.3:8000,10.0.0.1:8000,bogus,10.0.0.4:8000,10.0.0.5:8000"
	dyn, _ := structpb.NewStruct(map[string]any{MetadataNamespace: map[string]any{HeaderDestination: dest}})
	switch f.mode {
	case "metadata-only":
		hm.SetHeaders = []*corev3.HeaderValueOption{hv("x-prefiller-host-port", "10.0.0.9:8000")}
	case "disagree":
		hm.SetHeaders = []*corev3.HeaderValueOption{hv(HeaderDestination, "10.0.0.7:8000")}
	default:
		hm.SetHeaders = []*corev3.HeaderValueOption{
			hv(HeaderDestination, dest), hv("x-prefiller-host-port", "10.0.0.9:8000"), hv("Content-Length", "5"),
		}
	}
	if err := st.Send(&extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_RequestHeaders{RequestHeaders: &extprocv3.HeadersResponse{
			Response: &extprocv3.CommonResponse{HeaderMutation: hm, ClearRouteCache: true}}},
		DynamicMetadata: dyn,
	}); err != nil {
		return err
	}
	if len(body) > 0 {
		out := body
		if f.mode == "ok" {
			out = bytes.Replace(body, []byte(`"model":"alias"`), []byte(`"model":"served-model"`), 1)
		}
		half := len(out) / 2
		for i, chunk := range [][]byte{out[:half], out[half:]} {
			if err := st.Send(&extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_RequestBody{
				RequestBody: &extprocv3.BodyResponse{Response: &extprocv3.CommonResponse{BodyMutation: &extprocv3.BodyMutation{
					Mutation: &extprocv3.BodyMutation_StreamedResponse{StreamedResponse: &extprocv3.StreamedBodyResponse{Body: chunk, EndOfStream: i == 1}}}}}}}); err != nil {
				return err
			}
		}
	}

	// Response phase.
	for {
		msg, err := st.Recv()
		if err != nil {
			return err
		}
		switch r := msg.Request.(type) {
		case *extprocv3.ProcessingRequest_ResponseHeaders:
			f.mu.Lock()
			f.respStatus = make(map[string]string)
			for _, h := range r.ResponseHeaders.GetHeaders().GetHeaders() {
				f.respStatus[h.Key] = string(h.RawValue)
			}
			if lb := msg.GetMetadataContext().GetFilterMetadata()[MetadataNamespace]; lb != nil {
				f.served = lb.GetFields()[HeaderServed].GetStringValue()
			}
			f.mu.Unlock()
			if err := st.Send(&extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseHeaders{
				ResponseHeaders: &extprocv3.HeadersResponse{Response: &extprocv3.CommonResponse{}}}}); err != nil {
				return err
			}
		case *extprocv3.ProcessingRequest_ResponseBody:
			if r.ResponseBody.GetEndOfStream() {
				f.mu.Lock()
				f.respEOS = true
				f.mu.Unlock()
				return st.Send(&extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseBody{
					ResponseBody: &extprocv3.BodyResponse{Response: &extprocv3.CommonResponse{}}}})
			}
		}
	}
}

func startFakeEpp(t *testing.T, f *fakeEpp, serverTLS bool) (addr string, stop func()) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var opts []grpc.ServerOption
	if serverTLS {
		opts = append(opts, grpc.Creds(credentials.NewServerTLSFromCert(selfSignedCert(t))))
	}
	srv := grpc.NewServer(opts...)
	extprocv3.RegisterExternalProcessorServer(srv, f)
	go srv.Serve(lis)
	return lis.Addr().String(), srv.Stop
}

func selfSignedCert(t *testing.T) *tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "epp"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func sampleRequest() *Request {
	// A body larger than one chunk so chunking and reassembly are exercised.
	pad := strings.Repeat("x", 3*bodyChunk/2)
	body := []byte(`{"model":"alias","prompt":"` + pad + `"}`)
	return &Request{
		Method: "POST", Path: "/v1/completions", Authority: "vip:8080", Scheme: "http",
		Headers: []Header{{"content-type", "application/json"}, {"x-drop", "1"}},
		Body:    body, Subset: []string{"10.0.0.1:8000", "10.0.0.2:8000"},
	}
}

func TestEppClientRequestPhaseAndResponsePhase(t *testing.T) {
	f := newFakeEpp("ok")
	addr, stop := startFakeEpp(t, f, false)
	defer stop()
	c := NewClient()
	defer c.Close()

	req := sampleRequest()
	dec, s := c.Submit(context.Background(), RuleCfg{Endpoint: addr, Plaintext: true, TimeoutMs: 3000}, req)
	if dec.Status != StatusOK || s == nil {
		t.Fatalf("decision %+v stream=%v", dec, s)
	}
	want := []string{"10.0.0.1:8000", "10.0.0.2:8000", "10.0.0.3:8000", "10.0.0.4:8000"}
	if strings.Join(dec.Candidates, ",") != strings.Join(want, ",") {
		t.Fatalf("candidates %v, want %v (ordered, de-duplicated, malformed dropped, capped at %d)", dec.Candidates, want, MaxCandidates)
	}
	if len(dec.HdrSet) != 1 || dec.HdrSet[0] != (Header{"x-prefiller-host-port", "10.0.0.9:8000"}) {
		t.Fatalf("header set %v: destination kept out, content-length dropped, prefill hint kept", dec.HdrSet)
	}
	if len(dec.HdrDel) != 1 || dec.HdrDel[0] != "x-drop" {
		t.Fatalf("header del %v", dec.HdrDel)
	}
	if !dec.BodyChanged || !bytes.Contains(dec.NewBody, []byte(`"model":"served-model"`)) || len(dec.NewBody) != len(req.Body)+len("served-model")-len("alias") {
		t.Fatalf("body rewrite not applied: changed=%v len=%d", dec.BodyChanged, len(dec.NewBody))
	}

	f.mu.Lock()
	if f.reqHeaders[":method"] != "POST" || f.reqHeaders[":path"] != "/v1/completions" ||
		f.reqHeaders[":authority"] != "vip:8080" || f.reqHeaders[":scheme"] != "http" ||
		f.reqHeaders["content-type"] != "application/json" {
		t.Fatalf("EPP saw headers %v", f.reqHeaders)
	}
	if strings.Join(f.subset, ",") != "10.0.0.1:8000,10.0.0.2:8000" {
		t.Fatalf("EPP saw subset %v", f.subset)
	}
	if !bytes.Equal(f.body, req.Body) {
		t.Fatalf("EPP reassembled %d body bytes, want %d", len(f.body), len(req.Body))
	}
	f.mu.Unlock()

	if err := s.ReportResponseHeaders(200, []Header{{"content-type", "text/event-stream"}}, "10.0.0.2:8000"); err != nil {
		t.Fatal(err)
	}
	if err := s.ReportResponseEnd(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-f.streamClosed:
	case <-time.After(3 * time.Second):
		t.Fatal("EPP stream did not end after the response report")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.respStatus[":status"] != "200" || f.respStatus["status"] != "200" || f.respStatus["content-type"] != "text/event-stream" {
		t.Fatalf("EPP saw response headers %v", f.respStatus)
	}
	if f.served != "10.0.0.2:8000" || !f.respEOS {
		t.Fatalf("served=%q eos=%v", f.served, f.respEOS)
	}
}

func TestEppClientEchoedBodyIsNotAChange(t *testing.T) {
	f := newFakeEpp("echo")
	addr, stop := startFakeEpp(t, f, false)
	defer stop()
	c := NewClient()
	defer c.Close()
	dec, s := c.Submit(context.Background(), RuleCfg{Endpoint: addr, Plaintext: true}, sampleRequest())
	if dec.Status != StatusOK || dec.BodyChanged || dec.NewBody != nil {
		t.Fatalf("echoed body reported as a change: %+v", dec)
	}
	s.Abort()
}

func TestEppClientHeadersOnlyRequest(t *testing.T) {
	f := newFakeEpp("echo")
	addr, stop := startFakeEpp(t, f, false)
	defer stop()
	c := NewClient()
	defer c.Close()
	req := &Request{Method: "GET", Path: "/v1/models", Authority: "vip", Scheme: "http"}
	dec, s := c.Submit(context.Background(), RuleCfg{Endpoint: addr, Plaintext: true}, req)
	if dec.Status != StatusOK || len(dec.Candidates) != 4 || dec.BodyChanged {
		t.Fatalf("GET decision %+v", dec)
	}
	s.Abort()
}

func TestEppClientImmediateResponse(t *testing.T) {
	f := newFakeEpp("immediate")
	addr, stop := startFakeEpp(t, f, false)
	defer stop()
	c := NewClient()
	defer c.Close()
	dec, s := c.Submit(context.Background(), RuleCfg{Endpoint: addr, Plaintext: true}, sampleRequest())
	if s != nil {
		t.Fatal("immediate response must not leave a stream open")
	}
	if dec.Status != StatusImmediate || dec.ImmCode != 429 || string(dec.ImmBody) != `{"error":"shed"}` ||
		len(dec.ImmHeaders) != 1 || dec.ImmHeaders[0] != (Header{"retry-after", "1"}) {
		t.Fatalf("immediate decision %+v", dec)
	}
}

func TestEppClientTimeoutIsAnError(t *testing.T) {
	f := newFakeEpp("hang")
	addr, stop := startFakeEpp(t, f, false)
	defer stop()
	c := NewClient()
	defer c.Close()
	start := time.Now()
	dec, s := c.Submit(context.Background(), RuleCfg{Endpoint: addr, Plaintext: true, TimeoutMs: 200}, sampleRequest())
	if s != nil || dec.Status != StatusError || !errors.Is(dec.Err, context.DeadlineExceeded) {
		t.Fatalf("timeout decision %+v stream=%v", dec, s)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("deadline not enforced: took %s", el)
	}
	select {
	case <-f.streamClosed:
	case <-time.After(3 * time.Second):
		t.Fatal("EPP did not see the abort after the timeout")
	}
}

func TestEppClientUnreachableIsAnError(t *testing.T) {
	lis, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := lis.Addr().String()
	lis.Close()
	c := NewClient()
	defer c.Close()
	dec, s := c.Submit(context.Background(), RuleCfg{Endpoint: addr, Plaintext: true, TimeoutMs: 500}, sampleRequest())
	if s != nil || dec.Status != StatusError || dec.Err == nil {
		t.Fatalf("unreachable decision %+v", dec)
	}
}

func TestEppClientTLSWithoutVerification(t *testing.T) {
	f := newFakeEpp("echo")
	addr, stop := startFakeEpp(t, f, true)
	defer stop()
	c := NewClient()
	defer c.Close()
	dec, s := c.Submit(context.Background(), RuleCfg{Endpoint: addr}, sampleRequest())
	if dec.Status != StatusOK || len(dec.Candidates) != 4 {
		t.Fatalf("TLS decision %+v", dec)
	}
	s.Abort()
	// The same client must refuse plaintext against the TLS server.
	dec, _ = c.Submit(context.Background(), RuleCfg{Endpoint: addr, Plaintext: true, TimeoutMs: 500}, sampleRequest())
	if dec.Status != StatusError {
		t.Fatalf("plaintext against TLS accepted: %+v", dec)
	}
}

func TestEppClientDestinationFromMetadata(t *testing.T) {
	for _, mode := range []string{"metadata-only", "disagree"} {
		t.Run(mode, func(t *testing.T) {
			f := newFakeEpp(mode)
			addr, stop := startFakeEpp(t, f, false)
			defer stop()
			c := NewClient()
			defer c.Close()
			dec, s := c.Submit(context.Background(), RuleCfg{Endpoint: addr, Plaintext: true}, sampleRequest())
			if dec.Status != StatusOK {
				t.Fatalf("decision %+v", dec)
			}
			s.Abort()
			if mode == "metadata-only" && len(dec.Candidates) != 4 {
				t.Fatalf("metadata destination not used: %v", dec.Candidates)
			}
			if mode == "disagree" && (len(dec.Candidates) != 1 || dec.Candidates[0] != "10.0.0.7:8000") {
				t.Fatalf("header must win over metadata: %v", dec.Candidates)
			}
		})
	}
}

func TestParseHTTP1Request(t *testing.T) {
	raw := []byte("POST /v1/chat/completions HTTP/1.1\r\nHost: vip:8080\r\nContent-Type: application/json\r\nContent-Length: 2\r\nX-Session-Id: abc\r\n\r\n{}")
	req, err := ParseHTTP1Request(raw, "https")
	if err != nil {
		t.Fatal(err)
	}
	if req.Method != "POST" || req.Path != "/v1/chat/completions" || req.Authority != "vip:8080" || req.Scheme != "https" {
		t.Fatalf("request line %+v", req)
	}
	want := []Header{{"content-type", "application/json"}, {"content-length", "2"}, {"x-session-id", "abc"}}
	if len(req.Headers) != len(want) {
		t.Fatalf("headers %v", req.Headers)
	}
	for i := range want {
		if req.Headers[i] != want[i] {
			t.Fatalf("header %d = %v, want %v", i, req.Headers[i], want[i])
		}
	}
	if _, err := ParseHTTP1Request([]byte(""), "http"); err == nil {
		t.Fatal("empty head accepted")
	}
	if _, err := ParseHTTP1Request([]byte("GET\r\n\r\n"), "http"); err == nil {
		t.Fatal("request line without a target accepted")
	}
}
