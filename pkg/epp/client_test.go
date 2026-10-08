/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package epp_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/loxilb-io/loxilb/pkg/epp"
	"github.com/loxilb-io/loxilb/pkg/epp/epptest"
)

func sampleRequest() *epp.Request {
	// A body larger than one chunk so chunking and reassembly are exercised.
	pad := strings.Repeat("x", 3*epp.BodyChunk/2)
	body := []byte(`{"model":"alias","prompt":"` + pad + `"}`)
	return &epp.Request{
		Method: "POST", Path: "/v1/completions", Authority: "vip:8080", Scheme: "http",
		Headers: []epp.Header{{"content-type", "application/json"}, {"x-drop", "1"}},
		Body:    body, Subset: []string{"10.0.0.1:8000", "10.0.0.2:8000"},
	}
}

func TestEppClientRequestPhaseAndResponsePhase(t *testing.T) {
	f := epptest.New("ok")
	addr, stop := epptest.Start(t, f, false)
	defer stop()
	c := epp.NewClient()
	defer c.Close()

	req := sampleRequest()
	dec, s := c.Submit(context.Background(), epp.RuleCfg{Endpoint: addr, Plaintext: true, TimeoutMs: 3000}, req)
	if dec.Status != epp.StatusOK || s == nil {
		t.Fatalf("decision %+v stream=%v", dec, s)
	}
	want := []string{"10.0.0.1:8000", "10.0.0.2:8000", "10.0.0.3:8000", "10.0.0.4:8000"}
	if strings.Join(dec.Candidates, ",") != strings.Join(want, ",") {
		t.Fatalf("candidates %v, want %v (ordered, de-duplicated, malformed dropped, capped at %d)", dec.Candidates, want, epp.MaxCandidates)
	}
	if len(dec.HdrSet) != 1 || dec.HdrSet[0] != (epp.Header{"x-prefiller-host-port", "10.0.0.9:8000"}) {
		t.Fatalf("header set %v: destination, content-length and pseudo headers kept out, prefill hint kept", dec.HdrSet)
	}
	if len(dec.HdrDel) != 1 || dec.HdrDel[0] != "x-drop" {
		t.Fatalf("header del %v", dec.HdrDel)
	}
	if !dec.BodyChanged || !bytes.Contains(dec.NewBody, []byte(`"model":"served-model"`)) || len(dec.NewBody) != len(req.Body)+len("served-model")-len("alias") {
		t.Fatalf("body rewrite not applied: changed=%v len=%d", dec.BodyChanged, len(dec.NewBody))
	}

	f.Mu.Lock()
	if f.ReqHeaders[":method"] != "POST" || f.ReqHeaders[":path"] != "/v1/completions" ||
		f.ReqHeaders[":authority"] != "vip:8080" || f.ReqHeaders[":scheme"] != "http" ||
		f.ReqHeaders["content-type"] != "application/json" {
		t.Fatalf("EPP saw headers %v", f.ReqHeaders)
	}
	if strings.Join(f.Subset, ",") != "10.0.0.1:8000,10.0.0.2:8000" {
		t.Fatalf("EPP saw subset %v", f.Subset)
	}
	if !bytes.Equal(f.Body, req.Body) {
		t.Fatalf("EPP reassembled %d body bytes, want %d", len(f.Body), len(req.Body))
	}
	f.Mu.Unlock()

	if err := s.ReportResponseHeaders(200, []epp.Header{{"content-type", "text/event-stream"}}, "10.0.0.2:8000"); err != nil {
		t.Fatal(err)
	}
	if err := s.ReportResponseEnd(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-f.StreamClosed:
	case <-time.After(3 * time.Second):
		t.Fatal("EPP stream did not end after the response report")
	}
	f.Mu.Lock()
	defer f.Mu.Unlock()
	if f.RespStatus[":status"] != "200" || f.RespStatus["status"] != "200" || f.RespStatus["content-type"] != "text/event-stream" {
		t.Fatalf("EPP saw response headers %v", f.RespStatus)
	}
	if f.Served != "10.0.0.2:8000" || !f.RespEOS {
		t.Fatalf("served=%q eos=%v", f.Served, f.RespEOS)
	}
}

func TestEppClientEchoedBodyIsNotAChange(t *testing.T) {
	f := epptest.New("echo")
	addr, stop := epptest.Start(t, f, false)
	defer stop()
	c := epp.NewClient()
	defer c.Close()
	dec, s := c.Submit(context.Background(), epp.RuleCfg{Endpoint: addr, Plaintext: true}, sampleRequest())
	if dec.Status != epp.StatusOK || dec.BodyChanged || dec.NewBody != nil {
		t.Fatalf("echoed body reported as a change: %+v", dec)
	}
	s.Abort()
}

func TestEppClientHeadersOnlyRequest(t *testing.T) {
	f := epptest.New("echo")
	addr, stop := epptest.Start(t, f, false)
	defer stop()
	c := epp.NewClient()
	defer c.Close()
	req := &epp.Request{Method: "GET", Path: "/v1/models", Authority: "vip", Scheme: "http"}
	dec, s := c.Submit(context.Background(), epp.RuleCfg{Endpoint: addr, Plaintext: true}, req)
	if dec.Status != epp.StatusOK || len(dec.Candidates) != 4 || dec.BodyChanged {
		t.Fatalf("GET decision %+v", dec)
	}
	s.Abort()
}

func TestEppClientImmediateResponse(t *testing.T) {
	f := epptest.New("immediate")
	addr, stop := epptest.Start(t, f, false)
	defer stop()
	c := epp.NewClient()
	defer c.Close()
	dec, s := c.Submit(context.Background(), epp.RuleCfg{Endpoint: addr, Plaintext: true}, sampleRequest())
	if s != nil {
		t.Fatal("immediate response must not leave a stream open")
	}
	if dec.Status != epp.StatusImmediate || dec.ImmCode != 429 || string(dec.ImmBody) != `{"error":"shed"}` ||
		len(dec.ImmHeaders) != 1 || dec.ImmHeaders[0] != (epp.Header{"retry-after", "1"}) {
		t.Fatalf("immediate decision %+v", dec)
	}
}

func TestEppClientTimeoutIsAnError(t *testing.T) {
	f := epptest.New("hang")
	addr, stop := epptest.Start(t, f, false)
	defer stop()
	c := epp.NewClient()
	defer c.Close()
	start := time.Now()
	dec, s := c.Submit(context.Background(), epp.RuleCfg{Endpoint: addr, Plaintext: true, TimeoutMs: 200}, sampleRequest())
	if s != nil || dec.Status != epp.StatusError || !errors.Is(dec.Err, context.DeadlineExceeded) {
		t.Fatalf("timeout decision %+v stream=%v", dec, s)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("deadline not enforced: took %s", el)
	}
	select {
	case <-f.StreamClosed:
	case <-time.After(3 * time.Second):
		t.Fatal("EPP did not see the abort after the timeout")
	}
}

func TestEppClientUnreachableIsAnError(t *testing.T) {
	lis, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := lis.Addr().String()
	lis.Close()
	c := epp.NewClient()
	defer c.Close()
	dec, s := c.Submit(context.Background(), epp.RuleCfg{Endpoint: addr, Plaintext: true, TimeoutMs: 500}, sampleRequest())
	if s != nil || dec.Status != epp.StatusError || dec.Err == nil {
		t.Fatalf("unreachable decision %+v", dec)
	}
}

func TestEppClientTLSWithoutVerification(t *testing.T) {
	f := epptest.New("echo")
	addr, stop := epptest.Start(t, f, true)
	defer stop()
	c := epp.NewClient()
	defer c.Close()
	dec, s := c.Submit(context.Background(), epp.RuleCfg{Endpoint: addr}, sampleRequest())
	if dec.Status != epp.StatusOK || len(dec.Candidates) != 4 {
		t.Fatalf("TLS decision %+v", dec)
	}
	s.Abort()
	// The same client must refuse plaintext against the TLS server.
	dec, _ = c.Submit(context.Background(), epp.RuleCfg{Endpoint: addr, Plaintext: true, TimeoutMs: 500}, sampleRequest())
	if dec.Status != epp.StatusError {
		t.Fatalf("plaintext against TLS accepted: %+v", dec)
	}
}

func TestEppClientDestinationFromMetadata(t *testing.T) {
	for _, mode := range []string{"metadata-only", "disagree"} {
		t.Run(mode, func(t *testing.T) {
			f := epptest.New(mode)
			addr, stop := epptest.Start(t, f, false)
			defer stop()
			c := epp.NewClient()
			defer c.Close()
			dec, s := c.Submit(context.Background(), epp.RuleCfg{Endpoint: addr, Plaintext: true}, sampleRequest())
			if dec.Status != epp.StatusOK {
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
	req, err := epp.ParseHTTP1Request(raw, "https")
	if err != nil {
		t.Fatal(err)
	}
	if req.Method != "POST" || req.Path != "/v1/chat/completions" || req.Authority != "vip:8080" || req.Scheme != "https" {
		t.Fatalf("request line %+v", req)
	}
	want := []epp.Header{{"content-type", "application/json"}, {"content-length", "2"}, {"x-session-id", "abc"}}
	if len(req.Headers) != len(want) {
		t.Fatalf("headers %v", req.Headers)
	}
	for i := range want {
		if req.Headers[i] != want[i] {
			t.Fatalf("header %d = %v, want %v", i, req.Headers[i], want[i])
		}
	}
	if _, err := epp.ParseHTTP1Request([]byte(""), "http"); err == nil {
		t.Fatal("empty head accepted")
	}
	if _, err := epp.ParseHTTP1Request([]byte("GET\r\n\r\n"), "http"); err == nil {
		t.Fatal("request line without a target accepted")
	}
}

func TestEppClientEvictionDuringResponse(t *testing.T) {
	f := epptest.New("evict")
	addr, stop := epptest.Start(t, f, false)
	defer stop()
	c := epp.NewClient()
	defer c.Close()
	dec, s := c.Submit(context.Background(), epp.RuleCfg{Endpoint: addr, Plaintext: true}, sampleRequest())
	if dec.Status != epp.StatusOK || s == nil {
		t.Fatalf("decision %+v", dec)
	}
	evicted := make(chan int, 1)
	s.OnEvict(func(code int) { evicted <- code })
	if err := s.ReportResponseHeaders(200, nil, "10.0.0.1:8000"); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-evicted:
		if code != 429 {
			t.Fatalf("eviction code %d", code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("eviction not seen")
	}
	if !s.Evicted() {
		t.Fatal("Evicted() false after the handler ran")
	}
	s.Abort()
}
