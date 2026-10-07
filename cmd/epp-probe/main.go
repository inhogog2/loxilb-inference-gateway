/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

// epp-probe sends one request to an Endpoint Picker (EPP) over ext_proc
// exactly as the loxilb data plane will, prints the decision, and then
// reports a response phase so the EPP's in-flight accounting is exercised
// end to end. Pure Go: build with CGO_ENABLED=0 and run it anywhere that
// reaches the EPP service (a pod, a node, a port-forward).
//
//	epp-probe -epp pd-disaggregation-epp.llm-d-pd-disaggregation.svc:9002 \
//	          -model Qwen/Qwen3-0.6B -prompt "hello" -subset 10.0.0.1:8000,10.0.0.2:8000
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/loxilb-io/loxilb/pkg/epp"
)

func main() {
	var (
		endpoint  = flag.String("epp", "", "EPP gRPC address host:port (required)")
		plaintext = flag.Bool("plaintext", false, "connect without TLS (default: TLS without verification)")
		timeoutMs = flag.Uint("timeout-ms", 3000, "request-phase deadline in ms")
		path      = flag.String("path", "/v1/completions", "request path (:path)")
		authority = flag.String("authority", "vip:8080", "request authority (:authority)")
		scheme    = flag.String("scheme", "http", "request scheme (:scheme)")
		model     = flag.String("model", "", "model name for the JSON body")
		prompt    = flag.String("prompt", "hello", "prompt for the JSON body")
		body      = flag.String("body", "", "raw request body (overrides -model/-prompt)")
		subset    = flag.String("subset", "", "comma-separated ip:port subset hint")
		headers   = flag.String("header", "", "extra request headers, 'k: v;k2: v2'")
		status    = flag.Int("resp-status", 200, "status code to report in the response phase")
		served    = flag.String("served", "", "ip:port to report as served (default: first candidate)")
		noResp    = flag.Bool("no-response-phase", false, "abort after the decision instead of reporting a response")
		repeat    = flag.Int("n", 1, "number of requests to send")
	)
	flag.Parse()
	if *endpoint == "" {
		fmt.Fprintln(os.Stderr, "epp-probe: -epp is required")
		flag.Usage()
		os.Exit(2)
	}

	reqBody := []byte(*body)
	if len(reqBody) == 0 {
		b, _ := json.Marshal(map[string]any{"model": *model, "prompt": *prompt, "max_tokens": 16})
		reqBody = b
	}
	req := &epp.Request{
		Method: "POST", Path: *path, Authority: *authority, Scheme: *scheme,
		Headers: []epp.Header{{Key: "content-type", Value: "application/json"},
			{Key: "content-length", Value: fmt.Sprint(len(reqBody))}},
		Body: reqBody,
	}
	for _, kv := range strings.Split(*headers, ";") {
		if k, v, ok := strings.Cut(kv, ":"); ok {
			req.Headers = append(req.Headers, epp.Header{Key: strings.ToLower(strings.TrimSpace(k)), Value: strings.TrimSpace(v)})
		}
	}
	if *subset != "" {
		for _, s := range strings.Split(*subset, ",") {
			if s = strings.TrimSpace(s); s != "" {
				req.Subset = append(req.Subset, s)
			}
		}
	}
	cfg := epp.RuleCfg{Endpoint: *endpoint, Plaintext: *plaintext, TimeoutMs: uint32(*timeoutMs)}
	client := epp.NewClient()
	defer client.Close()

	exit := 0
	for i := 0; i < *repeat; i++ {
		start := time.Now()
		dec, stream := client.Submit(context.Background(), cfg, req)
		took := time.Since(start)
		fmt.Printf("request %d: status=%s took=%s\n", i+1, statusName(dec.Status), took.Round(time.Millisecond))
		switch dec.Status {
		case epp.StatusError:
			fmt.Printf("  error: %v\n", dec.Err)
			exit = 1
			continue
		case epp.StatusImmediate:
			fmt.Printf("  immediate response: %d headers=%v body=%q\n", dec.ImmCode, dec.ImmHeaders, string(dec.ImmBody))
			continue
		}
		fmt.Printf("  candidates: %v\n", dec.Candidates)
		for _, h := range dec.HdrSet {
			fmt.Printf("  set-header: %s: %s\n", h.Key, h.Value)
		}
		for _, k := range dec.HdrDel {
			fmt.Printf("  remove-header: %s\n", k)
		}
		if dec.BodyChanged {
			fmt.Printf("  body rewritten (%d -> %d bytes): %s\n", len(req.Body), len(dec.NewBody), trim(dec.NewBody))
		} else {
			fmt.Printf("  body unchanged\n")
		}
		if *noResp {
			stream.Abort()
			continue
		}
		srv := *served
		if srv == "" && len(dec.Candidates) > 0 {
			srv = dec.Candidates[0]
		}
		if err := stream.ReportResponseHeaders(*status, []epp.Header{{Key: "content-type", Value: "application/json"}}, srv); err != nil {
			fmt.Printf("  response headers report failed: %v\n", err)
			exit = 1
		}
		if err := stream.ReportResponseEnd(); err != nil {
			fmt.Printf("  response end report failed: %v\n", err)
			exit = 1
		} else {
			fmt.Printf("  response phase reported (status %d, served %s)\n", *status, srv)
		}
	}
	os.Exit(exit)
}

func statusName(s epp.Status) string {
	switch s {
	case epp.StatusOK:
		return "OK"
	case epp.StatusImmediate:
		return "IMMEDIATE"
	default:
		return "ERROR"
	}
}

func trim(b []byte) string {
	if len(b) > 200 {
		return string(b[:200]) + "..."
	}
	return string(b)
}
