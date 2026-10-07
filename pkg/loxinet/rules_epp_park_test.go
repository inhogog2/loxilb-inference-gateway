/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package loxinet

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	cmn "github.com/loxilb-io/loxilb/common"
	"github.com/loxilb-io/loxilb/pkg/epp/epptest"
)

// Phase 1 M4 completion checks, end to end through the in-process data
// plane (the loxinet harness runs the sockproxy workers): an EPP rule's
// request is handed to Go, the client parks without blocking its worker,
// the decision resumes it, and a deadline, a client that leaves or a
// recycled slot leaks nothing. Needs TestMain -> loxiNetInit (root).

const eppTestVIP = "127.0.0.1"

func eppTestBackend(t *testing.T) (*httptest.Server, cmn.LbEndPointArg) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"served":true,"bytes":%d}`, len(body))
	}))
	t.Cleanup(srv.Close)
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	var p int
	fmt.Sscanf(port, "%d", &p)
	return srv, cmn.LbEndPointArg{EpIP: host, EpPort: uint16(p), Weight: 1}
}

func eppTestRule(t *testing.T, port uint16, eppAddr, failureMode string, timeoutMs uint32, ep cmn.LbEndPointArg) cmn.LbServiceArg {
	t.Helper()
	serv := cmn.LbServiceArg{
		ServIP: eppTestVIP, ServPort: port, Proto: "tcp", Mode: cmn.LBModeFullProxy, Sel: cmn.LbSelRr,
		EppEndpoint: eppAddr, EppFailureMode: failureMode, EppTimeoutMs: timeoutMs, EppPlaintext: true,
	}
	if _, err := mh.zr.Rules.AddLbRule(serv, nil, nil, nil, []cmn.LbEndPointArg{ep}); err != nil {
		t.Fatalf("add rule on :%d: %v", port, err)
	}
	t.Cleanup(func() { mh.zr.Rules.DeleteLbRule(serv) })
	return serv
}

// eppTestRequest sends one JSON POST through the VIP and returns the
// status code and body, or an error (a cut connection).
func eppTestRequest(port uint16, body string, timeout time.Duration) (int, string, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(eppTestVIP, fmt.Sprint(port)), 2*time.Second)
	if err != nil {
		return 0, "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	req := fmt.Sprintf("POST /v1/completions HTTP/1.1\r\nHost: %s:%d\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		eppTestVIP, port, len(body), body)
	if _, err := conn.Write([]byte(req)); err != nil {
		return 0, "", err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), nil
}

func eppTestSettled(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if EppInflight() == 0 && EppPendingDecisions() == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("EPP state did not settle: inflight=%d pending=%d", EppInflight(), EppPendingDecisions())
}

func TestEppParkResumeThroughDataPlane(t *testing.T) {
	if mh.zr == nil || mh.dpEbpf == nil {
		t.Skip("loxinet harness not initialized (run the whole package as root)")
	}
	_, ep := eppTestBackend(t)
	body := `{"model":"alias","prompt":"hello"}`

	t.Run("decision resumes the request", func(t *testing.T) {
		f := epptest.New("ok")
		addr, stop := epptest.Start(t, f, false)
		defer stop()
		eppTestRule(t, 28100, addr, cmn.EppFailureModeFailClose, 3000, ep)
		code, resp, err := eppTestRequest(28100, body, 5*time.Second)
		if err != nil || code != 200 || !strings.Contains(resp, `"served":true`) {
			t.Fatalf("code=%d resp=%q err=%v", code, resp, err)
		}
		f.Mu.Lock()
		defer f.Mu.Unlock()
		if f.ReqHeaders[":method"] != "POST" || f.ReqHeaders[":path"] != "/v1/completions" || string(f.Body) != body {
			t.Fatalf("EPP saw headers=%v body=%q", f.ReqHeaders, f.Body)
		}
		if len(f.Subset) != 1 || f.Subset[0] != fmt.Sprintf("%s:%d", ep.EpIP, ep.EpPort) {
			t.Fatalf("EPP saw subset %v, want the rule's healthy endpoint", f.Subset)
		}
	})

	t.Run("deadline: FailOpen falls back, FailClose answers 503", func(t *testing.T) {
		f := epptest.New("hang")
		addr, stop := epptest.Start(t, f, false)
		defer stop()
		eppTestRule(t, 28102, addr, cmn.EppFailureModeFailOpen, 300, ep)
		eppTestRule(t, 28104, addr, cmn.EppFailureModeFailClose, 300, ep)
		start := time.Now()
		code, _, err := eppTestRequest(28102, body, 5*time.Second)
		if err != nil || code != 200 {
			t.Fatalf("FailOpen after the deadline: code=%d err=%v", code, err)
		}
		if el := time.Since(start); el < 250*time.Millisecond || el > 3*time.Second {
			t.Fatalf("FailOpen took %s, want about the 300 ms deadline", el)
		}
		code, resp, err := eppTestRequest(28104, body, 5*time.Second)
		if err != nil || code != 503 || !strings.Contains(resp, "epp_unavailable") {
			t.Fatalf("FailClose after the deadline: code=%d resp=%q err=%v", code, resp, err)
		}
		eppTestSettled(t)
	})

	t.Run("immediate response is relayed", func(t *testing.T) {
		f := epptest.New("immediate")
		addr, stop := epptest.Start(t, f, false)
		defer stop()
		eppTestRule(t, 28106, addr, cmn.EppFailureModeFailClose, 3000, ep)
		code, resp, err := eppTestRequest(28106, body, 5*time.Second)
		if err != nil || code != 429 || !strings.Contains(resp, "shed") {
			t.Fatalf("immediate: code=%d resp=%q err=%v", code, resp, err)
		}
		eppTestSettled(t)
	})

	t.Run("a parked request does not block other connections", func(t *testing.T) {
		f := epptest.New("hang")
		addr, stop := epptest.Start(t, f, false)
		defer stop()
		eppTestRule(t, 28108, addr, cmn.EppFailureModeFailOpen, 2000, ep)
		plain := cmn.LbServiceArg{ServIP: eppTestVIP, ServPort: 28110, Proto: "tcp", Mode: cmn.LBModeFullProxy, Sel: cmn.LbSelRr}
		if _, err := mh.zr.Rules.AddLbRule(plain, nil, nil, nil, []cmn.LbEndPointArg{ep}); err != nil {
			t.Fatal(err)
		}
		defer mh.zr.Rules.DeleteLbRule(plain)

		// Park several requests on every worker, then push plain traffic
		// through: it must complete long before the parked ones resume.
		const parked = 16
		var wg sync.WaitGroup
		for i := 0; i < parked; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				eppTestRequest(28108, body, 10*time.Second)
			}()
		}
		time.Sleep(200 * time.Millisecond)
		if EppInflight() != parked {
			t.Fatalf("%d requests parked, want %d", EppInflight(), parked)
		}
		start := time.Now()
		for i := 0; i < 8; i++ {
			code, _, err := eppTestRequest(28110, body, 5*time.Second)
			if err != nil || code != 200 {
				t.Fatalf("plain request %d while %d are parked: code=%d err=%v", i, parked, code, err)
			}
		}
		if el := time.Since(start); el > time.Second {
			t.Fatalf("plain requests took %s while EPP requests were parked", el)
		}
		wg.Wait()
		eppTestSettled(t)
	})

	t.Run("a client that leaves while parked aborts the stream", func(t *testing.T) {
		f := epptest.New("hang")
		addr, stop := epptest.Start(t, f, false)
		defer stop()
		eppTestRule(t, 28112, addr, cmn.EppFailureModeFailOpen, 5000, ep)
		conn, err := net.Dial("tcp", net.JoinHostPort(eppTestVIP, "28112"))
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(conn, "POST /v1/completions HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
		time.Sleep(200 * time.Millisecond)
		if EppInflight() != 1 {
			t.Fatalf("inflight=%d, want the parked request", EppInflight())
		}
		conn.Close()
		select {
		case <-f.StreamClosed:
		case <-time.After(3 * time.Second):
			t.Fatal("the EPP did not see the stream end after the client left")
		}
		eppTestSettled(t)
	})
}
