/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

// epp-fake is a stand-in Endpoint Picker for CI: an ext_proc server that
// names a fixed destination list for every request and plays the response
// phase like the llm-d EPP does. Pure Go (CGO_ENABLED=0).
//
//	epp-fake -listen 0.0.0.0:9002 -dest 10.42.0.7:8000,10.42.0.8:8000
//
// -mode selects the behaviour (ok, echo, immediate, hang, evict); -tls
// serves a self-signed certificate (the llm-d default), else plaintext.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/loxilb-io/loxilb/pkg/epp/epptest"
)

func main() {
	listen := flag.String("listen", "0.0.0.0:9002", "address to serve ext_proc on")
	dest := flag.String("dest", "", "comma-separated ip:port destination list named for every request")
	mode := flag.String("mode", "echo", "behaviour: ok, echo, immediate, hang, evict")
	useTLS := flag.Bool("tls", false, "serve TLS with a self-signed certificate")
	flag.Parse()

	f := epptest.New(*mode)
	f.Dest = *dest
	addr, stop, err := epptest.ListenAndServe(*listen, f, *useTLS)
	if err != nil {
		fmt.Fprintln(os.Stderr, "epp-fake:", err)
		os.Exit(1)
	}
	fmt.Printf("epp-fake: serving mode=%s dest=%q tls=%v on %s\n", *mode, *dest, *useTLS, addr)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	stop()
}
