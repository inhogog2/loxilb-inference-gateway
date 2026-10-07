/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package handler

import (
	"encoding/json"
	"testing"

	"github.com/loxilb-io/loxilb/api/models"
	cmn "github.com/loxilb-io/loxilb/common"
)

// The Endpoint Picker fields cross the REST boundary verbatim on POST and
// read back zero-suppressed on GET, so a rule without an EPP serializes
// exactly as it did before the fields existed.
func TestEppArgumentsRoundTrip(t *testing.T) {
	src := &models.LoadbalanceEntryServiceArguments{
		EppEndpoint: "pd-disaggregation-epp.llm-d.svc:9002", EppFailureMode: "FailOpen",
		EppTimeoutMs: 2500, EppPlaintext: true,
	}
	var serv cmn.LbServiceArg
	applyEppArguments(&serv, src)
	if serv.EppEndpoint != src.EppEndpoint || serv.EppFailureMode != "FailOpen" ||
		serv.EppTimeoutMs != 2500 || !serv.EppPlaintext {
		t.Fatalf("POST conversion lost a field: %+v", serv)
	}
	var out models.LoadbalanceEntryServiceArguments
	serializeEppArguments(&out, serv)
	if out.EppEndpoint != src.EppEndpoint || out.EppFailureMode != src.EppFailureMode ||
		out.EppTimeoutMs != src.EppTimeoutMs || out.EppPlaintext != src.EppPlaintext {
		t.Fatalf("GET serialization differs from POST: got %+v want %+v", out, *src)
	}
}

func TestEppArgumentsAbsentStayAbsent(t *testing.T) {
	var serv cmn.LbServiceArg
	applyEppArguments(&serv, &models.LoadbalanceEntryServiceArguments{Mode: 4, Sel: 8})
	applyEppArguments(&serv, nil)
	if serv.EppEndpoint != "" || serv.EppFailureMode != "" || serv.EppTimeoutMs != 0 || serv.EppPlaintext {
		t.Fatalf("absent fields produced a value: %+v", serv)
	}
	var out models.LoadbalanceEntryServiceArguments
	serializeEppArguments(&out, serv)
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"eppEndpoint", "eppFailureMode", "eppTimeoutMs", "eppPlaintext"} {
		if containsKey(raw, key) {
			t.Fatalf("GET of a rule without an EPP carries %s: %s", key, raw)
		}
	}
}

func TestEppFailureModeEnumRejectedBySchema(t *testing.T) {
	args := models.LoadbalanceEntryServiceArguments{EppEndpoint: "epp:9002", EppFailureMode: "failopen"}
	if err := args.Validate(nil); err == nil {
		t.Fatal("schema accepted a failure mode outside its enum")
	}
	args.EppFailureMode = "FailClose"
	args.EppTimeoutMs = 600001
	if err := args.Validate(nil); err == nil {
		t.Fatal("schema accepted a timeout above its maximum")
	}
}

func containsKey(raw []byte, key string) bool {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return false
	}
	_, ok := m[key]
	return ok
}
