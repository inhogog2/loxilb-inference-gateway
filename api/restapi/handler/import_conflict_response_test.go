package handler

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/go-openapi/runtime"
	cmn "github.com/loxilb-io/loxilb/common"
)

// Pin the actual error classifier and HTTP writer used by API-key creation.
func TestImportedCredentialConflictHTTPResponse(t *testing.T) {
	const safe = "imported API key is already registered"
	response := &ErrorResponse{Payload: ResultErrorResponseError(cmn.NewConflictError(safe))}
	recorder := httptest.NewRecorder()
	response.WriteResponse(recorder, runtime.JSONProducer())
	if recorder.Code != 409 {
		t.Fatalf("status=%d, want409", recorder.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["result"] != safe || body["code"] != float64(409) {
		t.Fatal("unexpected public conflict payload")
	}
}
