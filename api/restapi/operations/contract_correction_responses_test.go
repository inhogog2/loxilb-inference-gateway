package operations_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-openapi/runtime"
	"github.com/loxilb-io/loxilb/api/models"
	"github.com/loxilb-io/loxilb/api/restapi/operations"
	ai "github.com/loxilb-io/loxilb/api/restapi/operations/ai"
)

func TestContractCorrectionGeneratedResponses(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		response interface {
			WriteResponse(http.ResponseWriter, runtime.Producer)
		}
	}{
		{"capabilities credential-store unavailable", 503, operations.NewGetStatusCapabilitiesServiceUnavailable().WithPayload(&models.Error{Code: 503, Message: "Credential store unavailable"})},
		{"imported credential conflict", 409, ai.NewPostConfigAiApikeyConflict().WithPayload(&models.Error{Code: 409, Result: "imported API key is already registered"})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			tc.response.WriteResponse(recorder, runtime.JSONProducer())
			if recorder.Code != tc.status {
				t.Fatalf("status=%d, want %d", recorder.Code, tc.status)
			}
			var body map[string]any
			if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body["code"] != float64(tc.status) {
				t.Fatal("response body status drift")
			}
		})
	}
}
