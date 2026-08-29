package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealth(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequest(http.MethodGet, "/health", nil)
	response := httptest.NewRecorder()
	NewHandler("test", nil, nil, nil).ServeHTTP(response, request)

	if got, want := response.Code, http.StatusOK; got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}

	var body struct {
		Service string `json:"service"`
		Status  string `json:"status"`
		Version string `json:"version"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Service != "agentguard" || body.Status != "ok" || body.Version != "test" {
		t.Fatalf("unexpected health body: %+v", body)
	}
}

func TestHealthRejectsOtherMethods(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequest(http.MethodPost, "/health", nil)
	response := httptest.NewRecorder()
	NewHandler("test", nil, nil, nil).ServeHTTP(response, request)

	if got, want := response.Code, http.StatusMethodNotAllowed; got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}
}

func TestAuditRouteUsesAuditHandler(t *testing.T) {
	t.Parallel()

	auditHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	toolHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})
	request := httptest.NewRequest(http.MethodGet, "/api/audit/events", nil)
	response := httptest.NewRecorder()
	NewHandler("test", nil, toolHandler, auditHandler).ServeHTTP(response, request)

	if got, want := response.Code, http.StatusNoContent; got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}
}
