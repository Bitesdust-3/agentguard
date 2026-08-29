package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bitesdust/agentguard/internal/config"
	"github.com/bitesdust/agentguard/internal/provider"
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

func TestProviderComposition(t *testing.T) {
	mock, err := newProvider(config.Default().Provider)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := mock.(provider.Mock); !ok {
		t.Fatalf("mock provider type = %T", mock)
	}

	cfg := config.ProviderConfig{Type: "openai_compatible", BaseURL: "https://example.invalid", Model: "fixture-model", TimeoutMS: 1000, APIKeyEnv: "AGENTGUARD_PROVIDER_API_KEY"}
	t.Setenv(cfg.APIKeyEnv, "")
	if _, err := newProvider(cfg); err == nil || !strings.Contains(err.Error(), cfg.APIKeyEnv) {
		t.Fatalf("missing-key error = %v", err)
	}
	t.Setenv(cfg.APIKeyEnv, "fixture-key")
	if realProvider, err := newProvider(cfg); err != nil {
		t.Fatal(err)
	} else if _, ok := realProvider.(*provider.OpenAICompatible); !ok {
		t.Fatalf("real provider type = %T", realProvider)
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

func TestDashboardRouteUsesDashboardHandler(t *testing.T) {
	t.Parallel()

	dashboard := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	request := httptest.NewRequest(http.MethodGet, "/dashboard/events", nil)
	response := httptest.NewRecorder()
	NewHandler("test", nil, nil, nil, dashboard).ServeHTTP(response, request)

	if got, want := response.Code, http.StatusNoContent; got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}
}
