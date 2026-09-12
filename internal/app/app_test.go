package app

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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

func TestApplicationKeepsDashboardAvailableWithoutProviderCredential(t *testing.T) {
	cfg := config.Default()
	cfg.Storage.SQLitePath = filepath.Join(t.TempDir(), "unconfigured.db")
	cfg.Provider = config.ProviderConfig{
		Type: "openai_compatible", BaseURL: "https://example.invalid", Model: "fixture-model",
		TimeoutMS: 1000, APIKeyEnv: "AGENTGUARD_PROVIDER_API_KEY",
	}
	t.Setenv(cfg.Provider.APIKeyEnv, "")
	application, err := New(context.Background(), cfg, "test", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = application.store.Close() })

	dashboard := httptest.NewRecorder()
	application.Server.Handler.ServeHTTP(dashboard, httptest.NewRequest(http.MethodGet, "/dashboard/playground", nil))
	if dashboard.Code != http.StatusOK || !strings.Contains(dashboard.Body.String(), `data-provider-configured="false"`) {
		t.Fatalf("dashboard status=%d body=%s", dashboard.Code, dashboard.Body.String())
	}

	chat := httptest.NewRecorder()
	application.Server.Handler.ServeHTTP(chat, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"fixture","messages":[{"role":"user","content":"normal question"}]}`)))
	if chat.Code != http.StatusServiceUnavailable || !strings.Contains(chat.Body.String(), `"code":"provider_configuration_error"`) {
		t.Fatalf("chat status=%d body=%s", chat.Code, chat.Body.String())
	}
	for _, forbidden := range []string{cfg.Provider.APIKeyEnv, "Authorization", "example.invalid"} {
		if strings.Contains(chat.Body.String(), forbidden) {
			t.Fatalf("configuration response leaked %q", forbidden)
		}
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
	if unconfigured, err := newProvider(cfg); err != nil {
		t.Fatal(err)
	} else if _, ok := unconfigured.(provider.Unconfigured); !ok {
		t.Fatalf("missing-key provider type = %T", unconfigured)
	}
	if providerConfigured(cfg) {
		t.Fatal("providerConfigured() = true without credential")
	}
	t.Setenv(cfg.APIKeyEnv, "fixture-key")
	if realProvider, err := newProvider(cfg); err != nil {
		t.Fatal(err)
	} else if _, ok := realProvider.(*provider.OpenAICompatible); !ok {
		t.Fatalf("real provider type = %T", realProvider)
	}
	if !providerConfigured(cfg) {
		t.Fatal("providerConfigured() = false with credential")
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
