// Package app composes AgentGuard's infrastructure without embedding security
// business logic in the process entry point.
package app

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/bitesdust/agentguard/internal/audit"
	"github.com/bitesdust/agentguard/internal/config"
	"github.com/bitesdust/agentguard/internal/detection"
	"github.com/bitesdust/agentguard/internal/gateway"
	"github.com/bitesdust/agentguard/internal/policy"
	"github.com/bitesdust/agentguard/internal/provider"
	"github.com/bitesdust/agentguard/internal/storage"
	"github.com/bitesdust/agentguard/internal/tools"
	"github.com/bitesdust/agentguard/internal/web"
)

const (
	serviceName = "agentguard"
	statusOK    = "ok"
)

// Application owns the HTTP server and the storage lifecycle.
type Application struct {
	Server *http.Server
	store  *storage.Store
}

// New initializes the infrastructure required to serve AgentGuard.
func New(ctx context.Context, cfg config.Config, version string, logger *slog.Logger) (*Application, error) {
	chatProvider, err := newProvider(cfg.Provider)
	if err != nil {
		return nil, err
	}
	store, err := storage.Open(ctx, cfg.Storage.SQLitePath)
	if err != nil {
		return nil, fmt.Errorf("initialize storage: %w", err)
	}
	inputDetector := newInputDetector(cfg.Detection)
	inputPolicy, err := newPolicy(cfg.Policy.Input, policy.StageInput)
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	outputDetector := newOutputDetector(cfg.Detection)
	outputPolicy, err := newPolicy(cfg.Policy.Output, policy.StageOutput)
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	auditStore := audit.New(store.DB())
	toolHandler := tools.NewHandler(tools.NewService(store.DB(), cfg.Tools, auditStore))
	dashboard, err := web.New(store.DB(), version, web.Runtime{
		ProviderMode:       cfg.Provider.Type,
		ProviderModel:      cfg.Provider.Model,
		ProviderConfigured: providerConfigured(cfg.Provider),
	})
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("initialize dashboard: %w", err)
	}

	return &Application{
		Server: &http.Server{
			Addr:              cfg.ListenAddr(),
			Handler:           NewHandler(version, gateway.New(chatProvider, inputDetector, inputPolicy, outputDetector, outputPolicy, auditStore), toolHandler, auditStore, dashboard),
			ReadHeaderTimeout: 5 * time.Second,
			IdleTimeout:       60 * time.Second,
			ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelError),
		},
		store: store,
	}, nil
}

func newInputDetector(cfg config.DetectionConfig) *detection.Engine {
	detectors := make([]detection.Detector, 0, 3)
	thresholds := make(map[detection.DetectionType]float64, 3)
	if cfg.PII.Enabled {
		detectors = append(detectors, detection.NewPIIDetector())
		thresholds[detection.DetectionTypePII] = cfg.PII.Threshold
	}
	if cfg.Secret.Enabled {
		detectors = append(detectors, detection.NewSecretDetector())
		thresholds[detection.DetectionTypeSecret] = cfg.Secret.Threshold
	}
	if cfg.PromptInjection.Enabled {
		detectors = append(detectors, detection.NewPromptInjectionDetector())
		thresholds[detection.DetectionTypePromptInjection] = cfg.PromptInjection.Threshold
	}
	return detection.NewEngine(detectors, thresholds)
}

func newOutputDetector(cfg config.DetectionConfig) *detection.Engine {
	detectors := make([]detection.Detector, 0, 2)
	thresholds := make(map[detection.DetectionType]float64, 2)
	if cfg.PII.Enabled {
		detectors = append(detectors, detection.NewPIIDetector())
		thresholds[detection.DetectionTypePII] = cfg.PII.Threshold
	}
	if cfg.Secret.Enabled {
		detectors = append(detectors, detection.NewSecretDetector())
		thresholds[detection.DetectionTypeSecret] = cfg.Secret.Threshold
	}
	return detection.NewEngine(detectors, thresholds)
}

func newPolicy(cfg config.InputPolicyConfig, stage policy.Stage) (*policy.Engine, error) {
	rules := make([]policy.Rule, 0, len(cfg.Rules))
	for _, rule := range cfg.Rules {
		rules = append(rules, policy.Rule{
			ID:            rule.ID,
			DetectionType: detection.DetectionType(rule.When.DetectionType),
			MinScore:      rule.When.MinScore,
			Action:        policy.Action(rule.Action),
		})
	}
	return policy.NewEngine(policy.Config{Stage: stage, DefaultAction: policy.Action(cfg.DefaultAction), Rules: rules})
}

func newProvider(cfg config.ProviderConfig) (provider.Provider, error) {
	switch cfg.Type {
	case "mock":
		return provider.NewMock(), nil
	case "openai_compatible":
		apiKey := strings.TrimSpace(os.Getenv(cfg.APIKeyEnv))
		if apiKey == "" {
			return provider.NewUnconfigured(), nil
		}
		result, err := provider.NewOpenAICompatible(cfg.BaseURL, cfg.Model, apiKey, time.Duration(cfg.TimeoutMS)*time.Millisecond)
		if err != nil {
			return nil, fmt.Errorf("initialize openai-compatible provider: %w", err)
		}
		return result, nil
	default:
		return nil, fmt.Errorf("unsupported provider type %q", cfg.Type)
	}
}

func providerConfigured(cfg config.ProviderConfig) bool {
	return cfg.Type == "mock" || strings.TrimSpace(os.Getenv(cfg.APIKeyEnv)) != ""
}

// ListenAndServe starts the HTTP server.
func (a *Application) ListenAndServe() error {
	return a.Server.ListenAndServe()
}

// Shutdown stops HTTP serving before closing SQLite.
func (a *Application) Shutdown(ctx context.Context) error {
	if err := a.Server.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutdown http server: %w", err)
	}
	if err := a.store.Close(); err != nil {
		return fmt.Errorf("close storage: %w", err)
	}
	return nil
}

// NewHandler mounts the public gateway, local management APIs, and health endpoint.
func NewHandler(version string, chatHandler http.Handler, toolHandler http.Handler, auditHandler http.Handler, dashboardHandler ...http.Handler) http.Handler {
	mux := http.NewServeMux()
	if chatHandler != nil {
		mux.Handle("/v1/chat/completions", chatHandler)
	}
	if toolHandler != nil {
		mux.Handle("/api/", toolHandler)
	}
	if auditHandler != nil {
		mux.Handle("/api/audit/events", auditHandler)
	}
	if len(dashboardHandler) > 0 && dashboardHandler[0] != nil {
		mux.Handle("/dashboard", dashboardHandler[0])
		mux.Handle("/dashboard/", dashboardHandler[0])
	}
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if err := json.NewEncoder(w).Encode(struct {
			Service string `json:"service"`
			Status  string `json:"status"`
			Version string `json:"version"`
		}{
			Service: serviceName,
			Status:  statusOK,
			Version: version,
		}); err != nil {
			return
		}
	})
	return mux
}
