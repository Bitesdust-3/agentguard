// Package app composes AgentGuard's infrastructure without embedding security
// business logic in the process entry point.
package app

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/bitesdust/agentguard/internal/config"
	"github.com/bitesdust/agentguard/internal/storage"
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
	store, err := storage.Open(ctx, cfg.Storage.SQLitePath)
	if err != nil {
		return nil, fmt.Errorf("initialize storage: %w", err)
	}

	return &Application{
		Server: &http.Server{
			Addr:              cfg.ListenAddr(),
			Handler:           NewHandler(version),
			ReadHeaderTimeout: 5 * time.Second,
			IdleTimeout:       60 * time.Second,
			ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelError),
		},
		store: store,
	}, nil
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

// NewHandler exposes only the infrastructure health endpoint in this stage.
func NewHandler(version string) http.Handler {
	mux := http.NewServeMux()
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
