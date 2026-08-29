package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bitesdust/agentguard/internal/app"
	"github.com/bitesdust/agentguard/internal/config"
)

var version = "v1.0.0"

func main() {
	configPath := flag.String("config", "", "path to a YAML configuration file")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("configuration load failed", "error", err)
		os.Exit(1)
	}

	application, err := app.New(context.Background(), cfg, version, logger)
	if err != nil {
		logger.Error("storage initialization failed", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errCh := make(chan error, 1)
	go func() {
		logger.Info("service starting", "address", application.Server.Addr, "version", version)
		errCh <- application.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Error("service exited unexpectedly", "error", err)
			os.Exit(1)
		}
	case <-ctx.Done():
		logger.Info("service shutdown requested")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := application.Shutdown(shutdownCtx); err != nil {
			logger.Error("service shutdown failed", "error", err)
			os.Exit(1)
		}
		if err := <-errCh; err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("service exited unexpectedly", "error", err)
			os.Exit(1)
		}
	}
}
