// Package storage provides the SQLite connection and schema bootstrap used by
// AgentGuard. Business repositories are intentionally not part of this stage.
package storage

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

// Store owns the application's SQLite connection pool.
type Store struct {
	db *sql.DB
}

// Open creates a SQLite connection, enables foreign-key enforcement, verifies
// it, and applies the infrastructure schema bootstrap.
func Open(ctx context.Context, path string) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("sqlite path must not be empty")
	}
	if path != ":memory:" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, fmt.Errorf("create sqlite directory: %w", err)
		}
	}

	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	store := &Store{db: db}
	if err := store.configure(ctx); err != nil {
		_ = store.Close()
		return nil, err
	}
	if err := store.Migrate(ctx); err != nil {
		_ = store.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) configure(ctx context.Context) error {
	if err := s.db.PingContext(ctx); err != nil {
		return fmt.Errorf("ping sqlite: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, "PRAGMA foreign_keys = ON"); err != nil {
		return fmt.Errorf("enable sqlite foreign keys: %w", err)
	}

	var enabled int
	if err := s.db.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&enabled); err != nil {
		return fmt.Errorf("verify sqlite foreign keys: %w", err)
	}
	if enabled != 1 {
		return fmt.Errorf("sqlite foreign keys are not enabled")
	}
	return nil
}

// DB exposes the connection only for future storage repositories and tests.
func (s *Store) DB() *sql.DB {
	return s.db
}

// Close releases the SQLite connection.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}
