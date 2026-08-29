package storage

import (
	"context"
	"fmt"
	"time"
)

type migration struct {
	version    int
	statements []string
}

var migrations = []migration{
	{version: 1},
	{version: 2, statements: []string{
		`CREATE TABLE tool_calls (id TEXT PRIMARY KEY, tool_name TEXT NOT NULL, target_type TEXT NOT NULL, external INTEGER NOT NULL, destructive INTEGER NOT NULL, sensitive INTEGER NOT NULL, decision TEXT NOT NULL CHECK(decision IN ('PASS','BLOCK','APPROVAL')), state TEXT NOT NULL CHECK(state IN ('RECEIVED','EVALUATED','PASS','BLOCK','PENDING_APPROVAL','APPROVED','REJECTED','EXECUTED','FAILED')), policy_id TEXT NOT NULL, arguments_summary TEXT NOT NULL, result_summary TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)`,
		`CREATE TABLE approvals (id TEXT PRIMARY KEY, tool_call_id TEXT NOT NULL UNIQUE REFERENCES tool_calls(id), status TEXT NOT NULL CHECK(status IN ('PENDING','APPROVED','REJECTED')), reason TEXT, requested_at TEXT NOT NULL, decided_at TEXT)`,
		`CREATE INDEX idx_tool_calls_state_updated ON tool_calls(state, updated_at)`,
		`CREATE INDEX idx_approvals_status_requested ON approvals(status, requested_at)`,
	}},
}

// Migrate records schema versions in a single metadata table. Migration 1 is
// an infrastructure bootstrap only; the v1.0 business tables are deliberately
// deferred until their owning modules are implemented.
func (s *Store) Migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			applied_at TEXT NOT NULL
		)`); err != nil {
		return fmt.Errorf("create schema migrations table: %w", err)
	}

	for _, migration := range migrations {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin migration %d: %w", migration.version, err)
		}

		var applied bool
		if err := tx.QueryRowContext(ctx,
			"SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = ?)",
			migration.version,
		).Scan(&applied); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("check migration %d: %w", migration.version, err)
		}
		if applied {
			if err := tx.Rollback(); err != nil {
				return fmt.Errorf("rollback checked migration %d: %w", migration.version, err)
			}
			continue
		}

		for _, statement := range migration.statements {
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				_ = tx.Rollback()
				return fmt.Errorf("apply migration %d: %w", migration.version, err)
			}
		}
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
			migration.version,
			time.Now().UTC().Format(time.RFC3339Nano),
		); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("record migration %d: %w", migration.version, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %d: %w", migration.version, err)
		}
	}
	return nil
}
