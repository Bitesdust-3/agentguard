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
