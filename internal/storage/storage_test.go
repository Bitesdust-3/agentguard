package storage

import (
	"context"
	"path/filepath"
	"testing"
)

func TestOpenInitializesSQLite(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := Open(ctx, filepath.Join(t.TempDir(), "agentguard.db"))
	if err != nil {
		t.Fatalf("Open() error: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("Close() error: %v", err)
		}
	})

	var foreignKeys int
	if err := store.DB().QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
		t.Fatalf("query foreign_keys: %v", err)
	}
	if foreignKeys != 1 {
		t.Fatalf("foreign_keys = %d, want 1", foreignKeys)
	}

	var migrations int
	if err := store.DB().QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_migrations").Scan(&migrations); err != nil {
		t.Fatalf("query schema migrations: %v", err)
	}
	if migrations != 4 {
		t.Fatalf("schema migrations = %d, want 4", migrations)
	}
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("second Migrate() error: %v", err)
	}
	if err := store.DB().QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_migrations").Scan(&migrations); err != nil {
		t.Fatalf("query schema migrations after second run: %v", err)
	}
	if migrations != 4 {
		t.Fatalf("schema migrations after second run = %d, want 4", migrations)
	}
}
