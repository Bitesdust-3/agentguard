package storage

import (
	"context"
	"path/filepath"
	"testing"
)

func TestAuditSchemaIntegrityAndMigrationOrder(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, filepath.Join(t.TempDir(), "audit-integrity.db"))
	if err != nil {
		t.Fatalf("Open() error: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	var foreignKeys int
	if err := store.DB().QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
		t.Fatal(err)
	}
	if foreignKeys != 1 {
		t.Fatalf("foreign_keys = %d, want 1", foreignKeys)
	}

	var foreignKeyCheck string
	if err := store.DB().QueryRowContext(ctx, "PRAGMA foreign_key_check").Scan(&foreignKeyCheck); err == nil {
		t.Fatalf("foreign_key_check unexpectedly reported %q", foreignKeyCheck)
	}
	var integrity string
	if err := store.DB().QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&integrity); err != nil {
		t.Fatal(err)
	}
	if integrity != "ok" {
		t.Fatalf("integrity_check = %q, want ok", integrity)
	}

	rows, err := store.DB().QueryContext(ctx, "SELECT version FROM schema_migrations ORDER BY version")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var versions []int
	for rows.Next() {
		var version int
		if err := rows.Scan(&version); err != nil {
			t.Fatal(err)
		}
		versions = append(versions, version)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(versions) != 3 || versions[0] != 1 || versions[1] != 2 || versions[2] != 3 {
		t.Fatalf("migration versions = %v, want [1 2 3]", versions)
	}
	for _, table := range []string{"requests", "detections", "policy_decisions", "audit_events"} {
		var count int
		if err := store.DB().QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("table %s count = %d, want 1", table, count)
		}
	}
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("second Migrate() error: %v", err)
	}
}
