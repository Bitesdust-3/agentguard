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
	{version: 3, statements: []string{
		`CREATE TABLE requests (id TEXT PRIMARY KEY, model TEXT NOT NULL, request_fingerprint TEXT NOT NULL, input_summary TEXT NOT NULL, output_summary TEXT, status TEXT NOT NULL CHECK(status IN ('PROCESSING','COMPLETED','BLOCKED','FAILED')), final_decision TEXT CHECK(final_decision IN ('PASS','REDACT','BLOCK')), detection_count INTEGER NOT NULL DEFAULT 0, latency_ms INTEGER, created_at TEXT NOT NULL, completed_at TEXT)`,
		`CREATE TABLE detections (id TEXT PRIMARY KEY, subject_type TEXT NOT NULL CHECK(subject_type IN ('REQUEST','TOOL_CALL')), request_id TEXT REFERENCES requests(id), tool_call_id TEXT REFERENCES tool_calls(id), detection_type TEXT NOT NULL CHECK(detection_type IN ('PII','SECRET','PROMPT_INJECTION')), rule_id TEXT NOT NULL, score REAL NOT NULL CHECK(score >= 0 AND score <= 1), confidence REAL NOT NULL CHECK(confidence >= 0 AND confidence <= 1), evidence TEXT NOT NULL, source TEXT NOT NULL CHECK(source IN ('INPUT','OUTPUT','TOOL_ARGUMENT')), metadata TEXT NOT NULL, created_at TEXT NOT NULL, CHECK((request_id IS NOT NULL) != (tool_call_id IS NOT NULL)))`,
		`CREATE TABLE policy_decisions (id TEXT PRIMARY KEY, subject_type TEXT NOT NULL CHECK(subject_type IN ('REQUEST','TOOL_CALL')), request_id TEXT REFERENCES requests(id), tool_call_id TEXT REFERENCES tool_calls(id), stage TEXT NOT NULL CHECK(stage IN ('INPUT','OUTPUT','TOOL')), decision TEXT NOT NULL CHECK(decision IN ('PASS','REDACT','BLOCK','APPROVAL')), policy_id TEXT NOT NULL, risk_score REAL NOT NULL CHECK(risk_score >= 0 AND risk_score <= 1), matched_rules TEXT NOT NULL, redactions TEXT NOT NULL, reason TEXT NOT NULL, approval_required INTEGER NOT NULL, created_at TEXT NOT NULL, CHECK((request_id IS NOT NULL) != (tool_call_id IS NOT NULL)))`,
		`CREATE TABLE audit_events (id TEXT PRIMARY KEY, event_type TEXT NOT NULL, actor TEXT NOT NULL, source TEXT NOT NULL, request_id TEXT REFERENCES requests(id), tool_call_id TEXT REFERENCES tool_calls(id), approval_id TEXT REFERENCES approvals(id), detection_type TEXT, rule_id TEXT, decision TEXT, risk_score REAL, summary TEXT NOT NULL, created_at TEXT NOT NULL)`,
		`ALTER TABLE tool_calls ADD COLUMN execution_key TEXT`,
		`CREATE UNIQUE INDEX idx_tool_calls_execution_key ON tool_calls(execution_key)`,
		`CREATE INDEX idx_audit_events_request_created ON audit_events(request_id, created_at)`,
		`CREATE INDEX idx_audit_events_tool_created ON audit_events(tool_call_id, created_at)`,
		`CREATE INDEX idx_audit_events_type_created ON audit_events(event_type, created_at)`,
		`CREATE INDEX idx_detections_request_created ON detections(request_id, created_at)`,
		`CREATE INDEX idx_detections_tool_created ON detections(tool_call_id, created_at)`,
		`CREATE INDEX idx_detections_type_rule ON detections(detection_type, rule_id)`,
		`CREATE INDEX idx_policy_decisions_request_stage_created ON policy_decisions(request_id, stage, created_at)`,
		`CREATE INDEX idx_policy_decisions_tool_created ON policy_decisions(tool_call_id, created_at)`,
		`CREATE INDEX idx_policy_decisions_decision_created ON policy_decisions(decision, created_at)`,
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
