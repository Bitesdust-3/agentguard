// Package audit persists privacy-minimized security facts. It never decides outcomes.
package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/bitesdust/agentguard/internal/detection"
	"github.com/bitesdust/agentguard/internal/identifier"
	"github.com/bitesdust/agentguard/internal/policy"
)

const (
	EventChatRequest          = "CHAT_REQUEST"
	EventInputDetection       = "INPUT_DETECTION"
	EventInputPolicy          = "INPUT_POLICY"
	EventProviderDone         = "PROVIDER_COMPLETED"
	EventProviderFailed       = "PROVIDER_FAILED"
	EventOutputDetection      = "OUTPUT_DETECTION"
	EventOutputPolicy         = "OUTPUT_POLICY"
	EventChatCompleted        = "CHAT_COMPLETED"
	EventChatBlocked          = "CHAT_BLOCKED"
	EventToolCallCreated      = "TOOL_CALL_CREATED"
	EventToolPolicy           = "TOOL_POLICY"
	EventApprovalRequested    = "APPROVAL_REQUESTED"
	EventApprovalApproved     = "APPROVAL_APPROVED"
	EventApprovalRejected     = "APPROVAL_REJECTED"
	EventToolExecutionStarted = "TOOL_EXECUTION_STARTED"
	EventToolExecuted         = "TOOL_EXECUTED"
	EventToolFailed           = "TOOL_FAILED"
	EventToolBlocked          = "TOOL_BLOCKED"

	ActorGateway = "GATEWAY"
	ActorTool    = "TOOL_SERVICE"
)

// Request is the privacy-minimized lifecycle record for one gateway attempt.
type Request struct {
	ID                 string        `json:"id"`
	Model              string        `json:"model"`
	RequestFingerprint string        `json:"request_fingerprint"`
	InputSummary       string        `json:"input_summary"`
	OutputSummary      string        `json:"output_summary,omitempty"`
	Status             string        `json:"status"`
	FinalDecision      policy.Action `json:"final_decision,omitempty"`
	DetectionCount     int           `json:"detection_count"`
	LatencyMS          int64         `json:"latency_ms,omitempty"`
	CreatedAt          time.Time     `json:"created_at"`
	CompletedAt        *time.Time    `json:"completed_at,omitempty"`
}

// RequestCompletion contains only safe terminal metadata.
type RequestCompletion struct {
	Status         string
	FinalDecision  policy.Action
	DetectionCount int
	OutputSummary  string
	LatencyMS      int64
}

// Event is the public, privacy-minimized AuditEvent wire model.
type Event struct {
	ID            string    `json:"id"`
	EventType     string    `json:"event_type"`
	Actor         string    `json:"actor"`
	Source        string    `json:"source"`
	RequestID     string    `json:"request_id,omitempty"`
	ToolCallID    string    `json:"tool_call_id,omitempty"`
	ApprovalID    string    `json:"approval_id,omitempty"`
	DetectionType string    `json:"detection_type,omitempty"`
	RuleID        string    `json:"rule_id,omitempty"`
	Decision      string    `json:"decision,omitempty"`
	RiskScore     *float64  `json:"risk_score,omitempty"`
	Summary       string    `json:"summary"`
	CreatedAt     time.Time `json:"created_at"`
}

// Recorder is the append boundary used by request pipelines.
type Recorder interface {
	StartRequest(context.Context, Request) error
	Detection(context.Context, detection.DetectionResult) error
	Decision(context.Context, policy.Decision) error
	Event(context.Context, Event) error
	CompleteRequest(context.Context, string, RequestCompletion) error
}

// SQLExecutor is implemented by both *sql.DB and *sql.Tx.
type SQLExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

// TransactionalRecorder lets stateful workflows append audit facts in the
// same SQLite transaction as their authoritative state transition.
type TransactionalRecorder interface {
	DecisionWith(context.Context, SQLExecutor, policy.Decision) error
	EventWith(context.Context, SQLExecutor, Event) error
}

type Filter struct {
	EventType     string
	Decision      string
	DetectionType string
	RequestID     string
	ToolCallID    string
	Limit         int
}

type Store struct{ db *sql.DB }

func New(db *sql.DB) *Store { return &Store{db: db} }

func nextID() string { return identifier.New("audit") }

func timestamp(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }

func (s *Store) StartRequest(ctx context.Context, request Request) error {
	if request.CreatedAt.IsZero() {
		request.CreatedAt = time.Now().UTC()
	}
	if request.Status == "" {
		request.Status = "PROCESSING"
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO requests(
			id, model, request_fingerprint, input_summary, status,
			final_decision, detection_count, created_at
		) VALUES(?, ?, ?, ?, ?, NULL, 0, ?)`,
		request.ID, request.Model, request.RequestFingerprint, request.InputSummary,
		request.Status, timestamp(request.CreatedAt),
	)
	return err
}

func (s *Store) Detection(ctx context.Context, result detection.DetectionResult) error {
	metadata, err := json.Marshal(result.Metadata)
	if err != nil {
		return fmt.Errorf("encode detection metadata: %w", err)
	}
	var requestID, toolCallID any
	switch result.SubjectType {
	case detection.SubjectTypeRequest:
		requestID = result.SubjectID
	case detection.SubjectTypeToolCall:
		toolCallID = result.SubjectID
	default:
		return fmt.Errorf("unsupported detection subject type %q", result.SubjectType)
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO detections(
			id, subject_type, request_id, tool_call_id, detection_type, rule_id,
			score, confidence, evidence, source, metadata, created_at
		) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		result.ID, result.SubjectType, requestID, toolCallID, result.DetectionType,
		result.RuleID, result.Score, result.Confidence, result.Evidence, result.Source,
		string(metadata), timestamp(result.CreatedAt),
	)
	return err
}

func (s *Store) Decision(ctx context.Context, decision policy.Decision) error {
	return s.DecisionWith(ctx, s.db, decision)
}

func (s *Store) DecisionWith(ctx context.Context, executor SQLExecutor, decision policy.Decision) error {
	matchedRules, err := json.Marshal(decision.MatchedRules)
	if err != nil {
		return fmt.Errorf("encode matched rules: %w", err)
	}
	redactions, err := json.Marshal(decision.Redactions)
	if err != nil {
		return fmt.Errorf("encode redactions: %w", err)
	}
	var requestID, toolCallID any
	switch decision.SubjectType {
	case detection.SubjectTypeRequest:
		requestID = decision.SubjectID
	case detection.SubjectTypeToolCall:
		toolCallID = decision.SubjectID
	default:
		return fmt.Errorf("unsupported policy subject type %q", decision.SubjectType)
	}
	_, err = executor.ExecContext(ctx, `
		INSERT INTO policy_decisions(
			id, subject_type, request_id, tool_call_id, stage, decision, policy_id,
			risk_score, matched_rules, redactions, reason, approval_required, created_at
		) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		decision.ID, decision.SubjectType, requestID, toolCallID, decision.Stage,
		decision.Decision, decision.PolicyID, decision.RiskScore, string(matchedRules),
		string(redactions), decision.Reason, decision.ApprovalRequired,
		timestamp(decision.CreatedAt),
	)
	return err
}

func (s *Store) Event(ctx context.Context, event Event) error {
	return s.EventWith(ctx, s.db, event)
}

func (s *Store) EventWith(ctx context.Context, executor SQLExecutor, event Event) error {
	if event.ID == "" {
		event.ID = nextID()
	}
	if event.Actor == "" {
		event.Actor = ActorGateway
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}
	_, err := executor.ExecContext(ctx, `
		INSERT INTO audit_events(
			id, event_type, actor, source, request_id, tool_call_id, approval_id, detection_type,
			rule_id, decision, risk_score, summary, created_at
		) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		event.ID, event.EventType, event.Actor, event.Source, nullString(event.RequestID),
		nullString(event.ToolCallID), nullString(event.ApprovalID), nullString(event.DetectionType), nullString(event.RuleID),
		nullString(event.Decision), event.RiskScore, event.Summary, timestamp(event.CreatedAt),
	)
	return err
}

func (s *Store) CompleteRequest(ctx context.Context, requestID string, completion RequestCompletion) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE requests SET
			status = ?, final_decision = ?, detection_count = ?, output_summary = ?,
			latency_ms = ?, completed_at = ?
		WHERE id = ?`,
		completion.Status, nullString(string(completion.FinalDecision)), completion.DetectionCount,
		nullString(completion.OutputSummary), completion.LatencyMS,
		timestamp(time.Now().UTC()), requestID,
	)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return fmt.Errorf("request %q was not found", requestID)
	}
	return nil
}

func nullString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func (s *Store) List(ctx context.Context, filter Filter) ([]Event, error) {
	if filter.Limit <= 0 {
		filter.Limit = 50
	}
	if filter.Limit > 100 {
		return nil, fmt.Errorf("invalid limit")
	}
	query := `SELECT id, event_type, actor, source, COALESCE(request_id, ''),
		COALESCE(tool_call_id, ''), COALESCE(approval_id, ''), COALESCE(detection_type, ''), COALESCE(rule_id, ''),
		COALESCE(decision, ''), risk_score, summary, created_at
		FROM audit_events WHERE 1=1`
	args := []any{}
	for _, value := range []struct {
		column string
		value  string
	}{
		{"event_type", filter.EventType},
		{"decision", filter.Decision},
		{"detection_type", filter.DetectionType},
		{"request_id", filter.RequestID},
		{"tool_call_id", filter.ToolCallID},
	} {
		if value.value != "" {
			query += " AND " + value.column + " = ?"
			args = append(args, value.value)
		}
	}
	query += " ORDER BY created_at DESC, rowid DESC LIMIT ?"
	args = append(args, filter.Limit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	events := make([]Event, 0)
	for rows.Next() {
		var createdAt string
		var score sql.NullFloat64
		var event Event
		if err := rows.Scan(
			&event.ID, &event.EventType, &event.Actor, &event.Source, &event.RequestID,
			&event.ToolCallID, &event.ApprovalID, &event.DetectionType, &event.RuleID, &event.Decision,
			&score, &event.Summary, &createdAt,
		); err != nil {
			return nil, err
		}
		if score.Valid {
			event.RiskScore = &score.Float64
		}
		event.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
		if err != nil {
			return nil, fmt.Errorf("parse audit event timestamp: %w", err)
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

var _ Recorder = (*Store)(nil)
var _ TransactionalRecorder = (*Store)(nil)
