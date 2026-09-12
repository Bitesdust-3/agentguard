// Package tools implements the persisted, controlled demo-tool workflow.
package tools

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bitesdust/agentguard/internal/audit"
	"github.com/bitesdust/agentguard/internal/config"
	"github.com/bitesdust/agentguard/internal/detection"
	"github.com/bitesdust/agentguard/internal/identifier"
	"github.com/bitesdust/agentguard/internal/policy"
)

type State string

const (
	StateReceived  State = "RECEIVED"
	StateEvaluated State = "EVALUATED"
	StatePass      State = "PASS"
	StateBlock     State = "BLOCK"
	StatePending   State = "PENDING_APPROVAL"
	StateApproved  State = "APPROVED"
	StateRejected  State = "REJECTED"
	StateExecuted  State = "EXECUTED"
	StateFailed    State = "FAILED"
)

type ApprovalStatus string

const (
	ApprovalPending  ApprovalStatus = "PENDING"
	ApprovalApproved ApprovalStatus = "APPROVED"
	ApprovalRejected ApprovalStatus = "REJECTED"
)

type Call struct {
	ID               string        `json:"id"`
	ToolName         string        `json:"tool_name"`
	TargetType       string        `json:"target_type"`
	External         bool          `json:"external"`
	Destructive      bool          `json:"destructive"`
	Sensitive        bool          `json:"sensitive"`
	Decision         policy.Action `json:"decision"`
	State            State         `json:"state"`
	PolicyID         string        `json:"policy_id"`
	ArgumentsSummary string        `json:"arguments_summary"`
	ResultSummary    string        `json:"result_summary,omitempty"`
	CreatedAt        time.Time     `json:"created_at"`
	UpdatedAt        time.Time     `json:"updated_at"`
}
type Approval struct {
	ID          string         `json:"id"`
	ToolCallID  string         `json:"tool_call_id"`
	Status      ApprovalStatus `json:"status"`
	Reason      string         `json:"reason,omitempty"`
	RequestedAt time.Time      `json:"requested_at"`
	DecidedAt   *time.Time     `json:"decided_at,omitempty"`
}
type Request struct {
	ToolName    string          `json:"tool_name"`
	Arguments   json.RawMessage `json:"arguments"`
	TargetType  string          `json:"target_type"`
	External    bool            `json:"external"`
	Destructive bool            `json:"destructive"`
	Sensitive   bool            `json:"sensitive"`
}
type Service struct {
	db       *sql.DB
	cfg      config.ToolsConfig
	audit    audit.TransactionalRecorder
	executor Executor
	mu       sync.Mutex
}

// Executor invokes one controlled demo tool after the service has persisted
// its authorization and execution claim.
type Executor interface {
	Execute(context.Context, Call) error
}

type mockExecutor struct{}

func NewService(db *sql.DB, cfg config.ToolsConfig, auditRecorder audit.TransactionalRecorder) *Service {
	return newService(db, cfg, auditRecorder, mockExecutor{})
}

func newService(db *sql.DB, cfg config.ToolsConfig, auditRecorder audit.TransactionalRecorder, executor Executor) *Service {
	return &Service{db: db, cfg: cfg, audit: auditRecorder, executor: executor}
}

func next(prefix string) string { return identifier.New(prefix) }

func (s *Service) Submit(ctx context.Context, request Request) (Call, *Approval, error) {
	if !safeLabel(request.ToolName) || !safeLabel(request.TargetType) {
		return Call{}, nil, ErrInvalidRequest
	}
	action, policyID := EvaluatePolicy(s.cfg, request)
	now := time.Now().UTC()
	call := Call{ID: next("tool"), ToolName: request.ToolName, TargetType: request.TargetType, External: request.External, Destructive: request.Destructive, Sensitive: request.Sensitive, Decision: action, PolicyID: policyID, ArgumentsSummary: summarizeArguments(request.Arguments), CreatedAt: now, UpdatedAt: now}
	switch action {
	case policy.ActionPass:
		call.State = StatePass
	case policy.ActionApproval:
		call.State = StatePending
	default:
		call.State = StateBlock
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Call{}, nil, err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO tool_calls(id,tool_name,target_type,external,destructive,sensitive,decision,state,policy_id,arguments_summary,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, call.ID, call.ToolName, call.TargetType, call.External, call.Destructive, call.Sensitive, call.Decision, call.State, call.PolicyID, call.ArgumentsSummary, stamp(now), stamp(now))
	if err != nil {
		return Call{}, nil, err
	}
	if err := s.recordEvent(ctx, tx, audit.Event{
		EventType: audit.EventToolCallCreated, Actor: audit.ActorTool, Source: string(policy.StageTool),
		ToolCallID: call.ID, Summary: safeToolSummary(call),
	}); err != nil {
		return Call{}, nil, err
	}
	decision := toolPolicyDecision(call, now)
	if s.audit == nil {
		return Call{}, nil, ErrAuditPersistence
	}
	if err := s.audit.DecisionWith(ctx, tx, decision); err != nil {
		return Call{}, nil, auditError(err)
	}
	score := decision.RiskScore
	if err := s.recordEvent(ctx, tx, audit.Event{
		EventType: audit.EventToolPolicy, Actor: audit.ActorTool, Source: string(policy.StageTool),
		ToolCallID: call.ID, Decision: string(call.Decision), RiskScore: &score,
		Summary: "tool policy decision recorded",
	}); err != nil {
		return Call{}, nil, err
	}
	var approval *Approval
	if action == policy.ActionApproval {
		a := Approval{ID: next("approval"), ToolCallID: call.ID, Status: ApprovalPending, RequestedAt: now}
		_, err = tx.ExecContext(ctx, `INSERT INTO approvals(id,tool_call_id,status,requested_at) VALUES(?,?,?,?)`, a.ID, a.ToolCallID, a.Status, stamp(now))
		if err != nil {
			return Call{}, nil, err
		}
		if err := s.recordEvent(ctx, tx, audit.Event{
			EventType: audit.EventApprovalRequested, Actor: audit.ActorTool, Source: string(policy.StageTool),
			ToolCallID: call.ID, ApprovalID: a.ID, Decision: string(policy.ActionApproval),
			Summary: "tool approval requested",
		}); err != nil {
			return Call{}, nil, err
		}
		approval = &a
	}
	if action == policy.ActionBlock {
		if err := s.recordEvent(ctx, tx, audit.Event{
			EventType: audit.EventToolBlocked, Actor: audit.ActorTool, Source: string(policy.StageTool),
			ToolCallID: call.ID, Decision: string(policy.ActionBlock), Summary: "tool call blocked by policy",
		}); err != nil {
			return Call{}, nil, err
		}
	}
	if err = tx.Commit(); err != nil {
		return Call{}, nil, err
	}
	if action == policy.ActionPass {
		call, err = s.execute(ctx, call.ID)
		return call, nil, err
	}
	return call, approval, nil
}

func (s *Service) recordEvent(ctx context.Context, executor audit.SQLExecutor, event audit.Event) error {
	if s.audit == nil {
		return ErrAuditPersistence
	}
	if err := s.audit.EventWith(ctx, executor, event); err != nil {
		return auditError(err)
	}
	return nil
}

func toolPolicyDecision(call Call, createdAt time.Time) policy.Decision {
	return policy.Decision{
		ID:               next("policy_tool"),
		SubjectType:      detection.SubjectTypeToolCall,
		SubjectID:        call.ID,
		Stage:            policy.StageTool,
		Decision:         call.Decision,
		PolicyID:         call.PolicyID,
		Reason:           "tool attributes matched configured policy",
		RiskScore:        toolRiskScore(call),
		MatchedRules:     []string{call.PolicyID},
		ApprovalRequired: call.Decision == policy.ActionApproval,
		CreatedAt:        createdAt,
	}
}

func toolRiskScore(call Call) float64 {
	switch {
	case call.Destructive:
		return 1
	case call.Sensitive:
		return 0.8
	case call.External:
		return 0.6
	default:
		return 0
	}
}

func safeToolSummary(call Call) string {
	return fmt.Sprintf("tool=%s; target_type=%s; external=%t; destructive=%t; sensitive=%t", call.ToolName, call.TargetType, call.External, call.Destructive, call.Sensitive)
}

func summarizeArguments(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return "argument_count=0"
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err == nil {
		keys := make([]string, 0, len(object))
		for key := range object {
			if safeLabel(key) {
				keys = append(keys, key)
			}
		}
		sort.Strings(keys)
		return fmt.Sprintf("argument_count=%d; fields=%s", len(object), strings.Join(keys, ","))
	}
	return "arguments_present=true; values_not_retained"
}

func safeLabel(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '.' || char == '_' || char == '-' {
			continue
		}
		return false
	}
	return true
}

// EvaluatePolicy applies the production Tool Policy without creating a Tool
// Call or invoking an Executor. It is used by the deterministic Benchmark.
func EvaluatePolicy(cfg config.ToolsConfig, request Request) (policy.Action, string) {
	for _, rule := range cfg.Rules {
		if match(rule.Match, request) {
			return policy.Action(rule.Action), rule.ID
		}
	}
	if !known(request.ToolName) {
		return policy.ActionBlock, "tools.unknown.block.v1"
	}
	return policy.Action(cfg.DefaultAction), "tools.default.v1"
}
func match(m config.ToolRuleMatch, r Request) bool {
	return m.Name == r.ToolName && (m.TargetType == "" || m.TargetType == r.TargetType) && (m.External == nil || *m.External == r.External) && (m.Destructive == nil || *m.Destructive == r.Destructive) && (m.Sensitive == nil || *m.Sensitive == r.Sensitive)
}
func known(name string) bool {
	for _, v := range []string{"weather.read", "file.read", "email.send", "database.query", "file.delete"} {
		if name == v {
			return true
		}
	}
	return false
}

func (s *Service) Get(ctx context.Context, id string) (Call, *Approval, error) {
	c, err := scanCall(s.db.QueryRowContext(ctx, `SELECT id,tool_name,target_type,external,destructive,sensitive,decision,state,policy_id,arguments_summary,COALESCE(result_summary,''),created_at,updated_at FROM tool_calls WHERE id=?`, id))
	if err != nil {
		return Call{}, nil, err
	}
	a, err := scanApproval(s.db.QueryRowContext(ctx, `SELECT id,tool_call_id,status,COALESCE(reason,''),requested_at,decided_at FROM approvals WHERE tool_call_id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return c, nil, nil
	}
	return c, &a, err
}
func (s *Service) Pending(ctx context.Context) ([]Approval, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,tool_call_id,status,COALESCE(reason,''),requested_at,decided_at FROM approvals WHERE status='PENDING' ORDER BY requested_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Approval
	for rows.Next() {
		a, err := scanApproval(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
func (s *Service) Decide(ctx context.Context, id string, approve bool, reason string) (Call, Approval, error) {
	s.mu.Lock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		s.mu.Unlock()
		return Call{}, Approval{}, err
	}
	a, err := scanApproval(tx.QueryRowContext(ctx, `SELECT id,tool_call_id,status,COALESCE(reason,''),requested_at,decided_at FROM approvals WHERE id=?`, id))
	if err != nil {
		_ = tx.Rollback()
		s.mu.Unlock()
		return Call{}, Approval{}, err
	}
	if a.Status != ApprovalPending {
		_ = tx.Rollback()
		s.mu.Unlock()
		return Call{}, Approval{}, ErrConflict
	}
	now := time.Now().UTC()
	if approve {
		a.Status = ApprovalApproved
	} else {
		a.Status = ApprovalRejected
	}
	a.Reason = safeApprovalReason(reason)
	a.DecidedAt = &now
	_, err = tx.ExecContext(ctx, `UPDATE approvals SET status=?,reason=?,decided_at=? WHERE id=? AND status='PENDING'`, a.Status, a.Reason, stamp(now), a.ID)
	if err != nil {
		_ = tx.Rollback()
		s.mu.Unlock()
		return Call{}, Approval{}, err
	}
	state := StateRejected
	if approve {
		state = StateApproved
	}
	res, err := tx.ExecContext(ctx, `UPDATE tool_calls SET state=?,updated_at=? WHERE id=? AND state='PENDING_APPROVAL'`, state, stamp(now), a.ToolCallID)
	if err != nil {
		_ = tx.Rollback()
		s.mu.Unlock()
		return Call{}, Approval{}, err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		_ = tx.Rollback()
		s.mu.Unlock()
		return Call{}, Approval{}, ErrConflict
	}
	eventType := audit.EventApprovalRejected
	if approve {
		eventType = audit.EventApprovalApproved
	}
	if err := s.recordEvent(ctx, tx, audit.Event{
		EventType: eventType, Actor: audit.ActorTool, Source: string(policy.StageTool),
		ToolCallID: a.ToolCallID, ApprovalID: a.ID, Summary: "tool approval decision recorded",
	}); err != nil {
		_ = tx.Rollback()
		s.mu.Unlock()
		return Call{}, Approval{}, err
	}
	if err = tx.Commit(); err != nil {
		s.mu.Unlock()
		return Call{}, Approval{}, err
	}
	s.mu.Unlock()
	c, _, err := s.Get(ctx, a.ToolCallID)
	if err != nil {
		return Call{}, Approval{}, err
	}
	if approve {
		c, err = s.execute(ctx, c.ID)
	}
	return c, a, err
}
func (s *Service) execute(ctx context.Context, id string) (Call, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Call{}, err
	}
	defer tx.Rollback()
	c, err := scanCall(tx.QueryRowContext(ctx, `SELECT id,tool_name,target_type,external,destructive,sensitive,decision,state,policy_id,arguments_summary,COALESCE(result_summary,''),created_at,updated_at FROM tool_calls WHERE id=?`, id))
	if err != nil {
		return Call{}, err
	}
	if c.State != StatePass && c.State != StateApproved {
		return Call{}, ErrNotExecutable
	}
	executionKey := next("execution")
	claim, err := tx.ExecContext(ctx, `UPDATE tool_calls SET execution_key=? WHERE id=? AND state IN ('PASS','APPROVED') AND execution_key IS NULL`, executionKey, id)
	if err != nil {
		return Call{}, err
	}
	claimed, err := claim.RowsAffected()
	if err != nil {
		return Call{}, err
	}
	if claimed != 1 {
		return Call{}, ErrNotExecutable
	}
	if err := s.recordEvent(ctx, tx, audit.Event{
		EventType: audit.EventToolExecutionStarted, Actor: audit.ActorTool, Source: string(policy.StageTool),
		ToolCallID: id, Decision: string(c.Decision), Summary: "tool execution authorized",
	}); err != nil {
		return Call{}, err
	}
	if err := tx.Commit(); err != nil {
		return Call{}, err
	}

	executionErr := s.executor.Execute(ctx, c)
	now := time.Now().UTC()
	state := StateExecuted
	eventType := audit.EventToolExecuted
	resultSummary := "mock tool execution completed"
	if executionErr != nil {
		state = StateFailed
		eventType = audit.EventToolFailed
		resultSummary = "mock tool execution failed"
	}
	finalTx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Call{}, err
	}
	defer finalTx.Rollback()
	result, err := finalTx.ExecContext(ctx, `UPDATE tool_calls SET state=?,result_summary=?,updated_at=? WHERE id=? AND execution_key=? AND state IN ('PASS','APPROVED')`, state, resultSummary, stamp(now), id, executionKey)
	if err != nil {
		return Call{}, err
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return Call{}, err
	}
	if updated != 1 {
		return Call{}, ErrConflict
	}
	if err := s.recordEvent(ctx, finalTx, audit.Event{
		EventType: eventType, Actor: audit.ActorTool, Source: string(policy.StageTool),
		ToolCallID: id, Decision: string(c.Decision), Summary: resultSummary,
	}); err != nil {
		return Call{}, err
	}
	if err := finalTx.Commit(); err != nil {
		return Call{}, err
	}
	c, _, err = s.Get(ctx, id)
	if err != nil {
		return Call{}, err
	}
	if executionErr != nil {
		return c, executionErr
	}
	return c, nil
}

func (mockExecutor) Execute(_ context.Context, c Call) error {
	switch c.ToolName {
	case "weather.read", "file.read", "email.send", "database.query":
		return nil
	default:
		return fmt.Errorf("mock executor has no action for tool")
	}
}

func safeApprovalReason(reason string) string {
	if strings.TrimSpace(reason) == "" {
		return ""
	}
	return "approval reason provided but not retained"
}

var (
	ErrInvalidRequest   = errors.New("invalid tool request")
	ErrConflict         = errors.New("tool state conflict")
	ErrNotExecutable    = errors.New("tool is not executable")
	ErrAuditPersistence = errors.New("required audit persistence failed")
)

func auditError(err error) error {
	return fmt.Errorf("%w: %v", ErrAuditPersistence, err)
}

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

type scanner interface{ Scan(...any) error }

func scanCall(s scanner) (Call, error) {
	var c Call
	var created, updated string
	err := s.Scan(&c.ID, &c.ToolName, &c.TargetType, &c.External, &c.Destructive, &c.Sensitive, &c.Decision, &c.State, &c.PolicyID, &c.ArgumentsSummary, &c.ResultSummary, &created, &updated)
	if err != nil {
		return c, err
	}
	c.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	c.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	return c, nil
}
func scanApproval(s scanner) (Approval, error) {
	var a Approval
	var requested string
	var decided sql.NullString
	err := s.Scan(&a.ID, &a.ToolCallID, &a.Status, &a.Reason, &requested, &decided)
	if err != nil {
		return a, err
	}
	a.RequestedAt, _ = time.Parse(time.RFC3339Nano, requested)
	if decided.Valid {
		v, _ := time.Parse(time.RFC3339Nano, decided.String)
		a.DecidedAt = &v
	}
	return a, nil
}

// Handler implements only the frozen local-admin tool routes.
type Handler struct{ service *Service }

func NewHandler(service *Service) *Handler { return &Handler{service} }
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	switch {
	case p == "/api/tool-calls" && r.Method == http.MethodPost:
		h.submit(w, r)
	case strings.HasPrefix(p, "/api/tool-calls/") && r.Method == http.MethodGet:
		h.get(w, r, strings.TrimPrefix(p, "/api/tool-calls/"))
	case p == "/api/approvals" && r.Method == http.MethodGet:
		h.pending(w, r)
	case strings.HasPrefix(p, "/api/approvals/") && strings.HasSuffix(p, "/approve") && r.Method == http.MethodPost:
		h.decide(w, r, strings.TrimSuffix(strings.TrimPrefix(p, "/api/approvals/"), "/approve"), true)
	case strings.HasPrefix(p, "/api/approvals/") && strings.HasSuffix(p, "/reject") && r.Method == http.MethodPost:
		h.decide(w, r, strings.TrimSuffix(strings.TrimPrefix(p, "/api/approvals/"), "/reject"), false)
	default:
		http.NotFound(w, r)
	}
}
func decode(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	var extra any
	return d.Decode(&extra)
}
func (h *Handler) submit(w http.ResponseWriter, r *http.Request) {
	var v Request
	if err := decode(w, r, &v); err != ioEOF {
		returnError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	c, a, err := h.service.Submit(r.Context(), v)
	if err != nil {
		status := http.StatusBadRequest
		code := "tool_rejected"
		if errors.Is(err, ErrAuditPersistence) {
			status = http.StatusInternalServerError
			code = "audit_persistence_failed"
		}
		returnError(w, status, code)
		return
	}
	write(w, http.StatusCreated, struct {
		Call     Call      `json:"tool_call"`
		Approval *Approval `json:"approval,omitempty"`
	}{c, a})
}

var ioEOF = io.EOF

func (h *Handler) get(w http.ResponseWriter, r *http.Request, id string) {
	c, a, err := h.service.Get(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		code := "internal_error"
		if errors.Is(err, ErrAuditPersistence) {
			code = "audit_persistence_failed"
		}
		returnError(w, 500, code)
		return
	}
	write(w, 200, struct {
		Call     Call      `json:"tool_call"`
		Approval *Approval `json:"approval,omitempty"`
	}{c, a})
}
func (h *Handler) pending(w http.ResponseWriter, r *http.Request) {
	a, err := h.service.Pending(r.Context())
	if err != nil {
		code := "internal_error"
		if errors.Is(err, ErrAuditPersistence) {
			code = "audit_persistence_failed"
		}
		returnError(w, 500, code)
		return
	}
	write(w, 200, struct {
		Items []Approval `json:"items"`
	}{a})
}
func (h *Handler) decide(w http.ResponseWriter, r *http.Request, id string, approve bool) {
	var v struct {
		Reason string `json:"reason"`
	}
	if err := decode(w, r, &v); err != ioEOF {
		returnError(w, 400, "invalid_request")
		return
	}
	c, a, err := h.service.Decide(r.Context(), id, approve, v.Reason)
	if errors.Is(err, ErrConflict) {
		returnError(w, 409, "approval_conflict")
		return
	}
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		code := "internal_error"
		if errors.Is(err, ErrAuditPersistence) {
			code = "audit_persistence_failed"
		}
		returnError(w, 500, code)
		return
	}
	write(w, 200, struct {
		Call     Call     `json:"tool_call"`
		Approval Approval `json:"approval"`
	}{c, a})
}
func write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func returnError(w http.ResponseWriter, status int, code string) {
	write(w, status, map[string]any{"error": map[string]string{"code": code, "message": "tool request could not be completed"}})
}
