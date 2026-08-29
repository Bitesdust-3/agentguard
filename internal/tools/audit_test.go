package tools

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/bitesdust/agentguard/internal/audit"
	"github.com/bitesdust/agentguard/internal/config"
	"github.com/bitesdust/agentguard/internal/policy"
	"github.com/bitesdust/agentguard/internal/storage"
)

func TestToolAuditCompletePolicyAndExecutionChains(t *testing.T) {
	tests := []struct {
		name       string
		request    Request
		wantState  State
		wantAction policy.Action
		wantEvents []string
	}{
		{name: "weather pass", request: Request{ToolName: "weather.read", TargetType: "city"}, wantState: StateExecuted, wantAction: policy.ActionPass, wantEvents: []string{audit.EventToolCallCreated, audit.EventToolPolicy, audit.EventToolExecutionStarted, audit.EventToolExecuted}},
		{name: "file read pass", request: Request{ToolName: "file.read", TargetType: "fixture"}, wantState: StateExecuted, wantAction: policy.ActionPass, wantEvents: []string{audit.EventToolCallCreated, audit.EventToolPolicy, audit.EventToolExecutionStarted, audit.EventToolExecuted}},
		{name: "email approval", request: Request{ToolName: "email.send", TargetType: "email", External: true}, wantState: StatePending, wantAction: policy.ActionApproval, wantEvents: []string{audit.EventToolCallCreated, audit.EventToolPolicy, audit.EventApprovalRequested}},
		{name: "database approval", request: Request{ToolName: "database.query", TargetType: "database", Sensitive: true}, wantState: StatePending, wantAction: policy.ActionApproval, wantEvents: []string{audit.EventToolCallCreated, audit.EventToolPolicy, audit.EventApprovalRequested}},
		{name: "file delete block", request: Request{ToolName: "file.delete", TargetType: "fixture", Destructive: true}, wantState: StateBlock, wantAction: policy.ActionBlock, wantEvents: []string{audit.EventToolCallCreated, audit.EventToolPolicy, audit.EventToolBlocked}},
		{name: "unknown block", request: Request{ToolName: "unknown.tool", TargetType: "fixture"}, wantState: StateBlock, wantAction: policy.ActionBlock, wantEvents: []string{audit.EventToolCallCreated, audit.EventToolPolicy, audit.EventToolBlocked}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			db, recorder := openToolAuditStore(t)
			executor := &countingExecutor{}
			service := newService(db, config.Default().Tools, recorder, executor)
			call, approval, err := service.Submit(context.Background(), test.request)
			if err != nil {
				t.Fatalf("Submit() error: %v", err)
			}
			if call.State != test.wantState || call.Decision != test.wantAction {
				t.Fatalf("call = %+v, want state %s action %s", call, test.wantState, test.wantAction)
			}
			if test.wantAction == policy.ActionApproval {
				if approval == nil || approval.ToolCallID != call.ID {
					t.Fatalf("approval = %+v, want tool call %q", approval, call.ID)
				}
				assertApprovalEventID(t, db, call.ID, approval.ID, audit.EventApprovalRequested)
			} else if approval != nil {
				t.Fatalf("unexpected approval: %+v", approval)
			}
			if test.wantState == StateExecuted && executor.calls != 1 {
				t.Fatalf("executor calls = %d, want 1", executor.calls)
			}
			if test.wantState != StateExecuted && executor.calls != 0 {
				t.Fatalf("executor calls = %d, want 0", executor.calls)
			}
			assertEventChain(t, recorder, call.ID, test.wantEvents)
			assertToolPolicyRecord(t, db, call)
		})
	}
}

func TestApprovalAuditApprovedAndRejected(t *testing.T) {
	t.Run("approved executes", func(t *testing.T) {
		db, recorder := openToolAuditStore(t)
		executor := &countingExecutor{}
		service := newService(db, config.Default().Tools, recorder, executor)
		call, approval, err := service.Submit(context.Background(), Request{ToolName: "email.send", TargetType: "email", External: true})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := service.execute(context.Background(), call.ID); !errors.Is(err, ErrNotExecutable) {
			t.Fatalf("pending execute error = %v, want not executable", err)
		}
		call, decided, err := service.Decide(context.Background(), approval.ID, true, "fictional approval")
		if err != nil || call.State != StateExecuted || decided.Status != ApprovalApproved || executor.calls != 1 {
			t.Fatalf("call=%+v approval=%+v calls=%d err=%v", call, decided, executor.calls, err)
		}
		assertEventChain(t, recorder, call.ID, []string{audit.EventToolCallCreated, audit.EventToolPolicy, audit.EventApprovalRequested, audit.EventApprovalApproved, audit.EventToolExecutionStarted, audit.EventToolExecuted})
		assertApprovalEventID(t, db, call.ID, approval.ID, audit.EventApprovalApproved)
		if _, err := service.execute(context.Background(), call.ID); !errors.Is(err, ErrNotExecutable) {
			t.Fatalf("executed retry error = %v, want not executable", err)
		}
		if executor.calls != 1 {
			t.Fatalf("executor retried: calls = %d", executor.calls)
		}
	})

	t.Run("rejected never executes", func(t *testing.T) {
		db, recorder := openToolAuditStore(t)
		executor := &countingExecutor{}
		service := newService(db, config.Default().Tools, recorder, executor)
		call, approval, err := service.Submit(context.Background(), Request{ToolName: "email.send", TargetType: "email", External: true})
		if err != nil {
			t.Fatal(err)
		}
		call, decided, err := service.Decide(context.Background(), approval.ID, false, "fictional rejection")
		if err != nil || call.State != StateRejected || decided.Status != ApprovalRejected || executor.calls != 0 {
			t.Fatalf("call=%+v approval=%+v calls=%d err=%v", call, decided, executor.calls, err)
		}
		assertEventChain(t, recorder, call.ID, []string{audit.EventToolCallCreated, audit.EventToolPolicy, audit.EventApprovalRequested, audit.EventApprovalRejected})
		assertEventAbsent(t, recorder, call.ID, audit.EventToolExecuted)
		assertApprovalEventID(t, db, call.ID, approval.ID, audit.EventApprovalRejected)
		if _, _, err := service.Decide(context.Background(), approval.ID, false, "repeat"); !errors.Is(err, ErrConflict) {
			t.Fatalf("repeated reject error = %v, want conflict", err)
		}
	})
}

func TestToolAuditFailureInjectionFailClosed(t *testing.T) {
	tests := []struct {
		name       string
		request    Request
		failEvent  string
		failPolicy bool
		wantRows   int
	}{
		{name: "tool creation audit", request: Request{ToolName: "weather.read", TargetType: "city"}, failEvent: audit.EventToolCallCreated},
		{name: "tool policy decision audit", request: Request{ToolName: "weather.read", TargetType: "city"}, failPolicy: true},
		{name: "tool policy event audit", request: Request{ToolName: "weather.read", TargetType: "city"}, failEvent: audit.EventToolPolicy},
		{name: "pass execution authorization audit", request: Request{ToolName: "weather.read", TargetType: "city"}, failEvent: audit.EventToolExecutionStarted, wantRows: 1},
		{name: "approval requested audit", request: Request{ToolName: "email.send", TargetType: "email", External: true}, failEvent: audit.EventApprovalRequested},
		{name: "blocked audit", request: Request{ToolName: "file.delete", TargetType: "fixture", Destructive: true}, failEvent: audit.EventToolBlocked},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			db, store := openToolAuditStore(t)
			recorder := &faultToolAudit{store: store, failEvent: test.failEvent, failPolicy: test.failPolicy}
			executor := &countingExecutor{}
			handler := NewHandler(newService(db, config.Default().Tools, recorder, executor))
			response := performToolSubmit(handler, test.request)
			assertToolAuditFailureResponse(t, response)
			if executor.calls != 0 {
				t.Fatalf("executor calls = %d, want 0", executor.calls)
			}
			var rows int
			if err := db.QueryRow(`SELECT COUNT(*) FROM tool_calls`).Scan(&rows); err != nil {
				t.Fatal(err)
			}
			if rows != test.wantRows {
				t.Fatalf("tool rows = %d, want %d", rows, test.wantRows)
			}
		})
	}
}

func TestApprovalAuditFailureInjectionFailClosed(t *testing.T) {
	for _, test := range []struct {
		name      string
		approve   bool
		failEvent string
	}{
		{name: "approved audit", approve: true, failEvent: audit.EventApprovalApproved},
		{name: "rejected audit", approve: false, failEvent: audit.EventApprovalRejected},
	} {
		t.Run(test.name, func(t *testing.T) {
			db, store := openToolAuditStore(t)
			recorder := &faultToolAudit{store: store}
			executor := &countingExecutor{}
			service := newService(db, config.Default().Tools, recorder, executor)
			call, approval, err := service.Submit(context.Background(), Request{ToolName: "email.send", TargetType: "email", External: true})
			if err != nil {
				t.Fatal(err)
			}
			recorder.failEvent = test.failEvent
			handler := NewHandler(service)
			response := performApprovalDecision(handler, approval.ID, test.approve)
			assertToolAuditFailureResponse(t, response)
			if executor.calls != 0 {
				t.Fatalf("executor calls = %d, want 0", executor.calls)
			}
			storedCall, storedApproval, err := service.Get(context.Background(), call.ID)
			if err != nil {
				t.Fatal(err)
			}
			if storedCall.State != StatePending || storedApproval.Status != ApprovalPending {
				t.Fatalf("state changed despite audit failure: call=%s approval=%s", storedCall.State, storedApproval.Status)
			}
		})
	}
}

func TestExecutionTerminalAuditFailuresCannotRetry(t *testing.T) {
	for _, test := range []struct {
		name      string
		failEvent string
		failExec  bool
	}{
		{name: "executed event", failEvent: audit.EventToolExecuted},
		{name: "failed event", failEvent: audit.EventToolFailed, failExec: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			db, store := openToolAuditStore(t)
			recorder := &faultToolAudit{store: store, failEvent: test.failEvent}
			executor := &countingExecutor{fail: test.failExec}
			service := newService(db, config.Default().Tools, recorder, executor)
			response := performToolSubmit(NewHandler(service), Request{ToolName: "weather.read", TargetType: "city"})
			assertToolAuditFailureResponse(t, response)
			if executor.calls != 1 {
				t.Fatalf("executor calls = %d, want 1", executor.calls)
			}
			var id string
			if err := db.QueryRow(`SELECT id FROM tool_calls`).Scan(&id); err != nil {
				t.Fatal(err)
			}
			recorder.failEvent = ""
			if _, err := service.execute(context.Background(), id); !errors.Is(err, ErrNotExecutable) {
				t.Fatalf("retry error = %v, want not executable", err)
			}
			if executor.calls != 1 {
				t.Fatalf("executor retried: calls = %d", executor.calls)
			}
		})
	}
}

func TestFailedExecutionPersistsFailedStateAndAudit(t *testing.T) {
	db, recorder := openToolAuditStore(t)
	executor := &countingExecutor{fail: true}
	service := newService(db, config.Default().Tools, recorder, executor)
	_, _, err := service.Submit(context.Background(), Request{ToolName: "weather.read", TargetType: "city"})
	if err == nil {
		t.Fatal("Submit() error = nil, want executor failure")
	}
	var id, state string
	if err := db.QueryRow(`SELECT id, state FROM tool_calls`).Scan(&id, &state); err != nil {
		t.Fatal(err)
	}
	if state != string(StateFailed) {
		t.Fatalf("state = %q, want FAILED", state)
	}
	assertEventChain(t, recorder, id, []string{audit.EventToolFailed})
	if _, err := service.execute(context.Background(), id); !errors.Is(err, ErrNotExecutable) {
		t.Fatalf("failed retry error = %v, want not executable", err)
	}
}

func TestToolArgumentsAreMinimizedEverywhere(t *testing.T) {
	db, recorder := openToolAuditStore(t)
	service := newService(db, config.Default().Tools, recorder, &countingExecutor{})
	values := []string{
		"demo.private@example.test",
		"fictional email body with private details",
		"sk-agentguard-tool-test-000000000000000000000",
		"fictional-password-000000",
		"/private/example/system/path",
	}
	arguments, err := json.Marshal(map[string]string{
		"to": values[0], "body": values[1], "token": values[2], "password": values[3], "path": values[4],
	})
	if err != nil {
		t.Fatal(err)
	}
	call, approval, err := service.Submit(context.Background(), Request{ToolName: "email.send", TargetType: "email", External: true, Sensitive: true, Arguments: arguments})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = service.Decide(context.Background(), approval.ID, false, strings.Join(values, " "))
	if err != nil {
		t.Fatal(err)
	}
	database := toolDatabaseContents(t, db, []string{"tool_calls", "approvals", "policy_decisions", "audit_events"})
	for _, value := range values {
		if strings.Contains(database, value) {
			t.Fatalf("database contains raw tool value %q", value)
		}
	}
	if !strings.Contains(call.ArgumentsSummary, "fields=body,password,path,to,token") {
		t.Fatalf("arguments summary = %q, want only sorted field names", call.ArgumentsSummary)
	}
}

func TestToolAuditQueryFiltersByToolCallID(t *testing.T) {
	db, recorder := openToolAuditStore(t)
	service := newService(db, config.Default().Tools, recorder, &countingExecutor{})
	passCall, _, err := service.Submit(context.Background(), Request{ToolName: "weather.read", TargetType: "city"})
	if err != nil {
		t.Fatal(err)
	}
	approvedCall, approved, err := service.Submit(context.Background(), Request{ToolName: "email.send", TargetType: "email", External: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.Decide(context.Background(), approved.ID, true, "approve"); err != nil {
		t.Fatal(err)
	}
	rejectedCall, rejected, err := service.Submit(context.Background(), Request{ToolName: "email.send", TargetType: "email", External: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.Decide(context.Background(), rejected.ID, false, "reject"); err != nil {
		t.Fatal(err)
	}
	blockedCall, _, err := service.Submit(context.Background(), Request{ToolName: "file.delete", TargetType: "fixture", Destructive: true})
	if err != nil {
		t.Fatal(err)
	}
	failingService := newService(db, config.Default().Tools, recorder, &countingExecutor{fail: true})
	_, _, _ = failingService.Submit(context.Background(), Request{ToolName: "file.read", TargetType: "fixture"})
	var failedCallID string
	if err := db.QueryRow(`SELECT id FROM tool_calls WHERE tool_name='file.read'`).Scan(&failedCallID); err != nil {
		t.Fatal(err)
	}

	filters := []struct {
		toolCallID string
		eventType  string
	}{
		{passCall.ID, audit.EventToolPolicy},
		{approvedCall.ID, audit.EventApprovalRequested},
		{approvedCall.ID, audit.EventApprovalApproved},
		{rejectedCall.ID, audit.EventApprovalRejected},
		{passCall.ID, audit.EventToolExecuted},
		{blockedCall.ID, audit.EventToolBlocked},
		{failedCallID, audit.EventToolFailed},
	}
	for _, filter := range filters {
		request := httptest.NewRequest(http.MethodGet, "/api/audit/events?tool_call_id="+filter.toolCallID+"&event_type="+filter.eventType, nil)
		response := httptest.NewRecorder()
		recorder.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("query status = %d: %s", response.Code, response.Body.String())
		}
		if !strings.Contains(response.Body.String(), `"tool_call_id":"`+filter.toolCallID+`"`) || !strings.Contains(response.Body.String(), `"event_type":"`+filter.eventType+`"`) {
			t.Fatalf("unexpected query response for %s: %s", filter.eventType, response.Body.String())
		}
	}
}

func TestConcurrentApproveRejectHasOneLegalTerminalDecision(t *testing.T) {
	db, recorder := openToolAuditStore(t)
	service := newService(db, config.Default().Tools, recorder, &countingExecutor{})
	_, approval, err := service.Submit(context.Background(), Request{ToolName: "email.send", TargetType: "email", External: true})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errorsOut := make(chan error, 2)
	for _, approve := range []bool{true, false} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := service.Decide(context.Background(), approval.ID, approve, "fictional decision")
			errorsOut <- err
		}()
	}
	wg.Wait()
	close(errorsOut)
	success, conflicts := 0, 0
	for err := range errorsOut {
		if err == nil {
			success++
		} else if errors.Is(err, ErrConflict) {
			conflicts++
		}
	}
	if success != 1 || conflicts != 1 {
		t.Fatalf("success=%d conflicts=%d", success, conflicts)
	}
	var status, state string
	if err := db.QueryRow(`SELECT a.status,t.state FROM approvals a JOIN tool_calls t ON t.id=a.tool_call_id WHERE a.id=?`, approval.ID).Scan(&status, &state); err != nil {
		t.Fatal(err)
	}
	if !((status == string(ApprovalApproved) && state == string(StateExecuted)) || (status == string(ApprovalRejected) && state == string(StateRejected))) {
		t.Fatalf("illegal concurrent result: approval=%s tool=%s", status, state)
	}
	var decisionEvents int
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE approval_id=? AND event_type IN ('APPROVAL_APPROVED','APPROVAL_REJECTED')`, approval.ID).Scan(&decisionEvents); err != nil {
		t.Fatal(err)
	}
	if decisionEvents != 1 {
		t.Fatalf("approval decision events = %d, want 1", decisionEvents)
	}
}

func openToolAuditStore(t *testing.T) (*sql.DB, *audit.Store) {
	t.Helper()
	store, err := storage.Open(context.Background(), t.TempDir()+"/tools-audit.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store.DB(), audit.New(store.DB())
}

func performToolSubmit(handler http.Handler, request Request) *httptest.ResponseRecorder {
	body, _ := json.Marshal(request)
	httpRequest := httptest.NewRequest(http.MethodPost, "/api/tool-calls", strings.NewReader(string(body)))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httpRequest)
	return response
}

func performApprovalDecision(handler http.Handler, approvalID string, approve bool) *httptest.ResponseRecorder {
	action := "reject"
	if approve {
		action = "approve"
	}
	request := httptest.NewRequest(http.MethodPost, "/api/approvals/"+approvalID+"/"+action, strings.NewReader(`{"reason":"fictional decision"}`))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func assertToolAuditFailureResponse(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "audit_persistence_failed") {
		t.Fatalf("response = %d %s, want safe audit failure", response.Code, response.Body.String())
	}
}

func assertEventChain(t *testing.T, recorder *audit.Store, toolCallID string, want []string) {
	t.Helper()
	events, err := recorder.List(context.Background(), audit.Filter{ToolCallID: toolCallID, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool, len(events))
	for _, event := range events {
		if event.ToolCallID != toolCallID {
			t.Fatalf("event tool_call_id = %q, want %q", event.ToolCallID, toolCallID)
		}
		seen[event.EventType] = true
	}
	for _, eventType := range want {
		if !seen[eventType] {
			t.Fatalf("events %+v missing %s", seen, eventType)
		}
	}
}

func assertEventAbsent(t *testing.T, recorder *audit.Store, toolCallID, eventType string) {
	t.Helper()
	events, err := recorder.List(context.Background(), audit.Filter{ToolCallID: toolCallID, EventType: eventType})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("unexpected %s event: %+v", eventType, events)
	}
}

func assertToolPolicyRecord(t *testing.T, db *sql.DB, call Call) {
	t.Helper()
	var subjectType, stage, decision, policyID, matchedRules string
	if err := db.QueryRow(`SELECT subject_type,stage,decision,policy_id,matched_rules FROM policy_decisions WHERE tool_call_id=?`, call.ID).Scan(&subjectType, &stage, &decision, &policyID, &matchedRules); err != nil {
		t.Fatal(err)
	}
	if subjectType != "TOOL_CALL" || stage != "TOOL" || decision != string(call.Decision) || policyID != call.PolicyID || !strings.Contains(matchedRules, call.PolicyID) {
		t.Fatalf("policy subject=%q stage=%q decision=%q policy=%q rules=%q", subjectType, stage, decision, policyID, matchedRules)
	}
}

func assertApprovalEventID(t *testing.T, db *sql.DB, toolCallID, approvalID, eventType string) {
	t.Helper()
	var got string
	if err := db.QueryRow(`SELECT approval_id FROM audit_events WHERE tool_call_id=? AND event_type=?`, toolCallID, eventType).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != approvalID {
		t.Fatalf("approval_id = %q, want %q", got, approvalID)
	}
}

func toolDatabaseContents(t *testing.T, db *sql.DB, tables []string) string {
	t.Helper()
	var contents strings.Builder
	for _, table := range tables {
		rows, err := db.Query(`SELECT * FROM ` + table)
		if err != nil {
			t.Fatal(err)
		}
		columns, _ := rows.Columns()
		for rows.Next() {
			values := make([]any, len(columns))
			pointers := make([]any, len(columns))
			for index := range values {
				pointers[index] = &values[index]
			}
			if err := rows.Scan(pointers...); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			for _, value := range values {
				if bytes, ok := value.([]byte); ok {
					contents.Write(bytes)
				} else {
					fmt.Fprint(&contents, value)
				}
			}
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return contents.String()
}

type faultToolAudit struct {
	store      *audit.Store
	failEvent  string
	failPolicy bool
}

func (f *faultToolAudit) DecisionWith(ctx context.Context, executor audit.SQLExecutor, decision policy.Decision) error {
	if f.failPolicy {
		return errors.New("injected policy audit failure")
	}
	return f.store.DecisionWith(ctx, executor, decision)
}

func (f *faultToolAudit) EventWith(ctx context.Context, executor audit.SQLExecutor, event audit.Event) error {
	if event.EventType == f.failEvent {
		return errors.New("injected event audit failure")
	}
	return f.store.EventWith(ctx, executor, event)
}

type countingExecutor struct {
	mu    sync.Mutex
	calls int
	fail  bool
}

func (e *countingExecutor) Execute(context.Context, Call) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls++
	if e.fail {
		return errors.New("injected mock executor failure")
	}
	return nil
}
