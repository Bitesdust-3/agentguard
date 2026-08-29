package tools

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/bitesdust/agentguard/internal/config"
	"github.com/bitesdust/agentguard/internal/storage"
)

func TestServiceLifecycle(t *testing.T) {
	t.Parallel()
	s := testService(t)
	ctx := context.Background()

	weather, approval, err := s.Submit(ctx, Request{ToolName: "weather.read", TargetType: "city"})
	if err != nil || approval != nil || weather.Decision != "PASS" || weather.State != StateExecuted || weather.ResultSummary == "" {
		t.Fatalf("weather = %+v, approval=%+v, err=%v", weather, approval, err)
	}

	email, approval, err := s.Submit(ctx, Request{ToolName: "email.send", TargetType: "email", External: true})
	if err != nil || approval == nil || email.State != StatePending {
		t.Fatalf("email = %+v, approval=%+v, err=%v", email, approval, err)
	}
	approved, _, err := s.Decide(ctx, approval.ID, true, "fictional demo approval")
	if err != nil || approved.State != StateExecuted {
		t.Fatalf("approved = %+v, err=%v", approved, err)
	}
	if _, _, err := s.Decide(ctx, approval.ID, false, "late"); !errors.Is(err, ErrConflict) {
		t.Fatalf("second decision error = %v, want conflict", err)
	}

	blocked, approval, err := s.Submit(ctx, Request{ToolName: "file.delete", TargetType: "file", Destructive: true})
	if err != nil || approval != nil || blocked.State != StateBlock {
		t.Fatalf("blocked = %+v, err=%v", blocked, err)
	}
	if _, err := s.execute(ctx, blocked.ID); !errors.Is(err, ErrNotExecutable) {
		t.Fatalf("blocked execute error = %v, want not executable", err)
	}
}

func TestRejectAndConcurrentApproval(t *testing.T) {
	t.Parallel()
	s := testService(t)
	ctx := context.Background()
	_, a, err := s.Submit(ctx, Request{ToolName: "email.send", TargetType: "email", External: true})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); _, _, err := s.Decide(ctx, a.ID, true, "demo"); results <- err }()
	}
	wg.Wait()
	close(results)
	success := 0
	conflicts := 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, ErrConflict) {
			conflicts++
		}
	}
	if success != 1 || conflicts != 1 {
		t.Fatalf("success=%d conflicts=%d", success, conflicts)
	}
	_, rejectedApproval, err := s.Submit(ctx, Request{ToolName: "database.query", TargetType: "database", Sensitive: true})
	if err != nil {
		t.Fatal(err)
	}
	rejected, _, err := s.Decide(ctx, rejectedApproval.ID, false, "not approved")
	if err != nil || rejected.State != StateRejected {
		t.Fatalf("rejected=%+v err=%v", rejected, err)
	}
	if _, err := s.execute(ctx, rejected.ID); !errors.Is(err, ErrNotExecutable) {
		t.Fatalf("rejected execute = %v", err)
	}
}

func TestHandlerRejectsForgedStateAndAcceptsToolCall(t *testing.T) {
	t.Parallel()
	h := NewHandler(testService(t))
	forged := httptest.NewRequest(http.MethodPost, "/api/tool-calls", strings.NewReader(`{"tool_name":"weather.read","target_type":"city","decision":"PASS"}`))
	forgedResponse := httptest.NewRecorder()
	h.ServeHTTP(forgedResponse, forged)
	if forgedResponse.Code != http.StatusBadRequest {
		t.Fatalf("forged status = %d, want 400", forgedResponse.Code)
	}
	valid := httptest.NewRequest(http.MethodPost, "/api/tool-calls", strings.NewReader(`{"tool_name":"weather.read","target_type":"city"}`))
	validResponse := httptest.NewRecorder()
	h.ServeHTTP(validResponse, valid)
	if validResponse.Code != http.StatusCreated || !strings.Contains(validResponse.Body.String(), `"state":"EXECUTED"`) {
		t.Fatalf("valid response = %d %s", validResponse.Code, validResponse.Body.String())
	}
}

func testService(t *testing.T) *Service {
	t.Helper()
	store, err := storage.Open(context.Background(), filepath.Join(t.TempDir(), "tools.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return NewService(store.DB(), config.Default().Tools)
}
