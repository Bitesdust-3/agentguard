package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/bitesdust/agentguard/internal/config"
	"github.com/bitesdust/agentguard/internal/provider"
	"github.com/bitesdust/agentguard/internal/tools"
)

func TestFinalAuditSensitiveDataDoesNotPersistAcrossChatAndTools(t *testing.T) {
	db, recorder := openGatewayAuditStore(t)
	values := []string{
		"sk-agentguard-final-test-000000000000000000000",
		"ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ",
		"Bearer agentguard-final-bearer-token-000000",
		"password=fictional-password-000000",
		"final.person@example.test",
		"13800138000",
		"11010519491231002X",
		"postgres://demo:final-password@example.invalid/agentguard",
		"fictional private email body",
		"/fictional/private/tool/path",
		"provider.output@example.test",
	}

	input := strings.Join(values[:8], " ")
	chat := newTestHandlerWithAudit(&recordingProvider{}, recorder)
	response := performChat(chat, fmt.Sprintf(`{"model":"mock","messages":[{"role":"user","content":%q}]}`, input))
	if response.Code != http.StatusForbidden {
		t.Fatalf("sensitive chat status = %d, want 403: %s", response.Code, response.Body.String())
	}

	output := "private provider response " + strings.Join([]string{values[0], values[4], values[10]}, " ")
	response = performChat(newTestHandlerWithAudit(&fixedProvider{content: output}, recorder), `{"model":"mock","messages":[{"role":"user","content":"safe request"}]}`)
	if response.Code != http.StatusOK {
		t.Fatalf("sensitive provider output status = %d, want 200: %s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), values[0]) || strings.Contains(response.Body.String(), values[4]) || strings.Contains(response.Body.String(), values[10]) {
		t.Fatalf("response leaked raw provider output: %s", response.Body.String())
	}

	arguments, err := json.Marshal(map[string]string{
		"body": values[8], "path": values[9], "token": values[0], "to": values[4],
	})
	if err != nil {
		t.Fatal(err)
	}
	toolService := tools.NewService(db, config.Default().Tools, recorder)
	_, approval, err := toolService.Submit(context.Background(), tools.Request{
		ToolName: "email.send", TargetType: "email", External: true, Sensitive: true, Arguments: arguments,
	})
	if err != nil {
		t.Fatalf("tool submit: %v", err)
	}
	if _, _, err := toolService.Decide(context.Background(), approval.ID, false, strings.Join(values, " ")); err != nil {
		t.Fatalf("tool reject: %v", err)
	}

	database := databaseContents(t, db, []string{"requests", "detections", "policy_decisions", "audit_events", "tool_calls", "approvals"})
	for _, value := range values {
		if strings.Contains(database, value) {
			t.Fatalf("database contains raw sensitive test value %q", value)
		}
	}
}

func TestFinalAuditConcurrentChatRequestIDsRemainIndependent(t *testing.T) {
	db, recorder := openGatewayAuditStore(t)
	handler := newTestHandlerWithAudit(provider.NewMock(), recorder)

	const calls = 16
	ids := make(map[string]struct{}, calls)
	var mutex sync.Mutex
	var group sync.WaitGroup
	for index := 0; index < calls; index++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			response := performChat(handler, fmt.Sprintf(`{"model":"mock","messages":[{"role":"user","content":"normal request %d"}]}`, index))
			if response.Code != http.StatusOK {
				t.Errorf("request %d status = %d: %s", index, response.Code, response.Body.String())
				return
			}
			requestID := response.Header().Get("X-AgentGuard-Request-ID")
			if requestID == "" {
				t.Errorf("request %d missing request ID", index)
				return
			}
			mutex.Lock()
			ids[requestID] = struct{}{}
			mutex.Unlock()
		}(index)
	}
	group.Wait()
	if len(ids) != calls {
		t.Fatalf("unique request IDs = %d, want %d", len(ids), calls)
	}
	var requestCount, policyCount, eventCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM requests`).Scan(&requestCount); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM policy_decisions WHERE request_id IS NOT NULL`).Scan(&policyCount); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE request_id IS NOT NULL`).Scan(&eventCount); err != nil {
		t.Fatal(err)
	}
	if requestCount != calls || policyCount != calls*2 || eventCount != calls*5 {
		t.Fatalf("audit counts requests=%d policies=%d events=%d", requestCount, policyCount, eventCount)
	}
}
