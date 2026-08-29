package audit_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bitesdust/agentguard/internal/audit"
	"github.com/bitesdust/agentguard/internal/storage"
)

func TestAuditQueryAPI(t *testing.T) {
	ctx := context.Background()
	store := openAuditStore(t)
	createdAt := time.Date(2026, 8, 29, 10, 0, 0, 0, time.UTC)
	for _, request := range []audit.Request{
		{ID: "req_one", Model: "mock", RequestFingerprint: "fingerprint-one", InputSummary: "message_count=1", CreatedAt: createdAt},
		{ID: "req_two", Model: "mock", RequestFingerprint: "fingerprint-two", InputSummary: "message_count=1", CreatedAt: createdAt},
	} {
		if err := store.StartRequest(ctx, request); err != nil {
			t.Fatalf("StartRequest() error: %v", err)
		}
	}
	events := []audit.Event{
		{ID: "event_old", EventType: audit.EventInputDetection, Source: "INPUT", RequestID: "req_one", DetectionType: "PII", RuleID: "pii.email.v1", Decision: "REDACT", Summary: "safe older event", CreatedAt: createdAt},
		{ID: "event_new", EventType: audit.EventChatCompleted, Source: "OUTPUT", RequestID: "req_two", Decision: "PASS", Summary: "safe newest event", CreatedAt: createdAt.Add(time.Second)},
	}
	for _, event := range events {
		if err := store.Event(ctx, event); err != nil {
			t.Fatalf("Event() error: %v", err)
		}
	}

	tests := []struct {
		name      string
		query     string
		wantID    string
		wantCount int
	}{
		{name: "normal query sorted descending", query: "", wantID: "event_new", wantCount: 2},
		{name: "request id", query: "?request_id=req_one", wantID: "event_old", wantCount: 1},
		{name: "event type", query: "?event_type=INPUT_DETECTION", wantID: "event_old", wantCount: 1},
		{name: "decision", query: "?decision=REDACT", wantID: "event_old", wantCount: 1},
		{name: "detection type", query: "?detection_type=PII", wantID: "event_old", wantCount: 1},
		{name: "limit", query: "?limit=1", wantID: "event_new", wantCount: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/api/audit/events"+test.query, nil)
			response := httptest.NewRecorder()
			store.ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200: %s", response.Code, response.Body.String())
			}
			rawBody := response.Body.String()
			if test.name == "normal query sorted descending" {
				for _, field := range []string{`"event_type"`, `"request_id"`, `"created_at"`} {
					if !strings.Contains(rawBody, field) {
						t.Fatalf("query JSON %s missing snake_case field %s", rawBody, field)
					}
				}
				if strings.Contains(rawBody, "EventType") || strings.Contains(rawBody, "RequestID") {
					t.Fatalf("query JSON contains Go field names: %s", rawBody)
				}
			}
			var body struct {
				Items []audit.Event `json:"items"`
			}
			if err := json.Unmarshal([]byte(rawBody), &body); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if len(body.Items) != test.wantCount || body.Items[0].ID != test.wantID {
				t.Fatalf("items = %+v, want count %d first %q", body.Items, test.wantCount, test.wantID)
			}
		})
	}

	request := httptest.NewRequest(http.MethodGet, "/api/audit/events?limit=invalid", nil)
	response := httptest.NewRecorder()
	store.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid limit status = %d, want 400", response.Code)
	}
}

func TestAuditEventJSONUsesSnakeCaseAndOmitsRawContent(t *testing.T) {
	event := audit.Event{
		ID: "event_one", EventType: audit.EventInputDetection, Actor: audit.ActorGateway,
		Source: "INPUT", RequestID: "req_one", ApprovalID: "approval_one", DetectionType: "PII",
		RuleID: "pii.email.v1", Decision: "REDACT", Summary: "masked finding",
		CreatedAt: time.Date(2026, 8, 29, 10, 0, 0, 0, time.UTC),
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}
	text := string(encoded)
	for _, field := range []string{`"event_type"`, `"request_id"`, `"approval_id"`, `"detection_type"`, `"rule_id"`, `"created_at"`} {
		if !strings.Contains(text, field) {
			t.Fatalf("JSON %s missing snake_case field %s", text, field)
		}
	}
	for _, forbidden := range []string{"EventType", "RequestID", "DetectionType", "RuleID", "CreatedAt"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("JSON %s contains Go field name %q", text, forbidden)
		}
	}
}

func openAuditStore(t *testing.T) *audit.Store {
	t.Helper()
	store, err := storage.Open(context.Background(), t.TempDir()+"/audit.db")
	if err != nil {
		t.Fatalf("storage.Open() error: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return audit.New(store.DB())
}
