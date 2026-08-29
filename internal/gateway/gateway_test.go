package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bitesdust/agentguard/internal/detection"
	"github.com/bitesdust/agentguard/internal/policy"
	"github.com/bitesdust/agentguard/internal/provider"
)

func TestChatCompletions(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(provider.NewMock())
	handler.now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{
		"model":"mock-model",
		"messages":[{"role":"user","content":"Hello AgentGuard"}]
	}`))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if got, want := response.Code, http.StatusOK; got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}
	var body chatCompletionResponseDTO
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.ID != "chatcmpl_mock" || body.Object != "chat.completion" || body.Created != 1_700_000_000 || body.Model != "mock-model" {
		t.Fatalf("unexpected response metadata: %+v", body)
	}
	if len(body.Choices) != 1 || body.Choices[0].Message.Role != "assistant" || body.Choices[0].Message.Content != "Mock response from AgentGuard." || body.Choices[0].FinishReason != "stop" {
		t.Fatalf("unexpected choice: %+v", body.Choices)
	}
	if body.Usage != (usageDTO{}) {
		t.Fatalf("usage = %+v, want stable zero mock usage", body.Usage)
	}
}

func TestChatCompletionsErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		method     string
		body       string
		wantStatus int
		wantCode   string
	}{
		{name: "method", method: http.MethodGet, wantStatus: http.StatusMethodNotAllowed, wantCode: "method_not_allowed"},
		{name: "invalid json", method: http.MethodPost, body: `{`, wantStatus: http.StatusBadRequest, wantCode: "invalid_json"},
		{name: "empty model", method: http.MethodPost, body: `{"model":"","messages":[{"role":"user","content":"hi"}]}`, wantStatus: http.StatusBadRequest, wantCode: "model_required"},
		{name: "empty messages", method: http.MethodPost, body: `{"model":"mock","messages":[]}`, wantStatus: http.StatusBadRequest, wantCode: "messages_required"},
		{name: "unsupported role", method: http.MethodPost, body: `{"model":"mock","messages":[{"role":"tool","content":"hi"}]}`, wantStatus: http.StatusBadRequest, wantCode: "unsupported_role"},
		{name: "streaming", method: http.MethodPost, body: `{"model":"mock","messages":[{"role":"user","content":"hi"}],"stream":true}`, wantStatus: http.StatusBadRequest, wantCode: "stream_unsupported"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, "/v1/chat/completions", strings.NewReader(test.body))
			response := httptest.NewRecorder()
			newTestHandler(provider.NewMock()).ServeHTTP(response, request)

			if got := response.Code; got != test.wantStatus {
				t.Fatalf("status = %d, want %d", got, test.wantStatus)
			}
			var body errorResponseDTO
			if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
				t.Fatalf("decode error response: %v", err)
			}
			if got := body.Error.Code; got != test.wantCode {
				t.Fatalf("code = %q, want %q", got, test.wantCode)
			}
		})
	}
}

func TestChatCompletionsRejectsLargeBody(t *testing.T) {
	t.Parallel()

	body := `{"model":"mock","messages":[{"role":"user","content":"` + strings.Repeat("a", int(maxRequestBodyBytes)) + `"}]}`
	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	response := httptest.NewRecorder()
	newTestHandler(provider.NewMock()).ServeHTTP(response, request)

	if got, want := response.Code, http.StatusRequestEntityTooLarge; got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}
}

func TestChatCompletionsPropagatesProviderFailure(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"mock","messages":[{"role":"user","content":"hi"}]}`))
	response := httptest.NewRecorder()
	newTestHandler(failingProvider{}).ServeHTTP(response, request)

	if got, want := response.Code, http.StatusBadGateway; got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}
	var body errorResponseDTO
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if got, want := body.Error.Code, "provider_error"; got != want {
		t.Fatalf("code = %q, want %q", got, want)
	}
}

func TestChatCompletionsRedactsBeforeProvider(t *testing.T) {
	t.Parallel()

	capture := &recordingProvider{}
	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"mock","messages":[{"role":"user","content":"contact demo.user@example.test"}]}`))
	response := httptest.NewRecorder()

	newTestHandler(capture).ServeHTTP(response, request)

	if got, want := response.Code, http.StatusOK; got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}
	if capture.calls != 1 {
		t.Fatalf("provider calls = %d, want 1", capture.calls)
	}
	got := capture.request.Messages[0].Content
	if strings.Contains(got, "demo.user@example.test") || !strings.Contains(got, "[REDACTED_EMAIL]") {
		t.Fatalf("provider received %q, want only redacted email", got)
	}
}

func TestChatCompletionsBlocksBeforeProvider(t *testing.T) {
	t.Parallel()

	capture := &recordingProvider{}
	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"mock","messages":[{"role":"user","content":"postgres://demo:fictional-password@example.invalid/agentguard"}]}`))
	response := httptest.NewRecorder()

	newTestHandler(capture).ServeHTTP(response, request)

	if got, want := response.Code, http.StatusForbidden; got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}
	if capture.calls != 0 {
		t.Fatalf("provider calls = %d, want 0", capture.calls)
	}
	var body errorResponseDTO
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if body.Error.Code != "security_blocked" || body.Error.Decision != "BLOCK" || body.Error.RuleID != "secret.database_url.v1" {
		t.Fatalf("unexpected blocked response: %+v", body.Error)
	}
}

func TestChatCompletionsInspectsEveryMessage(t *testing.T) {
	t.Parallel()

	capture := &recordingProvider{}
	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"mock","messages":[{"role":"system","content":"contact demo.user@example.test"},{"role":"user","content":"normal question"}]}`))
	response := httptest.NewRecorder()

	newTestHandler(capture).ServeHTTP(response, request)

	if got, want := response.Code, http.StatusOK; got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}
	if got := capture.request.Messages[0].Content; got != "contact [REDACTED_EMAIL]" {
		t.Fatalf("system message = %q, want redacted", got)
	}
	if got := capture.request.Messages[1].Content; got != "normal question" {
		t.Fatalf("user message = %q, want unchanged", got)
	}
}

func newTestHandler(chatProvider provider.Provider) *Handler {
	inputPolicy, err := policy.NewEngine(policy.Config{
		DefaultAction: policy.ActionPass,
		Rules: []policy.Rule{
			{ID: "input.secret.block.v1", DetectionType: detection.DetectionTypeSecret, MinScore: 0.98, Action: policy.ActionBlock},
			{ID: "input.secret.redact.v1", DetectionType: detection.DetectionTypeSecret, MinScore: 0.80, Action: policy.ActionRedact},
			{ID: "input.pii.redact.v1", DetectionType: detection.DetectionTypePII, MinScore: 0.80, Action: policy.ActionRedact},
		},
	})
	if err != nil {
		panic(err)
	}
	return New(chatProvider, detection.NewEngine([]detection.Detector{
		detection.NewSecretDetector(),
		detection.NewPIIDetector(),
	}, map[detection.DetectionType]float64{
		detection.DetectionTypeSecret: 0.80,
		detection.DetectionTypePII:    0.80,
	}), inputPolicy)
}

type recordingProvider struct {
	calls   int
	request provider.ChatRequest
}

func (p *recordingProvider) Chat(_ context.Context, request provider.ChatRequest) (provider.ChatResponse, error) {
	p.calls++
	p.request = request
	return provider.ChatResponse{ID: "recorded", Model: request.Model, Message: provider.ChatMessage{Role: "assistant", Content: "ok"}, FinishReason: "stop"}, nil
}

type failingProvider struct{}

func (failingProvider) Chat(context.Context, provider.ChatRequest) (provider.ChatResponse, error) {
	return provider.ChatResponse{}, errors.New("provider unavailable")
}
