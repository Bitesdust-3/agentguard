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

	"github.com/bitesdust/agentguard/internal/provider"
)

func TestChatCompletions(t *testing.T) {
	t.Parallel()

	handler := New(provider.NewMock())
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
			New(provider.NewMock()).ServeHTTP(response, request)

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
	New(provider.NewMock()).ServeHTTP(response, request)

	if got, want := response.Code, http.StatusRequestEntityTooLarge; got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}
}

func TestChatCompletionsPropagatesProviderFailure(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"mock","messages":[{"role":"user","content":"hi"}]}`))
	response := httptest.NewRecorder()
	New(failingProvider{}).ServeHTTP(response, request)

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

type failingProvider struct{}

func (failingProvider) Chat(context.Context, provider.ChatRequest) (provider.ChatResponse, error) {
	return provider.ChatResponse{}, errors.New("provider unavailable")
}
