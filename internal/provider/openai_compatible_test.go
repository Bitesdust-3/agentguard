package provider

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestOpenAICompatibleSuccessUsesConfiguredModelAndKey(t *testing.T) {
	const apiKey = "fixture-provider-key-never-real"
	var got upstreamRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" || r.Method != http.MethodPost {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if value := r.Header.Get("Authorization"); value != "Bearer "+apiKey {
			t.Fatalf("authorization = %q", value)
		}
		var wire map[string]any
		if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(wire)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(encoded, &got); err != nil {
			t.Fatal(err)
		}
		messages, ok := wire["messages"].([]any)
		if !ok || len(messages) != 1 {
			t.Fatalf("wire messages = %#v", wire["messages"])
		}
		message, ok := messages[0].(map[string]any)
		if !ok || message["role"] != "user" || message["content"] != "hello" {
			t.Fatalf("wire message = %#v", messages[0])
		}
		if _, exists := message["Role"]; exists {
			t.Fatalf("wire message contains internal field Role: %#v", message)
		}
		if _, exists := message["Content"]; exists {
			t.Fatalf("wire message contains internal field Content: %#v", message)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl_upstream","object":"chat.completion","created":1,"model":"configured-model","choices":[{"index":0,"message":{"role":"assistant","content":"safe upstream response"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":4,"total_tokens":7}}`))
	}))
	defer server.Close()

	client, err := NewOpenAICompatible(server.URL, "configured-model", apiKey, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Chat(context.Background(), ChatRequest{Model: "client-model-must-not-route", Messages: []ChatMessage{{Role: "user", Content: "hello"}}})
	if err != nil {
		t.Fatal(err)
	}
	if got.Model != "configured-model" || got.Stream || len(got.Messages) != 1 || got.Messages[0].Content != "hello" {
		t.Fatalf("upstream request = %+v", got)
	}
	if response.ID != "chatcmpl_upstream" || response.Model != "configured-model" || response.Message.Content != "safe upstream response" || response.Usage.TotalTokens != 7 {
		t.Fatalf("response = %+v", response)
	}
}

func TestOpenAICompatibleNormalizesChatCompletionsEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		basePath string
		wantPath string
	}{
		{name: "root", basePath: "", wantPath: "/v1/chat/completions"},
		{name: "vendor api", basePath: "/api", wantPath: "/api/v1/chat/completions"},
		{name: "versioned api", basePath: "/api/v1", wantPath: "/api/v1/chat/completions"},
		{name: "versioned api trailing slash", basePath: "/api/v1/", wantPath: "/api/v1/chat/completions"},
		{name: "complete endpoint", basePath: "/api/v1/chat/completions", wantPath: "/api/v1/chat/completions"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, err := NewOpenAICompatible("https://example.test"+test.basePath, "configured-model", "fixture-key", time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.TrimPrefix(client.endpoint, "https://example.test"); got != test.wantPath {
				t.Fatalf("endpoint path = %q, want %q", got, test.wantPath)
			}
		})
	}
}

func TestOpenAICompatibleAcceptsReasoningMetadataWithContent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"one","object":"chat.completion","created":1,"model":"reasoning-model","choices":[{"message":{"role":"assistant","content":"final answer","reasoning":"internal reasoning","reasoning_details":[]},"finish_reason":"stop"}]}`))
	}))
	defer server.Close()
	client, err := NewOpenAICompatible(server.URL, "reasoning-model", "fixture-key", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Chat(context.Background(), ChatRequest{Messages: []ChatMessage{{Role: "user", Content: "hello"}}})
	if err != nil {
		t.Fatal(err)
	}
	if response.Message.Content != "final answer" {
		t.Fatalf("content = %q", response.Message.Content)
	}
}

func TestOpenAICompatibleAllowsMissingUsage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"one","object":"chat.completion","created":1,"model":"configured-model","choices":[{"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`))
	}))
	defer server.Close()
	client, err := NewOpenAICompatible(server.URL, "configured-model", "fixture-key", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Chat(context.Background(), ChatRequest{Messages: []ChatMessage{{Role: "user", Content: "hello"}}})
	if err != nil || response.Usage != (Usage{}) {
		t.Fatalf("response=%+v err=%v", response, err)
	}
}

func TestOpenAICompatibleRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"one","model":"configured-model","choices":[{"message":{"role":"assistant","content":"` + strings.Repeat("a", int(maxUpstreamResponseBytes)) + `"}}]}`))
	}))
	defer server.Close()
	client, err := NewOpenAICompatible(server.URL, "configured-model", "fixture-key", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Chat(context.Background(), ChatRequest{Messages: []ChatMessage{{Role: "user", Content: "hello"}}})
	assertProviderError(t, err, ErrorInvalidResponse)
}

func TestUnconfiguredProviderReturnsSafeConfigurationError(t *testing.T) {
	_, err := NewUnconfigured().Chat(context.Background(), ChatRequest{})
	assertProviderError(t, err, ErrorConfiguration)
}

func TestOpenAICompatibleClassifiesSafeFailures(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		want   ErrorCode
	}{
		{name: "401", status: http.StatusUnauthorized, body: `{"error":"account fixture-provider-key-never-real"}`, want: ErrorUnauthorized},
		{name: "403", status: http.StatusForbidden, body: `forbidden private request id`, want: ErrorForbidden},
		{name: "404", status: http.StatusNotFound, body: `private deployment details`, want: ErrorNotFound},
		{name: "429", status: http.StatusTooManyRequests, body: `private quota details`, want: ErrorRateLimited},
		{name: "500", status: http.StatusInternalServerError, body: `private upstream stack`, want: ErrorUpstream},
		{name: "invalid json", status: http.StatusOK, body: `{`, want: ErrorInvalidResponse},
		{name: "empty choices", status: http.StatusOK, body: `{"model":"configured-model","choices":[]}`, want: ErrorInvalidResponse},
		{name: "empty content", status: http.StatusOK, body: `{"model":"configured-model","choices":[{"message":{"role":"assistant","content":""}}]}`, want: ErrorInvalidResponse},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			client, err := NewOpenAICompatible(server.URL, "configured-model", "fixture-provider-key-never-real", time.Second)
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Chat(context.Background(), ChatRequest{Messages: []ChatMessage{{Role: "user", Content: "hello"}}})
			var providerError *Error
			if !errors.As(err, &providerError) || providerError.Code != test.want {
				t.Fatalf("error = %v, want %s", err, test.want)
			}
			for _, forbidden := range []string{"fixture-provider-key-never-real", test.body, "private"} {
				if forbidden != "" && strings.Contains(err.Error(), forbidden) {
					t.Fatalf("safe error leaked %q: %v", forbidden, err)
				}
			}
		})
	}
}

func TestOpenAICompatibleTimeoutAndConnectionFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(50 * time.Millisecond)
		_, _ = w.Write([]byte(`{"model":"configured-model","choices":[{"message":{"role":"assistant","content":"late"}}]}`))
	}))
	defer server.Close()
	client, err := NewOpenAICompatible(server.URL, "configured-model", "fixture-key", 5*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Chat(context.Background(), ChatRequest{})
	assertProviderError(t, err, ErrorTimeout)

	unavailable, err := NewOpenAICompatible("http://127.0.0.1:1", "configured-model", "fixture-key", 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	_, err = unavailable.Chat(context.Background(), ChatRequest{})
	assertProviderError(t, err, ErrorUnavailable)
}

func assertProviderError(t *testing.T, err error, want ErrorCode) {
	t.Helper()
	var providerError *Error
	if !errors.As(err, &providerError) || providerError.Code != want {
		t.Fatalf("error = %v, want %s", err, want)
	}
}

func TestOpenAICompatibleRejectsUnsafeConfiguration(t *testing.T) {
	for _, baseURL := range []string{"", "file:///tmp/model", "ftp://example.test", "javascript:alert(1)", "https://user:pass@example.test", "https://example.test?token=value"} {
		if _, err := NewOpenAICompatible(baseURL, "model", "fixture-key", time.Second); err == nil {
			t.Fatalf("base URL %q accepted", baseURL)
		}
	}
}
