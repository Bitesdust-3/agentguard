package provider

import (
	"context"
	"testing"
)

func TestMockChatIsDeterministic(t *testing.T) {
	t.Parallel()

	response, err := NewMock().Chat(context.Background(), ChatRequest{
		Model: "mock-model",
		Messages: []ChatMessage{{
			Role:    "user",
			Content: "Hello AgentGuard",
		}},
	})
	if err != nil {
		t.Fatalf("Chat() error: %v", err)
	}
	if got, want := response.ID, "chatcmpl_mock"; got != want {
		t.Fatalf("ID = %q, want %q", got, want)
	}
	if got, want := response.Model, "mock-model"; got != want {
		t.Fatalf("Model = %q, want %q", got, want)
	}
	if got, want := response.Message.Content, mockResponseContent; got != want {
		t.Fatalf("Content = %q, want %q", got, want)
	}
	if response.Usage != (Usage{}) {
		t.Fatalf("Usage = %+v, want zero mock usage", response.Usage)
	}
}
