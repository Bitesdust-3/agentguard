// Package provider defines the small, transport-independent boundary between
// AgentGuard's gateway and an LLM implementation.
package provider

import "context"

// Provider produces a chat response for an already-validated internal request.
type Provider interface {
	Chat(context.Context, ChatRequest) (ChatResponse, error)
}

// ChatRequest is independent of the OpenAI HTTP request DTO.
type ChatRequest struct {
	RequestID string
	Model     string
	Messages  []ChatMessage
}

type ChatMessage struct {
	Role    string
	Content string
}

// ChatResponse is the provider result that the gateway maps to its HTTP DTO.
type ChatResponse struct {
	ID           string
	Model        string
	Message      ChatMessage
	FinishReason string
	Usage        Usage
}

// Usage is exposed in the OpenAI-style response. Mock usage values are stable
// placeholders, not estimates of a real model tokenizer.
type Usage struct {
	PromptTokens     int
	CompletionTokens int
	TotalTokens      int
}
