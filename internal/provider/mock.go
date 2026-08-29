package provider

import "context"

const mockResponseContent = "Mock response from AgentGuard."

// Mock is a deterministic, local-only Provider used to verify the gateway
// boundary. It does not perform model inference or access a network.
type Mock struct{}

func NewMock() Mock {
	return Mock{}
}

func (Mock) Chat(_ context.Context, request ChatRequest) (ChatResponse, error) {
	return ChatResponse{
		ID:    "chatcmpl_mock",
		Model: request.Model,
		Message: ChatMessage{
			Role:    "assistant",
			Content: mockResponseContent,
		},
		FinishReason: "stop",
		Usage: Usage{
			PromptTokens:     0,
			CompletionTokens: 0,
			TotalTokens:      0,
		},
	}, nil
}
