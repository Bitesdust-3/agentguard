package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxUpstreamResponseBytes int64 = 1 << 20

type ErrorCode string

const (
	ErrorUnavailable     ErrorCode = "unavailable"
	ErrorTimeout         ErrorCode = "timeout"
	ErrorUnauthorized    ErrorCode = "unauthorized"
	ErrorForbidden       ErrorCode = "forbidden"
	ErrorNotFound        ErrorCode = "not_found"
	ErrorRateLimited     ErrorCode = "rate_limited"
	ErrorUpstream        ErrorCode = "upstream_error"
	ErrorInvalidResponse ErrorCode = "invalid_response"
)

// Error describes an upstream failure without retaining response bodies,
// credentials, account details, or provider request identifiers.
type Error struct {
	Code       ErrorCode
	HTTPStatus int
}

func (e *Error) Error() string { return "openai-compatible provider " + string(e.Code) }

type OpenAICompatible struct {
	endpoint string
	model    string
	apiKey   string
	client   *http.Client
}

func NewOpenAICompatible(baseURL, model, apiKey string, timeout time.Duration) (*OpenAICompatible, error) {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, fmt.Errorf("openai-compatible base URL must use http or https")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("openai-compatible base URL must not contain credentials, query, or fragment")
	}
	if strings.TrimSpace(model) == "" {
		return nil, fmt.Errorf("openai-compatible model must not be empty")
	}
	if strings.TrimSpace(apiKey) == "" {
		return nil, fmt.Errorf("openai-compatible API key must not be empty")
	}
	if timeout <= 0 {
		return nil, fmt.Errorf("openai-compatible timeout must be greater than zero")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + "/v1/chat/completions"
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &OpenAICompatible{endpoint: parsed.String(), model: model, apiKey: apiKey, client: client}, nil
}

type upstreamRequest struct {
	Model    string        `json:"model"`
	Messages []ChatMessage `json:"messages"`
	Stream   bool          `json:"stream"`
}

type upstreamResponse struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	Model   string `json:"model"`
	Choices []struct {
		Index        int         `json:"index"`
		Message      ChatMessage `json:"message"`
		FinishReason string      `json:"finish_reason"`
	} `json:"choices"`
	Usage *struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
}

func (p *OpenAICompatible) Chat(ctx context.Context, request ChatRequest) (ChatResponse, error) {
	payload, err := json.Marshal(upstreamRequest{Model: p.model, Messages: request.Messages, Stream: false})
	if err != nil {
		return ChatResponse{}, &Error{Code: ErrorInvalidResponse}
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, bytes.NewReader(payload))
	if err != nil {
		return ChatResponse{}, &Error{Code: ErrorUnavailable}
	}
	httpRequest.Header.Set("Authorization", "Bearer "+p.apiKey)
	httpRequest.Header.Set("Content-Type", "application/json")

	response, err := p.client.Do(httpRequest)
	if err != nil {
		var netError net.Error
		if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netError) && netError.Timeout()) {
			return ChatResponse{}, &Error{Code: ErrorTimeout}
		}
		return ChatResponse{}, &Error{Code: ErrorUnavailable}
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxUpstreamResponseBytes))
		return ChatResponse{}, statusError(response.StatusCode)
	}

	decoder := json.NewDecoder(io.LimitReader(response.Body, maxUpstreamResponseBytes+1))
	var decoded upstreamResponse
	if err := decoder.Decode(&decoded); err != nil {
		return ChatResponse{}, &Error{Code: ErrorInvalidResponse}
	}
	if len(decoded.Choices) == 0 || decoded.Choices[0].Message.Role != "assistant" || strings.TrimSpace(decoded.Choices[0].Message.Content) == "" || strings.TrimSpace(decoded.Model) == "" {
		return ChatResponse{}, &Error{Code: ErrorInvalidResponse}
	}
	result := ChatResponse{
		ID: decoded.ID, Model: decoded.Model, Message: decoded.Choices[0].Message,
		FinishReason: decoded.Choices[0].FinishReason,
	}
	if decoded.Usage != nil {
		result.Usage = Usage{PromptTokens: decoded.Usage.PromptTokens, CompletionTokens: decoded.Usage.CompletionTokens, TotalTokens: decoded.Usage.TotalTokens}
	}
	return result, nil
}

func statusError(status int) error {
	code := ErrorUpstream
	switch status {
	case http.StatusUnauthorized:
		code = ErrorUnauthorized
	case http.StatusForbidden:
		code = ErrorForbidden
	case http.StatusNotFound:
		code = ErrorNotFound
	case http.StatusTooManyRequests:
		code = ErrorRateLimited
	}
	return &Error{Code: code, HTTPStatus: status}
}

var _ Provider = (*OpenAICompatible)(nil)
