// Package gateway implements the HTTP compatibility boundary. Security
// detection and policy evaluation intentionally do not belong here yet.
package gateway

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bitesdust/agentguard/internal/detection"
	"github.com/bitesdust/agentguard/internal/policy"
	"github.com/bitesdust/agentguard/internal/provider"
)

const maxRequestBodyBytes int64 = 1 << 20 // 1 MiB

type Handler struct {
	provider     provider.Provider
	detector     detection.Detector
	inputPolicy  *policy.Engine
	now          func() time.Time
	newRequestID func() string
}

func New(chatProvider provider.Provider, detector detection.Detector, inputPolicy *policy.Engine) *Handler {
	return &Handler{
		provider:     chatProvider,
		detector:     detector,
		inputPolicy:  inputPolicy,
		now:          time.Now,
		newRequestID: newRequestID,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "only POST is supported")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	var dto chatCompletionRequestDTO
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&dto); err != nil {
		if isBodyTooLarge(err) {
			writeError(w, http.StatusRequestEntityTooLarge, "request_too_large", "request body exceeds the 1 MiB limit")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid_json", "request body must contain valid JSON")
		return
	}
	if err := requireSingleJSONValue(decoder); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "request body must contain one JSON object")
		return
	}

	request, validationErr := normalizeRequest(dto)
	if validationErr != nil {
		writeError(w, http.StatusBadRequest, validationErr.code, validationErr.message)
		return
	}
	requestID := h.newRequestID()
	w.Header().Set("X-AgentGuard-Request-ID", requestID)
	securedMessages, decision := h.secureMessages(r.Context(), requestID, request.Messages)
	request.Messages = securedMessages
	if decision.Decision == policy.ActionBlock {
		writeSecurityBlocked(w, decision)
		return
	}

	response, err := h.provider.Chat(r.Context(), request)
	if err != nil {
		writeError(w, http.StatusBadGateway, "provider_error", "chat provider failed")
		return
	}

	writeJSON(w, http.StatusOK, chatCompletionResponseDTO{
		ID:      response.ID,
		Object:  "chat.completion",
		Created: h.now().UTC().Unix(),
		Model:   response.Model,
		Choices: []choiceDTO{{
			Index: 0,
			Message: chatMessageDTO{
				Role:    response.Message.Role,
				Content: response.Message.Content,
			},
			FinishReason: response.FinishReason,
		}},
		Usage: usageDTO{
			PromptTokens:     response.Usage.PromptTokens,
			CompletionTokens: response.Usage.CompletionTokens,
			TotalTokens:      response.Usage.TotalTokens,
		},
	})
}

func (h *Handler) secureMessages(ctx context.Context, requestID string, messages []provider.ChatMessage) ([]provider.ChatMessage, policy.Decision) {
	secured := append([]provider.ChatMessage(nil), messages...)
	if h.detector == nil || h.inputPolicy == nil {
		return secured, policy.Decision{Decision: policy.ActionPass}
	}

	resultsByMessage := make([][]detection.DetectionResult, len(messages))
	var results []detection.DetectionResult
	for index, message := range messages {
		messageResults := h.detector.Detect(ctx, detection.Input{
			SubjectType: detection.SubjectTypeRequest,
			SubjectID:   requestID,
			Source:      detection.SourceInput,
			Text:        message.Content,
		})
		for resultIndex := range messageResults {
			messageResults[resultIndex].Metadata["message_index"] = strconv.Itoa(index)
		}
		resultsByMessage[index] = messageResults
		results = append(results, messageResults...)
	}

	decision := h.inputPolicy.Evaluate(detection.SubjectTypeRequest, requestID, results)
	if decision.Decision != policy.ActionRedact {
		return secured, decision
	}
	for index, messageResults := range resultsByMessage {
		secured[index].Content, decision.Redactions = appendRedactions(secured[index].Content, messageResults, decision.Redactions)
	}
	return secured, decision
}

func appendRedactions(text string, results []detection.DetectionResult, existing []detection.Redaction) (string, []detection.Redaction) {
	redacted, redactions := detection.Redact(text, results)
	return redacted, append(existing, redactions...)
}

type chatCompletionRequestDTO struct {
	Model    string           `json:"model"`
	Messages []chatMessageDTO `json:"messages"`
	Stream   *bool            `json:"stream,omitempty"`
}

type chatMessageDTO struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatCompletionResponseDTO struct {
	ID      string      `json:"id"`
	Object  string      `json:"object"`
	Created int64       `json:"created"`
	Model   string      `json:"model"`
	Choices []choiceDTO `json:"choices"`
	Usage   usageDTO    `json:"usage"`
}

type choiceDTO struct {
	Index        int            `json:"index"`
	Message      chatMessageDTO `json:"message"`
	FinishReason string         `json:"finish_reason"`
}

type usageDTO struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

type requestValidationError struct {
	code    string
	message string
}

func (e *requestValidationError) Error() string {
	return e.message
}

func normalizeRequest(dto chatCompletionRequestDTO) (provider.ChatRequest, *requestValidationError) {
	if strings.TrimSpace(dto.Model) == "" {
		return provider.ChatRequest{}, &requestValidationError{code: "model_required", message: "model must not be empty"}
	}
	if len(dto.Messages) == 0 {
		return provider.ChatRequest{}, &requestValidationError{code: "messages_required", message: "messages must not be empty"}
	}
	if dto.Stream != nil && *dto.Stream {
		return provider.ChatRequest{}, &requestValidationError{code: "stream_unsupported", message: "streaming is not supported"}
	}

	messages := make([]provider.ChatMessage, 0, len(dto.Messages))
	for _, message := range dto.Messages {
		if !supportedRole(message.Role) {
			return provider.ChatRequest{}, &requestValidationError{code: "unsupported_role", message: "message role must be system, user, or assistant"}
		}
		messages = append(messages, provider.ChatMessage{
			Role:    message.Role,
			Content: message.Content,
		})
	}

	return provider.ChatRequest{Model: dto.Model, Messages: messages}, nil
}

func supportedRole(role string) bool {
	switch role {
	case "system", "user", "assistant":
		return true
	default:
		return false
	}
}

func requireSingleJSONValue(decoder *json.Decoder) error {
	var extra struct{}
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func isBodyTooLarge(err error) bool {
	var maxBytesError *http.MaxBytesError
	return errors.As(err, &maxBytesError)
}

type errorResponseDTO struct {
	Error apiErrorDTO `json:"error"`
}

type apiErrorDTO struct {
	Message       string `json:"message"`
	Type          string `json:"type"`
	Code          string `json:"code"`
	Decision      string `json:"decision,omitempty"`
	DetectionType string `json:"detection_type,omitempty"`
	RuleID        string `json:"rule_id,omitempty"`
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorResponseDTO{
		Error: apiErrorDTO{Message: message, Type: "invalid_request_error", Code: code},
	})
}

func writeSecurityBlocked(w http.ResponseWriter, decision policy.Decision) {
	detectionType := ""
	if len(decision.MatchedRules) > 0 {
		if strings.HasPrefix(decision.MatchedRules[0], "secret.") {
			detectionType = string(detection.DetectionTypeSecret)
		} else if strings.HasPrefix(decision.MatchedRules[0], "pii.") {
			detectionType = string(detection.DetectionTypePII)
		}
	}
	ruleID := ""
	if len(decision.MatchedRules) > 0 {
		ruleID = decision.MatchedRules[0]
	}
	writeJSON(w, http.StatusForbidden, errorResponseDTO{Error: apiErrorDTO{
		Message:       "request blocked by AgentGuard security policy",
		Type:          "security_error",
		Code:          "security_blocked",
		Decision:      string(policy.ActionBlock),
		DetectionType: detectionType,
		RuleID:        ruleID,
	}})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

var _ http.Handler = (*Handler)(nil)

func newRequestID() string {
	var value [12]byte
	if _, err := rand.Read(value[:]); err == nil {
		return "req_" + hex.EncodeToString(value[:])
	}
	return fmt.Sprintf("req_%d", time.Now().UTC().UnixNano())
}
