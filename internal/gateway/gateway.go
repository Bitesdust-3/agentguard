// Package gateway implements the HTTP compatibility boundary and orchestrates
// the frozen security pipeline without owning detector or policy rules.
package gateway

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bitesdust/agentguard/internal/audit"
	"github.com/bitesdust/agentguard/internal/detection"
	"github.com/bitesdust/agentguard/internal/policy"
	"github.com/bitesdust/agentguard/internal/provider"
)

const maxRequestBodyBytes int64 = 1 << 20 // 1 MiB

type Handler struct {
	provider       provider.Provider
	inputDetector  detection.Detector
	inputPolicy    *policy.Engine
	outputDetector detection.Detector
	outputPolicy   *policy.Engine
	audit          audit.Recorder
	now            func() time.Time
	newRequestID   func() string
}

func New(chatProvider provider.Provider, inputDetector detection.Detector, inputPolicy *policy.Engine, outputDetector detection.Detector, outputPolicy *policy.Engine, auditRecorder audit.Recorder) *Handler {
	return &Handler{
		provider:       chatProvider,
		inputDetector:  inputDetector,
		inputPolicy:    inputPolicy,
		outputDetector: outputDetector,
		outputPolicy:   outputPolicy,
		audit:          auditRecorder,
		now:            time.Now,
		newRequestID:   newRequestID,
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
	request.RequestID = requestID
	w.Header().Set("X-AgentGuard-Request-ID", requestID)
	startedAt := h.now().UTC()
	if h.audit == nil || h.audit.StartRequest(r.Context(), audit.Request{
		ID:                 requestID,
		Model:              request.Model,
		RequestFingerprint: requestFingerprint(request),
		InputSummary:       inputSummary(request.Messages),
		Status:             "PROCESSING",
		CreatedAt:          startedAt,
	}) != nil {
		writeAuditFailure(w)
		return
	}
	if err := h.audit.Event(r.Context(), audit.Event{
		EventType: audit.EventChatRequest,
		Source:    string(detection.SourceInput),
		RequestID: requestID,
		Summary:   "chat request accepted",
	}); err != nil {
		writeAuditFailure(w)
		return
	}

	securedMessages, inputDecision, inputResults := h.secureMessages(r.Context(), requestID, request.Messages)
	if err := h.recordDetections(r.Context(), requestID, audit.EventInputDetection, inputResults); err != nil {
		writeAuditFailure(w)
		return
	}
	if err := h.recordDecision(r.Context(), requestID, audit.EventInputPolicy, inputDecision); err != nil {
		writeAuditFailure(w)
		return
	}
	request.Messages = securedMessages
	if inputDecision.Decision == policy.ActionBlock {
		if err := h.complete(r.Context(), requestID, startedAt, "BLOCKED", policy.ActionBlock, len(inputResults), "", audit.EventChatBlocked, detection.SourceInput); err != nil {
			writeAuditFailure(w)
			return
		}
		writeSecurityBlocked(w, inputDecision, "security_blocked", "request blocked by AgentGuard security policy")
		return
	}

	response, err := h.provider.Chat(r.Context(), request)
	if err != nil {
		if auditErr := h.audit.Event(r.Context(), audit.Event{
			EventType: audit.EventProviderFailed,
			Source:    string(detection.SourceOutput),
			RequestID: requestID,
			Decision:  string(inputDecision.Decision),
			Summary:   "provider call failed",
		}); auditErr != nil {
			writeAuditFailure(w)
			return
		}
		if auditErr := h.audit.CompleteRequest(r.Context(), requestID, audit.RequestCompletion{
			Status:         "FAILED",
			FinalDecision:  inputDecision.Decision,
			DetectionCount: len(inputResults),
			LatencyMS:      elapsedMilliseconds(startedAt, h.now().UTC()),
		}); auditErr != nil {
			writeAuditFailure(w)
			return
		}
		writeError(w, http.StatusBadGateway, "provider_error", "chat provider failed")
		return
	}
	if err := h.audit.Event(r.Context(), audit.Event{
		EventType: audit.EventProviderDone,
		Source:    string(detection.SourceOutput),
		RequestID: requestID,
		Summary:   "provider call completed",
	}); err != nil {
		writeAuditFailure(w)
		return
	}

	rawOutputLength := len(response.Message.Content)
	securedOutput, outputDecision, outputResults := h.secureOutput(r.Context(), requestID, response.Message.Content)
	if err := h.recordDetections(r.Context(), requestID, audit.EventOutputDetection, outputResults); err != nil {
		writeAuditFailure(w)
		return
	}
	if err := h.recordDecision(r.Context(), requestID, audit.EventOutputPolicy, outputDecision); err != nil {
		writeAuditFailure(w)
		return
	}
	response.Message.Content = securedOutput
	allDetectionCount := len(inputResults) + len(outputResults)
	finalDecision := strongestDecision(inputDecision.Decision, outputDecision.Decision)
	if outputDecision.Decision == policy.ActionBlock {
		if err := h.complete(r.Context(), requestID, startedAt, "BLOCKED", policy.ActionBlock, allDetectionCount, outputSummary(rawOutputLength), audit.EventChatBlocked, detection.SourceOutput); err != nil {
			writeAuditFailure(w)
			return
		}
		writeSecurityBlocked(w, outputDecision, "output_security_blocked", "provider response blocked by AgentGuard security policy")
		return
	}
	if err := h.complete(r.Context(), requestID, startedAt, "COMPLETED", finalDecision, allDetectionCount, outputSummary(rawOutputLength), audit.EventChatCompleted, detection.SourceOutput); err != nil {
		writeAuditFailure(w)
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

func (h *Handler) secureMessages(ctx context.Context, requestID string, messages []provider.ChatMessage) ([]provider.ChatMessage, policy.Decision, []detection.DetectionResult) {
	secured := append([]provider.ChatMessage(nil), messages...)
	if h.inputDetector == nil || h.inputPolicy == nil {
		return secured, policy.Decision{SubjectType: detection.SubjectTypeRequest, SubjectID: requestID, Stage: policy.StageInput, Decision: policy.ActionPass}, nil
	}

	resultsByMessage := make([][]detection.DetectionResult, len(messages))
	var results []detection.DetectionResult
	for index, message := range messages {
		messageResults := h.inputDetector.Detect(ctx, detection.Input{
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
		return secured, decision, results
	}
	for index, messageResults := range resultsByMessage {
		secured[index].Content, decision.Redactions = appendRedactions(secured[index].Content, messageResults, decision.Redactions)
	}
	return secured, decision, results
}

func (h *Handler) secureOutput(ctx context.Context, requestID, content string) (string, policy.Decision, []detection.DetectionResult) {
	if h.outputDetector == nil || h.outputPolicy == nil {
		return content, policy.Decision{SubjectType: detection.SubjectTypeRequest, SubjectID: requestID, Stage: policy.StageOutput, Decision: policy.ActionPass}, nil
	}
	results := h.outputDetector.Detect(ctx, detection.Input{
		SubjectType: detection.SubjectTypeRequest,
		SubjectID:   requestID,
		Source:      detection.SourceOutput,
		Text:        content,
	})
	decision := h.outputPolicy.Evaluate(detection.SubjectTypeRequest, requestID, results)
	if decision.Decision != policy.ActionRedact {
		return content, decision, results
	}
	redacted, redactions := detection.Redact(content, results)
	decision.Redactions = redactions
	return redacted, decision, results
}

func (h *Handler) recordDetections(ctx context.Context, requestID, eventType string, results []detection.DetectionResult) error {
	for _, result := range results {
		if err := h.audit.Detection(ctx, result); err != nil {
			return err
		}
		score := result.Score
		if err := h.audit.Event(ctx, audit.Event{
			EventType:     eventType,
			Source:        string(result.Source),
			RequestID:     requestID,
			DetectionType: string(result.DetectionType),
			RuleID:        result.RuleID,
			RiskScore:     &score,
			Summary:       "security detection recorded",
		}); err != nil {
			return err
		}
	}
	return nil
}

func (h *Handler) recordDecision(ctx context.Context, requestID, eventType string, decision policy.Decision) error {
	if err := h.audit.Decision(ctx, decision); err != nil {
		return err
	}
	score := decision.RiskScore
	return h.audit.Event(ctx, audit.Event{
		EventType: eventType,
		Source:    string(decision.Stage),
		RequestID: requestID,
		Decision:  string(decision.Decision),
		RiskScore: &score,
		Summary:   "policy decision recorded",
	})
}

func (h *Handler) complete(ctx context.Context, requestID string, startedAt time.Time, status string, decision policy.Action, detectionCount int, outputSummaryValue, eventType string, source detection.Source) error {
	if err := h.audit.CompleteRequest(ctx, requestID, audit.RequestCompletion{
		Status:         status,
		FinalDecision:  decision,
		DetectionCount: detectionCount,
		OutputSummary:  outputSummaryValue,
		LatencyMS:      elapsedMilliseconds(startedAt, h.now().UTC()),
	}); err != nil {
		return err
	}
	return h.audit.Event(ctx, audit.Event{
		EventType: eventType,
		Source:    string(source),
		RequestID: requestID,
		Decision:  string(decision),
		Summary:   "chat request reached a terminal state",
	})
}

func requestFingerprint(request provider.ChatRequest) string {
	hash := sha256.New()
	_, _ = io.WriteString(hash, request.Model)
	for _, message := range request.Messages {
		_, _ = io.WriteString(hash, "\x00"+message.Role+"\x00"+message.Content)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func inputSummary(messages []provider.ChatMessage) string {
	contentBytes := 0
	for _, message := range messages {
		contentBytes += len(message.Content)
	}
	return fmt.Sprintf("message_count=%d; content_bytes=%d", len(messages), contentBytes)
}

func outputSummary(contentBytes int) string {
	return fmt.Sprintf("content_bytes=%d", contentBytes)
}

func elapsedMilliseconds(startedAt, completedAt time.Time) int64 {
	if completedAt.Before(startedAt) {
		return 0
	}
	return completedAt.Sub(startedAt).Milliseconds()
}

func strongestDecision(first, second policy.Action) policy.Action {
	if first == policy.ActionBlock || second == policy.ActionBlock {
		return policy.ActionBlock
	}
	if first == policy.ActionRedact || second == policy.ActionRedact {
		return policy.ActionRedact
	}
	return policy.ActionPass
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

func writeAuditFailure(w http.ResponseWriter) {
	writeJSON(w, http.StatusInternalServerError, errorResponseDTO{
		Error: apiErrorDTO{
			Message: "required audit persistence failed",
			Type:    "server_error",
			Code:    "audit_persistence_failed",
		},
	})
}

func writeSecurityBlocked(w http.ResponseWriter, decision policy.Decision, code, message string) {
	detectionType := ""
	if len(decision.MatchedRules) > 0 {
		if strings.HasPrefix(decision.MatchedRules[0], "secret.") {
			detectionType = string(detection.DetectionTypeSecret)
		} else if strings.HasPrefix(decision.MatchedRules[0], "pii.") {
			detectionType = string(detection.DetectionTypePII)
		} else if strings.HasPrefix(decision.MatchedRules[0], "prompt.") {
			detectionType = string(detection.DetectionTypePromptInjection)
		}
	}
	ruleID := ""
	if len(decision.MatchedRules) > 0 {
		ruleID = decision.MatchedRules[0]
	}
	writeJSON(w, http.StatusForbidden, errorResponseDTO{Error: apiErrorDTO{
		Message:       message,
		Type:          "security_error",
		Code:          code,
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
