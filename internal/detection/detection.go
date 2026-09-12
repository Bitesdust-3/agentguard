// Package detection defines reusable, privacy-minimized risk facts and the
// small detector boundary used by AgentGuard's security pipeline.
package detection

import (
	"context"
	"fmt"
	"time"

	"github.com/bitesdust/agentguard/internal/identifier"
)

type DetectionType string

const (
	DetectionTypePII             DetectionType = "PII"
	DetectionTypeSecret          DetectionType = "SECRET"
	DetectionTypePromptInjection DetectionType = "PROMPT_INJECTION"
)

type Source string

const (
	SourceInput        Source = "INPUT"
	SourceOutput       Source = "OUTPUT"
	SourceToolArgument Source = "TOOL_ARGUMENT"
)

type SubjectType string

const (
	SubjectTypeRequest  SubjectType = "REQUEST"
	SubjectTypeToolCall SubjectType = "TOOL_CALL"
)

// DetectionResult is a structured, safe-to-store detector finding. Metadata contains
// only safe numeric location information; it never contains matched content.
type DetectionResult struct {
	ID            string            `json:"id"`
	SubjectType   SubjectType       `json:"subject_type"`
	SubjectID     string            `json:"subject_id"`
	DetectionType DetectionType     `json:"detection_type"`
	RuleID        string            `json:"rule_id"`
	Score         float64           `json:"score"`
	Confidence    float64           `json:"confidence"`
	Evidence      string            `json:"evidence"`
	Source        Source            `json:"source"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	CreatedAt     time.Time         `json:"created_at"`
}

// Input gives detectors an immutable subject and one text fragment to inspect.
type Input struct {
	SubjectType SubjectType
	SubjectID   string
	Source      Source
	Text        string
}

// Detector reports risk facts only. It never changes text or selects a policy
// decision.
type Detector interface {
	Detect(context.Context, Input) []DetectionResult
}

// Engine composes the enabled rule-based detectors and applies their configured
// minimum risk scores. It is deliberately not a detector registry.
type Engine struct {
	detectors  []Detector
	thresholds map[DetectionType]float64
}

func NewEngine(detectors []Detector, thresholds map[DetectionType]float64) *Engine {
	return &Engine{detectors: detectors, thresholds: thresholds}
}

func (e *Engine) Detect(ctx context.Context, input Input) []DetectionResult {
	var results []DetectionResult
	for _, detector := range e.detectors {
		for _, result := range detector.Detect(ctx, input) {
			if result.Score >= e.thresholds[result.DetectionType] {
				results = append(results, result)
			}
		}
	}
	return results
}

func NewResult(input Input, detectionType DetectionType, ruleID string, score, confidence float64, evidence string, start, end int) DetectionResult {
	return DetectionResult{
		ID:            nextID(),
		SubjectType:   input.SubjectType,
		SubjectID:     input.SubjectID,
		DetectionType: detectionType,
		RuleID:        ruleID,
		Score:         score,
		Confidence:    confidence,
		Evidence:      evidence,
		Source:        input.Source,
		Metadata: map[string]string{
			"start_offset": fmt.Sprintf("%d", start),
			"end_offset":   fmt.Sprintf("%d", end),
			"length":       fmt.Sprintf("%d", end-start),
		},
		CreatedAt: time.Now().UTC(),
	}
}

func nextID() string {
	return identifier.New("detection")
}
