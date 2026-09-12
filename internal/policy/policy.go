// Package policy maps detector facts and fixed configuration to a security
// action. It intentionally never reads or scans raw request content.
package policy

import (
	"fmt"
	"strings"
	"time"

	"github.com/bitesdust/agentguard/internal/detection"
	"github.com/bitesdust/agentguard/internal/identifier"
)

type Action string

const (
	ActionPass     Action = "PASS"
	ActionRedact   Action = "REDACT"
	ActionBlock    Action = "BLOCK"
	ActionApproval Action = "APPROVAL"
)

type Stage string

const (
	StageInput  Stage = "INPUT"
	StageOutput Stage = "OUTPUT"
	StageTool   Stage = "TOOL"
)

type Rule struct {
	ID            string
	DetectionType detection.DetectionType
	MinScore      float64
	Action        Action
}

type Config struct {
	Stage         Stage
	DefaultAction Action
	Rules         []Rule
}

type Decision struct {
	ID               string                `json:"id"`
	SubjectType      detection.SubjectType `json:"subject_type"`
	SubjectID        string                `json:"subject_id"`
	Stage            Stage                 `json:"stage"`
	Decision         Action                `json:"decision"`
	PolicyID         string                `json:"policy_id"`
	Reason           string                `json:"reason"`
	RiskScore        float64               `json:"risk_score"`
	MatchedRules     []string              `json:"matched_rules"`
	Redactions       []detection.Redaction `json:"redactions,omitempty"`
	ApprovalRequired bool                  `json:"approval_required"`
	CreatedAt        time.Time             `json:"created_at"`
}

type Engine struct {
	config Config
}

func NewEngine(config Config) (*Engine, error) {
	if config.Stage == "" {
		config.Stage = StageInput
	}
	if err := Validate(config); err != nil {
		return nil, err
	}
	return &Engine{config: config}, nil
}

// Evaluate chooses the first matching configured rule. Rules are evaluated in
// YAML order, making precedence explicit and easy to audit.
func (e *Engine) Evaluate(subjectType detection.SubjectType, subjectID string, results []detection.DetectionResult) Decision {
	decision := Decision{
		ID:               nextID(),
		SubjectType:      subjectType,
		SubjectID:        subjectID,
		Stage:            e.config.Stage,
		Decision:         e.config.DefaultAction,
		PolicyID:         strings.ToLower(string(e.config.Stage)) + ".default.v1",
		Reason:           strings.ToLower(string(e.config.Stage)) + " policy default applied",
		RiskScore:        maxRiskScore(results),
		MatchedRules:     matchingDetectorRules(results),
		ApprovalRequired: false,
		CreatedAt:        time.Now().UTC(),
	}
	for _, rule := range e.config.Rules {
		if matches(rule, results) {
			decision.Decision = rule.Action
			decision.PolicyID = rule.ID
			decision.Reason = strings.ToLower(string(e.config.Stage)) + " detection matched configured policy"
			decision.MatchedRules = matchingRulesForPolicy(rule, results)
			return decision
		}
	}
	return decision
}

func matchingRulesForPolicy(rule Rule, results []detection.DetectionResult) []string {
	matching := make([]detection.DetectionResult, 0, len(results))
	for _, result := range results {
		if result.DetectionType == rule.DetectionType && result.Score >= rule.MinScore {
			matching = append(matching, result)
		}
	}
	return matchingDetectorRules(matching)
}

func Validate(config Config) error {
	if config.Stage != "" && config.Stage != StageInput && config.Stage != StageOutput {
		return fmt.Errorf("policy stage must be INPUT or OUTPUT")
	}
	if !validAction(config.DefaultAction) {
		return fmt.Errorf("policy default_action must be PASS, REDACT, or BLOCK")
	}
	for index, rule := range config.Rules {
		if strings.TrimSpace(rule.ID) == "" {
			return fmt.Errorf("policy rules[%d].id must not be empty", index)
		}
		if !validDetectionType(rule.DetectionType) {
			return fmt.Errorf("policy rules[%d].when.detection_type is invalid", index)
		}
		if rule.MinScore < 0 || rule.MinScore > 1 {
			return fmt.Errorf("policy rules[%d].when.min_score must be between 0 and 1", index)
		}
		if !validAction(rule.Action) {
			return fmt.Errorf("policy rules[%d].action must be PASS, REDACT, or BLOCK", index)
		}
	}
	return nil
}

func validAction(action Action) bool {
	return action == ActionPass || action == ActionRedact || action == ActionBlock
}

func validDetectionType(detectionType detection.DetectionType) bool {
	return detectionType == detection.DetectionTypePII || detectionType == detection.DetectionTypeSecret || detectionType == detection.DetectionTypePromptInjection
}

func matches(rule Rule, results []detection.DetectionResult) bool {
	for _, result := range results {
		if result.DetectionType == rule.DetectionType && result.Score >= rule.MinScore {
			return true
		}
	}
	return false
}

func maxRiskScore(results []detection.DetectionResult) float64 {
	var max float64
	for _, result := range results {
		if result.Score > max {
			max = result.Score
		}
	}
	return max
}

func matchingDetectorRules(results []detection.DetectionResult) []string {
	if len(results) == 0 {
		return []string{}
	}
	ids := make([]string, 0, len(results))
	seen := make(map[string]struct{}, len(results))
	for _, result := range results {
		if _, exists := seen[result.RuleID]; !exists {
			ids = append(ids, result.RuleID)
			seen[result.RuleID] = struct{}{}
		}
	}
	return ids
}

func nextID() string {
	return identifier.New("policy")
}
