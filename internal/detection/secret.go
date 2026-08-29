package detection

import (
	"context"
	"regexp"
)

type secretRule struct {
	id         string
	pattern    *regexp.Regexp
	matchGroup int
	score      float64
	confidence float64
}

// SecretDetector contains a deliberately small set of high-value credential
// formats. Its evidence describes a match without retaining the value.
type SecretDetector struct {
	rules []secretRule
}

func NewSecretDetector() *SecretDetector {
	return &SecretDetector{rules: []secretRule{
		{id: "secret.openai_api_key.v1", pattern: regexp.MustCompile(`\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b`), score: 0.95, confidence: 0.98},
		{id: "secret.github_token.v1", pattern: regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{20,})\b`), score: 0.95, confidence: 0.98},
		{id: "secret.bearer_token.v1", pattern: regexp.MustCompile(`(?i)\bBearer[[:space:]]+([A-Za-z0-9._~+/-]{16,})\b`), matchGroup: 1, score: 0.90, confidence: 0.94},
		{id: "secret.database_url.v1", pattern: regexp.MustCompile("(?i)\\b(?:postgres(?:ql)?|mysql|mongodb(?:\\+srv)?|sqlite)://[^[:space:]\\\"'`]+"), score: 0.98, confidence: 0.97},
		{id: "secret.password_assignment.v1", pattern: regexp.MustCompile(`(?i)\b(?:password|passwd|pwd)[[:space:]]*[:=][[:space:]]*([A-Za-z0-9._~+/-]{8,})`), matchGroup: 1, score: 0.90, confidence: 0.93},
		{id: "secret.assignment.v1", pattern: regexp.MustCompile(`(?i)\b(?:secret|token|api[_-]?key)[[:space:]]*[:=][[:space:]]*([A-Za-z0-9._~+/-]{16,})`), matchGroup: 1, score: 0.85, confidence: 0.90},
	}}
}

func (d *SecretDetector) Detect(_ context.Context, input Input) []DetectionResult {
	var results []DetectionResult
	for _, rule := range d.rules {
		for _, match := range rule.pattern.FindAllStringSubmatchIndex(input.Text, -1) {
			start, end := match[0], match[1]
			if rule.matchGroup > 0 {
				start, end = match[2*rule.matchGroup], match[2*rule.matchGroup+1]
			}
			results = append(results, NewResult(
				input,
				DetectionTypeSecret,
				rule.id,
				rule.score,
				rule.confidence,
				"credential-like value detected (masked)",
				start,
				end,
			))
		}
	}
	return results
}

var _ Detector = (*SecretDetector)(nil)
