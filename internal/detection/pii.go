package detection

import (
	"context"
	"regexp"
	"time"
)

type piiRule struct {
	id         string
	pattern    *regexp.Regexp
	score      float64
	confidence float64
	evidence   string
	valid      func(string) bool
}

// PIIDetector provides only the three rule-based PII formats in the v1 MVP.
type PIIDetector struct {
	rules []piiRule
}

func NewPIIDetector() *PIIDetector {
	return &PIIDetector{rules: []piiRule{
		{id: "pii.email.v1", pattern: regexp.MustCompile(`[A-Za-z0-9.!#$%&'*+/=?^_\x60{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+`), score: 0.80, confidence: 0.97, evidence: "email address detected (masked)"},
		{id: "pii.cn_mobile.v1", pattern: regexp.MustCompile(`(?:\+86[- ]?)?1[3-9][0-9]{9}\b`), score: 0.85, confidence: 0.96, evidence: "Chinese mainland mobile number detected (masked)"},
		{id: "pii.cn_id_card.v1", pattern: regexp.MustCompile(`\b[0-9]{17}[0-9Xx]\b`), score: 0.90, confidence: 0.99, evidence: "Chinese mainland identity-card number detected (masked)", valid: validChineseIDCard},
	}}
}

func (d *PIIDetector) Detect(_ context.Context, input Input) []DetectionResult {
	var results []DetectionResult
	for _, rule := range d.rules {
		for _, match := range rule.pattern.FindAllStringIndex(input.Text, -1) {
			value := input.Text[match[0]:match[1]]
			if rule.valid != nil && !rule.valid(value) {
				continue
			}
			results = append(results, NewResult(input, DetectionTypePII, rule.id, rule.score, rule.confidence, rule.evidence, match[0], match[1]))
		}
	}
	return results
}

func validChineseIDCard(value string) bool {
	if len(value) != 18 {
		return false
	}
	weights := [...]int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}
	checks := "10X98765432"
	sum := 0
	for i, weight := range weights {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
		sum += int(value[i]-'0') * weight
	}
	last := value[17]
	if last == 'x' {
		last = 'X'
	}
	if last != checks[sum%11] {
		return false
	}

	date, err := time.Parse("20060102", value[6:14])
	return err == nil && date.Format("20060102") == value[6:14]
}

var _ Detector = (*PIIDetector)(nil)
