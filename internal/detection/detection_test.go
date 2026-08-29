package detection

import (
	"context"
	"strings"
	"testing"
)

func TestSecretDetector(t *testing.T) {
	t.Parallel()

	openAIKey := "sk-agentguard-test-000000000000000000000"
	githubToken := "ghp_" + strings.Repeat("a", 36)
	tests := []struct {
		name   string
		text   string
		ruleID string
		secret string
	}{
		{name: "OpenAI-style key", text: "key=" + openAIKey, ruleID: "secret.openai_api_key.v1", secret: openAIKey},
		{name: "GitHub token", text: "token=" + githubToken, ruleID: "secret.github_token.v1", secret: githubToken},
		{name: "bearer token", text: "Authorization: Bearer agentguard-demo-token-000000", ruleID: "secret.bearer_token.v1", secret: "Bearer agentguard-demo-token-000000"},
		{name: "password assignment", text: "password=fictional-password-123", ruleID: "secret.password_assignment.v1", secret: "password=fictional-password-123"},
		{name: "database URL", text: "postgres://demo:fictional-password@example.invalid/agentguard", ruleID: "secret.database_url.v1", secret: "postgres://demo:fictional-password@example.invalid/agentguard"},
		{name: "generic assignment", text: "api_key=agentguard-fake-value-000000", ruleID: "secret.assignment.v1", secret: "api_key=agentguard-fake-value-000000"},
	}

	detector := NewSecretDetector()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := detector.Detect(context.Background(), testInput(test.text))
			if len(results) == 0 {
				t.Fatal("Detect() returned no findings")
			}
			result := results[0]
			if result.RuleID != test.ruleID {
				t.Fatalf("rule_id = %q, want %q", result.RuleID, test.ruleID)
			}
			if result.DetectionType != DetectionTypeSecret || result.Score < 0 || result.Score > 1 || result.Confidence < 0 || result.Confidence > 1 {
				t.Fatalf("invalid detection result: %+v", result)
			}
			if strings.Contains(result.Evidence, test.secret) {
				t.Fatalf("evidence leaked complete secret: %q", result.Evidence)
			}
		})
	}
}

func TestSecretDetectorNegativeCases(t *testing.T) {
	t.Parallel()

	for _, text := range []string{
		"The password policy is documented here.",
		"Explain what a token is.",
		"An API key identifies a client.",
		"This email example contains no address.",
	} {
		if results := NewSecretDetector().Detect(context.Background(), testInput(text)); len(results) != 0 {
			t.Fatalf("Detect(%q) = %+v, want no findings", text, results)
		}
	}
}

func TestPIIDetector(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		text   string
		ruleID string
	}{
		{name: "email", text: "contact demo.user@example.test", ruleID: "pii.email.v1"},
		{name: "Chinese mainland mobile", text: "phone 13800138000", ruleID: "pii.cn_mobile.v1"},
		{name: "valid Chinese identity card", text: "ID 11010519491231002X", ruleID: "pii.cn_id_card.v1"},
	}

	detector := NewPIIDetector()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := detector.Detect(context.Background(), testInput(test.text))
			if len(results) != 1 || results[0].RuleID != test.ruleID {
				t.Fatalf("Detect() = %+v, want %q", results, test.ruleID)
			}
		})
	}
}

func TestPIIDetectorRejectsInvalidOrOrdinaryNumbers(t *testing.T) {
	t.Parallel()

	for _, text := range []string{
		"ID 110105194912310021", // checksum is invalid.
		"There are 1234567890 items.",
		"The email field is optional.",
	} {
		if results := NewPIIDetector().Detect(context.Background(), testInput(text)); len(results) != 0 {
			t.Fatalf("Detect(%q) = %+v, want no findings", text, results)
		}
	}
}

func TestRedact(t *testing.T) {
	t.Parallel()

	detector := NewPIIDetector()
	text := "email demo.user@example.test and phone 13800138000 remain private"
	redacted, operations := Redact(text, detector.Detect(context.Background(), testInput(text)))
	if got, want := redacted, "email [REDACTED_EMAIL] and phone [REDACTED_PHONE] remain private"; got != want {
		t.Fatalf("Redact() = %q, want %q", got, want)
	}
	if len(operations) != 2 {
		t.Fatalf("redaction operations = %d, want 2", len(operations))
	}
}

func TestRedactOverlappingMatchesIsStable(t *testing.T) {
	t.Parallel()

	text := "abcdefghij"
	results := []DetectionResult{
		NewResult(testInput(text), DetectionTypeSecret, "secret.assignment.v1", 0.85, 0.90, "masked", 2, 8),
		NewResult(testInput(text), DetectionTypeSecret, "secret.assignment.v1", 0.85, 0.90, "masked", 2, 6),
	}
	redacted, operations := Redact(text, results)
	if got, want := redacted, "ab[REDACTED_SECRET]ij"; got != want {
		t.Fatalf("Redact() = %q, want %q", got, want)
	}
	if len(operations) != 1 {
		t.Fatalf("operations = %d, want 1", len(operations))
	}
}

func TestSecretRedactionPreservesAssignmentContext(t *testing.T) {
	t.Parallel()

	text := "password=fictional-password-123"
	redacted, operations := Redact(text, NewSecretDetector().Detect(context.Background(), testInput(text)))
	if got, want := redacted, "password=[REDACTED_SECRET]"; got != want {
		t.Fatalf("Redact() = %q, want %q", got, want)
	}
	if len(operations) != 1 {
		t.Fatalf("operations = %d, want 1", len(operations))
	}
}

func testInput(text string) Input {
	return Input{SubjectType: SubjectTypeRequest, SubjectID: "request-test", Source: SourceInput, Text: text}
}
