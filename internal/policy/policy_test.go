package policy

import (
	"testing"

	"github.com/bitesdust/agentguard/internal/detection"
)

func TestEngineEvaluate(t *testing.T) {
	t.Parallel()

	engine, err := NewEngine(Config{DefaultAction: ActionPass, Rules: []Rule{
		{ID: "input.secret.block.v1", DetectionType: detection.DetectionTypeSecret, MinScore: 0.98, Action: ActionBlock},
		{ID: "input.pii.redact.v1", DetectionType: detection.DetectionTypePII, MinScore: 0.80, Action: ActionRedact},
	}})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	tests := []struct {
		name    string
		results []detection.DetectionResult
		want    Action
	}{
		{name: "no detections", want: ActionPass},
		{name: "PII", results: []detection.DetectionResult{{DetectionType: detection.DetectionTypePII, RuleID: "pii.email.v1", Score: 0.80}}, want: ActionRedact},
		{name: "high-risk secret", results: []detection.DetectionResult{{DetectionType: detection.DetectionTypePII, RuleID: "pii.email.v1", Score: 0.80}, {DetectionType: detection.DetectionTypeSecret, RuleID: "secret.database_url.v1", Score: 0.98}}, want: ActionBlock},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision := engine.Evaluate(detection.SubjectTypeRequest, "request-test", test.results)
			if decision.Decision != test.want {
				t.Fatalf("decision = %s, want %s", decision.Decision, test.want)
			}
			if decision.RiskScore < 0 || decision.RiskScore > 1 {
				t.Fatalf("risk_score = %f outside [0,1]", decision.RiskScore)
			}
			if test.want == ActionBlock && (len(decision.MatchedRules) != 1 || decision.MatchedRules[0] != "secret.database_url.v1") {
				t.Fatalf("matched_rules = %v, want only triggering secret rule", decision.MatchedRules)
			}
		})
	}
}

func TestValidateRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()

	for _, config := range []Config{
		{DefaultAction: ActionApproval},
		{DefaultAction: ActionPass, Rules: []Rule{{ID: "bad-score", DetectionType: detection.DetectionTypePII, MinScore: 1.1, Action: ActionRedact}}},
		{DefaultAction: ActionPass, Rules: []Rule{{ID: "bad-action", DetectionType: detection.DetectionTypePII, Action: ActionApproval}}},
	} {
		if err := Validate(config); err == nil {
			t.Fatal("Validate() returned nil error")
		}
	}
}

func TestOutputEngineSetsOutputStage(t *testing.T) {
	t.Parallel()

	engine, err := NewEngine(Config{Stage: StageOutput, DefaultAction: ActionPass})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	decision := engine.Evaluate(detection.SubjectTypeRequest, "request-test", nil)
	if decision.Stage != StageOutput || decision.PolicyID != "output.default.v1" {
		t.Fatalf("decision = %+v, want output policy default", decision)
	}
}
