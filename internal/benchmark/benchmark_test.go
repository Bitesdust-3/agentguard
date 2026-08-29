package benchmark

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bitesdust/agentguard/internal/config"
	"github.com/bitesdust/agentguard/internal/storage"
)

func TestLoadDevelopmentDatasetAndRunProductionLogic(t *testing.T) {
	dataset, err := Load(filepath.Join("..", "..", "tests", "benchmark", "development.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(dataset.Samples) != 42 {
		t.Fatalf("samples = %d, want 42", len(dataset.Samples))
	}
	runner, err := NewRunner(config.Default())
	if err != nil {
		t.Fatal(err)
	}
	run, err := runner.Run(context.Background(), dataset, 42, "test")
	if err != nil {
		t.Fatal(err)
	}
	if run.TotalSamples != 42 || len(run.Results) != 42 || run.Status != "COMPLETED" {
		t.Fatalf("unexpected run: %+v", run)
	}
	if run.ByCategory[CategoryTool].SampleCount != 6 || run.ByCategory[CategoryBypass].SampleCount != 6 {
		t.Fatalf("tool category metrics missing: %+v", run.ByCategory)
	}
	for _, result := range run.Results {
		if result.ID == "tool-002" && string(result.ActualDecision) != "APPROVAL" {
			t.Fatalf("tool policy not reused: %+v", result)
		}
		if result.ID == "tool-004" && string(result.ActualDecision) != "BLOCK" {
			t.Fatalf("tool block not reused: %+v", result)
		}
		if result.ID == "bypass-001" && string(result.ActualDecision) == "PASS" {
			t.Fatalf("approval bypass became PASS: %+v", result)
		}
	}
}

func TestDatasetValidationAndHashes(t *testing.T) {
	positive := true
	dataset := Dataset{Version: "v1", Samples: []Sample{{ID: "one", Category: CategoryPII, Input: "demo@example.test", ExpectedDetection: &positive, ExpectedDecision: "REDACT", Notes: "fictional"}}}
	first, err := DatasetHash(dataset)
	if err != nil {
		t.Fatal(err)
	}
	second, err := DatasetHash(dataset)
	if err != nil || first != second {
		t.Fatalf("hash unstable: %q %q %v", first, second, err)
	}
	dataset.Samples[0].Notes = "changed"
	changed, err := DatasetHash(dataset)
	if err != nil || changed == first {
		t.Fatalf("hash did not change: %q %q", first, changed)
	}
	for _, invalid := range []Dataset{
		{Version: "v1", Samples: []Sample{{ID: "one", Category: CategoryNormal, Input: "a", ExpectedDetection: &positive, ExpectedDecision: "PASS", Notes: "x"}, {ID: "one", Category: CategoryNormal, Input: "b", ExpectedDetection: &positive, ExpectedDecision: "PASS", Notes: "x"}}},
		{Version: "v1", Samples: []Sample{{ID: "one", Category: "unknown", Input: "a", ExpectedDetection: &positive, ExpectedDecision: "PASS", Notes: "x"}}},
		{Version: "v1", Samples: []Sample{{ID: "one", Category: CategoryNormal, Input: "a", ExpectedDetection: &positive, ExpectedDecision: "ALLOW", Notes: "x"}}},
	} {
		if err := ValidateDataset(invalid); err == nil {
			t.Fatal("invalid dataset accepted")
		}
	}
	runner, err := NewRunner(config.Default())
	if err != nil {
		t.Fatal(err)
	}
	if runner.ConfigHash() != runner.ConfigHash() || runner.ConfigHash() == "" {
		t.Fatal("config hash unstable")
	}
}

func TestMetricsAndPersistenceNeverStoreRawInput(t *testing.T) {
	trueValue, falseValue := true, false
	metrics := calculateMetrics([]CaseResult{
		{ExpectedDetection: &trueValue, ActualDetection: true, ExpectedDecision: "PASS", ActualDecision: "PASS", Passed: true, Latency: 4},
		{ExpectedDetection: &falseValue, ActualDetection: true, ExpectedDecision: "PASS", ActualDecision: "PASS", Passed: false, Latency: 3},
		{ExpectedDetection: &falseValue, ActualDetection: false, ExpectedDecision: "PASS", ActualDecision: "BLOCK", Passed: false, Latency: 2},
		{ExpectedDetection: &trueValue, ActualDetection: false, ExpectedDecision: "PASS", ActualDecision: "PASS", Passed: false, Latency: 1},
	})
	if metrics.Counts != (Counts{TP: 1, FP: 1, TN: 1, FN: 1}) || metrics.Accuracy != 0.5 || metrics.Precision != 0.5 || metrics.Recall != 0.5 || metrics.FalsePositiveRate != 0.5 || metrics.FalseNegativeRate != 0.5 || metrics.DecisionAccuracy != 0.75 || metrics.P50 != 2 || metrics.P95 != 3 {
		t.Fatalf("unexpected metrics: %+v", metrics)
	}
	if empty := calculateMetrics(nil); empty.Accuracy != 0 || empty.Precision != 0 || empty.Recall != 0 || empty.FalsePositiveRate != 0 || empty.FalseNegativeRate != 0 {
		t.Fatalf("zero denominator produced nonzero metric: %+v", empty)
	}

	positive := true
	dataset := Dataset{Version: "persist-v1", Samples: []Sample{{ID: "secret", Category: CategorySecret, Input: "sk-agentguard-persist-fake-000000000000000000", ExpectedDetection: &positive, ExpectedDecision: "REDACT", ExpectedRule: "secret.openai_api_key.v1", Notes: "synthetic"}}}
	runner, err := NewRunner(config.Default())
	if err != nil {
		t.Fatal(err)
	}
	run, err := runner.Run(context.Background(), dataset, 7, "test")
	if err != nil {
		t.Fatal(err)
	}
	store, err := storage.Open(context.Background(), filepath.Join(t.TempDir(), "benchmark.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := Persist(context.Background(), store.DB(), run); err != nil {
		t.Fatal(err)
	}
	var runCount, resultCount int
	if err := store.DB().QueryRow("SELECT COUNT(*) FROM benchmark_runs").Scan(&runCount); err != nil {
		t.Fatal(err)
	}
	if err := store.DB().QueryRow("SELECT COUNT(*) FROM benchmark_results").Scan(&resultCount); err != nil {
		t.Fatal(err)
	}
	if runCount != 1 || resultCount != 1 {
		t.Fatalf("persisted rows: %d %d", runCount, resultCount)
	}
	rows, err := store.DB().Query(`SELECT id,benchmark_run_id,case_id,category,COALESCE(expected_rule,''),COALESCE(matched_rule,''),safe_reason FROM benchmark_results`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var values [7]string
		pointers := make([]any, len(values))
		for i := range values {
			pointers[i] = &values[i]
		}
		if err := rows.Scan(pointers...); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(strings.Join(values[:], "|"), dataset.Samples[0].Input) {
			t.Fatal("raw benchmark input persisted")
		}
	}
}
