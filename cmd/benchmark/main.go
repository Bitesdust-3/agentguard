package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/bitesdust/agentguard/internal/benchmark"
	"github.com/bitesdust/agentguard/internal/config"
	"github.com/bitesdust/agentguard/internal/storage"
)

const version = "dev"

func main() {
	configPath := flag.String("config", "", "path to AgentGuard YAML configuration")
	datasetPath := flag.String("dataset", "tests/benchmark/development.yaml", "path to benchmark dataset")
	seed := flag.Int64("seed", 42, "fixed reproducibility seed")
	flag.Parse()
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load config:", err)
		os.Exit(1)
	}
	dataset, err := benchmark.Load(*datasetPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load dataset:", err)
		os.Exit(1)
	}
	runner, err := benchmark.NewRunner(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "create runner:", err)
		os.Exit(1)
	}
	run, err := runner.Run(context.Background(), dataset, *seed, version)
	if err != nil {
		fmt.Fprintln(os.Stderr, "run benchmark:", err)
		os.Exit(1)
	}
	store, err := storage.Open(context.Background(), cfg.Storage.SQLitePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open storage:", err)
		os.Exit(1)
	}
	defer store.Close()
	if err := benchmark.Persist(context.Background(), store.DB(), run); err != nil {
		fmt.Fprintln(os.Stderr, "persist benchmark:", err)
		os.Exit(1)
	}
	fmt.Printf("Benchmark %s: samples=%d accuracy=%.3f precision=%.3f recall=%.3f fpr=%.3f fnr=%.3f decision_accuracy=%.3f average_added_latency=%s p50=%s p95=%s\n", run.ID, run.Metrics.SampleCount, run.Metrics.Accuracy, run.Metrics.Precision, run.Metrics.Recall, run.Metrics.FalsePositiveRate, run.Metrics.FalseNegativeRate, run.Metrics.DecisionAccuracy, run.Metrics.AverageLatency, run.Metrics.P50, run.Metrics.P95)
	fmt.Printf("  dataset_hash=%s config_hash=%s seed=%d version=%s\n", run.DatasetHash, run.ConfigHash, run.RandomSeed, run.AgentGuardVersion)
	fmt.Printf("  tp=%d fp=%d tn=%d fn=%d\n", run.Metrics.Counts.TP, run.Metrics.Counts.FP, run.Metrics.Counts.TN, run.Metrics.Counts.FN)
	for _, category := range []string{benchmark.CategoryNormal, benchmark.CategoryPII, benchmark.CategorySecret, benchmark.CategoryDirect, benchmark.CategoryIndirect, benchmark.CategoryTool, benchmark.CategoryBypass} {
		metrics := run.ByCategory[category]
		fmt.Printf("  %s: samples=%d detection_accuracy=%s decision_accuracy=%.3f\n", category, metrics.SampleCount, detectionAccuracy(metrics), metrics.DecisionAccuracy)
	}
	failures, decisionMismatches, ruleMismatches := 0, 0, 0
	for _, result := range run.Results {
		if result.ActualDecision != result.ExpectedDecision {
			decisionMismatches++
		}
		if result.ExpectedRule != "" && result.MatchedRule != result.ExpectedRule {
			ruleMismatches++
		}
		if result.Passed {
			continue
		}
		failures++
		fmt.Printf("  failure sample_id=%s category=%s expected=%s actual=%s matched_rule=%s reason=%s\n", result.ID, result.Category, result.ExpectedDecision, result.ActualDecision, valueOrNone(result.MatchedRule), result.SafeReason)
	}
	fmt.Printf("  failures=%d passed=%d decision_mismatches=%d rule_mismatches=%d\n", failures, run.Metrics.Passed, decisionMismatches, ruleMismatches)
}

func detectionAccuracy(metrics benchmark.Metrics) string {
	counts := metrics.Counts
	if counts.TP+counts.FP+counts.TN+counts.FN == 0 {
		return "N/A"
	}
	return fmt.Sprintf("%.3f", metrics.Accuracy)
}

func valueOrNone(value string) string {
	if value == "" {
		return "none"
	}
	return value
}
