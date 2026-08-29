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
	fmt.Printf("Benchmark %s: samples=%d accuracy=%.3f precision=%.3f recall=%.3f fpr=%.3f fnr=%.3f decision_accuracy=%.3f average_added_latency=%s\n", run.ID, run.Metrics.SampleCount, run.Metrics.Accuracy, run.Metrics.Precision, run.Metrics.Recall, run.Metrics.FalsePositiveRate, run.Metrics.FalseNegativeRate, run.Metrics.DecisionAccuracy, run.Metrics.AverageLatency)
	for _, category := range []string{benchmark.CategoryNormal, benchmark.CategoryPII, benchmark.CategorySecret, benchmark.CategoryDirect, benchmark.CategoryIndirect, benchmark.CategoryTool, benchmark.CategoryBypass} {
		metrics := run.ByCategory[category]
		fmt.Printf("  %s: samples=%d detection_accuracy=%s decision_accuracy=%.3f\n", category, metrics.SampleCount, detectionAccuracy(metrics), metrics.DecisionAccuracy)
	}
}

func detectionAccuracy(metrics benchmark.Metrics) string {
	counts := metrics.Counts
	if counts.TP+counts.FP+counts.TN+counts.FN == 0 {
		return "N/A"
	}
	return fmt.Sprintf("%.3f", metrics.Accuracy)
}
