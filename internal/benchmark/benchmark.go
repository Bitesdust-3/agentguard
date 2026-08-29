// Package benchmark executes versioned, fictional fixtures through production
// detectors and policies without HTTP, providers, or Tool Executors.
package benchmark

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/bitesdust/agentguard/internal/config"
	"github.com/bitesdust/agentguard/internal/detection"
	"github.com/bitesdust/agentguard/internal/policy"
	"github.com/bitesdust/agentguard/internal/tools"
	"gopkg.in/yaml.v3"
)

const (
	CategoryNormal   = "normal"
	CategoryPII      = "pii"
	CategorySecret   = "secret"
	CategoryDirect   = "direct_prompt_injection"
	CategoryIndirect = "indirect_prompt_injection"
	CategoryTool     = "tool_misuse"
	CategoryBypass   = "approval_bypass"
)

type Dataset struct {
	Version string   `yaml:"version" json:"version"`
	Samples []Sample `yaml:"samples" json:"samples"`
}

type Sample struct {
	ID                string `yaml:"id" json:"id"`
	Category          string `yaml:"category" json:"category"`
	Input             string `yaml:"input" json:"input"`
	ExpectedDetection *bool  `yaml:"expected_detection" json:"expected_detection"`
	ExpectedDecision  string `yaml:"expected_decision" json:"expected_decision"`
	ExpectedRule      string `yaml:"expected_rule" json:"expected_rule"`
	Notes             string `yaml:"notes" json:"notes"`
	ToolName          string `yaml:"tool_name" json:"tool_name"`
	TargetType        string `yaml:"target_type" json:"target_type"`
	External          bool   `yaml:"external" json:"external"`
	Destructive       bool   `yaml:"destructive" json:"destructive"`
	Sensitive         bool   `yaml:"sensitive" json:"sensitive"`
}

type Counts struct{ TP, FP, TN, FN int }

type Metrics struct {
	Counts            Counts
	Accuracy          float64
	Precision         float64
	Recall            float64
	FalsePositiveRate float64
	FalseNegativeRate float64
	DecisionAccuracy  float64
	SampleCount       int
	Passed            int
	Failed            int
	TotalLatency      time.Duration
	AverageLatency    time.Duration
	P50               time.Duration
	P95               time.Duration
}

type CaseResult struct {
	ID                string
	Category          string
	ExpectedDetection *bool
	ActualDetection   bool
	ExpectedDecision  policy.Action
	ActualDecision    policy.Action
	ExpectedRule      string
	MatchedRule       string
	Passed            bool
	Latency           time.Duration
	SafeReason        string
}

type Run struct {
	ID                string
	DatasetVersion    string
	DatasetHash       string
	ConfigHash        string
	ProviderMode      string
	RandomSeed        int64
	AgentGuardVersion string
	Status            string
	StartedAt         time.Time
	CompletedAt       time.Time
	TotalSamples      int
	Results           []CaseResult
	Metrics           Metrics
	ByCategory        map[string]Metrics
}

type Runner struct {
	detector   *detection.Engine
	policy     *policy.Engine
	tools      config.ToolsConfig
	configHash string
}

func Load(path string) (Dataset, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Dataset{}, fmt.Errorf("read dataset: %w", err)
	}
	var dataset Dataset
	if err := yaml.Unmarshal(data, &dataset); err != nil {
		return Dataset{}, fmt.Errorf("decode dataset: %w", err)
	}
	if err := ValidateDataset(dataset); err != nil {
		return Dataset{}, err
	}
	return dataset, nil
}

func ValidateDataset(dataset Dataset) error {
	if strings.TrimSpace(dataset.Version) == "" {
		return fmt.Errorf("dataset version is required")
	}
	if len(dataset.Samples) == 0 {
		return fmt.Errorf("dataset must contain samples")
	}
	seen := map[string]bool{}
	for i, sample := range dataset.Samples {
		if sample.ID == "" || seen[sample.ID] {
			return fmt.Errorf("samples[%d] has invalid or duplicate id", i)
		}
		seen[sample.ID] = true
		if !validCategory(sample.Category) {
			return fmt.Errorf("samples[%d] has unknown category %q", i, sample.Category)
		}
		if !validAction(sample.ExpectedDecision) {
			return fmt.Errorf("samples[%d] has invalid expected_decision", i)
		}
		if strings.TrimSpace(sample.Notes) == "" {
			return fmt.Errorf("samples[%d] requires notes", i)
		}
		if sample.Category == CategoryTool || sample.Category == CategoryBypass {
			if sample.ToolName == "" || sample.TargetType == "" {
				return fmt.Errorf("samples[%d] tool category requires tool_name and target_type", i)
			}
			if sample.ExpectedDetection != nil {
				return fmt.Errorf("samples[%d] tool category expected_detection must be null", i)
			}
		} else if sample.ExpectedDetection == nil || strings.TrimSpace(sample.Input) == "" {
			return fmt.Errorf("samples[%d] text category requires input and expected_detection", i)
		}
	}
	return nil
}

func DatasetHash(dataset Dataset) (string, error) {
	if err := ValidateDataset(dataset); err != nil {
		return "", err
	}
	canonical := Dataset{Version: dataset.Version, Samples: append([]Sample(nil), dataset.Samples...)}
	sort.Slice(canonical.Samples, func(i, j int) bool { return canonical.Samples[i].ID < canonical.Samples[j].ID })
	data, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	return hash(data), nil
}

func NewRunner(cfg config.Config) (*Runner, error) {
	detectors := make([]detection.Detector, 0, 3)
	thresholds := make(map[detection.DetectionType]float64, 3)
	if cfg.Detection.PII.Enabled {
		detectors = append(detectors, detection.NewPIIDetector())
		thresholds[detection.DetectionTypePII] = cfg.Detection.PII.Threshold
	}
	if cfg.Detection.Secret.Enabled {
		detectors = append(detectors, detection.NewSecretDetector())
		thresholds[detection.DetectionTypeSecret] = cfg.Detection.Secret.Threshold
	}
	if cfg.Detection.PromptInjection.Enabled {
		detectors = append(detectors, detection.NewPromptInjectionDetector())
		thresholds[detection.DetectionTypePromptInjection] = cfg.Detection.PromptInjection.Threshold
	}
	rules := make([]policy.Rule, 0, len(cfg.Policy.Input.Rules))
	for _, rule := range cfg.Policy.Input.Rules {
		rules = append(rules, policy.Rule{ID: rule.ID, DetectionType: detection.DetectionType(rule.When.DetectionType), MinScore: rule.When.MinScore, Action: policy.Action(rule.Action)})
	}
	engine, err := policy.NewEngine(policy.Config{Stage: policy.StageInput, DefaultAction: policy.Action(cfg.Policy.Input.DefaultAction), Rules: rules})
	if err != nil {
		return nil, err
	}
	securityConfig := struct {
		Detection config.DetectionConfig
		Policy    config.InputPolicyConfig
		Tools     config.ToolsConfig
	}{cfg.Detection, cfg.Policy.Input, cfg.Tools}
	data, err := json.Marshal(securityConfig)
	if err != nil {
		return nil, err
	}
	return &Runner{detector: detection.NewEngine(detectors, thresholds), policy: engine, tools: cfg.Tools, configHash: hash(data)}, nil
}

func (r *Runner) ConfigHash() string { return r.configHash }

func (r *Runner) Run(ctx context.Context, dataset Dataset, seed int64, version string) (Run, error) {
	if err := ValidateDataset(dataset); err != nil {
		return Run{}, err
	}
	datasetHash, err := DatasetHash(dataset)
	if err != nil {
		return Run{}, err
	}
	startedAt := time.Now().UTC()
	run := Run{ID: fmt.Sprintf("benchmark_%d", startedAt.UnixNano()), DatasetVersion: dataset.Version, DatasetHash: datasetHash, ConfigHash: r.configHash, ProviderMode: "internal", RandomSeed: seed, AgentGuardVersion: version, Status: "RUNNING", StartedAt: startedAt, TotalSamples: len(dataset.Samples), ByCategory: map[string]Metrics{}}
	for _, sample := range dataset.Samples {
		result := r.runCase(ctx, sample)
		run.Results = append(run.Results, result)
	}
	run.CompletedAt, run.Status = time.Now().UTC(), "COMPLETED"
	run.Metrics = calculateMetrics(run.Results)
	for _, category := range categories() {
		group := make([]CaseResult, 0)
		for _, result := range run.Results {
			if result.Category == category {
				group = append(group, result)
			}
		}
		run.ByCategory[category] = calculateMetrics(group)
	}
	return run, nil
}

func (r *Runner) runCase(ctx context.Context, sample Sample) CaseResult {
	result := CaseResult{ID: sample.ID, Category: sample.Category, ExpectedDetection: sample.ExpectedDetection, ExpectedDecision: policy.Action(sample.ExpectedDecision), ExpectedRule: sample.ExpectedRule}
	start := time.Now()
	baselineStart := time.Now()
	baseline := time.Since(baselineStart)
	if sample.Category == CategoryTool || sample.Category == CategoryBypass {
		decision, rule := tools.EvaluatePolicy(r.tools, tools.Request{ToolName: sample.ToolName, TargetType: sample.TargetType, External: sample.External, Destructive: sample.Destructive, Sensitive: sample.Sensitive})
		result.ActualDecision, result.MatchedRule = decision, rule
		result.ActualDetection = false
	} else {
		findings := r.detector.Detect(ctx, detection.Input{SubjectType: detection.SubjectTypeRequest, SubjectID: "benchmark_" + sample.ID, Source: detection.SourceInput, Text: sample.Input})
		result.ActualDetection = detectedForCategory(sample.Category, findings)
		result.MatchedRule = firstRule(findings)
		decision := r.policy.Evaluate(detection.SubjectTypeRequest, "benchmark_"+sample.ID, findings)
		result.ActualDecision = decision.Decision
		if sample.ExpectedRule != "" {
			result.MatchedRule = matchingRule(sample.ExpectedRule, findings)
		}
	}
	elapsed := time.Since(start) - baseline
	if elapsed < 0 {
		elapsed = 0
	}
	result.Latency = elapsed
	detectionPass := sample.ExpectedDetection == nil || result.ActualDetection == *sample.ExpectedDetection
	rulePass := sample.ExpectedRule == "" || result.MatchedRule == sample.ExpectedRule
	decisionPass := result.ActualDecision == result.ExpectedDecision
	result.Passed = detectionPass && rulePass && decisionPass
	result.SafeReason = safeReason(result, detectionPass, rulePass, decisionPass)
	return result
}

func calculateMetrics(results []CaseResult) Metrics {
	metrics := Metrics{SampleCount: len(results)}
	latencies := make([]time.Duration, 0, len(results))
	decisionTotal := 0
	for _, result := range results {
		if result.Passed {
			metrics.Passed++
		} else {
			metrics.Failed++
		}
		if result.ActualDecision == result.ExpectedDecision {
			decisionTotal++
		}
		latencies = append(latencies, result.Latency)
		metrics.TotalLatency += result.Latency
		if result.ExpectedDetection != nil {
			switch {
			case *result.ExpectedDetection && result.ActualDetection:
				metrics.Counts.TP++
			case *result.ExpectedDetection && !result.ActualDetection:
				metrics.Counts.FN++
			case !*result.ExpectedDetection && result.ActualDetection:
				metrics.Counts.FP++
			default:
				metrics.Counts.TN++
			}
		}
	}
	metrics.Accuracy = ratio(metrics.Counts.TP+metrics.Counts.TN, metrics.Counts.TP+metrics.Counts.TN+metrics.Counts.FP+metrics.Counts.FN)
	metrics.Precision = ratio(metrics.Counts.TP, metrics.Counts.TP+metrics.Counts.FP)
	metrics.Recall = ratio(metrics.Counts.TP, metrics.Counts.TP+metrics.Counts.FN)
	metrics.FalsePositiveRate = ratio(metrics.Counts.FP, metrics.Counts.FP+metrics.Counts.TN)
	metrics.FalseNegativeRate = ratio(metrics.Counts.FN, metrics.Counts.FN+metrics.Counts.TP)
	metrics.DecisionAccuracy = ratio(decisionTotal, len(results))
	if len(results) > 0 {
		metrics.AverageLatency = metrics.TotalLatency / time.Duration(len(results))
		sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
		metrics.P50 = percentile(latencies, 0.50)
		metrics.P95 = percentile(latencies, 0.95)
	}
	return metrics
}

// Summarize calculates presentation-safe aggregate metrics from persisted
// case outcomes. It does not inspect Dataset input content.
func Summarize(results []CaseResult) Metrics { return calculateMetrics(results) }

func Persist(ctx context.Context, db *sql.DB, run Run) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO benchmark_runs(id,dataset_version,dataset_hash,config_hash,provider_mode,random_seed,agentguard_version,status,total_samples,started_at,completed_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, run.ID, run.DatasetVersion, run.DatasetHash, run.ConfigHash, run.ProviderMode, run.RandomSeed, run.AgentGuardVersion, run.Status, run.TotalSamples, stamp(run.StartedAt), stamp(run.CompletedAt))
	if err != nil {
		return err
	}
	for index, result := range run.Results {
		var expected any
		if result.ExpectedDetection != nil {
			expected = *result.ExpectedDetection
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO benchmark_results(id,benchmark_run_id,case_id,category,expected_detection,actual_detection,expected_decision,actual_decision,expected_rule,matched_rule,passed,latency_ns,safe_reason,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, fmt.Sprintf("benchmark_result_%s_%d", run.ID, index), run.ID, result.ID, result.Category, expected, result.ActualDetection, result.ExpectedDecision, result.ActualDecision, nullString(result.ExpectedRule), nullString(result.MatchedRule), result.Passed, result.Latency.Nanoseconds(), result.SafeReason, stamp(run.CompletedAt))
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func validCategory(value string) bool {
	for _, category := range categories() {
		if value == category {
			return true
		}
	}
	return false
}
func categories() []string {
	return []string{CategoryNormal, CategoryPII, CategorySecret, CategoryDirect, CategoryIndirect, CategoryTool, CategoryBypass}
}
func validAction(value string) bool {
	return value == "PASS" || value == "REDACT" || value == "BLOCK" || value == "APPROVAL"
}
func hash(data []byte) string { value := sha256.Sum256(data); return hex.EncodeToString(value[:]) }
func ratio(n, d int) float64 {
	if d == 0 {
		return 0
	}
	return float64(n) / float64(d)
}
func percentile(values []time.Duration, fraction float64) time.Duration {
	if len(values) == 0 {
		return 0
	}
	index := int(float64(len(values)-1) * fraction)
	return values[index]
}
func firstRule(results []detection.DetectionResult) string {
	if len(results) == 0 {
		return ""
	}
	return results[0].RuleID
}
func matchingRule(want string, results []detection.DetectionResult) string {
	for _, result := range results {
		if result.RuleID == want {
			return want
		}
	}
	return firstRule(results)
}
func detectedForCategory(category string, results []detection.DetectionResult) bool {
	if category == CategoryNormal {
		return len(results) > 0
	}
	target := map[string]detection.DetectionType{CategoryPII: detection.DetectionTypePII, CategorySecret: detection.DetectionTypeSecret, CategoryDirect: detection.DetectionTypePromptInjection, CategoryIndirect: detection.DetectionTypePromptInjection}[category]
	for _, result := range results {
		if result.DetectionType == target {
			return true
		}
	}
	return false
}
func safeReason(result CaseResult, detectionPass, rulePass, decisionPass bool) string {
	parts := []string{}
	if !detectionPass {
		parts = append(parts, "detection mismatch")
	}
	if !rulePass {
		parts = append(parts, "rule mismatch")
	}
	if !decisionPass {
		parts = append(parts, "decision mismatch")
	}
	if len(parts) == 0 {
		return "expected safety outcome observed"
	}
	return strings.Join(parts, "; ")
}
func nullString(value string) any {
	if value == "" {
		return nil
	}
	return value
}
func stamp(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }
