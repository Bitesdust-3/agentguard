// Package config loads the small runtime configuration needed by the current
// AgentGuard infrastructure layer.
package config

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config contains only the settings implemented in the current stage.
type Config struct {
	Server    ServerConfig    `yaml:"server"`
	Storage   StorageConfig   `yaml:"storage"`
	Provider  ProviderConfig  `yaml:"provider"`
	Detection DetectionConfig `yaml:"detection"`
	Policy    PolicyConfig    `yaml:"policy"`
}

type ServerConfig struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

type StorageConfig struct {
	SQLitePath string `yaml:"sqlite_path"`
}

type ProviderConfig struct {
	Type string `yaml:"type"`
}

type DetectionConfig struct {
	PII             DetectorConfig `yaml:"pii"`
	Secret          DetectorConfig `yaml:"secret"`
	PromptInjection DetectorConfig `yaml:"prompt_injection"`
}

type DetectorConfig struct {
	Enabled   bool    `yaml:"enabled"`
	Threshold float64 `yaml:"threshold"`
}

type PolicyConfig struct {
	Input  InputPolicyConfig `yaml:"input"`
	Output InputPolicyConfig `yaml:"output"`
}

type InputPolicyConfig struct {
	DefaultAction string       `yaml:"default_action"`
	Rules         []PolicyRule `yaml:"rules"`
}

type PolicyRule struct {
	ID     string         `yaml:"id"`
	When   PolicyRuleWhen `yaml:"when"`
	Action string         `yaml:"action"`
}

type PolicyRuleWhen struct {
	DetectionType string  `yaml:"detection_type"`
	MinScore      float64 `yaml:"min_score"`
}

// Default returns a safe local-development configuration.
func Default() Config {
	return Config{
		Server: ServerConfig{
			Host: "127.0.0.1",
			Port: 8080,
		},
		Storage: StorageConfig{
			SQLitePath: "data/agentguard.db",
		},
		Provider: ProviderConfig{Type: "mock"},
		Detection: DetectionConfig{
			PII:             DetectorConfig{Enabled: true, Threshold: 0.80},
			Secret:          DetectorConfig{Enabled: true, Threshold: 0.80},
			PromptInjection: DetectorConfig{Enabled: true, Threshold: 0.85},
		},
		Policy: PolicyConfig{Input: InputPolicyConfig{
			DefaultAction: "PASS",
			Rules: []PolicyRule{
				{ID: "input.secret.block.v1", When: PolicyRuleWhen{DetectionType: "SECRET", MinScore: 0.98}, Action: "BLOCK"},
				{ID: "input.secret.redact.v1", When: PolicyRuleWhen{DetectionType: "SECRET", MinScore: 0.80}, Action: "REDACT"},
				{ID: "input.pii.redact.v1", When: PolicyRuleWhen{DetectionType: "PII", MinScore: 0.80}, Action: "REDACT"},
				{ID: "input.prompt_injection.block.v1", When: PolicyRuleWhen{DetectionType: "PROMPT_INJECTION", MinScore: 0.85}, Action: "BLOCK"},
			},
		}, Output: InputPolicyConfig{
			DefaultAction: "PASS",
			Rules: []PolicyRule{
				{ID: "output.secret.block.v1", When: PolicyRuleWhen{DetectionType: "SECRET", MinScore: 0.98}, Action: "BLOCK"},
				{ID: "output.secret.redact.v1", When: PolicyRuleWhen{DetectionType: "SECRET", MinScore: 0.80}, Action: "REDACT"},
				{ID: "output.pii.redact.v1", When: PolicyRuleWhen{DetectionType: "PII", MinScore: 0.80}, Action: "REDACT"},
			},
		}},
	}
}

// Load reads a YAML file. An empty path selects the built-in defaults.
func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read configuration: %w", err)
	}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode configuration: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate reports configuration errors before the server starts.
func (c Config) Validate() error {
	if strings.TrimSpace(c.Server.Host) == "" {
		return fmt.Errorf("server.host must not be empty")
	}
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("server.port must be between 1 and 65535")
	}
	if strings.TrimSpace(c.Storage.SQLitePath) == "" {
		return fmt.Errorf("storage.sqlite_path must not be empty")
	}
	if c.Provider.Type != "mock" {
		return fmt.Errorf("provider.type must be mock")
	}
	if err := validateDetectorConfig("detection.pii", c.Detection.PII); err != nil {
		return err
	}
	if err := validateDetectorConfig("detection.secret", c.Detection.Secret); err != nil {
		return err
	}
	if err := validateDetectorConfig("detection.prompt_injection", c.Detection.PromptInjection); err != nil {
		return err
	}
	if err := validateTextPolicyConfig("policy.input", c.Policy.Input); err != nil {
		return err
	}
	return validateTextPolicyConfig("policy.output", c.Policy.Output)
}

func validateTextPolicyConfig(name string, policy InputPolicyConfig) error {
	if !validTextPolicyAction(policy.DefaultAction) {
		return fmt.Errorf("%s.default_action must be PASS, REDACT, or BLOCK", name)
	}
	for index, rule := range policy.Rules {
		if strings.TrimSpace(rule.ID) == "" {
			return fmt.Errorf("%s.rules[%d].id must not be empty", name, index)
		}
		if rule.When.DetectionType != "PII" && rule.When.DetectionType != "SECRET" && rule.When.DetectionType != "PROMPT_INJECTION" {
			return fmt.Errorf("%s.rules[%d].when.detection_type must be PII, SECRET, or PROMPT_INJECTION", name, index)
		}
		if rule.When.MinScore < 0 || rule.When.MinScore > 1 {
			return fmt.Errorf("%s.rules[%d].when.min_score must be between 0 and 1", name, index)
		}
		if !validTextPolicyAction(rule.Action) {
			return fmt.Errorf("%s.rules[%d].action must be PASS, REDACT, or BLOCK", name, index)
		}
	}
	return nil
}

func validateDetectorConfig(name string, config DetectorConfig) error {
	if config.Threshold < 0 || config.Threshold > 1 {
		return fmt.Errorf("%s.threshold must be between 0 and 1", name)
	}
	return nil
}

func validTextPolicyAction(action string) bool {
	return action == "PASS" || action == "REDACT" || action == "BLOCK"
}

// ListenAddr returns the configured host and port in a form accepted by
// net/http.
func (c Config) ListenAddr() string {
	return net.JoinHostPort(c.Server.Host, strconv.Itoa(c.Server.Port))
}
