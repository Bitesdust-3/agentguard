package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoad(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.yaml")
	contents := "server:\n  host: 127.0.0.1\n  port: 9090\nstorage:\n  sqlite_path: test.db\nprovider:\n  type: mock\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write configuration: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load configuration: %v", err)
	}
	if got, want := cfg.ListenAddr(), "127.0.0.1:9090"; got != want {
		t.Fatalf("ListenAddr() = %q, want %q", got, want)
	}
	if got, want := cfg.Storage.SQLitePath, "test.db"; got != want {
		t.Fatalf("SQLitePath = %q, want %q", got, want)
	}
}

func TestLoadRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.yaml")
	contents := "server:\n  host: ''\n  port: 70000\nstorage:\n  sqlite_path: ''\nprovider:\n  type: mock\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write configuration: %v", err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() returned nil error for invalid configuration")
	}
	if !strings.Contains(err.Error(), "server.host") {
		t.Fatalf("Load() error = %q, want server.host error", err)
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.yaml")
	contents := "server:\n  host: 127.0.0.1\n  port: 8080\n  unknown: true\nstorage:\n  sqlite_path: test.db\nprovider:\n  type: mock\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write configuration: %v", err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() returned nil error for unknown field")
	}
}

func TestLoadRejectsUnknownProvider(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.yaml")
	contents := "provider:\n  type: unknown\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write configuration: %v", err)
	}

	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "provider.type") {
		t.Fatalf("Load() error = %v, want provider.type error", err)
	}
}

func TestOpenAICompatibleProviderConfiguration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	contents := "provider:\n  type: openai_compatible\n  base_url: https://api.example.invalid\n  model: fixture-model\n  timeout_ms: 15000\n  api_key_env: AGENTGUARD_PROVIDER_API_KEY\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Provider.Model != "fixture-model" || cfg.Provider.TimeoutMS != 15000 || cfg.Provider.APIKeyEnv != "AGENTGUARD_PROVIDER_API_KEY" {
		t.Fatalf("provider config = %+v", cfg.Provider)
	}
}

func TestOpenAICompatibleProviderRejectsUnsafeConfiguration(t *testing.T) {
	for _, test := range []struct {
		name, fields string
	}{
		{name: "empty URL", fields: "base_url: ''\n  model: fixture\n  timeout_ms: 1\n  api_key_env: KEY"},
		{name: "file URL", fields: "base_url: file:///tmp/model\n  model: fixture\n  timeout_ms: 1\n  api_key_env: KEY"},
		{name: "URL credentials", fields: "base_url: https://user:pass@example.invalid\n  model: fixture\n  timeout_ms: 1\n  api_key_env: KEY"},
		{name: "empty model", fields: "base_url: https://example.invalid\n  model: ''\n  timeout_ms: 1\n  api_key_env: KEY"},
		{name: "invalid timeout", fields: "base_url: https://example.invalid\n  model: fixture\n  timeout_ms: 0\n  api_key_env: KEY"},
		{name: "empty key environment", fields: "base_url: https://example.invalid\n  model: fixture\n  timeout_ms: 1\n  api_key_env: ''"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			contents := "provider:\n  type: openai_compatible\n  " + test.fields + "\n"
			if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Fatal("invalid provider configuration accepted")
			}
		})
	}
}

func TestLoadRejectsInvalidInputPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		contents string
		want     string
	}{
		{
			name:     "invalid action",
			contents: "policy:\n  input:\n    default_action: APPROVAL\n",
			want:     "default_action",
		},
		{
			name:     "invalid score",
			contents: "policy:\n  input:\n    rules:\n      - id: invalid\n        when:\n          detection_type: SECRET\n          min_score: 1.1\n        action: BLOCK\n",
			want:     "min_score",
		},
		{
			name:     "invalid detector threshold",
			contents: "detection:\n  pii:\n    threshold: -0.1\n",
			want:     "detection.pii.threshold",
		},
		{
			name:     "invalid output action",
			contents: "policy:\n  output:\n    default_action: APPROVAL\n",
			want:     "policy.output.default_action",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(test.contents), 0o600); err != nil {
				t.Fatalf("write configuration: %v", err)
			}
			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Load() error = %v, want %q", err, test.want)
			}
		})
	}
}
