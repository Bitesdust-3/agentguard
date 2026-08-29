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
	Server   ServerConfig   `yaml:"server"`
	Storage  StorageConfig  `yaml:"storage"`
	Provider ProviderConfig `yaml:"provider"`
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
	return nil
}

// ListenAddr returns the configured host and port in a form accepted by
// net/http.
func (c Config) ListenAddr() string {
	return net.JoinHostPort(c.Server.Host, strconv.Itoa(c.Server.Port))
}
