// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - ACP Configuration Loader
// =========================================================================

package acp

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ConfigLoader loads ACP configuration from file
type ConfigLoader struct{}

func NewConfigLoader() *ConfigLoader {
	return &ConfigLoader{}
}

// LoadConfig loads ACP configuration from a YAML file
func (cl *ConfigLoader) LoadConfig(path string) (*ACPGuardConfig, error) {
	// Validate path to prevent file inclusion attacks (G304)
	//lint:ignore SAST_PATH - sanitized path is validated before use
	sanitizedPath := filepath.Clean(path)
	if !strings.HasPrefix(sanitizedPath, "/") && !strings.HasPrefix(sanitizedPath, "./") && !strings.HasPrefix(sanitizedPath, "../") {
		return nil, fmt.Errorf("invalid config path: path must be absolute or relative")
	}
	data, err := os.ReadFile(sanitizedPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	expanded := expandEnvVars(string(data))

	var cfg YAMLConfig
	if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	return cl.yamlToGuardConfig(&cfg), nil
}

// YAMLConfig represents the YAML configuration structure
type YAMLConfig struct {
	Enabled         bool           `yaml:"enabled"`
	HMAC            YAMLHMACConfig `yaml:"hmac"`
	RateLimit       YAMLRateLimit  `yaml:"rate_limit"`
	InputValidation YAMLInputVal   `yaml:"input_validation"`
	Capabilities    YAMLCapConfig  `yaml:"capabilities"`
	Scanning        YAMLScanning   `yaml:"scanning"`
	Logging         YAMLLogging    `yaml:"logging"`
}

type YAMLHMACConfig struct {
	Enabled            bool   `yaml:"enabled"`
	Secret             string `yaml:"secret"`
	TimestampTolerance string `yaml:"timestamp_tolerance"`
}

type YAMLRateLimit struct {
	Enabled           bool `yaml:"enabled"`
	RequestsPerMinute int  `yaml:"requests_per_minute"`
	Burst             int  `yaml:"burst"`
}

type YAMLInputVal struct {
	Enabled        bool     `yaml:"enabled"`
	BlockedMethods []string `yaml:"blocked_methods"`
}

type YAMLCapConfig struct {
	Enabled       bool   `yaml:"enabled"`
	DefaultPolicy string `yaml:"default_policy"`
}

type YAMLScanning struct {
	ResponseScanning    bool   `yaml:"response_scanning"`
	DetectPII           bool   `yaml:"detect_pii"`
	DetectSecrets       bool   `yaml:"detect_secrets"`
	DetectToxicity      bool   `yaml:"detect_toxicity"`
	DetectHallucination bool   `yaml:"detect_hallucination"`
	Timeout             string `yaml:"timeout"`
}

type YAMLLogging struct {
	Level      string `yaml:"level"`
	LogBlocked bool   `yaml:"log_blocked"`
	LogPII     bool   `yaml:"log_pii"`
}

func (cl *ConfigLoader) yamlToGuardConfig(yamlCfg *YAMLConfig) *ACPGuardConfig {
	cfg := DefaultACPGuardConfig()

	cfg.EnableHMAC = yamlCfg.HMAC.Enabled
	cfg.HMACSecret = yamlCfg.HMAC.Secret

	cfg.EnableRateLimiting = yamlCfg.RateLimit.Enabled
	cfg.RateLimitPerMinute = yamlCfg.RateLimit.RequestsPerMinute
	cfg.RateLimitBurst = yamlCfg.RateLimit.Burst

	cfg.EnableInputValidation = yamlCfg.InputValidation.Enabled
	cfg.BlockedMethods = yamlCfg.InputValidation.BlockedMethods

	cfg.EnableCapabilityEnf = yamlCfg.Capabilities.Enabled

	if yamlCfg.Scanning.Timeout != "" {
		if timeout, err := time.ParseDuration(yamlCfg.Scanning.Timeout); err == nil {
			cfg.ScanTimeout = timeout
		}
	}

	return cfg
}

func expandEnvVars(s string) string {
	return os.Expand(s, func(key string) string {
		if val := os.Getenv(key); val != "" {
			return val
		}
		return ""
	})
}

// LoadConfigFromEnv loads configuration from environment variables
func LoadConfigFromEnv() *ACPGuardConfig {
	cfg := DefaultACPGuardConfig()

	if v := os.Getenv("ACP_ENABLED"); v == "false" || v == "0" {
		cfg.EnableHMAC = false
		cfg.EnableRateLimiting = false
		cfg.EnableCapabilityEnf = false
	}

	if v := os.Getenv("ACP_HMAC_ENABLED"); v != "" {
		cfg.EnableHMAC = v == "true" || v == "1"
	}

	if v := os.Getenv("ACP_HMAC_SECRET"); v != "" {
		cfg.HMACSecret = v
	}

	if v := os.Getenv("ACP_RATE_LIMIT_ENABLED"); v != "" {
		cfg.EnableRateLimiting = v == "true" || v == "1"
	}

	if v := os.Getenv("ACP_RATE_LIMIT_RPM"); v != "" {
		if _, err := fmt.Sscanf(v, "%d", &cfg.RateLimitPerMinute); err != nil {
			cfg.RateLimitPerMinute = 100
		}
	}

	if v := os.Getenv("ACP_RATE_LIMIT_BURST"); v != "" {
		if _, err := fmt.Sscanf(v, "%d", &cfg.RateLimitBurst); err != nil {
			cfg.RateLimitBurst = 20
		}
	}

	return cfg
}
