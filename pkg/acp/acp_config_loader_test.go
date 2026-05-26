// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - ACP Config Loader Tests

package acp

import (
	"os"
	"testing"
)

func TestNewConfigLoader(t *testing.T) {
	loader := NewConfigLoader()
	if loader == nil {
		t.Fatal("Expected non-nil loader")
	}
}

func TestLoadConfigFile(t *testing.T) {
	content := []byte("acp:\n  enabled: true\n")
	tmpfile, err := os.CreateTemp("", "acp-config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())
	if _, err := tmpfile.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}
	loader := NewConfigLoader()
	cfg, err := loader.LoadConfig(tmpfile.Name())
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("Expected non-nil config")
	}
}

func TestLoadConfigNotFound(t *testing.T) {
	loader := NewConfigLoader()
	_, err := loader.LoadConfig("/nonexistent/config.yaml")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

func TestLoadConfigFromEnv(t *testing.T) {
	os.Setenv("ACP_HMAC_SECRET", "env-secret-key-32-bytes-long!!!!")
	defer os.Unsetenv("ACP_HMAC_SECRET")
	cfg := LoadConfigFromEnv()
	if cfg == nil {
		t.Fatal("Expected non-nil config from env")
	}
}

func TestExpandEnvVars(t *testing.T) {
	os.Setenv("TEST_VAR", "test-value")
	defer os.Unsetenv("TEST_VAR")
	result := expandEnvVars("prefix_${TEST_VAR}_suffix")
	if result != "prefix_test-value_suffix" {
		t.Errorf("Expected expanded value, got %s", result)
	}
}

func TestExpandEnvVarsNoVar(t *testing.T) {
	result := expandEnvVars("no-variables-here")
	if result != "no-variables-here" {
		t.Errorf("Expected unchanged string, got %s", result)
	}
}

func TestYamlToGuardConfig(t *testing.T) {
	yamlCfg := &YAMLConfig{
		Enabled: true,
		HMAC: YAMLHMACConfig{
			Enabled: true,
			Secret:  "test-secret-key-32-bytes-long!!!!",
		},
	}
	loader := NewConfigLoader()
	cfg := loader.yamlToGuardConfig(yamlCfg)
	if cfg == nil {
		t.Fatal("Expected non-nil config from yaml")
	}
}

func TestLoadConfigFromEnvDefaults(t *testing.T) {
	os.Unsetenv("ACP_HMAC_SECRET")
	cfg := LoadConfigFromEnv()
	if cfg == nil {
		t.Fatal("Expected non-nil config")
	}
}

func TestExpandEnvVarsMissing(t *testing.T) {
	os.Unsetenv("MISSING_VAR")
	result := expandEnvVars("${MISSING_VAR}")
	if result != "" {
		t.Errorf("Expected empty for missing var, got %s", result)
	}
}

func TestYamlToGuardConfigDefaults(t *testing.T) {
	yamlCfg := &YAMLConfig{}
	loader := NewConfigLoader()
	cfg := loader.yamlToGuardConfig(yamlCfg)
	if cfg == nil {
		t.Fatal("Expected non-nil config")
	}
}

func TestLoadConfigInvalidYAML(t *testing.T) {
	tmpfile, _ := os.CreateTemp("", "invalid-*.yaml")
	defer os.Remove(tmpfile.Name())
	tmpfile.WriteString("invalid: yaml: content: [")
	tmpfile.Close()
	_, err := NewConfigLoader().LoadConfig(tmpfile.Name())
	if err == nil {
		t.Error("Expected error for invalid YAML")
	}
}

func TestYamlToGuardConfigFull(t *testing.T) {
	yamlCfg := &YAMLConfig{
		Enabled: true,
		HMAC: YAMLHMACConfig{
			Enabled: true,
			Secret:  "test-secret-key-32-bytes-long!!!!",
		},
		RateLimit: YAMLRateLimit{
			Enabled:           true,
			Burst:             25,
			RequestsPerMinute: 150,
		},
		Capabilities: YAMLCapConfig{
			Enabled:       true,
			DefaultPolicy: "deny",
		},
		Scanning: YAMLScanning{
			ResponseScanning: true,
			DetectPII:        true,
			DetectSecrets:    true,
		},
	}
	cfg := NewConfigLoader().yamlToGuardConfig(yamlCfg)
	if cfg == nil {
		t.Fatal("Expected non-nil config")
	}
}

func TestLoadConfigFromEnvWithHMAC(t *testing.T) {
	os.Setenv("ACP_HMAC_SECRET", "test-secret-key-32-bytes-long!!!!")
	defer os.Unsetenv("ACP_HMAC_SECRET")
	cfg := LoadConfigFromEnv()
	if cfg == nil {
		t.Fatal("Expected non-nil config")
	}
	if cfg.HMACSecret == "" {
		t.Error("Expected HMAC secret to be set")
	}
}
