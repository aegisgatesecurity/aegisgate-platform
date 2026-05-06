// SPDX-License-Identifier: Apache-2.0
//go:build !race

package a2a

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig_ValidConfig(t *testing.T) {
	dir := t.TempDir()
	configsDir := filepath.Join(dir, "configs")
	if err := os.MkdirAll(configsDir, 0755); err != nil {
		t.Fatalf("Failed to create configs dir: %v", err)
	}

	validYAML := `secret: "my-secret-key"
rate_limit:
  capacity: 100
  refill: 10
  interval: "1s"
`
	configPath := filepath.Join(configsDir, "a2a.yaml")
	if err := os.WriteFile(configPath, []byte(validYAML), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig() returned unexpected error: %v", err)
	}
	if cfg.Secret != "my-secret-key" {
		t.Errorf("Expected secret 'my-secret-key', got %q", cfg.Secret)
	}
	if cfg.RateLimit.Capacity != 100 {
		t.Errorf("Expected capacity 100, got %d", cfg.RateLimit.Capacity)
	}
	if cfg.RateLimit.Refill != 10 {
		t.Errorf("Expected refill 10, got %d", cfg.RateLimit.Refill)
	}
	if cfg.RateLimit.Interval != "1s" {
		t.Errorf("Expected interval '1s', got %q", cfg.RateLimit.Interval)
	}
}

func TestLoadConfig_PathTraversal(t *testing.T) {
	_, err := LoadConfig("../etc/passwd")
	if err == nil {
		t.Fatal("LoadConfig() should reject path traversal, but got nil error")
	}
}

func TestLoadConfig_NonConfigsDirectory(t *testing.T) {
	dir := t.TempDir()
	// Place the file outside any "configs" directory
	nonConfigsPath := filepath.Join(dir, "a2a.yaml")
	if err := os.WriteFile(nonConfigsPath, []byte("secret: test\n"), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	_, err := LoadConfig(nonConfigsPath)
	if err == nil {
		t.Fatal("LoadConfig() should reject files outside configs directory, but got nil error")
	}
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	configsDir := filepath.Join(dir, "configs")
	if err := os.MkdirAll(configsDir, 0755); err != nil {
		t.Fatalf("Failed to create configs dir: %v", err)
	}

	invalidYAML := `{{invalid yaml content`
	configPath := filepath.Join(configsDir, "bad.yaml")
	if err := os.WriteFile(configPath, []byte(invalidYAML), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	_, err := LoadConfig(configPath)
	if err == nil {
		t.Fatal("LoadConfig() should return parse error for invalid YAML, but got nil error")
	}
}

func TestLoadConfig_MissingFile(t *testing.T) {
	dir := t.TempDir()
	configsDir := filepath.Join(dir, "configs")
	if err := os.MkdirAll(configsDir, 0755); err != nil {
		t.Fatalf("Failed to create configs dir: %v", err)
	}

	missingPath := filepath.Join(configsDir, "nonexistent.yaml")

	_, err := LoadConfig(missingPath)
	if err == nil {
		t.Fatal("LoadConfig() should return error for missing file, but got nil error")
	}
}

func TestLoadConfig_InvalidIntervalFormat(t *testing.T) {
	dir := t.TempDir()
	configsDir := filepath.Join(dir, "configs")
	if err := os.MkdirAll(configsDir, 0755); err != nil {
		t.Fatalf("Failed to create configs dir: %v", err)
	}

	badIntervalYAML := `secret: "my-secret-key"
rate_limit:
  capacity: 100
  refill: 10
  interval: "not-a-duration"
`
	configPath := filepath.Join(configsDir, "bad_interval.yaml")
	if err := os.WriteFile(configPath, []byte(badIntervalYAML), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	_, err := LoadConfig(configPath)
	if err == nil {
		t.Fatal("LoadConfig() should return error for invalid interval format, but got nil error")
	}
}
