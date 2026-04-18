package config

import (
	"os"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig() returned nil")
	}
	if cfg.Server.Port != 8080 {
		t.Errorf("Server.Port = %d, want 8080", cfg.Server.Port)
	}
	if cfg.Server.Host != "0.0.0.0" {
		t.Errorf("Server.Host = %s, want 0.0.0.0", cfg.Server.Host)
	}
	if cfg.Session.MaxSessions != 1000 {
		t.Errorf("Session.MaxSessions = %d, want 1000", cfg.Session.MaxSessions)
	}
	if cfg.Audit.Enabled != true {
		t.Error("Audit.Enabled should be true by default")
	}
}

func TestLoadConfig(t *testing.T) {
	// Create a temporary config file
	content := `
server:
  host: "127.0.0.1"
  port: 9090

policies:
  default_allow:
    - "test_tool"
  high_risk:
    - "dangerous_tool"
`
	tmpFile, err := os.CreateTemp("", "aegisguard-*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}
	tmpFile.Close()

	cfg, err := Load(tmpFile.Name())
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Server.Port != 9090 {
		t.Errorf("Server.Port = %d, want 9090", cfg.Server.Port)
	}
	if cfg.Server.Host != "127.0.0.1" {
		t.Errorf("Server.Host = %s, want 127.0.0.1", cfg.Server.Host)
	}
	if len(cfg.Policies.DefaultAllow) != 1 || cfg.Policies.DefaultAllow[0] != "test_tool" {
		t.Errorf("Policies.DefaultAllow = %v, want [test_tool]", cfg.Policies.DefaultAllow)
	}
}

func TestLoadConfigFileNotFound(t *testing.T) {
	_, err := Load("nonexistent.yaml")
	if err == nil {
		t.Error("Load() should return error for nonexistent file")
	}
}

func TestEnvOverrides(t *testing.T) {
	// Set environment variables
	os.Setenv("AEGIS_PORT", "9999")
	os.Setenv("AEGIS_HOST", "localhost")
	os.Setenv("AEGIS_LOG_LEVEL", "debug")
	os.Setenv("AEGIS_MAX_SESSIONS", "500")
	defer func() {
		os.Unsetenv("AEGIS_PORT")
		os.Unsetenv("AEGIS_HOST")
		os.Unsetenv("AEGIS_LOG_LEVEL")
		os.Unsetenv("AEGIS_MAX_SESSIONS")
	}()

	cfg := DefaultConfig()
	cfg.applyEnvOverrides()

	if cfg.Server.Port != 9999 {
		t.Errorf("AEGIS_PORT override: Port = %d, want 9999", cfg.Server.Port)
	}
	if cfg.Server.Host != "localhost" {
		t.Errorf("AEGIS_HOST override: Host = %s, want localhost", cfg.Server.Host)
	}
	if cfg.Logging.Level != "debug" {
		t.Errorf("AEGIS_LOG_LEVEL override: Level = %s, want debug", cfg.Logging.Level)
	}
	if cfg.Session.MaxSessions != 500 {
		t.Errorf("AEGIS_MAX_SESSIONS override: MaxSessions = %d, want 500", cfg.Session.MaxSessions)
	}
}

func TestIsHighRiskTool(t *testing.T) {
	cfg := DefaultConfig()

	if !cfg.IsHighRiskTool("shell_command") {
		t.Error("shell_command should be high risk")
	}
	if !cfg.IsHighRiskTool("code_execute") {
		t.Error("code_execute should be high risk")
	}
	if cfg.IsHighRiskTool("file_read") {
		t.Error("file_read should NOT be high risk")
	}
}

func TestRequiresApproval(t *testing.T) {
	cfg := DefaultConfig()

	if !cfg.RequiresApproval("file_write") {
		t.Error("file_write should require approval")
	}
	if !cfg.RequiresApproval("network_call") {
		t.Error("network_call should require approval")
	}
	if cfg.RequiresApproval("file_read") {
		t.Error("file_read should NOT require approval")
	}
}

func TestIsAllowedByDefault(t *testing.T) {
	cfg := DefaultConfig()

	if !cfg.IsAllowedByDefault("file_read") {
		t.Error("file_read should be allowed by default")
	}
	if !cfg.IsAllowedByDefault("web_search") {
		t.Error("web_search should be allowed by default")
	}
	if cfg.IsAllowedByDefault("shell_command") {
		t.Error("shell_command should NOT be allowed by default")
	}
}

func TestGetRiskLevel(t *testing.T) {
	cfg := DefaultConfig()

	tests := []struct {
		score    int
		expected string
	}{
		{10, "none"},
		{30, "low"},
		{60, "medium"},
		{80, "high"},
		{95, "critical"},
		{100, "critical"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if level := cfg.GetRiskLevel(tt.score); level != tt.expected {
				t.Errorf("GetRiskLevel(%d) = %s, want %s", tt.score, level, tt.expected)
			}
		})
	}
}
