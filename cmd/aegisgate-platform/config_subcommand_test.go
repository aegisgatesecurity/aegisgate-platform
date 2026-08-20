// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — Config Subcommand Tests
// =========================================================================

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestConfigSubcommandValidateValid tests that `aegisgate config validate`
// passes for a valid config file.
func TestConfigSubcommandValidateValid(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "valid.yaml")
	content := `
platform:
  mode: standalone
proxy:
  bind_address: "0.0.0.0:8080"
  upstream: "https://api.openai.com"
  rate_limit: 100
dashboard:
  enabled: true
  bind_addr: "0.0.0.0"
  port: 8443
agent:
  server:
    port: 8081
logging:
  level: info
  format: json
persistence:
  enabled: true
  data_dir: "/data"
  audit_dir: "/data/audit"
`
	os.WriteFile(cfgPath, []byte(content), 0644)

	exit := runConfigSubcommand([]string{"validate", cfgPath})
	if exit != 0 {
		t.Errorf("Expected exit 0 for valid config, got %d", exit)
	}
}

// TestConfigSubcommandValidateInvalid tests that `aegisgate config validate`
// returns non-zero for an invalid config file.
func TestConfigSubcommandValidateInvalid(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "invalid.yaml")
	content := `
proxy:
  bind_address: "0.0.0.0:8080"
  upstream: ""
  rate_limit: -1
dashboard:
  enabled: true
  port: 8080
agent:
  server:
    port: 8080
logging:
  level: "verbose"
  format: "xml"
`
	os.WriteFile(cfgPath, []byte(content), 0644)

	exit := runConfigSubcommand([]string{"validate", cfgPath})
	if exit == 0 {
		t.Error("Expected non-zero exit for invalid config")
	}
}

// TestConfigSubcommandValidateNonexistent tests that validating a
// nonexistent file returns non-zero.
func TestConfigSubcommandValidateNonexistent(t *testing.T) {
	exit := runConfigSubcommand([]string{"validate", "/nonexistent/config.yaml"})
	if exit == 0 {
		t.Error("Expected non-zero exit for nonexistent file")
	}
}

// TestConfigSubcommandShowYAML tests that `aegisgate config show` outputs YAML.
func TestConfigSubcommandShowYAML(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")
	content := `
proxy:
  upstream: "https://api.anthropic.com"
`
	os.WriteFile(cfgPath, []byte(content), 0644)

	// Capture stdout by replacing os.Stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	exit := runConfigSubcommand([]string{"show", cfgPath})

	w.Close()
	os.Stdout = oldStdout

	if exit != 0 {
		t.Errorf("Expected exit 0 for show, got %d", exit)
	}

	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	output := string(buf[:n])
	if len(output) == 0 {
		t.Error("Expected non-empty output from show")
	}
}

// TestConfigSubcommandShowJSON tests `aegisgate config show --format json`.
func TestConfigSubcommandShowJSON(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")
	os.WriteFile(cfgPath, []byte("proxy:\n  upstream: https://test.com\n"), 0644)

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	exit := runConfigSubcommand([]string{"show", cfgPath, "--format", "json"})

	w.Close()
	os.Stdout = oldStdout

	if exit != 0 {
		t.Errorf("Expected exit 0 for show json, got %d", exit)
	}

	buf := make([]byte, 8192)
	n, _ := r.Read(buf)
	output := string(buf[:n])
	if len(output) == 0 {
		t.Error("Expected non-empty JSON output")
	}
}

// TestConfigSubcommandProfiles tests `aegisgate config profiles`.
func TestConfigSubcommandProfiles(t *testing.T) {
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	exit := runConfigSubcommand([]string{"profiles"})

	w.Close()
	os.Stdout = oldStdout

	if exit != 0 {
		t.Errorf("Expected exit 0 for profiles, got %d", exit)
	}

	buf := make([]byte, 16384)
	n, _ := r.Read(buf)
	output := string(buf[:n])
	if len(output) == 0 {
		t.Error("Expected non-empty output from profiles")
	}
}

// TestConfigSubcommandHelp tests `aegisgate config help`.
func TestConfigSubcommandHelp(t *testing.T) {
	exit := runConfigSubcommand([]string{"help"})
	if exit != 0 {
		t.Errorf("Expected exit 0 for help, got %d", exit)
	}
}

// TestConfigSubcommandNoArgs tests `aegisgate config` with no verb.
func TestConfigSubcommandNoArgs(t *testing.T) {
	exit := runConfigSubcommand([]string{})
	if exit != 0 {
		t.Errorf("Expected exit 0 for no args, got %d", exit)
	}
}

// TestConfigSubcommandUnknownVerb tests unknown verb.
func TestConfigSubcommandUnknownVerb(t *testing.T) {
	exit := runConfigSubcommand([]string{"bogus"})
	if exit == 0 {
		t.Error("Expected non-zero exit for unknown verb")
	}
}

// TestIsConfigSubcommand tests the detection function.
func TestIsConfigSubcommand(t *testing.T) {
	// Save and restore os.Args
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"aegisgate", "config", "validate"}
	if !isConfigSubcommand() {
		t.Error("isConfigSubcommand should return true for 'config'")
	}

	os.Args = []string{"aegisgate", "--config", "file.yaml"}
	if isConfigSubcommand() {
		t.Error("isConfigSubcommand should return false for '--config' flag")
	}

	os.Args = []string{"aegisgate", "status"}
	if isConfigSubcommand() {
		t.Error("isConfigSubcommand should return false for 'status'")
	}
}
