// SPDX-License-Identifier: Apache-2.0
//go:build !race

package a2a

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadCaps_ValidConfig(t *testing.T) {
	dir := t.TempDir()
	configsDir := filepath.Join(dir, "configs")
	if err := os.MkdirAll(configsDir, 0755); err != nil {
		t.Fatalf("Failed to create configs dir: %v", err)
	}

	yamlContent := `agents:
  agent-a:
    - read
    - write
  agent-b:
    - execute
`
	configPath := filepath.Join(configsDir, "caps.yaml")
	if err := os.WriteFile(configPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	agents, err := LoadCaps(configPath)
	if err != nil {
		t.Fatalf("LoadCaps() error: %v", err)
	}

	if len(agents) != 2 {
		t.Fatalf("got %d agents, want 2", len(agents))
	}

	if caps := agents["agent-a"]; len(caps) != 2 {
		t.Fatalf("agent-a caps: %v, want 2", caps)
	}
	if caps := agents["agent-b"]; len(caps) != 1 {
		t.Fatalf("agent-b caps: %v, want 1", caps)
	}
}

func TestLoadCaps_PathTraversal(t *testing.T) {
	_, err := LoadCaps("/etc/passwd")
	if err == nil {
		t.Fatal("expected error for path traversal, got nil")
	}
}

func TestLoadCaps_NonConfigsDirectory(t *testing.T) {
	dir := t.TempDir()
	// Write file outside configs/
	configPath := filepath.Join(dir, "outside.yaml")
	if err := os.WriteFile(configPath, []byte(`agents: {}`), 0644); err != nil {
		t.Fatalf("Failed to write file: %v", err)
	}

	_, err := LoadCaps(configPath)
	if err == nil {
		t.Fatal("expected error for non-configs path, got nil")
	}
}

func TestLoadCaps_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	configsDir := filepath.Join(dir, "configs")
	if err := os.MkdirAll(configsDir, 0755); err != nil {
		t.Fatalf("Failed to create configs dir: %v", err)
	}

	configPath := filepath.Join(configsDir, "bad.yaml")
	if err := os.WriteFile(configPath, []byte(`not: [yaml: at all`), 0644); err != nil {
		t.Fatalf("Failed to write bad YAML: %v", err)
	}

	_, err := LoadCaps(configPath)
	if err == nil {
		t.Fatal("expected error for invalid YAML, got nil")
	}
}

func TestLoadCaps_MissingFile(t *testing.T) {
	_, err := LoadCaps("/no/such/file.yaml")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}
