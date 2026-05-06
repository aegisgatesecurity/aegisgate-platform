// SPDX-License-Identifier: Apache-2.0
//go:build !race

package a2a

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestPersistentCapEnforcer_New(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "caps.json")

	pce, err := NewPersistentCapEnforcer(path)
	if err != nil {
		t.Fatalf("NewPersistentCapEnforcer() error: %v", err)
	}
	if pce == nil {
		t.Fatal("NewPersistentCapEnforcer() returned nil")
	}

	// No file should exist initially
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("Expected no file to exist initially")
	}
}

func TestPersistentCapEnforcer_SetAndGet(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "caps.json")

	pce, err := NewPersistentCapEnforcer(path)
	if err != nil {
		t.Fatalf("NewPersistentCapEnforcer() error: %v", err)
	}

	// Set capabilities
	if err := pce.SetCapabilities("agent-1", []string{"read", "write"}); err != nil {
		t.Fatalf("SetCapabilities() error: %v", err)
	}

	// Verify capabilities
	allowed, err := pce.IsAllowed("agent-1", "read")
	if err != nil || !allowed {
		t.Error("agent-1 should be allowed 'read'")
	}

	allowed, err = pce.IsAllowed("agent-1", "write")
	if err != nil || !allowed {
		t.Error("agent-1 should be allowed 'write'")
	}

	allowed, err = pce.IsAllowed("agent-1", "delete")
	if err != nil || allowed {
		t.Error("agent-1 should NOT be allowed 'delete'")
	}

	// Verify file was created
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("Persistent capability file should exist after SetCapabilities")
	}
}

func TestPersistentCapEnforcer_Persistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "caps.json")

	// Create and write capabilities
	pce1, err := NewPersistentCapEnforcer(path)
	if err != nil {
		t.Fatalf("NewPersistentCapEnforcer() error: %v", err)
	}

	if err := pce1.SetCapabilities("agent-1", []string{"read", "write"}); err != nil {
		t.Fatalf("SetCapabilities() error: %v", err)
	}
	if err := pce1.SetCapabilities("agent-2", []string{"execute"}); err != nil {
		t.Fatalf("SetCapabilities() error: %v", err)
	}

	// Load from the same file in a new enforcer (simulates pod restart)
	pce2, err := NewPersistentCapEnforcer(path)
	if err != nil {
		t.Fatalf("NewPersistentCapEnforcer() on reload: %v", err)
	}

	// Verify capabilities persisted across "restart"
	allowed, err := pce2.IsAllowed("agent-1", "read")
	if err != nil || !allowed {
		t.Error("agent-1 should be allowed 'read' after reload")
	}

	allowed, err = pce2.IsAllowed("agent-2", "execute")
	if err != nil || !allowed {
		t.Error("agent-2 should be allowed 'execute' after reload")
	}

	// Verify unknown agent is denied (fail-closed)
	allowed, err = pce2.IsAllowed("unknown-agent", "read")
	if err != nil || allowed {
		t.Error("unknown-agent should be denied (fail-closed)")
	}
}

func TestPersistentCapEnforcer_RemoveAgent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "caps.json")

	pce, err := NewPersistentCapEnforcer(path)
	if err != nil {
		t.Fatalf("NewPersistentCapEnforcer() error: %v", err)
	}

	if err := pce.SetCapabilities("agent-1", []string{"read"}); err != nil {
		t.Fatalf("SetCapabilities() error: %v", err)
	}

	// Remove the agent
	if err := pce.RemoveAgent("agent-1"); err != nil {
		t.Fatalf("RemoveAgent() error: %v", err)
	}

	// Verify agent is denied (fail-closed)
	allowed, err := pce.IsAllowed("agent-1", "read")
	if err != nil || allowed {
		t.Error("removed agent should be denied (fail-closed)")
	}

	// Verify removal persisted — reload from file
	pce2, err := NewPersistentCapEnforcer(path)
	if err != nil {
		t.Fatalf("NewPersistentCapEnforcer() on reload: %v", err)
	}

	allowed, err = pce2.IsAllowed("agent-1", "read")
	if err != nil || allowed {
		t.Error("removed agent should still be denied after reload (fail-closed)")
	}
}

func TestPersistentCapEnforcer_LoadFromYAML(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "caps.json")

	// Create a YAML caps file
	yamlContent := `agents:
  agent-from-yaml:
    - yaml-read
    - yaml-write
`
	yamlPath := filepath.Join(dir, "caps.yaml")
	if err := os.WriteFile(yamlPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("Failed to write YAML file: %v", err)
	}

	// Need to put YAML in a configs/ directory for LoadCaps path validation
	configsDir := filepath.Join(dir, "configs")
	if err := os.MkdirAll(configsDir, 0755); err != nil {
		t.Fatalf("Failed to create configs dir: %v", err)
	}
	yamlConfigPath := filepath.Join(configsDir, "caps.yaml")
	if err := os.WriteFile(yamlConfigPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("Failed to write YAML config: %v", err)
	}

	pce, err := NewPersistentCapEnforcer(jsonPath)
	if err != nil {
		t.Fatalf("NewPersistentCapEnforcer() error: %v", err)
	}

	// Load from YAML
	if err := pce.LoadFromYAML(yamlConfigPath); err != nil {
		t.Fatalf("LoadFromYAML() error: %v", err)
	}

	// Verify YAML capabilities were loaded
	allowed, err := pce.IsAllowed("agent-from-yaml", "yaml-read")
	if err != nil || !allowed {
		t.Error("agent-from-yaml should be allowed 'yaml-read'")
	}

	// Verify they were persisted to JSON
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("Failed to read persisted caps: %v", err)
	}

	var caps map[string][]string
	if err := json.Unmarshal(data, &caps); err != nil {
		t.Fatalf("Failed to parse persisted caps: %v", err)
	}

	if _, ok := caps["agent-from-yaml"]; !ok {
		t.Error("agent-from-yaml should be in persisted capabilities")
	}
}

func TestPersistentCapEnforcer_Agents(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "caps.json")

	pce, err := NewPersistentCapEnforcer(path)
	if err != nil {
		t.Fatalf("NewPersistentCapEnforcer() error: %v", err)
	}

	if err := pce.SetCapabilities("agent-1", []string{"read"}); err != nil {
		t.Fatalf("SetCapabilities() error: %v", err)
	}
	if err := pce.SetCapabilities("agent-2", []string{"write"}); err != nil {
		t.Fatalf("SetCapabilities() error: %v", err)
	}

	agents := pce.Agents()
	if len(agents) != 2 {
		t.Errorf("Expected 2 agents, got %d", len(agents))
	}
}

func TestPersistentCapEnforcer_OverwriteCapabilities(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "caps.json")

	pce, err := NewPersistentCapEnforcer(path)
	if err != nil {
		t.Fatalf("NewPersistentCapEnforcer() error: %v", err)
	}

	// Set initial capabilities
	if err := pce.SetCapabilities("agent-1", []string{"read", "write"}); err != nil {
		t.Fatalf("SetCapabilities() error: %v", err)
	}

	// Overwrite with new capabilities
	if err := pce.SetCapabilities("agent-1", []string{"execute"}); err != nil {
		t.Fatalf("SetCapabilities() overwrite error: %v", err)
	}

	// Old capabilities should be gone (fail-closed)
	allowed, err := pce.IsAllowed("agent-1", "read")
	if err != nil || allowed {
		t.Error("overwritten capability 'read' should be denied (fail-closed)")
	}

	// New capability should work
	allowed, err = pce.IsAllowed("agent-1", "execute")
	if err != nil || !allowed {
		t.Error("new capability 'execute' should be allowed")
	}

	// Verify persistence after overwrite
	pce2, err := NewPersistentCapEnforcer(path)
	if err != nil {
		t.Fatalf("NewPersistentCapEnforcer() on reload: %v", err)
	}

	allowed, err = pce2.IsAllowed("agent-1", "execute")
	if err != nil || !allowed {
		t.Error("overwritten capability should persist after reload")
	}

	allowed, err = pce2.IsAllowed("agent-1", "read")
	if err != nil || allowed {
		t.Error("removed capability should still be denied after reload (fail-closed)")
	}
}
