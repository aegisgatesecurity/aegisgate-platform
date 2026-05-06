// SPDX-License-Identifier: Apache-2.0
package a2a

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
)

// PersistentCapEnforcer wraps an InMemoryCapEnforcer and persists capability
// changes to a JSON file. It loads capabilities from the file on startup
// (falling back to the YAML config if the file doesn't exist) and saves
// atomically on every SetCapabilities call.
//
// This ensures A2A capability policies survive pod restarts.
type PersistentCapEnforcer struct {
	mu       sync.RWMutex
	inner    *InMemoryCapEnforcer
	filePath string
	logger   *slog.Logger
}

// NewPersistentCapEnforcer creates a persistent capability enforcer that
// loads from filePath. If the file doesn't exist, it starts empty and will
// be created on the first SetCapabilities call.
func NewPersistentCapEnforcer(filePath string) (*PersistentCapEnforcer, error) {
	p := &PersistentCapEnforcer{
		inner:    NewInMemoryCapEnforcer(),
		filePath: filePath,
		logger:   slog.Default().With("component", "a2a-caps-persistent"),
	}

	if err := p.load(); err != nil {
		// If the file doesn't exist, start empty (will be populated by
		// SetCapabilities or the initial YAML config load).
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to load capability file %s: %w", filePath, err)
		}
		p.logger.Info("No existing capability file, starting fresh", "path", filePath)
	}

	return p, nil
}

// LoadFromYAML loads initial capabilities from the YAML config and persists
// them to the JSON file. This is called on startup to seed the persistent
// store from the config file.
func (p *PersistentCapEnforcer) LoadFromYAML(yamlPath string) error {
	agents, err := LoadCaps(yamlPath)
	if err != nil {
		return fmt.Errorf("failed to load YAML capabilities: %w", err)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	for agentID, caps := range agents {
		p.inner.SetCapabilities(agentID, caps)
	}

	p.logger.Info("Loaded capabilities from YAML config", "path", yamlPath, "agents", len(agents))

	// Persist the YAML-loaded capabilities to the JSON file.
	if err := p.saveLocked(); err != nil {
		p.logger.Error("Failed to persist YAML capabilities", "error", err)
		return fmt.Errorf("failed to persist capabilities: %w", err)
	}

	return nil
}

// IsAllowed checks if an agent has a specific capability.
func (p *PersistentCapEnforcer) IsAllowed(agentID, capability string) (bool, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.inner.IsAllowed(agentID, capability)
}

// SetCapabilities sets the capabilities for an agent and persists the change.
func (p *PersistentCapEnforcer) SetCapabilities(agentID string, caps []string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.inner.SetCapabilities(agentID, caps)

	if err := p.saveLocked(); err != nil {
		p.logger.Error("Failed to persist capabilities after SetCapabilities",
			"agent", agentID, "error", err)
		return fmt.Errorf("capabilities set in memory but not persisted: %w", err)
	}

	p.logger.Info("Persisted capabilities for agent", "agent", agentID, "capability_count", len(caps))
	return nil
}

// RemoveAgent removes an agent and its capabilities, and persists the change.
func (p *PersistentCapEnforcer) RemoveAgent(agentID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Set empty capabilities to remove the agent from the map.
	// The InMemoryCapEnforcer will overwrite the entry.
	p.inner.SetCapabilities(agentID, nil)

	if err := p.saveLocked(); err != nil {
		p.logger.Error("Failed to persist capabilities after RemoveAgent",
			"agent", agentID, "error", err)
		return fmt.Errorf("agent removed from memory but not persisted: %w", err)
	}

	p.logger.Info("Removed agent capabilities", "agent", agentID)
	return nil
}

// Agents returns a snapshot of all registered agent IDs.
func (p *PersistentCapEnforcer) Agents() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.inner.Agents()
}

// load reads capabilities from the JSON file into the in-memory store.
func (p *PersistentCapEnforcer) load() error {
	data, err := os.ReadFile(p.filePath) // #nosec G304 — path is validated by caller
	if err != nil {
		return err
	}

	var caps map[string][]string
	if err := json.Unmarshal(data, &caps); err != nil {
		return fmt.Errorf("invalid capability file format: %w", err)
	}

	for agentID, agentCaps := range caps {
		p.inner.SetCapabilities(agentID, agentCaps)
	}

	p.logger.Info("Loaded persisted capabilities", "agents", len(caps))
	return nil
}

// saveLocked persists the current capabilities to the JSON file.
// Caller MUST hold p.mu for writing.
func (p *PersistentCapEnforcer) saveLocked() error {
	// Ensure the directory exists.
	dir := filepath.Dir(p.filePath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0750); err != nil { // #nosec G301 -- capability store needs group-readable parent dir
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// Atomic write: write to temp file then rename.
	agents := p.inner.Agents()
	caps := make(map[string][]string, len(agents))
	for _, agentID := range agents {
		// We need to reconstruct the caps list from the inner map.
		// Since inner.IsAllowed checks membership, we need a different approach.
		// The inner store has the data; we serialize through the Agents() + per-agent
		// capability lookup. But InMemoryCapEnforcer doesn't expose GetCapabilities.
		// Instead, we'll use the snapshot approach.
		caps[agentID] = p.inner.GetCapabilities(agentID)
	}

	data, err := json.MarshalIndent(caps, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal capabilities: %w", err)
	}

	tmpFile := p.filePath + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0600); err != nil { // #nosec G306 -- capability file contains auth secrets
		return fmt.Errorf("failed to write temp capability file: %w", err)
	}

	if err := os.Rename(tmpFile, p.filePath); err != nil {
		// Clean up temp file on failure.
		_ = os.Remove(tmpFile)
		return fmt.Errorf("failed to rename capability file: %w", err)
	}

	return nil
}
