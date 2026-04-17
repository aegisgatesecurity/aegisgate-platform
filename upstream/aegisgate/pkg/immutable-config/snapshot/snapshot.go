// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

package snapshot

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	immutableconfig "github.com/aegisgatesecurity/aegisgate/pkg/immutable-config"
)

// Snapshot represents a point-in-time capture of configuration state
type Snapshot struct {
	ID          string                                 `json:"id"`
	Name        string                                 `json:"name"`
	Description string                                 `json:"description,omitempty"`
	Created     time.Time                              `json:"created"`
	Configs     map[string]*immutableconfig.ConfigData `json:"configs"`
	Checksum    string                                 `json:"checksum"`
	Metadata    map[string]string                      `json:"metadata,omitempty"`
}

// SnapshotManager manages configuration snapshots
type SnapshotManager struct {
	mu        sync.RWMutex
	basePath  string
	snapshots map[string]*Snapshot
}

// SnapshotOptions for creating snapshots
type SnapshotOptions struct {
	Name        string
	Description string
	Metadata    map[string]string
}

// NewSnapshotManager creates a new snapshot manager
func NewSnapshotManager(basePath string) (*SnapshotManager, error) {
	sm := &SnapshotManager{
		basePath:  basePath,
		snapshots: make(map[string]*Snapshot),
	}

	// Create directory if it doesn't exist
	if err := os.MkdirAll(basePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create snapshot directory: %w", err)
	}

	// Load existing snapshots
	if err := sm.loadExisting(); err != nil {
		return nil, fmt.Errorf("failed to load existing snapshots: %w", err)
	}

	return sm, nil
}

// Create creates a new snapshot from the provided configurations
func (sm *SnapshotManager) Create(provider immutableconfig.Provider, opts *SnapshotOptions) (*Snapshot, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Get all versions
	versions, err := provider.ListVersions()
	if err != nil {
		return nil, fmt.Errorf("failed to list versions: %w", err)
	}

	// Collect all configurations
	configs := make(map[string]*immutableconfig.ConfigData)
	for _, v := range versions {
		config, err := provider.Load(v.Version)
		if err != nil {
			return nil, fmt.Errorf("failed to load version %s: %w", v.Version, err)
		}
		configs[v.Version] = config
	}

	// Generate ID
	id := generateSnapshotID()

	// Create snapshot
	snapshot := &Snapshot{
		ID:          id,
		Name:        opts.Name,
		Description: opts.Description,
		Created:     time.Now().UTC(),
		Configs:     configs,
		Metadata:    opts.Metadata,
	}

	// Calculate checksum
	checksum, err := sm.calculateChecksum(snapshot)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate checksum: %w", err)
	}
	snapshot.Checksum = checksum

	// Save to disk
	if err := sm.saveToDisk(snapshot); err != nil {
		return nil, fmt.Errorf("failed to save snapshot: %w", err)
	}

	// Store in memory
	sm.snapshots[id] = snapshot

	return snapshot, nil
}

// Get retrieves a snapshot by ID
func (sm *SnapshotManager) Get(id string) (*Snapshot, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	snapshot, exists := sm.snapshots[id]
	if !exists {
		return nil, fmt.Errorf("snapshot %s not found", id)
	}

	return snapshot, nil
}

// List lists all snapshots
func (sm *SnapshotManager) List() ([]*Snapshot, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	snapshots := make([]*Snapshot, 0, len(sm.snapshots))
	for _, snapshot := range sm.snapshots {
		snapshots = append(snapshots, snapshot)
	}

	// Sort by creation time (newest first)
	for i := 0; i < len(snapshots)-1; i++ {
		for j := i + 1; j < len(snapshots); j++ {
			if snapshots[j].Created.After(snapshots[i].Created) {
				snapshots[i], snapshots[j] = snapshots[j], snapshots[i]
			}
		}
	}

	return snapshots, nil
}

// Delete deletes a snapshot
func (sm *SnapshotManager) Delete(id string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if _, exists := sm.snapshots[id]; !exists {
		return fmt.Errorf("snapshot %s not found", id)
	}

	// Delete from disk
	snapshotPath := filepath.Join(sm.basePath, id+".snapshot")
	if err := os.RemoveAll(snapshotPath); err != nil {
		return fmt.Errorf("failed to delete snapshot from disk: %w", err)
	}

	delete(sm.snapshots, id)
	return nil
}

// Verify verifies the integrity of a snapshot
func (sm *SnapshotManager) Verify(id string) (bool, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	snapshot, exists := sm.snapshots[id]
	if !exists {
		return false, fmt.Errorf("snapshot %s not found", id)
	}

	// Recalculate checksum
	checksum, err := sm.calculateChecksum(snapshot)
	if err != nil {
		return false, err
	}

	return checksum == snapshot.Checksum, nil
}

// Restore restores configurations from a snapshot to a provider
func (sm *SnapshotManager) Restore(id string, provider immutableconfig.Provider) error {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	snapshot, exists := sm.snapshots[id]
	if !exists {
		return fmt.Errorf("snapshot %s not found", id)
	}

	// Verify snapshot integrity before restore
	if verified, err := sm.Verify(id); err != nil {
		return fmt.Errorf("failed to verify snapshot: %w", err)
	} else if !verified {
		return fmt.Errorf("snapshot integrity verification failed")
	}

	// Restore each configuration
	for version, config := range snapshot.Configs {
		if _, err := provider.Save(config); err != nil {
			return fmt.Errorf("failed to restore version %s: %w", version, err)
		}
	}

	return nil
}

// GetChecksum retrieves the checksum of a snapshot
func (sm *SnapshotManager) GetChecksum(id string) (string, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	snapshot, exists := sm.snapshots[id]
	if !exists {
		return "", fmt.Errorf("snapshot %s not found", id)
	}

	return snapshot.Checksum, nil
}

// Private methods

func (sm *SnapshotManager) saveToDisk(snapshot *Snapshot) error {
	snapshotPath := filepath.Join(sm.basePath, snapshot.ID+".snapshot")
	if err := os.MkdirAll(snapshotPath, 0755); err != nil {
		return err
	}

	// Save snapshot metadata
	meta := map[string]interface{}{
		"id":          snapshot.ID,
		"name":        snapshot.Name,
		"description": snapshot.Description,
		"created":     snapshot.Created.Format(time.RFC3339Nano),
		"checksum":    snapshot.Checksum,
		"metadata":    snapshot.Metadata,
	}
	metaData, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	metaPath := filepath.Join(snapshotPath, "meta.json")
	if err := os.WriteFile(metaPath, metaData, 0644); err != nil {
		return err
	}

	// Save configurations
	configsPath := filepath.Join(snapshotPath, "configs")
	if err := os.MkdirAll(configsPath, 0755); err != nil {
		return err
	}

	for version, config := range snapshot.Configs {
		configData, err := json.MarshalIndent(config, "", "  ")
		if err != nil {
			return err
		}
		configPath := filepath.Join(configsPath, version+".json")
		if err := os.WriteFile(configPath, configData, 0644); err != nil {
			return err
		}
	}

	return nil
}

func (sm *SnapshotManager) loadExisting() error {
	entries, err := os.ReadDir(sm.basePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, entry := range entries {
		if !entry.IsDir() || filepath.Ext(entry.Name()) != ".snapshot" {
			continue
		}

		snapshotID := entry.Name()[:len(entry.Name())-len(".snapshot")]
		snapshot, err := sm.loadFromDisk(snapshotID)
		if err != nil {
			fmt.Printf("Warning: failed to load snapshot %s: %v\n", snapshotID, err)
			continue
		}

		sm.snapshots[snapshotID] = snapshot
	}

	return nil
}

func (sm *SnapshotManager) loadFromDisk(id string) (*Snapshot, error) {
	snapshotPath := filepath.Join(sm.basePath, id+".snapshot")

	// Load metadata
	metaPath := filepath.Join(snapshotPath, "meta.json")
	metaData, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, err
	}

	var meta map[string]interface{}
	if err := json.Unmarshal(metaData, &meta); err != nil {
		return nil, err
	}

	snapshot := &Snapshot{
		ID:          meta["id"].(string),
		Name:        meta["name"].(string),
		Description: getStringOrEmpty(meta, "description"),
		Checksum:    meta["checksum"].(string),
		Metadata:    make(map[string]string),
	}

	if created, ok := meta["created"].(string); ok {
		snapshot.Created, _ = time.Parse(time.RFC3339Nano, created)
	}

	if metadata, ok := meta["metadata"].(map[string]interface{}); ok {
		for k, v := range metadata {
			if vs, ok := v.(string); ok {
				snapshot.Metadata[k] = vs
			}
		}
	}

	// Load configurations
	snapshot.Configs = make(map[string]*immutableconfig.ConfigData)
	configsPath := filepath.Join(snapshotPath, "configs")

	entries, err := os.ReadDir(configsPath)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		version := entry.Name()[:len(entry.Name())-len(".json")]
		configPath := filepath.Join(configsPath, entry.Name())
		configData, err := os.ReadFile(configPath)
		if err != nil {
			continue
		}

		var config immutableconfig.ConfigData
		if err := json.Unmarshal(configData, &config); err != nil {
			continue
		}

		snapshot.Configs[version] = &config
	}

	return snapshot, nil
}

func (sm *SnapshotManager) calculateChecksum(snapshot *Snapshot) (string, error) {
	data, err := json.Marshal(snapshot.Configs)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

func generateSnapshotID() string {
	timestamp := time.Now().UTC().UnixNano()
	data := fmt.Sprintf("snapshot-%d", timestamp)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:8])
}

func getStringOrEmpty(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}
