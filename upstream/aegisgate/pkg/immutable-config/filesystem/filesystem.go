// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

package filesystem

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	immutableconfig "github.com/aegisgatesecurity/aegisgate/pkg/immutable-config"
	"github.com/aegisgatesecurity/aegisgate/pkg/immutable-config/integrity"
	"github.com/aegisgatesecurity/aegisgate/pkg/immutable-config/logging"
	"github.com/aegisgatesecurity/aegisgate/pkg/immutable-config/rollback"
	"github.com/aegisgatesecurity/aegisgate/pkg/immutable-config/snapshot"
	"github.com/aegisgatesecurity/aegisgate/pkg/immutable-config/wal"
	"github.com/aegisgatesecurity/aegisgate/pkg/immutable-config/watcher"
)

// ImmutableFilesystem provides a complete immutable, read-only filesystem implementation
type ImmutableFilesystem struct {
	mu          sync.RWMutex
	provider    *FilesystemProvider
	sealed      bool
	sealedAt    time.Time
	snapshotMgr *snapshot.SnapshotManager
	wal         *wal.WAL
	watcher     *watcher.Watcher
	integrity   *integrity.IntegrityChecker
	auditLogger *logging.AuditLogger
	rollbackMgr *rollback.RollbackManager
	basePath    string
}

// FilesystemConfig configures the immutable filesystem
type FilesystemConfig struct {
	BasePath        string
	MaxVersions     int
	MaxAuditEntries int
	WatchInterval   time.Duration
	EnableWatch     bool
	AutoSeal        bool
}

// DefaultFilesystemConfig returns default configuration
func DefaultFilesystemConfig() *FilesystemConfig {
	return &FilesystemConfig{
		BasePath:        "./config-data",
		MaxVersions:     100,
		MaxAuditEntries: 10000,
		WatchInterval:   5 * time.Second,
		EnableWatch:     true,
		AutoSeal:        false,
	}
}

// NewImmutableFilesystem creates a new immutable filesystem
func NewImmutableFilesystem(cfg *FilesystemConfig) (*ImmutableFilesystem, error) {
	if cfg == nil {
		cfg = DefaultFilesystemConfig()
	}

	// Create base directory
	if err := os.MkdirAll(cfg.BasePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create base directory: %w", err)
	}

	// Create filesystem provider
	provider, err := NewFilesystemProvider(&FilesystemOptions{
		BasePath:         cfg.BasePath,
		CreateIfNotExist: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create filesystem provider: %w", err)
	}

	// Create snapshot manager
	snapshotMgr, err := snapshot.NewSnapshotManager(filepath.Join(cfg.BasePath, "snapshots"))
	if err != nil {
		return nil, fmt.Errorf("failed to create snapshot manager: %w", err)
	}

	// Create WAL
	writeAheadLog, err := wal.NewWAL(&wal.WALOptions{
		BasePath:   filepath.Join(cfg.BasePath, "wal"),
		MaxEntries: cfg.MaxVersions,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create WAL: %w", err)
	}

	// Create watcher if enabled
	var fileWatcher *watcher.Watcher
	if cfg.EnableWatch {
		fileWatcher, err = watcher.NewWatcher(&watcher.WatcherOptions{
			BasePath: cfg.BasePath,
			Interval: cfg.WatchInterval,
			IgnorePaths: []string{
				filepath.Join(cfg.BasePath, "wal"),
				filepath.Join(cfg.BasePath, "snapshots"),
			},
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create watcher: %w", err)
		}
	}

	return &ImmutableFilesystem{
		provider:    provider,
		snapshotMgr: snapshotMgr,
		wal:         writeAheadLog,
		watcher:     fileWatcher,
		integrity:   integrity.NewIntegrityChecker(),
		auditLogger: logging.NewAuditLogger(cfg.MaxAuditEntries),
		rollbackMgr: rollback.NewRollbackManager(cfg.MaxVersions, true),
		basePath:    cfg.BasePath,
	}, nil
}

// Initialize initializes the immutable filesystem
func (fs *ImmutableFilesystem) Initialize() error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if err := fs.provider.Initialize(); err != nil {
		return err
	}

	// Start watcher if available
	if fs.watcher != nil {
		fs.watcher.AddHandler(fs.handleFileEvent)
		if err := fs.watcher.Start(); err != nil {
			return fmt.Errorf("failed to start watcher: %w", err)
		}
	}

	return nil
}

// Save saves a configuration with write-ahead logging
func (fs *ImmutableFilesystem) Save(config *immutableconfig.ConfigData) (*immutableconfig.ConfigVersion, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if fs.sealed {
		fs.auditLogger.Log(
			logging.EventIntegrityFail,
			config.Version,
			"save",
			"Attempted to save to sealed filesystem",
			"",
			"",
		)
		return nil, fmt.Errorf("filesystem is sealed: modifications are not allowed")
	}

	// Append to WAL
	entry, err := fs.wal.Append(wal.EntryTypeSave, config.Version, config.Data, config.Metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to append to WAL: %w", err)
	}

	// Compute integrity hash
	hash, err := fs.integrity.ComputeHash(config.Version, config.Data, config.Metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to compute hash: %w", err)
	}
	config.Hash = hash
	config.Created = time.Now().UTC().Format(time.RFC3339)

	// Save through provider
	version, err := fs.provider.Save(config)
	if err != nil {
		if rollbackErr := fs.wal.Rollback(entry.ID); rollbackErr != nil {
			// Log rollback error but return original error
			fmt.Printf("Warning: failed to rollback WAL entry: %v\n", rollbackErr)
		}
		return nil, err
	}

	// Commit WAL entry
	if err := fs.wal.Commit(entry.ID); err != nil {
		return nil, fmt.Errorf("failed to commit WAL: %w", err)
	}

	// Record in rollback manager
	fs.rollbackMgr.AddVersion(config.Version, hash, 0, "system") // nolint:errcheck // rollback manager tracks version history

	// Update watcher checksums
	if fs.watcher != nil {
		versionDir := filepath.Join(fs.basePath, config.Version)
		fs.watcher.ForceChecksum(filepath.Join(versionDir, "config.json"), hash)
	}

	// Log audit event
	fs.auditLogger.Log(
		logging.EventConfigSave,
		config.Version,
		"save",
		fmt.Sprintf("Saved configuration version %s", config.Version),
		hash,
		config.Signature,
	)

	return version, nil
}

// Load loads a configuration version
func (fs *ImmutableFilesystem) Load(version string) (*immutableconfig.ConfigData, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	config, err := fs.provider.Load(version)
	if err != nil {
		return nil, err
	}

	// Verify integrity
	if config.Hash != "" {
		verified, err := fs.integrity.Verify(config.Hash, config.Version, config.Data, config.Metadata)
		if err != nil {
			fs.auditLogger.Log(
				logging.EventIntegrityFail,
				version,
				"load",
				fmt.Sprintf("Integrity verification failed: %v", err),
				config.Hash,
				"",
			)
			return nil, fmt.Errorf("integrity verification failed: %w", err)
		}
		if !verified {
			fs.auditLogger.Log(
				logging.EventIntegrityFail,
				version,
				"load",
				"Hash mismatch detected",
				config.Hash,
				"",
			)
			return nil, fmt.Errorf("integrity verification failed: hash mismatch")
		}
	}

	// Log audit event
	fs.auditLogger.Log(
		logging.EventConfigLoad,
		version,
		"load",
		fmt.Sprintf("Loaded configuration version %s", version),
		config.Hash,
		config.Signature,
	)

	return config, nil
}

// LoadLatest loads the latest configuration version
func (fs *ImmutableFilesystem) LoadLatest() (*immutableconfig.ConfigData, error) {
	versions, err := fs.provider.ListVersions()
	if err != nil {
		return nil, err
	}

	if len(versions) == 0 {
		return nil, fmt.Errorf("no configurations available")
	}

	var latestVersion string
	var latestTime string
	for _, v := range versions {
		if v.Timestamp > latestTime {
			latestTime = v.Timestamp
			latestVersion = v.Version
		}
	}

	return fs.Load(latestVersion)
}

// ListVersions lists all available versions
func (fs *ImmutableFilesystem) ListVersions() ([]*immutableconfig.ConfigVersion, error) {
	return fs.provider.ListVersions()
}

// Delete deletes a configuration version (admin operation, requires unsealed)
func (fs *ImmutableFilesystem) Delete(version string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if fs.sealed {
		return fmt.Errorf("filesystem is sealed: deletions are not allowed")
	}

	// Append to WAL
	entry, err := fs.wal.Append(wal.EntryTypeDelete, version, nil, nil)
	if err != nil {
		return fmt.Errorf("failed to append to WAL: %w", err)
	}

	// Delete
	if err := fs.provider.DeleteVersion(version); err != nil {
		if rollbackErr := fs.wal.Rollback(entry.ID); rollbackErr != nil {
			// Log rollback error but return original error
			fmt.Printf("Warning: failed to rollback WAL entry: %v\n", rollbackErr)
		}
		return err
	}

	// Commit WAL
	if err := fs.wal.Commit(entry.ID); err != nil {
		return fmt.Errorf("failed to commit WAL: %w", err)
	}

	// Log audit
	fs.auditLogger.Log(
		logging.EventConfigDelete,
		version,
		"delete",
		fmt.Sprintf("Deleted configuration version %s", version),
		"",
		"",
	)

	return nil
}

// Seal seals the filesystem, preventing all future modifications
func (fs *ImmutableFilesystem) Seal() error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if fs.sealed {
		return fmt.Errorf("filesystem is already sealed")
	}

	// Append seal event to WAL
	entry, err := fs.wal.Append(wal.EntryTypeSeal, "", nil, map[string]string{
		"action": "seal",
	})
	if err != nil {
		return err
	}

	fs.sealed = true
	fs.sealedAt = time.Now().UTC()

	// Commit WAL
	if err := fs.wal.Commit(entry.ID); err != nil {
		fmt.Printf("Warning: failed to commit seal entry: %v\n", err)
	}

	// Set all files to read-only
	if err := fs.setAllReadOnly(); err != nil {
		fmt.Printf("Warning: failed to set files read-only: %v\n", err)
	}

	return nil
}

// Unseal unseals the filesystem (admin operation)
func (fs *ImmutableFilesystem) Unseal() error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if !fs.sealed {
		return fmt.Errorf("filesystem is not sealed")
	}

	fs.sealed = false
	fs.sealedAt = time.Time{}

	return nil
}

// IsSealed returns whether the filesystem is sealed
func (fs *ImmutableFilesystem) IsSealed() bool {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	return fs.sealed
}

// SealedAt returns when the filesystem was sealed
func (fs *ImmutableFilesystem) SealedAt() time.Time {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	return fs.sealedAt
}

// CreateSnapshot creates a point-in-time snapshot
func (fs *ImmutableFilesystem) CreateSnapshot(name string, description string) (*snapshot.Snapshot, error) {
	return fs.snapshotMgr.Create(fs.provider, &snapshot.SnapshotOptions{
		Name:        name,
		Description: description,
	})
}

// RestoreSnapshot restores from a snapshot
func (fs *ImmutableFilesystem) RestoreSnapshot(snapshotID string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if fs.sealed {
		return fmt.Errorf("filesystem is sealed: restore not allowed")
	}

	return fs.snapshotMgr.Restore(snapshotID, fs.provider)
}

// ListSnapshots lists all snapshots
func (fs *ImmutableFilesystem) ListSnapshots() ([]*snapshot.Snapshot, error) {
	return fs.snapshotMgr.List()
}

// DeleteSnapshot deletes a snapshot
func (fs *ImmutableFilesystem) DeleteSnapshot(snapshotID string) error {
	return fs.snapshotMgr.Delete(snapshotID)
}

// VerifyIntegrity verifies the integrity of all configurations
func (fs *ImmutableFilesystem) VerifyIntegrity() (map[string]bool, error) {
	return fs.provider.VerifyIntegrity()
}

// GetAuditLog returns the audit log
func (fs *ImmutableFilesystem) GetAuditLog() []*logging.AuditEntry {
	return fs.auditLogger.GetEntries()
}

// GetWALStats returns WAL statistics
func (fs *ImmutableFilesystem) GetWALStats() map[string]int64 {
	return fs.wal.GetStats()
}

// GetWatcherStatus returns watcher status
func (fs *ImmutableFilesystem) GetWatcherStatus() map[string]interface{} {
	if fs.watcher == nil {
		return map[string]interface{}{
			"enabled": false,
		}
	}

	return map[string]interface{}{
		"enabled": true,
		"running": fs.watcher.IsRunning(),
		"watched": len(fs.watcher.GetCurrentChecksums()),
	}
}

// ExportCheckpoint exports a complete checkpoint
func (fs *ImmutableFilesystem) ExportCheckpoint() (*Checkpoint, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	checkpoint := &Checkpoint{
		Created:   time.Now().UTC(),
		Checksums: make(map[string]string),
		WALStats:  fs.wal.GetStats(),
	}

	// Get watcher checksums if available
	if fs.watcher != nil {
		checkpoint.Checksums = fs.watcher.GetCurrentChecksums()
	}

	// Export configurations
	versions, err := fs.provider.ListVersions()
	if err != nil {
		return nil, err
	}

	checkpoint.Versions = make([]string, len(versions))
	for i, v := range versions {
		checkpoint.Versions[i] = v.Version
	}

	// Export audit log
	checkpoint.AuditLog = fs.auditLogger.GetEntries()

	return checkpoint, nil
}

// Recover recovers from WAL after a crash
func (fs *ImmutableFilesystem) Recover() error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	// Stop watcher during recovery (ignore error since we're recovering)
	if fs.watcher != nil {
		fs.watcher.Stop() // nolint:errcheck // best effort during recovery
		defer func() {
			fs.watcher.Start() // nolint:errcheck // best effort during recovery
		}()
	}

	return fs.wal.Recover(func(entry *wal.Entry) error {
		// Replay committed entries
		switch entry.Type {
		case wal.EntryTypeSave:
			config := &immutableconfig.ConfigData{
				Version:  entry.Version,
				Data:     entry.Data,
				Metadata: entry.Metadata,
			}
			_, err := fs.provider.Save(config)
			return err
		case wal.EntryTypeDelete:
			return fs.provider.DeleteVersion(entry.Version)
		}
		return nil
	})
}

// CompactWAL compacts the WAL
func (fs *ImmutableFilesystem) CompactWAL() error {
	return fs.wal.Compact()
}

// Close closes the immutable filesystem
func (fs *ImmutableFilesystem) Close() error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	var cerr error
	if fs.watcher != nil {
		if err := fs.watcher.Stop(); err != nil {
			cerr = err
		}
	}

	if err := fs.wal.Close(); err != nil {
		return err
	}

	if err := fs.provider.Close(); err != nil {
		cerr = err
	}

	return cerr
}

// Private methods

func (fs *ImmutableFilesystem) handleFileEvent(event watcher.Event) {
	switch event.Type {
	case watcher.EventModified:
		fs.auditLogger.Log(
			logging.EventIntegrityFail,
			"",
			"file_modified",
			fmt.Sprintf("Unauthorized modification detected: %s", event.Path),
			event.Checksum,
			"",
		)
	case watcher.EventCreated:
		fs.auditLogger.Log(
			logging.EventConfigSave,
			"",
			"file_created",
			fmt.Sprintf("File created: %s", event.Path),
			event.Checksum,
			"",
		)
	case watcher.EventDeleted:
		fs.auditLogger.Log(
			logging.EventIntegrityFail,
			"",
			"file_deleted",
			fmt.Sprintf("Unauthorized deletion detected: %s", event.Path),
			"",
			"",
		)
	}
}

func (fs *ImmutableFilesystem) setAllReadOnly() error {
	return filepath.Walk(fs.basePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		return os.Chmod(path, 0600) //nolint:gosec // G302: intentional read-only for immutable config
	})
}

// Checkpoint represents a complete filesystem checkpoint
type Checkpoint struct {
	Created   time.Time             `json:"created"`
	Versions  []string              `json:"versions"`
	Checksums map[string]string     `json:"checksums"`
	WALStats  map[string]int64      `json:"wal_stats"`
	AuditLog  []*logging.AuditEntry `json:"audit_log"`
}

// ToJSON exports the checkpoint to JSON
func (c *Checkpoint) ToJSON() (string, error) {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}
