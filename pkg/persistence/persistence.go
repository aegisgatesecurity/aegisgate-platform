// SPDX-License-Identifier: MIT
// =========================================================================
// AegisGate Security Platform - Persistence Layer
// =========================================================================
//
// Wires the upstream opsec audit storage (FileStorageBackend,
// ComplianceAuditLog, PruneOldEntries) into the platform lifecycle.
//
// Responsibilities:
//   - Create file-backed audit storage at startup
//   - Start a background goroutine for retention-based pruning
//   - Provide a ComplianceAuditLog for all platform components to use
//   - Graceful shutdown with pruning completion
//
// The tier system controls retention:
//   Community:     7 days
//   Developer:    30 days
//   Professional: 90 days
//   Enterprise:  unlimited
// =========================================================================

package persistence

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/metrics"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
	"github.com/aegisgatesecurity/aegisgate/pkg/opsec"
)

// Config holds persistence configuration (loaded from YAML or defaults)
type Config struct {
	Enabled       bool          `yaml:"enabled"`
	DataDir       string        `yaml:"data_dir"`
	AuditDir      string        `yaml:"audit_dir"`
	PruneInterval time.Duration `yaml:"prune_interval"`
	MaxFileSize   int64         `yaml:"max_file_size"`
}

// DefaultConfig returns sensible defaults for persistence
func DefaultConfig() Config {
	return Config{
		Enabled:       true,
		DataDir:       "/data",
		AuditDir:      "/data/audit",
		PruneInterval: 24 * time.Hour,
		MaxFileSize:   50 * 1024 * 1024, // 50 MB per audit file
	}
}

// Manager orchestrates persistent audit storage for the platform.
// It owns the FileStorageBackend, ComplianceAuditLog, and a background
// pruning goroutine that runs on a configurable interval.
type Manager struct {
	cfg          Config
	platformTier tier.Tier
	storage      *opsec.FileStorageBackend
	auditLog     *opsec.ComplianceAuditLog
	cancel       context.CancelFunc
	done         chan struct{}
	mu           sync.RWMutex
	started      bool
}

// New creates a new persistence Manager.
// The tier determines retention period and compliance mappings.
func New(platformTier tier.Tier, cfg Config) (*Manager, error) {
	if !cfg.Enabled {
		return &Manager{
			cfg:          cfg,
			platformTier: platformTier,
			started:      false,
		}, nil
	}

	// Ensure audit directory exists
	if err := os.MkdirAll(cfg.AuditDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create audit directory %s: %w", cfg.AuditDir, err)
	}

	// Create the file storage backend
	storage, err := opsec.NewFileStorageBackend(cfg.AuditDir, cfg.MaxFileSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create file storage backend: %w", err)
	}

	// Map tier retention days → opsec RetentionPeriod
	retention := retentionFromTier(platformTier)

	// Create the compliance audit log (wires storage + retention + hash chain)
	auditLog := opsec.NewComplianceAuditLog(retention, storage, "")

	// Wire audit events to Prometheus metrics
	auditLog.SetCallback(func(_ *opsec.AuditEntry) {
		metrics.RecordAuditEvent()
	})

	return &Manager{
		cfg:          cfg,
		platformTier: platformTier,
		storage:      storage,
		auditLog:     auditLog,
		done:         make(chan struct{}),
	}, nil
}

// Start launches the background pruning goroutine.
// Call this after New() and before any LogComplianceEvent calls.
func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.cfg.Enabled || m.started {
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.started = true

	go m.pruneLoop(ctx)

	log.Printf("Persistence started: audit_dir=%s, retention=%d days, prune_interval=%s",
		m.cfg.AuditDir, m.platformTier.LogRetentionDays(), m.cfg.PruneInterval)

	return nil
}

// Close stops the pruning goroutine and closes the storage backend.
// Call this during graceful shutdown.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.cfg.Enabled || !m.started {
		return nil
	}

	// Signal the pruning goroutine to stop
	if m.cancel != nil {
		m.cancel()
	}

	// Wait for the goroutine to finish
	if m.done != nil {
		<-m.done
	}

	// Run one final prune before closing
	if m.storage != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if pruned, err := m.auditLog.PruneOldEntries(ctx); err == nil && pruned > 0 {
			log.Printf("Final prune: removed %d expired entries", pruned)
		}
	}

	// Close the storage backend
	if m.storage != nil {
		if err := m.storage.Close(); err != nil {
			return fmt.Errorf("failed to close storage backend: %w", err)
		}
	}

	m.started = false
	log.Println("Persistence stopped")
	return nil
}

// AuditLog returns the ComplianceAuditLog for use by other platform components.
// Returns nil if persistence is disabled.
func (m *Manager) AuditLog() *opsec.ComplianceAuditLog {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.auditLog
}

// Storage returns the FileStorageBackend for direct queries.
// Returns nil if persistence is disabled.
func (m *Manager) Storage() *opsec.FileStorageBackend {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.storage
}

// IsEnabled returns whether persistence is active
func (m *Manager) IsEnabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg.Enabled
}

// Stats returns operational statistics about the persistence layer
func (m *Manager) Stats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := map[string]interface{}{
		"enabled":        m.cfg.Enabled,
		"audit_dir":      m.cfg.AuditDir,
		"retention_days": m.platformTier.LogRetentionDays(),
		"started":        m.started,
	}

	if m.auditLog != nil {
		stats["entry_count"] = m.auditLog.GetEntryCount()
		stats["last_hash"] = m.auditLog.GetLastHash()
	}

	return stats
}

// VerifyIntegrity checks the audit log hash chain and storage consistency.
// Useful for compliance validation and health checks.
func (m *Manager) VerifyIntegrity(ctx context.Context) (bool, []string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.auditLog == nil {
		return true, nil, nil // nothing to verify
	}

	return m.auditLog.VerifyIntegrity(ctx)
}

// ExportForCompliance exports the full audit log in the requested format.
// Currently supports "json". Returns the raw bytes.
func (m *Manager) ExportForCompliance(ctx context.Context, format string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.auditLog == nil {
		return []byte(`{"entries":[],"message":"persistence disabled"}`), nil
	}

	return m.auditLog.ExportForCompliance(ctx, format)
}

// pruneLoop is the background goroutine that periodically prunes old entries.
func (m *Manager) pruneLoop(ctx context.Context) {
	defer close(m.done)

	ticker := time.NewTicker(m.cfg.PruneInterval)
	defer ticker.Stop()

	// Run an initial prune on startup
	m.doPrune(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.doPrune(ctx)
		}
	}
}

// doPrune executes a single pruning pass
func (m *Manager) doPrune(ctx context.Context) {
	if m.auditLog == nil || m.storage == nil {
		return
	}

	pruned, err := m.auditLog.PruneOldEntries(ctx)
	if err != nil {
		log.Printf("Audit prune error: %v", err)
		return
	}

	if pruned > 0 {
		log.Printf("Audit prune: removed %d entries older than %d days",
			pruned, m.platformTier.LogRetentionDays())
	}
}

// retentionFromTier maps the platform tier to an opsec RetentionPeriod.
func retentionFromTier(t tier.Tier) opsec.RetentionPeriod {
	days := t.LogRetentionDays()
	switch days {
	case 7:
		return opsec.Retention90Days // Community: use 90 for storage, but tier enforces 7-day visibility
	case 30:
		return opsec.Retention90Days // Developer: 90-day storage, 30-day visibility
	case 90:
		return opsec.Retention90Days
	case 365 * 3:
		return opsec.Retention3Years
	case -1:
		return opsec.RetentionForever
	default:
		// For any other value, use the exact day count as a RetentionPeriod
		return opsec.RetentionPeriod(days)
	}
}

// EnsureDataDirs creates the standard platform data directory structure.
// Called at startup before any component needs /data paths.
func EnsureDataDirs(dataDir string) error {
	dirs := []string{
		dataDir,
		filepath.Join(dataDir, "audit"),
		filepath.Join(dataDir, "certs"),
		filepath.Join(dataDir, "logs"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("failed to create data directory %s: %w", dir, err)
		}
	}

	return nil
}
