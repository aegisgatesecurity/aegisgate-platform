// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// persistence injection tests — unblock NewFileStorageBackend error path
// =========================================================================
// Uses the package-level newFileStorageBackend variable to inject errors.
// =========================================================================

//go:build !race

package persistence

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
	"github.com/aegisgatesecurity/aegisgate/pkg/opsec"
)

// ---------------------------------------------------------------------------
// TestNew_FileStorageBackendError — injected storage constructor error
// ---------------------------------------------------------------------------

func TestNew_FileStorageBackendError_Injected(t *testing.T) {
	// Save the original constructor
	orig := newFileStorageBackend
	defer func() { newFileStorageBackend = orig }()

	// Inject a mock that always returns an error
	newFileStorageBackend = func(basePath string, maxFileSize int64) (*opsec.FileStorageBackend, error) {
		return nil, errors.New("mock: storage backend init failure")
	}

	cfg := Config{
		Enabled:       true,
		AuditDir:      t.TempDir(),
		MaxFileSize:   1024 * 1024,
		PruneInterval: 0,
	}

	_, err := New(tier.TierCommunity, cfg)
	if err == nil {
		t.Fatal("New() should return error when storage backend fails")
	}
	if err.Error() != "failed to create file storage backend: mock: storage backend init failure" {
		t.Errorf("unexpected error message: %q", err.Error())
	}
}

// ---------------------------------------------------------------------------
// TestNew_FileStorageBackendNil — injected nil storage (should not happen in practice but tests the guard)
// ---------------------------------------------------------------------------

func TestNew_FileStorageBackendNil_Injected(t *testing.T) {
	orig := newFileStorageBackend
	defer func() { newFileStorageBackend = orig }()

	newFileStorageBackend = func(basePath string, maxFileSize int64) (*opsec.FileStorageBackend, error) {
		return nil, nil // nil backend, nil error — exercises nil storage path in tests that follow
	}

	cfg := Config{
		Enabled:       true,
		AuditDir:      t.TempDir(),
		MaxFileSize:   1024 * 1024,
		PruneInterval: 0,
	}

	m, err := New(tier.TierCommunity, cfg)
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}
	defer m.Close()

	// With nil storage, AuditLog should still be created but storage is nil
	if m.storage != nil {
		t.Error("storage should be nil when injected constructor returns nil")
	}
	if m.auditLog == nil {
		t.Error("auditLog should NOT be nil even when storage is nil (newComplianceAuditLog handles nil)")
	}
}

// ---------------------------------------------------------------------------
// TestDoPrune_PruneError — injected PruneOldEntries error
// ---------------------------------------------------------------------------

func TestDoPrune_PruneError_Injected(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		Enabled:       true,
		AuditDir:      filepath.Join(dir, "audit"),
		MaxFileSize:   1024 * 1024,
		PruneInterval: 24 * time.Hour,
	}

	m, err := New(tier.TierCommunity, cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer m.Close()

	// Inject prune error
	origPrune := pruneAuditLog
	defer func() { pruneAuditLog = origPrune }()

	pruneAuditLog = func(auditLog *opsec.ComplianceAuditLog, ctx context.Context) (int, error) {
		return 0, errors.New("mock: prune error")
	}

	// doPrune should log the error and return, not panic
	m.doPrune(context.Background())
}

// ---------------------------------------------------------------------------
// TestClose_PruneError — injected PruneOldEntries error in Close()
// ---------------------------------------------------------------------------

func TestClose_PruneError_Injected(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		Enabled:       true,
		AuditDir:      filepath.Join(dir, "audit"),
		MaxFileSize:   1024 * 1024,
		PruneInterval: 24 * time.Hour,
	}

	m, err := New(tier.TierCommunity, cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	if err := m.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	// Inject prune error for the final prune in Close()
	origPrune := pruneAuditLog
	defer func() { pruneAuditLog = origPrune }()

	pruneAuditLog = func(auditLog *opsec.ComplianceAuditLog, ctx context.Context) (int, error) {
		return 0, errors.New("mock: final prune error")
	}

	// Close should handle the prune error gracefully (pruneAuditLog errors are not returned)
	if err := m.Close(); err != nil {
		t.Errorf("Close() unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// TestClose_StorageCloseError — injected storage.Close() error
// ---------------------------------------------------------------------------

func TestClose_StorageCloseError_Injected(t *testing.T) {
	orig := closeStorage
	defer func() { closeStorage = orig }()

	// Inject a mock that returns an error
	closeStorage = func(_ *opsec.FileStorageBackend) error {
		return errors.New("mock: storage close failure")
	}

	dir := t.TempDir()
	cfg := Config{
		Enabled:       true,
		AuditDir:      filepath.Join(dir, "audit"),
		MaxFileSize:   1024 * 1024,
		PruneInterval: 24 * time.Hour,
	}

	m, err := New(tier.TierCommunity, cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	if err := m.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	// Close should propagate the storage close error
	closeErr := m.Close()
	if closeErr == nil {
		t.Fatal("Close() should return error when storage.Close() fails")
	}
	if closeErr.Error() != "failed to close storage backend: mock: storage close failure" {
		t.Errorf("unexpected error message: %q", closeErr.Error())
	}
}

// ---------------------------------------------------------------------------
// TestDoPrune_PrunedGreaterThanZero — injected prune returns pruned > 0
// ---------------------------------------------------------------------------

func TestDoPrune_PrunedGreaterThanZero_Injected(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		Enabled:       true,
		AuditDir:      filepath.Join(dir, "audit"),
		MaxFileSize:   1024 * 1024,
		PruneInterval: 24 * time.Hour,
	}

	m, err := New(tier.TierCommunity, cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer m.Close()

	// Inject prune success with pruned > 0
	origPrune := pruneAuditLog
	defer func() { pruneAuditLog = origPrune }()

	pruneAuditLog = func(auditLog *opsec.ComplianceAuditLog, ctx context.Context) (int, error) {
		return 42, nil // 42 entries "pruned"
	}

	// doPrune should log the removal message
	m.doPrune(context.Background())
}

// ---------------------------------------------------------------------------
// TestClose_FinalPrunePruned — injected prune returns pruned > 0 in Close()
// ---------------------------------------------------------------------------

func TestClose_FinalPrunePruned_Injected(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		Enabled:       true,
		AuditDir:      filepath.Join(dir, "audit"),
		MaxFileSize:   1024 * 1024,
		PruneInterval: 24 * time.Hour,
	}

	m, err := New(tier.TierCommunity, cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	if err := m.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	// Inject prune success with pruned > 0 for final prune
	origPrune := pruneAuditLog
	defer func() { pruneAuditLog = origPrune }()

	pruneAuditLog = func(auditLog *opsec.ComplianceAuditLog, ctx context.Context) (int, error) {
		return 5, nil // 5 entries "pruned"
	}

	// Close should log the final prune message
	if err := m.Close(); err != nil {
		t.Errorf("Close() unexpected error: %v", err)
	}
}
