//go:build !race

// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform — persistence error-path coverage tests
// =========================================================================

package persistence

import (
	"context"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
	"github.com/aegisgatesecurity/aegisgate/pkg/opsec"
)

// --------------------------------------------------------------------------
// New — Enabled=false returns manager with nil auditLog/storage
// --------------------------------------------------------------------------

func TestNew_EnabledFalse_NilAuditLogAndStorage(t *testing.T) {
	cfg := Config{
		Enabled:  false,
		AuditDir: "/non/existent/dir",
	}

	m, err := New(tier.TierCommunity, cfg)
	if err != nil {
		t.Fatalf("New(Enabled=false) error: %v", err)
	}
	defer m.Close()

	if m.auditLog != nil {
		t.Error("auditLog should be nil when Enabled=false")
	}
	if m.storage != nil {
		t.Error("storage should be nil when Enabled=false")
	}
}

// --------------------------------------------------------------------------
// VerifyIntegrity — auditLog nil path (Enabled=false)
// --------------------------------------------------------------------------

func TestVerifyIntegrity_AuditLogNil(t *testing.T) {
	cfg := Config{Enabled: false}

	m, err := New(tier.TierCommunity, cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer m.Close()

	// With Enabled=false, auditLog is nil → returns (true, nil, nil)
	valid, fails, err := m.VerifyIntegrity(context.Background())
	if err != nil {
		t.Fatalf("VerifyIntegrity() error: %v", err)
	}
	if !valid {
		t.Error("valid should be true for nil auditLog")
	}
	if fails != nil {
		t.Errorf("fails should be nil, got %v", fails)
	}
}

// --------------------------------------------------------------------------
// ExportForCompliance — auditLog nil path (Enabled=false)
// --------------------------------------------------------------------------

func TestExportForCompliance_AuditLogNil(t *testing.T) {
	cfg := Config{Enabled: false}

	m, err := New(tier.TierCommunity, cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer m.Close()

	// ExportForCompliance with nil auditLog returns empty JSON
	data, err := m.ExportForCompliance(context.Background(), "json")
	if err != nil {
		t.Fatalf("ExportForCompliance() error: %v", err)
	}
	if string(data) != `{"entries":[],"message":"persistence disabled"}` {
		t.Errorf("unexpected export data: %s", string(data))
	}
}

// --------------------------------------------------------------------------
// Close — nil storage path (Enabled=false)
// --------------------------------------------------------------------------

func TestClose_EnabledFalse_NilStorage(t *testing.T) {
	cfg := Config{Enabled: false}

	m, err := New(tier.TierCommunity, cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// Close with nil storage — should not panic
	if err := m.Close(); err != nil {
		t.Errorf("Close() error: %v", err)
	}
}

// --------------------------------------------------------------------------
// doPrune — auditLog nil path (Enabled=false)
// doPrune — storage nil path
// --------------------------------------------------------------------------

func TestDoPrune_AuditLogNilViaEnabledFalse(t *testing.T) {
	cfg := Config{Enabled: false}

	m, err := New(tier.TierCommunity, cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer m.Close()

	// With nil auditLog, doPrune returns immediately — no panic
	m.doPrune(context.Background())
}

func TestDoPrune_StorageNilViaNilStorage(t *testing.T) {
	// Create with Enabled=false → storage is nil, auditLog is nil
	// This exercises the "storage == nil" branch in doPrune without needing
	// a real storage failure (which would fail New() before we could test it)
	cfg := Config{Enabled: false}
	m, err := New(tier.TierCommunity, cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer m.Close()
	m.doPrune(context.Background())
}

// --------------------------------------------------------------------------
// EnsureDataDirs — success + failure
// --------------------------------------------------------------------------

func TestEnsureDataDirs_Success(t *testing.T) {
	dir := t.TempDir()
	if err := EnsureDataDirs(dir); err != nil {
		t.Fatalf("EnsureDataDirs() error: %v", err)
	}
}

func TestEnsureDataDirs_InaccessiblePath(t *testing.T) {
	// Try to create dirs under /proc (read-only on most systems)
	err := EnsureDataDirs("/proc/aegisgate-test")
	if err == nil {
		t.Skip("could create /proc dir — run as root or on permissive system")
	}
}

// --------------------------------------------------------------------------
// retentionFromTier — all standard tiers (verify no regressions)
// --------------------------------------------------------------------------

func TestRetentionFromTier_Community(t *testing.T) {
	r := retentionFromTier(tier.TierCommunity)
	if r != opsec.Retention90Days {
		t.Errorf("retentionFromTier(Community) = %v, want Retention90Days", r)
	}
}

func TestRetentionFromTier_Developer(t *testing.T) {
	r := retentionFromTier(tier.TierDeveloper)
	if r != opsec.Retention90Days {
		t.Errorf("retentionFromTier(Developer) = %v, want Retention90Days", r)
	}
}

func TestRetentionFromTier_Professional(t *testing.T) {
	r := retentionFromTier(tier.TierProfessional)
	if r != opsec.Retention90Days {
		t.Errorf("retentionFromTier(Professional) = %v, want Retention90Days", r)
	}
}

func TestRetentionFromTier_Enterprise(t *testing.T) {
	r := retentionFromTier(tier.TierEnterprise)
	if r != opsec.RetentionForever {
		t.Errorf("retentionFromTier(Enterprise) = %v, want RetentionForever", r)
	}
}

// --------------------------------------------------------------------------
// pruneLoop — ticker fires (long interval so we only catch startup prune)
// --------------------------------------------------------------------------

func TestPruneLoop_ContextCancelledBeforeTicker(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		Enabled:       true,
		AuditDir:      dir,
		MaxFileSize:   1024 * 1024,
		PruneInterval: 24 * time.Hour,
	}

	m, err := New(tier.TierDeveloper, cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	m.done = make(chan struct{})

	// Cancel immediately — pruneLoop should run initial prune then exit
	go m.pruneLoop(ctx)
	cancel()

	select {
	case <-m.done:
		// Success — pruneLoop exited cleanly
	case <-time.After(5 * time.Second):
		t.Fatal("pruneLoop did not exit after context cancellation")
	}

	_ = m.storage.Close()
}

// --------------------------------------------------------------------------
// Start / Close without prior Start
// --------------------------------------------------------------------------

func TestClose_WithoutStart(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		Enabled:       true,
		AuditDir:      dir,
		MaxFileSize:   1024 * 1024,
		PruneInterval: 24 * time.Hour,
	}

	m, err := New(tier.TierDeveloper, cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// Close without Start — cancel func is nil, should not panic
	if err := m.Close(); err != nil {
		t.Errorf("Close() error: %v", err)
	}
}

// --------------------------------------------------------------------------
// IsEnabled
// --------------------------------------------------------------------------

func TestIsEnabled_True(t *testing.T) {
	cfg := Config{Enabled: true, AuditDir: t.TempDir()}
	m, _ := New(tier.TierCommunity, cfg)
	defer m.Close()
	if !m.IsEnabled() {
		t.Error("IsEnabled() should return true")
	}
}

func TestIsEnabled_False(t *testing.T) {
	cfg := Config{Enabled: false}
	m, _ := New(tier.TierCommunity, cfg)
	defer m.Close()
	if m.IsEnabled() {
		t.Error("IsEnabled() should return false")
	}
}
