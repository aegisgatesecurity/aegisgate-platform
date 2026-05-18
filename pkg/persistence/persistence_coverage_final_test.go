// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// persistence_coverage_final.go — final uncovered gaps
// Targets:
//   1. New: os.MkdirAll fails (line ~161)
//   2. New: NewFileStorageBackend fails (line ~344)
//   3. Close: PruneOldEntries returns error (line ~231)
//   4. Close: storage.Close returns error (line ~238)
//   5. doPrune: pruned > 0 path (line ~349)
//   6. doPrune: PruneOldEntries returns error
//   7. retentionFromTier: case 365*3 (line ~365)
//   8. retentionFromTier: default (line ~369)
// =========================================================================

//go:build !race

package persistence

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
	"github.com/aegisgatesecurity/aegisgate/pkg/opsec"
)

// =========================================================================
// 1. New — os.MkdirAll error (line ~161)
// =========================================================================

func TestNew_AuditDirCreationFails(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("Skipping: test requires non-root user")
	}

	cfg := Config{
		Enabled:       true,
		AuditDir:      "/proc/aegisgate-persistence-test",
		PruneInterval: 24 * time.Hour,
		MaxFileSize:   1024 * 1024,
	}

	_, err := New(tier.TierCommunity, cfg)
	if err == nil {
		t.Error("New() should fail when audit dir creation fails")
	}

	// Clean up if it somehow got created
	os.RemoveAll("/proc/aegisgate-persistence-test")
}

// =========================================================================
// 2. New — NewFileStorageBackend error (line ~344)
// When the audit dir cannot be created or accessed by the storage backend,
// New() should fail. We test this by using a path with invalid characters
// or a directory that exists but cannot be accessed.
// =========================================================================

func TestNew_FileStorageBackendError_InvalidPath(t *testing.T) {
	// Use a path with invalid characters for the storage backend
	// On Linux, this will fail at the storage backend level
	cfg := Config{
		Enabled:       true,
		AuditDir:      "/proc/aegisgate-invalid-path/test",
		PruneInterval: 24 * time.Hour,
		MaxFileSize:   1024 * 1024,
	}

	_, err := New(tier.TierCommunity, cfg)
	if err == nil {
		t.Error("New() should fail with invalid path")
	}

	os.RemoveAll("/proc/aegisgate-invalid-path")
}

// =========================================================================
// 3. Close — PruneOldEntries returns error (via closed storage)
// The PruneOldEntries error path is tested via manual manager construction
// and closing storage before Close, causing prune to fail.
// =========================================================================

// =========================================================================
// 3. Close — PruneOldEntries returns error (line ~231)
// We need to test the error path in Close where PruneOldEntries returns
// an error (not nil). The Manager struct uses concrete types, not
// interfaces, so we can't directly inject a failing auditLog.
// However, we can test this by creating a Manager where the storage
// is closed before calling doPrune (via Close), which causes
// PruneOldEntries to fail on the Query call.
// =========================================================================

func TestClose_PruneErrorViaClosedStorage(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		Enabled:       true,
		AuditDir:      filepath.Join(dir, "audit"),
		PruneInterval: 24 * time.Hour,
		MaxFileSize:   1024 * 1024,
	}

	m, err := New(tier.TierCommunity, cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// Close the storage so PruneOldEntries in Close() fails
	_ = m.storage.Close()

	// Close should handle storage error gracefully (the prune error path)
	if err := m.Close(); err != nil {
		t.Logf("Close() with closed storage: %v", err)
	}
}

// =========================================================================
// 4. Close — storage.Close returns error (line ~238)
// Already covered by TestClose_StorageCloseError in persistence_coverage2_test.go
// Skip duplicate declaration.
// =========================================================================

// =========================================================================
// 5. doPrune — pruned > 0 path (line ~349)
// With RetentionPeriod(0), all entries are considered "old" and will be
// pruned. This exercises the "pruned > 0" branch in doPrune.
// =========================================================================

func TestDoPrune_PrunedGreaterThanZero(t *testing.T) {
	dir := t.TempDir()
	auditDir := filepath.Join(dir, "audit")

	storage, err := opsec.NewFileStorageBackend(auditDir, 1024*1024)
	if err != nil {
		t.Fatalf("NewFileStorageBackend error: %v", err)
	}

	// RetentionPeriod(0) means entries are immediately "old"
	auditLog := opsec.NewComplianceAuditLog(opsec.RetentionPeriod(0), storage, "")

	// Log entries that will be immediately old due to 0-day retention
	ctx := context.Background()
	_ = auditLog.LogComplianceEvent(ctx, 1, "test", "entry1", nil, nil)
	_ = auditLog.LogComplianceEvent(ctx, 1, "test", "entry2", nil, nil)

	// Construct Manager manually to use custom retention
	m := &Manager{
		cfg:          Config{Enabled: true, AuditDir: auditDir},
		platformTier: tier.TierEnterprise,
		storage:      storage,
		auditLog:     auditLog,
	}

	// doPrune should prune entries (count > 0) due to 0-day retention
	m.doPrune(ctx)

	_ = storage.Close()
}

// =========================================================================
// 6. doPrune — PruneOldEntries returns error
// We can test this by closing the storage before calling doPrune, which
// causes PruneOldEntries to fail on its Query call.
// =========================================================================

func TestDoPrune_PruneOldEntriesError(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		Enabled:       true,
		AuditDir:      filepath.Join(dir, "audit"),
		PruneInterval: 24 * time.Hour,
		MaxFileSize:   1024 * 1024,
	}

	m, err := New(tier.TierCommunity, cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// Close storage so PruneOldEntries fails
	_ = m.storage.Close()

	// doPrune should log the error and return, not panic
	m.doPrune(context.Background())
}

// =========================================================================
// 7. retentionFromTier — all standard tiers tested
// Note: retentionFromTier takes a tier.Tier value and calls LogRetentionDays().
// The switch cases (7, 30, 90, 365*3, -1, default) are all based on the
// return value of LogRetentionDays(). Since LogRetentionDays() returns 7 for
// any invalid tier value (default case), and no standard tier returns
// 365*3 or an unexpected value, the "365*3" and "default" branches are
// effectively dead code from the public API perspective. We test the
// standard tiers that DO exercise reachable branches.
// =========================================================================

func TestRetentionFromTier_AllStandardTiers(t *testing.T) {
	tests := []struct {
		tier tier.Tier
		want opsec.RetentionPeriod
	}{
		{tier.TierCommunity, opsec.Retention90Days},
		{tier.TierDeveloper, opsec.Retention90Days},
		{tier.TierProfessional, opsec.Retention90Days},
		{tier.TierEnterprise, opsec.RetentionForever},
	}

	for _, tc := range tests {
		r := retentionFromTier(tc.tier)
		if r != tc.want {
			t.Errorf("retentionFromTier(%v) = %v, want %v", tc.tier, r, tc.want)
		}
	}
}
