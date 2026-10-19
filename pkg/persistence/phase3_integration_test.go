// SPDX-License-Identifier: Apache-2.0
//go:build integration

// Phase 3 integration tests for the persistence Manager with PostgreSQL backend.
// These tests exercise Manager-level functions that wrap the postgresStorageBackend:
// NewWithPostgres, Stats, doPrune, Close, store accessors, and retentionFromTier.

package persistence

import (
	"context"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/testdb"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
	"github.com/aegisgatesecurity/aegisgate/pkg/opsec"
)

// setupManager creates a persistence Manager backed by a testcontainers
// PostgreSQL instance and returns it with a cleanup function.
func setupManager(t *testing.T, platformTier tier.Tier) (*Manager, *ioc.PostgresStore, func()) {
	t.Helper()
	pgStore, dbCleanup := testdb.SetupTestDB(t)

	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.AuditDir = t.TempDir()

	mgr, err := NewWithPostgres(platformTier, cfg, pgStore)
	if err != nil {
		dbCleanup()
		t.Fatalf("NewWithPostgres: %v", err)
	}

	cleanup := func() {
		_ = mgr.Close()
		dbCleanup()
	}
	return mgr, pgStore, cleanup
}

func TestPhase3_NewWithPostgres_Success(t *testing.T) {
	mgr, _, cleanup := setupManager(t, tier.TierProfessional)
	defer cleanup()

	if !mgr.IsEnabled() {
		t.Fatal("expected manager to be enabled")
	}
	if !mgr.UsesPostgres() {
		t.Fatal("expected manager to use postgres")
	}
}

func TestPhase3_NewWithPostgres_NilStore_Fallback(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AuditDir = t.TempDir()

	mgr, err := NewWithPostgres(tier.TierCommunity, cfg, nil)
	if err != nil {
		t.Fatalf("NewWithPostgres with nil store: %v", err)
	}
	if mgr.UsesPostgres() {
		t.Fatal("expected file-based fallback, not postgres")
	}
	_ = mgr.Close()
}

func TestPhase3_NewWithPostgres_Disabled(t *testing.T) {
	pgStore, cleanup := testdb.SetupTestDB(t)
	defer cleanup()

	cfg := DefaultConfig()
	cfg.Enabled = false

	mgr, err := NewWithPostgres(tier.TierProfessional, cfg, pgStore)
	if err != nil {
		t.Fatalf("NewWithPostgres disabled: %v", err)
	}
	if mgr.IsEnabled() {
		t.Fatal("expected manager to be disabled")
	}
}

func TestPhase3_CorrelationStore(t *testing.T) {
	mgr, _, cleanup := setupManager(t, tier.TierProfessional)
	defer cleanup()

	store := mgr.CorrelationStore()
	if store == nil {
		t.Fatal("expected non-nil correlation store with postgres backend")
	}
}

func TestPhase3_AttestationStore(t *testing.T) {
	mgr, _, cleanup := setupManager(t, tier.TierProfessional)
	defer cleanup()

	store := mgr.AttestationStore()
	if store == nil {
		t.Fatal("expected non-nil attestation store with postgres backend")
	}
}

func TestPhase3_IncidentStore(t *testing.T) {
	mgr, _, cleanup := setupManager(t, tier.TierProfessional)
	defer cleanup()

	store := mgr.IncidentStore()
	if store == nil {
		t.Fatal("expected non-nil incident store with postgres backend")
	}
}

func TestPhase3_PostgresStore_Accessor(t *testing.T) {
	mgr, pgStore, cleanup := setupManager(t, tier.TierProfessional)
	defer cleanup()

	ps := mgr.PostgresStore()
	if ps == nil {
		t.Fatal("expected non-nil PostgresStore accessor")
	}
	if ps != pgStore {
		t.Fatal("PostgresStore accessor returned different store")
	}
}

func TestPhase3_Stats_Postgres(t *testing.T) {
	mgr, _, cleanup := setupManager(t, tier.TierProfessional)
	defer cleanup()

	stats := mgr.Stats()
	if stats["backend"] != "postgresql" {
		t.Fatalf("expected backend=postgresql, got %v", stats["backend"])
	}
	if stats["correlation_backend"] != "postgresql" {
		t.Fatalf("expected correlation_backend=postgresql, got %v", stats["correlation_backend"])
	}
	if stats["attestation_backend"] != "postgresql" {
		t.Fatalf("expected attestation_backend=postgresql, got %v", stats["attestation_backend"])
	}
	if stats["enabled"] != true {
		t.Fatal("expected enabled=true")
	}
}

func TestPhase3_Stats_File(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AuditDir = t.TempDir()

	mgr, err := NewWithPostgres(tier.TierCommunity, cfg, nil)
	if err != nil {
		t.Fatalf("NewWithPostgres: %v", err)
	}
	defer mgr.Close()

	stats := mgr.Stats()
	if stats["backend"] != "file" {
		t.Fatalf("expected backend=file, got %v", stats["backend"])
	}
}

// testHoldChecker implements LegalHoldChecker for testing.
type testHoldChecker struct {
	called bool
	result bool
}

func (c *testHoldChecker) IsUnderHold(_ context.Context, _ string) bool {
	c.called = true
	return c.result
}

func TestPhase3_SetLegalHoldChecker(t *testing.T) {
	mgr, _, cleanup := setupManager(t, tier.TierProfessional)
	defer cleanup()

	checker := &testHoldChecker{result: true}
	mgr.SetLegalHoldChecker(checker)

	// Verify the checker is set without calling it yet
	if checker.called {
		t.Fatal("checker should not have been called yet")
	}
}

func TestPhase3_StartAndClose_Postgres(t *testing.T) {
	mgr, _, cleanup := setupManager(t, tier.TierProfessional)
	defer cleanup()

	if err := mgr.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Give the prune goroutine a moment to run
	time.Sleep(100 * time.Millisecond)

	if err := mgr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestPhase3_doPrune_Postgres(t *testing.T) {
	mgr, pgStore, cleanup := setupManager(t, tier.TierProfessional)
	defer cleanup()

	// Start the manager to initialize the audit log
	if err := mgr.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Write an audit entry directly through the backend
	backend, err := newPostgresStorageBackend(pgStore)
	if err != nil {
		t.Fatalf("newPostgresStorageBackend: %v", err)
	}

	entry := makeEntry("prune-test-1", time.Now().Add(-48*time.Hour),
		opsec.AuditLevelInfo, "TEST", "old entry for pruning", "test", "tenant-1", "")
	if err := backend.Write(context.Background(), entry); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Call doPrune — with Professional tier (90 day retention), nothing should
	// be pruned. The function should complete without error.
	mgr.doPrune(context.Background())

	// Close to clean up
	_ = mgr.Close()
}

func TestPhase3_retentionFromTier(t *testing.T) {
	tests := []struct {
		name     string
		tier     tier.Tier
		expected opsec.RetentionPeriod
	}{
		{"Community", tier.TierCommunity, opsec.Retention90Days},
		{"Developer", tier.TierDeveloper, opsec.Retention90Days},
		{"Professional", tier.TierProfessional, opsec.Retention90Days},
		{"Enterprise", tier.TierEnterprise, opsec.RetentionForever},
		{"Custom", tier.Tier(100), opsec.Retention90Days}, // unknown tier → 7 days → mapped to 90
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := retentionFromTier(tc.tier)
			if got != tc.expected {
				t.Fatalf("retentionFromTier(%s) = %v, want %v", tc.name, got, tc.expected)
			}
		})
	}
}

func TestPhase3_Close_Disabled(t *testing.T) {
	pgStore, cleanup := testdb.SetupTestDB(t)
	defer cleanup()

	cfg := DefaultConfig()
	cfg.Enabled = false

	mgr, err := NewWithPostgres(tier.TierProfessional, cfg, pgStore)
	if err != nil {
		t.Fatalf("NewWithPostgres: %v", err)
	}

	// Close on a disabled manager should be a no-op
	if err := mgr.Close(); err != nil {
		t.Fatalf("Close disabled manager: %v", err)
	}
}

// TestPhase3_Close_FinalPrune writes an old entry then closes the manager,
// which triggers a final prune that removes expired entries.
func TestPhase3_Close_FinalPrune(t *testing.T) {
	pgStore, dbCleanup := testdb.SetupTestDB(t)

	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.AuditDir = t.TempDir()

	mgr, err := NewWithPostgres(tier.TierProfessional, cfg, pgStore)
	if err != nil {
		dbCleanup()
		t.Fatalf("NewWithPostgres: %v", err)
	}

	// Write an entry old enough to be pruned (100 days > 90-day retention)
	backend, err := newPostgresStorageBackend(pgStore)
	if err != nil {
		dbCleanup()
		t.Fatalf("newPostgresStorageBackend: %v", err)
	}

	oldEntry := makeEntry("prune-on-close-1", time.Now().Add(-100*24*time.Hour),
		opsec.AuditLevelInfo, "TEST", "very old entry", "test", "tenant-1", "")
	if err := backend.Write(context.Background(), oldEntry); err != nil {
		dbCleanup()
		t.Fatalf("Write: %v", err)
	}

	// Start then Close — Close runs a final prune that should remove the old entry
	if err := mgr.Start(); err != nil {
		dbCleanup()
		t.Fatalf("Start: %v", err)
	}

	if err := mgr.Close(); err != nil {
		dbCleanup()
		t.Fatalf("Close: %v", err)
	}

	dbCleanup()
}
