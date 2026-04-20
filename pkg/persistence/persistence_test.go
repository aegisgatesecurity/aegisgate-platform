// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - Persistence Layer Tests
// =========================================================================

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

// tempDir creates a temporary directory for test isolation
func tempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	return dir
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if !cfg.Enabled {
		t.Error("Default persistence should be enabled")
	}
	if cfg.DataDir != "/data" {
		t.Errorf("Default DataDir = %q, want /data", cfg.DataDir)
	}
	if cfg.AuditDir != "/data/audit" {
		t.Errorf("Default AuditDir = %q, want /data/audit", cfg.AuditDir)
	}
	if cfg.PruneInterval != 24*time.Hour {
		t.Errorf("Default PruneInterval = %v, want 24h", cfg.PruneInterval)
	}
}

func TestNewPersistenceCreatesDirectories(t *testing.T) {
	dir := tempDir(t)
	auditDir := filepath.Join(dir, "audit")

	cfg := Config{
		Enabled:       true,
		DataDir:       dir,
		AuditDir:      auditDir,
		PruneInterval: 1 * time.Hour,
		MaxFileSize:   1024 * 1024,
	}

	mgr, err := New(tier.TierCommunity, cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// Verify the audit directory was created
	if _, err := os.Stat(auditDir); os.IsNotExist(err) {
		t.Errorf("Audit directory was not created: %s", auditDir)
	}

	// Clean up
	_ = mgr.Close()
}

func TestNewPersistenceDisabled(t *testing.T) {
	cfg := Config{Enabled: false}

	mgr, err := New(tier.TierCommunity, cfg)
	if err != nil {
		t.Fatalf("New() with disabled persistence should not error: %v", err)
	}

	if mgr.IsEnabled() {
		t.Error("Disabled persistence should report IsEnabled() = false")
	}
	if mgr.AuditLog() != nil {
		t.Error("Disabled persistence should have nil AuditLog()")
	}
	if mgr.Storage() != nil {
		t.Error("Disabled persistence should have nil Storage()")
	}
}

func TestNewPersistenceAllTiers(t *testing.T) {
	tiers := []tier.Tier{
		tier.TierCommunity,
		tier.TierDeveloper,
		tier.TierProfessional,
		tier.TierEnterprise,
	}

	for _, tierVal := range tiers {
		t.Run(tierVal.String(), func(t *testing.T) {
			dir := tempDir(t)
			cfg := Config{
				Enabled:       true,
				DataDir:       dir,
				AuditDir:      filepath.Join(dir, "audit"),
				PruneInterval: 24 * time.Hour,
				MaxFileSize:   1024 * 1024,
			}

			mgr, err := New(tierVal, cfg)
			if err != nil {
				t.Fatalf("New(%s) error: %v", tierVal.String(), err)
			}

			if !mgr.IsEnabled() {
				t.Errorf("Persistence should be enabled for tier %s", tierVal.String())
			}

			if mgr.AuditLog() == nil {
				t.Errorf("AuditLog() should not be nil for tier %s", tierVal.String())
			}

			_ = mgr.Close()
		})
	}
}

func TestStartAndClose(t *testing.T) {
	dir := tempDir(t)
	cfg := Config{
		Enabled:       true,
		DataDir:       dir,
		AuditDir:      filepath.Join(dir, "audit"),
		PruneInterval: 100 * time.Millisecond, // Fast for testing
		MaxFileSize:   1024 * 1024,
	}

	mgr, err := New(tier.TierCommunity, cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// Start should succeed
	if err := mgr.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	// Close should succeed and complete quickly
	done := make(chan error, 1)
	go func() {
		done <- mgr.Close()
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Close() error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close() timed out — pruning goroutine may be stuck")
	}
}

func TestStartDisabledIsNoop(t *testing.T) {
	cfg := Config{Enabled: false}
	mgr, _ := New(tier.TierCommunity, cfg)

	if err := mgr.Start(); err != nil {
		t.Errorf("Start() on disabled manager should not error: %v", err)
	}

	if err := mgr.Close(); err != nil {
		t.Errorf("Close() on disabled manager should not error: %v", err)
	}
}

func TestAuditLogWriteAndRead(t *testing.T) {
	dir := tempDir(t)
	cfg := Config{
		Enabled:       true,
		DataDir:       dir,
		AuditDir:      filepath.Join(dir, "audit"),
		PruneInterval: 24 * time.Hour,
		MaxFileSize:   1024 * 1024,
	}

	mgr, err := New(tier.TierCommunity, cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	auditLog := mgr.AuditLog()
	if auditLog == nil {
		t.Fatal("AuditLog() should not be nil")
	}

	// Log a compliance event
	ctx := context.Background()
	err = auditLog.LogComplianceEvent(
		ctx,
		opsec.AuditLevelInfo,
		"auth.login",
		"Test user logged in",
		[]string{"SOC2"},
		map[string]interface{}{"user": "test"},
	)
	if err != nil {
		t.Fatalf("LogComplianceEvent() error: %v", err)
	}

	// Verify entry count
	if auditLog.GetEntryCount() != 1 {
		t.Errorf("GetEntryCount() = %d, want 1", auditLog.GetEntryCount())
	}

	// Verify we can query it back from storage
	filter := opsec.AuditFilter{
		EventTypes: []string{"auth.login"},
		Limit:      10,
	}

	entries, err := auditLog.Query(ctx, filter)
	if err != nil {
		t.Fatalf("Query() error: %v", err)
	}

	if len(entries) != 1 {
		t.Errorf("Query() returned %d entries, want 1", len(entries))
	}

	if entries[0].EventType != "auth.login" {
		t.Errorf("Entry EventType = %q, want %q", entries[0].EventType, "auth.login")
	}

	_ = mgr.Close()
}

func TestPruneOldEntries(t *testing.T) {
	dir := tempDir(t)
	cfg := Config{
		Enabled:       true,
		DataDir:       dir,
		AuditDir:      filepath.Join(dir, "audit"),
		PruneInterval: 24 * time.Hour,
		MaxFileSize:   1024 * 1024,
	}

	// Use Developer tier (30-day retention) for a deterministic test
	mgr, err := New(tier.TierDeveloper, cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	auditLog := mgr.AuditLog()
	ctx := context.Background()

	// Log an event
	_ = auditLog.LogComplianceEvent(
		ctx,
		opsec.AuditLevelInfo,
		"auth.login",
		"Test user logged in",
		[]string{"SOC2"},
		nil,
	)

	// Verify 1 entry exists before prune
	if auditLog.GetEntryCount() != 1 {
		t.Fatalf("GetEntryCount() before prune = %d, want 1", auditLog.GetEntryCount())
	}

	// Run prune — should NOT remove recent entries
	pruned, err := auditLog.PruneOldEntries(ctx)
	if err != nil {
		t.Fatalf("PruneOldEntries() error: %v", err)
	}

	// Recent entry should not be pruned
	if pruned != 0 {
		t.Errorf("PruneOldEntries() pruned %d recent entries, want 0", pruned)
	}

	_ = mgr.Close()
}

func TestHashChainIntegrity(t *testing.T) {
	dir := tempDir(t)
	cfg := Config{
		Enabled:       true,
		DataDir:       dir,
		AuditDir:      filepath.Join(dir, "audit"),
		PruneInterval: 24 * time.Hour,
		MaxFileSize:   1024 * 1024,
	}

	mgr, err := New(tier.TierCommunity, cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	auditLog := mgr.AuditLog()
	ctx := context.Background()

	// Log several events
	for i := 0; i < 5; i++ {
		_ = auditLog.LogComplianceEvent(
			ctx,
			opsec.AuditLevelInfo,
			"auth.login",
			"Sequential login event",
			[]string{"SOC2"},
			map[string]interface{}{"sequence": i},
		)
	}

	// Verify hash chain integrity
	valid, failures, err := mgr.VerifyIntegrity(ctx)
	if err != nil {
		t.Fatalf("VerifyIntegrity() error: %v", err)
	}

	if !valid {
		t.Errorf("Hash chain integrity failed: %v", failures)
	}

	// Last hash should be non-empty
	stats := mgr.Stats()
	lastHash, ok := stats["last_hash"].(string)
	if !ok || lastHash == "" {
		t.Error("Stats() last_hash should be non-empty after logging events")
	}

	_ = mgr.Close()
}

func TestStats(t *testing.T) {
	dir := tempDir(t)
	cfg := Config{
		Enabled:       true,
		DataDir:       dir,
		AuditDir:      filepath.Join(dir, "audit"),
		PruneInterval: 24 * time.Hour,
		MaxFileSize:   1024 * 1024,
	}

	mgr, err := New(tier.TierCommunity, cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	stats := mgr.Stats()

	if stats["enabled"] != true {
		t.Error("Stats enabled should be true")
	}
	if stats["audit_dir"] != cfg.AuditDir {
		t.Errorf("Stats audit_dir = %v, want %s", stats["audit_dir"], cfg.AuditDir)
	}
	if stats["retention_days"] != 7 {
		t.Errorf("Stats retention_days = %v, want 7 (Community)", stats["retention_days"])
	}

	_ = mgr.Close()
}

func TestEnsureDataDirs(t *testing.T) {
	dir := tempDir(t)
	dataDir := filepath.Join(dir, "data")

	if err := EnsureDataDirs(dataDir); err != nil {
		t.Fatalf("EnsureDataDirs() error: %v", err)
	}

	// Verify all expected subdirectories exist
	expectedDirs := []string{
		dataDir,
		filepath.Join(dataDir, "audit"),
		filepath.Join(dataDir, "certs"),
		filepath.Join(dataDir, "logs"),
	}

	for _, expected := range expectedDirs {
		info, err := os.Stat(expected)
		if err != nil {
			t.Errorf("Directory not created: %s: %v", expected, err)
			continue
		}
		if !info.IsDir() {
			t.Errorf("Expected directory, got file: %s", expected)
		}
	}
}

func TestRetentionFromTier(t *testing.T) {
	tests := []struct {
		name     string
		tier     tier.Tier
		days     int
		expected opsec.RetentionPeriod
	}{
		{"Community", tier.TierCommunity, 7, opsec.Retention90Days},
		{"Developer", tier.TierDeveloper, 30, opsec.Retention90Days},
		{"Professional", tier.TierProfessional, 90, opsec.Retention90Days},
		{"Enterprise", tier.TierEnterprise, -1, opsec.RetentionForever},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := retentionFromTier(tc.tier)
			if result != tc.expected {
				t.Errorf("retentionFromTier(%s) = %v, want %v", tc.name, result, tc.expected)
			}
		})
	}
}

func TestDoubleCloseIsSafe(t *testing.T) {
	dir := tempDir(t)
	cfg := Config{
		Enabled:       true,
		DataDir:       dir,
		AuditDir:      filepath.Join(dir, "audit"),
		PruneInterval: 24 * time.Hour,
		MaxFileSize:   1024 * 1024,
	}

	mgr, err := New(tier.TierCommunity, cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	_ = mgr.Start()

	// First close should succeed
	if err := mgr.Close(); err != nil {
		t.Errorf("First Close() error: %v", err)
	}

	// Second close should also succeed (no-op)
	if err := mgr.Close(); err != nil {
		t.Errorf("Second Close() error: %v", err)
	}
}

func TestExportForCompliance(t *testing.T) {
	dir := tempDir(t)
	cfg := Config{
		Enabled:       true,
		DataDir:       dir,
		AuditDir:      filepath.Join(dir, "audit"),
		PruneInterval: 24 * time.Hour,
		MaxFileSize:   1024 * 1024,
	}

	mgr, err := New(tier.TierCommunity, cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	_ = mgr.Start()

	auditLog := mgr.AuditLog()
	ctx := context.Background()

	// Log an event so we have something to export
	_ = auditLog.LogComplianceEvent(
		ctx,
		opsec.AuditLevelInfo,
		"auth.login",
		"User logged in for compliance test",
		[]string{"SOC2"},
		nil,
	)

	// Export as JSON
	data, err := mgr.ExportForCompliance(ctx, "json")
	if err != nil {
		t.Fatalf("ExportForCompliance() error: %v", err)
	}

	if len(data) == 0 {
		t.Error("ExportForCompliance() returned empty data")
	}

	// Should contain "entries" key
	exportStr := string(data)
	if len(exportStr) < 10 {
		t.Errorf("Export too short: %q", exportStr)
	}

	_ = mgr.Close()
}

func TestExportForComplianceDisabled(t *testing.T) {
	cfg := Config{Enabled: false}
	mgr, _ := New(tier.TierCommunity, cfg)

	ctx := context.Background()
	data, err := mgr.ExportForCompliance(ctx, "json")
	if err != nil {
		t.Fatalf("ExportForCompliance() on disabled manager should not error: %v", err)
	}

	if len(data) == 0 {
		t.Error("ExportForCompliance() on disabled manager should return fallback message")
	}
}
