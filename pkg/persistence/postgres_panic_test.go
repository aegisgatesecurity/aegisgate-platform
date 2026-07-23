// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Persistence PostgreSQL Panic-Recovery Unit Tests
//
// Tests pool-call paths via panic recovery to maximize coverage without
// requiring a live PostgreSQL connection.
//go:build !integration

package persistence

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
	"github.com/aegisgatesecurity/aegisgate/pkg/opsec"
)

// --------------------------------------------------------------------
// postgresStorageBackend panic-recovery tests
// --------------------------------------------------------------------

func TestPostgresBackend_Write_NilEntry(t *testing.T) {
	b := &postgresStorageBackend{closed: false}
	// Write with nil entry should return nil (no-op)
	if err := b.Write(context.Background(), nil); err != nil {
		t.Fatalf("expected nil for nil entry, got: %v", err)
	}
}

func TestPostgresBackend_Write_ClosedState(t *testing.T) {
	b := &postgresStorageBackend{closed: true}
	err := b.Write(context.Background(), &opsec.AuditEntry{ID: "test"})
	if err == nil {
		t.Fatal("expected error for closed backend")
	}
}

func TestPostgresBackend_Read_ClosedState(t *testing.T) {
	b := &postgresStorageBackend{closed: true}
	_, err := b.Read(context.Background(), "test-id")
	if err == nil {
		t.Fatal("expected error for closed backend")
	}
}

func TestPostgresBackend_Query_ClosedState(t *testing.T) {
	b := &postgresStorageBackend{closed: true}
	_, err := b.Query(context.Background(), opsec.AuditFilter{})
	if err == nil {
		t.Fatal("expected error for closed backend")
	}
}

func TestPostgresBackend_Delete_ClosedState(t *testing.T) {
	b := &postgresStorageBackend{closed: true}
	err := b.Delete(context.Background(), "test-id")
	if err == nil {
		t.Fatal("expected error for closed backend")
	}
}

func TestPostgresBackend_Count_ClosedState(t *testing.T) {
	b := &postgresStorageBackend{closed: true}
	_, err := b.Count(context.Background())
	if err == nil {
		t.Fatal("expected error for closed backend")
	}
}

func TestPostgresBackend_VerifyIntegrity_ClosedState(t *testing.T) {
	b := &postgresStorageBackend{closed: true}
	_, _, err := b.VerifyIntegrity(context.Background())
	if err == nil {
		t.Fatal("expected error for closed backend")
	}
}

func TestPostgresBackend_Write_PanicsOnNilPool(t *testing.T) {
	b := &postgresStorageBackend{closed: false, pool: nil}
	ctx := context.Background()

	entry := &opsec.AuditEntry{
		ID:        "test-entry-1",
		Timestamp: time.Now(),
		Level:     opsec.AuditLevelInfo,
		EventType: "test",
		Message:   "test message",
		Source:    "test-source",
	}

	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		_ = b.Write(ctx, entry)
	}()
	if !didPanic {
		t.Error("expected panic on nil pool in Write")
	}
}

func TestPostgresBackend_Read_PanicsOnNilPool(t *testing.T) {
	b := &postgresStorageBackend{closed: false, pool: nil}
	ctx := context.Background()

	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		_, _ = b.Read(ctx, "test-id")
	}()
	if !didPanic {
		t.Error("expected panic on nil pool in Read")
	}
}

func TestPostgresBackend_Query_PanicsOnNilPool(t *testing.T) {
	b := &postgresStorageBackend{closed: false, pool: nil}
	ctx := context.Background()

	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		_, _ = b.Query(ctx, opsec.AuditFilter{})
	}()
	if !didPanic {
		t.Error("expected panic on nil pool in Query")
	}
}

func TestPanicUnit_Delete_PanicsOnNilPool(t *testing.T) {
	b := &postgresStorageBackend{closed: false, pool: nil}
	ctx := context.Background()

	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		_ = b.Delete(ctx, "test-id")
	}()
	if !didPanic {
		t.Error("expected panic on nil pool in Delete")
	}
}

func TestPostgresBackend_PruneExpired_NegativeRetention(t *testing.T) {
	b := &postgresStorageBackend{closed: false, pool: nil}
	ctx := context.Background()

	// Negative retention should return 0, nil without accessing pool
	count, err := b.PruneExpired(ctx, -1)
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 count, got: %d", count)
	}
}

func TestPostgresBackend_PruneExpired_ZeroRetention(t *testing.T) {
	b := &postgresStorageBackend{closed: false, pool: nil}
	ctx := context.Background()

	// Zero retention should also return 0, nil
	count, err := b.PruneExpired(ctx, 0)
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 count, got: %d", count)
	}
}

func TestPostgresBackend_PruneExpired_PanicsOnNilPool(t *testing.T) {
	b := &postgresStorageBackend{closed: false, pool: nil}
	ctx := context.Background()

	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		_, _ = b.PruneExpired(ctx, 30)
	}()
	if !didPanic {
		t.Error("expected panic on nil pool in PruneExpired")
	}
}

func TestPostgresBackend_Count_PanicsOnNilPool(t *testing.T) {
	b := &postgresStorageBackend{closed: false, pool: nil}
	ctx := context.Background()

	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		_, _ = b.Count(ctx)
	}()
	if !didPanic {
		t.Error("expected panic on nil pool in Count")
	}
}

func TestPostgresBackend_VerifyIntegrity_PanicsOnNilPool(t *testing.T) {
	b := &postgresStorageBackend{closed: false, pool: nil}
	ctx := context.Background()

	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		_, _, _ = b.VerifyIntegrity(ctx)
	}()
	if !didPanic {
		t.Error("expected panic on nil pool in VerifyIntegrity")
	}
}

// --------------------------------------------------------------------
// Manager coverage: CorrelationStore, AttestationStore, IncidentStore
// --------------------------------------------------------------------

func TestManager_CorrelationStore_Nil(t *testing.T) {
	m := &Manager{}
	if cs := m.CorrelationStore(); cs != nil {
		t.Fatal("expected nil CorrelationStore")
	}
}

func TestManager_CorrelationStore_WithPostgres(t *testing.T) {
	// Create a Manager with usePostgres=true but nil stores
	m := &Manager{usePostgres: true, correlationStore: nil}
	if cs := m.CorrelationStore(); cs != nil {
		t.Fatal("expected nil CorrelationStore")
	}
}

func TestManager_AttestationStore_Nil(t *testing.T) {
	m := &Manager{}
	if as := m.AttestationStore(); as != nil {
		t.Fatal("expected nil AttestationStore")
	}
}

func TestManager_IncidentStore_Nil(t *testing.T) {
	m := &Manager{}
	if is := m.IncidentStore(); is != nil {
		t.Fatal("expected nil IncidentStore")
	}
}

func TestManager_Stats_Disabled(t *testing.T) {
	m := &Manager{cfg: Config{Enabled: false}}
	stats := m.Stats()
	if stats["enabled"] != false {
		t.Error("expected enabled=false")
	}
}

func TestManager_Stats_WithPostgres(t *testing.T) {
	m := &Manager{
		cfg:          Config{Enabled: true, AuditDir: "/tmp/test"},
		usePostgres:  true,
		platformTier: tier.TierProfessional,
	}
	stats := m.Stats()
	if stats["backend"] != "postgresql" {
		t.Errorf("expected backend=postgresql, got %v", stats["backend"])
	}
}

func TestManager_VerifyIntegrity_Disabled(t *testing.T) {
	m := &Manager{cfg: Config{Enabled: false}}
	ok, broken, err := m.VerifyIntegrity(context.Background())
	if !ok {
		t.Error("expected ok=true for disabled persistence")
	}
	if broken != nil {
		t.Error("expected nil broken for disabled persistence")
	}
	if err != nil {
		t.Errorf("expected nil err for disabled persistence, got: %v", err)
	}
}

func TestManager_ExportForCompliance_Disabled(t *testing.T) {
	m := &Manager{cfg: Config{Enabled: false}}
	data, err := m.ExportForCompliance(context.Background(), "json")
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if string(data) != `{"entries":[],"message":"persistence disabled"}` {
		t.Errorf("unexpected export data: %s", string(data))
	}
}

func TestPanicUnit_IsNoRows(t *testing.T) {
	// pgx.ErrNoRows case
	if !isNoRows(pgx.ErrNoRows) {
		t.Error("expected isNoRows(pgx.ErrNoRows) = true")
	}

	// nil case
	if isNoRows(nil) {
		t.Error("expected isNoRows(nil) = false")
	}

	// Generic error case
	if isNoRows(context.Canceled) {
		t.Error("expected isNoRows(context.Canceled) = false")
	}
}

func TestPanicUnit_JoinStrings(t *testing.T) {
	result := joinStrings([]string{"a", "b", "c"}, ", ")
	if result != "a, b, c" {
		t.Errorf("expected 'a, b, c', got '%s'", result)
	}

	// Empty slice
	result = joinStrings([]string{}, ", ")
	if result != "" {
		t.Errorf("expected empty string, got '%s'", result)
	}

	// Single element
	result = joinStrings([]string{"a"}, ", ")
	if result != "a" {
		t.Errorf("expected 'a', got '%s'", result)
	}
}

func TestPanicUnit_ParseAuditLevel_AllLevels(t *testing.T) {
	tests := []struct {
		input    string
		expected opsec.AuditLevel
	}{
		{"INFO", opsec.AuditLevelInfo},
		{"WARNING", opsec.AuditLevelWarning},
		{"ERROR", opsec.AuditLevelError},
		{"CRITICAL", opsec.AuditLevelCritical},
		{"ALERT", opsec.AuditLevelAlert},
		{"UNKNOWN", opsec.AuditLevelInfo}, // default
		{"", opsec.AuditLevelInfo},        // default
	}

	for _, tt := range tests {
		result := parseAuditLevel(tt.input)
		if result != tt.expected {
			t.Errorf("parseAuditLevel(%q) = %v, want %v", tt.input, result, tt.expected)
		}
	}
}

func TestPanicUnit_Query_WithFilters(t *testing.T) {
	// Query with filters builds dynamic SQL — test the closed path
	b := &postgresStorageBackend{closed: true}

	// With levels filter
	_, err := b.Query(context.Background(), opsec.AuditFilter{
		Levels: []opsec.AuditLevel{opsec.AuditLevelInfo, opsec.AuditLevelError},
	})
	if err == nil {
		t.Fatal("expected error for closed backend")
	}

	// With event types filter
	_, err = b.Query(context.Background(), opsec.AuditFilter{
		EventTypes: []string{"login", "logout"},
	})
	if err == nil {
		t.Fatal("expected error for closed backend")
	}

	// With tenant ID and source
	_, err = b.Query(context.Background(), opsec.AuditFilter{
		TenantID: "tenant-1",
		Source:   "auth-service",
	})
	if err == nil {
		t.Fatal("expected error for closed backend")
	}

	// With search text
	_, err = b.Query(context.Background(), opsec.AuditFilter{
		SearchText: "failed login",
	})
	if err == nil {
		t.Fatal("expected error for closed backend")
	}

	// With time range
	_, err = b.Query(context.Background(), opsec.AuditFilter{
		StartTime: time.Now().Add(-time.Hour),
		EndTime:   time.Now(),
	})
	if err == nil {
		t.Fatal("expected error for closed backend")
	}
}

func TestPanicUnit_Write_WithEntry(t *testing.T) {
	b := &postgresStorageBackend{closed: false, pool: nil}
	ctx := context.Background()

	entry := &opsec.AuditEntry{
		ID:             "test-entry-write",
		Timestamp:      time.Now(),
		Level:          opsec.AuditLevelInfo,
		EventType:      "test",
		Message:        "test message",
		Source:         "test-source",
		Data:           map[string]interface{}{"key": "value"},
		ComplianceTags: []string{"gdpr", "sox"},
	}

	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		_ = b.Write(ctx, entry)
	}()
	if !didPanic {
		t.Error("expected panic on nil pool")
	}
}

func TestRetentionFromTier_AllTiers(t *testing.T) {
	tests := []struct {
		tier     tier.Tier
		expected opsec.RetentionPeriod
	}{
		{tier.TierCommunity, opsec.Retention90Days},
		{tier.TierDeveloper, opsec.Retention90Days},
		{tier.TierProfessional, opsec.Retention90Days},
		{tier.TierEnterprise, opsec.RetentionForever},
	}

	for _, tt := range tests {
		result := retentionFromTier(tt.tier)
		if result != tt.expected {
			t.Errorf("retentionFromTier(%v) = %v, want %v", tt.tier, result, tt.expected)
		}
	}
}
