// SPDX-License-Identifier: Apache-2.0

package license

import (
	"context"
	"testing"
)

// =====================================================================
// PostgresLicenseCache — closed-state paths (no DB needed)
// =====================================================================

func TestPhase1aPostgresLicenseCache_Get_Closed(t *testing.T) {
	c := &PostgresLicenseCache{closed: true}
	result := c.Get(context.Background(), "test-key")
	if result != nil {
		t.Fatal("expected nil result from closed cache")
	}
}

func TestPhase1aPostgresLicenseCache_Get_ClosedWithTenant(t *testing.T) {
	c := &PostgresLicenseCache{closed: true}
	result := c.Get(context.Background(), "test-key", LicenseTenantContext{TenantID: "t1", IsAdmin: false})
	if result != nil {
		t.Fatal("expected nil result from closed cache")
	}
}

func TestPhase1aPostgresLicenseCache_Set_Closed(t *testing.T) {
	c := &PostgresLicenseCache{closed: true}
	err := c.Set(context.Background(), "test-key", &ValidationResult{Valid: true}, 60)
	if err == nil {
		t.Fatal("expected error from closed cache Set")
	}
}

func TestPhase1aPostgresLicenseCache_Invalidate_Closed(t *testing.T) {
	c := &PostgresLicenseCache{closed: true}
	err := c.Invalidate(context.Background(), "test-key")
	if err == nil {
		t.Fatal("expected error from closed cache Invalidate")
	}
}

func TestPhase1aPostgresLicenseCache_PruneExpired_Closed(t *testing.T) {
	c := &PostgresLicenseCache{closed: true}
	count, err := c.PruneExpired(context.Background())
	if err == nil {
		t.Fatal("expected error from closed cache PruneExpired")
	}
	if count != 0 {
		t.Fatalf("expected 0 pruned from closed cache, got %d", count)
	}
}

func TestPhase1aPostgresLicenseCache_Close_Idempotent(t *testing.T) {
	c := &PostgresLicenseCache{closed: true}
	err := c.Close()
	if err != nil {
		t.Fatalf("expected no error from already-closed cache: %v", err)
	}
}

func TestPhase1aPostgresLicenseCache_Close_FromOpen(t *testing.T) {
	c := &PostgresLicenseCache{closed: false}
	err := c.Close()
	if err != nil {
		t.Fatalf("expected no error from Close: %v", err)
	}
	if !c.closed {
		t.Fatal("expected closed=true after Close")
	}
}

// =====================================================================
// NewManager — dev mode path (GetEmbeddedPublicKey failure)
// =====================================================================

func TestPhase1aNewManager_DevMode(t *testing.T) {
	// NewManager should succeed even if the embedded key is a placeholder
	m, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager should not error: %v", err)
	}
	if m == nil {
		t.Fatal("expected non-nil manager")
	}
	if !m.cacheEnabled {
		t.Fatal("expected cache enabled")
	}
}

// =====================================================================
// NewWithPostgres — nil pgCache fallback
// =====================================================================

func TestPhase1aNewWithPostgres_NilCache(t *testing.T) {
	m, err := NewWithPostgres(nil)
	if err != nil {
		t.Fatalf("NewWithPostgres(nil) should not error: %v", err)
	}
	if m == nil {
		t.Fatal("expected non-nil manager")
	}
}
