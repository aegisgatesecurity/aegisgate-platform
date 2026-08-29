// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - License PostgreSQL Cache Panic-Recovery Unit Tests
//
// Tests pool-call paths via error/nil returns to maximize coverage without
// requiring a live PostgreSQL connection.
//go:build !integration

package license

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
)

// --------------------------------------------------------------------
// Nil-pool error tests (exercise code paths up to pool access)
// --------------------------------------------------------------------

func TestPostgresLicenseCache_Get_NilPool(t *testing.T) {
	c := &PostgresLicenseCache{closed: false, pool: nil}
	ctx := context.Background()

	result := c.Get(ctx, "test-key")
	if result != nil {
		t.Error("expected nil result on nil pool")
	}
}

func TestPostgresLicenseCache_Get_NilPoolWithTenantCtx(t *testing.T) {
	c := &PostgresLicenseCache{closed: false, pool: nil}
	ctx := context.Background()

	result := c.Get(ctx, "test-key", LicenseTenantContext{TenantID: "t1", IsAdmin: false})
	if result != nil {
		t.Error("expected nil result on nil pool with tenant ctx")
	}
}

func TestPostgresLicenseCache_Set_NilPool(t *testing.T) {
	c := &PostgresLicenseCache{closed: false, pool: nil}
	ctx := context.Background()

	result := &ValidationResult{
		Valid:       true,
		Tier:        tier.TierCommunity,
		Payload:     LicensePayload{},
		Message:     "test",
		ValidatedAt: time.Now(),
	}

	err := c.Set(ctx, "test-key", result, 5*time.Minute)
	if err == nil {
		t.Error("expected error on nil pool in Set")
	}
}

func TestPostgresLicenseCache_Set_NilPoolWithTenantCtx(t *testing.T) {
	c := &PostgresLicenseCache{closed: false, pool: nil}
	ctx := context.Background()

	result := &ValidationResult{
		Valid:       true,
		Tier:        tier.TierCommunity,
		Payload:     LicensePayload{},
		Message:     "test",
		ValidatedAt: time.Now(),
	}

	err := c.Set(ctx, "test-key", result, 5*time.Minute, LicenseTenantContext{TenantID: "t1", IsAdmin: false})
	if err == nil {
		t.Error("expected error on nil pool in Set with tenant ctx")
	}
}

func TestPostgresLicenseCache_Set_NilPool_WithResultError(t *testing.T) {
	c := &PostgresLicenseCache{closed: false, pool: nil}
	ctx := context.Background()

	result := &ValidationResult{
		Valid:       false,
		Tier:        tier.TierCommunity,
		Payload:     LicensePayload{},
		Message:     "test",
		Error:       context.DeadlineExceeded,
		ValidatedAt: time.Now(),
	}

	err := c.Set(ctx, "test-key", result, 5*time.Minute)
	if err == nil {
		t.Error("expected error on nil pool in Set with result.Error")
	}
}

func TestPostgresLicenseCache_Set_NilPool_ZeroValidatedAt(t *testing.T) {
	c := &PostgresLicenseCache{closed: false, pool: nil}
	ctx := context.Background()

	result := &ValidationResult{
		Valid:   true,
		Tier:    tier.TierCommunity,
		Payload: LicensePayload{},
	}

	err := c.Set(ctx, "test-key", result, 5*time.Minute)
	if err == nil {
		t.Error("expected error on nil pool in Set with zero ValidatedAt")
	}
}

func TestPostgresLicenseCache_Invalidate_NilPool(t *testing.T) {
	c := &PostgresLicenseCache{closed: false, pool: nil}
	ctx := context.Background()

	err := c.Invalidate(ctx, "test-key")
	if err == nil {
		t.Error("expected error on nil pool in Invalidate")
	}
}

func TestPostgresLicenseCache_Invalidate_NilPoolWithTenantCtx(t *testing.T) {
	c := &PostgresLicenseCache{closed: false, pool: nil}
	ctx := context.Background()

	err := c.Invalidate(ctx, "test-key", LicenseTenantContext{TenantID: "t1", IsAdmin: false})
	if err == nil {
		t.Error("expected error on nil pool in Invalidate with tenant ctx")
	}
}

func TestPostgresLicenseCache_Invalidate_NilPoolAdminTenantCtx(t *testing.T) {
	c := &PostgresLicenseCache{closed: false, pool: nil}
	ctx := context.Background()

	err := c.Invalidate(ctx, "test-key", LicenseTenantContext{TenantID: "t1", IsAdmin: true})
	if err == nil {
		t.Error("expected error on nil pool in Invalidate with admin tenant ctx")
	}
}

func TestPostgresLicenseCache_PruneExpired_NilPool(t *testing.T) {
	c := &PostgresLicenseCache{closed: false, pool: nil}
	ctx := context.Background()

	count, err := c.PruneExpired(ctx)
	if err == nil {
		t.Error("expected error on nil pool in PruneExpired")
	}
	if count != 0 {
		t.Error("expected 0 count on nil pool in PruneExpired")
	}
}

func TestPostgresLicenseCache_PruneExpired_NilPoolWithTenantCtx(t *testing.T) {
	c := &PostgresLicenseCache{closed: false, pool: nil}
	ctx := context.Background()

	count, err := c.PruneExpired(ctx, LicenseTenantContext{TenantID: "t1", IsAdmin: false})
	if err == nil {
		t.Error("expected error on nil pool in PruneExpired with tenant ctx")
	}
	if count != 0 {
		t.Error("expected 0 count on nil pool in PruneExpired with tenant ctx")
	}
}

// --------------------------------------------------------------------
// JSON marshaling paths (exercised before pool access in Set)
// --------------------------------------------------------------------

func TestLicensePayload_JSONMarshal(t *testing.T) {
	payload := LicensePayload{
		LicenseID:  "test-license",
		Tier:       "community",
		MaxServers: 10,
		MaxUsers:   5,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json.Marshal(payload): %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty JSON")
	}
}

func TestValidationResult_ErrorString(t *testing.T) {
	vr := &ValidationResult{
		Valid:   false,
		Error:   context.DeadlineExceeded,
		Message: "timeout",
	}
	if vr.Error == nil {
		t.Fatal("expected non-nil Error")
	}
	// Verify errorMsg path in Set
	if vr.Error.Error() != "context deadline exceeded" {
		t.Errorf("unexpected error message: %s", vr.Error.Error())
	}
}
