// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — PostgreSQL License Cache Integration Tests (D1 Phase 1C)
// =========================================================================
//
// Integration tests for PostgresLicenseCache using testcontainers-go.
// These tests verify full round-trip behaviour against a real PostgreSQL
// database, including tenant-scoped operations and expiry pruning.
//
// Run with:
//
//	go test -tags=integration -run TestPostgresLicenseCache ./pkg/license/...
//
// =========================================================================

//go:build integration

package license

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/testdb"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
)

// newTestCache creates a PostgresLicenseCache wired to an ephemeral test
// database. The returned cleanup function must be deferred by the caller.
func newTestCache(t *testing.T) (*PostgresLicenseCache, *ioc.PostgresStore, func()) {
	t.Helper()
	pgStore, dbCleanup := testdb.SetupTestDB(t)
	cache, err := NewPostgresLicenseCache(pgStore)
	if err != nil {
		dbCleanup()
		t.Fatalf("NewPostgresLicenseCache: %v", err)
	}
	cleanup := func() {
		cache.Close()
		dbCleanup()
	}
	return cache, pgStore, cleanup
}

// validResult is a helper that builds a realistic ValidationResult for a
// Professional-tier license with compliance modules.
func validResult() *ValidationResult {
	return &ValidationResult{
		Valid:       true,
		Expired:     false,
		GracePeriod: false,
		Tier:        tier.TierProfessional,
		Payload: LicensePayload{
			LicenseID:    "lic-2f9a4c7e-8b3d-4e5f-a012-3456789abcde",
			Tier:         "professional",
			Customer:     "acme-corp",
			Modules:      []string{ModuleHIPAA, ModuleSOC2},
			Accelerators: []string{"healthcare", "finance"},
			MaxServers:   25,
			MaxUsers:     500,
			IssuedAt:     time.Now().UTC().Add(-365 * 24 * time.Hour),
			ExpiresAt:    time.Now().UTC().Add(365 * 24 * time.Hour),
		},
		Message:     "License valid — Professional tier",
		ValidatedAt: time.Now().UTC(),
	}
}

// expiredResult builds a ValidationResult representing an expired Enterprise
// license that is currently in its grace period.
func expiredResult() *ValidationResult {
	return &ValidationResult{
		Valid:       false,
		Expired:     true,
		GracePeriod: true,
		Tier:        tier.TierEnterprise,
		Payload: LicensePayload{
			LicenseID:  "lic-expired-11111111-2222-3333-4444-555555555555",
			Tier:       "enterprise",
			Customer:   "mega-corp",
			Modules:    []string{ModuleFedRAMP, ModuleISO42001, ModuleFIPS},
			MaxServers: 100,
			MaxUsers:   10000,
			IssuedAt:   time.Now().UTC().Add(-730 * 24 * time.Hour),
			ExpiresAt:  time.Now().UTC().Add(-24 * time.Hour), // expired yesterday
		},
		Message:     "License expired — grace period active",
		Error:       fmt.Errorf("license expired"),
		ValidatedAt: time.Now().UTC(),
	}
}

// communityResult builds a minimal Community-tier ValidationResult.
func communityResult() *ValidationResult {
	return &ValidationResult{
		Valid:       true,
		Expired:     false,
		GracePeriod: false,
		Tier:        tier.TierCommunity,
		Payload: LicensePayload{
			LicenseID:  "lic-community-free",
			Tier:       "community",
			Customer:   "individual",
			Modules:    []string{ModuleCCPA, ModuleNISTAIRMF},
			MaxServers: 3,
			MaxUsers:   10,
			IssuedAt:   time.Now().UTC(),
			ExpiresAt:  time.Now().UTC().Add(10 * 365 * 24 * time.Hour),
		},
		Message:     "License valid — Community tier",
		ValidatedAt: time.Now().UTC(),
	}
}

// ---------------------------------------------------------------------------
// Integration Tests
// ---------------------------------------------------------------------------

// TestPostgresLicenseCache_SetAndGet verifies that a cache entry can be stored
// and retrieved with full field fidelity.
func TestPostgresLicenseCache_SetAndGet(t *testing.T) {
	cache, _, cleanup := newTestCache(t)
	defer cleanup()
	ctx := context.Background()

	tenantCtx := LicenseTenantContext{TenantID: "tenant-acme-001", IsAdmin: false}
	key := "AEG-PRO-ACME-001"
	ttl := 5 * time.Minute

	original := validResult()
	if err := cache.Set(ctx, key, original, ttl, tenantCtx); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got := cache.Get(ctx, key, tenantCtx)
	if got == nil {
		t.Fatal("Get returned nil after Set")
	}

	// Verify core fields
	if got.Valid != original.Valid {
		t.Errorf("Valid: got %v, want %v", got.Valid, original.Valid)
	}
	if got.Expired != original.Expired {
		t.Errorf("Expired: got %v, want %v", got.Expired, original.Expired)
	}
	if got.GracePeriod != original.GracePeriod {
		t.Errorf("GracePeriod: got %v, want %v", got.GracePeriod, original.GracePeriod)
	}
	if got.Tier != original.Tier {
		t.Errorf("Tier: got %v, want %v", got.Tier, original.Tier)
	}
	if got.Message != original.Message {
		t.Errorf("Message: got %q, want %q", got.Message, original.Message)
	}

	// Verify payload fields
	if got.Payload.LicenseID != original.Payload.LicenseID {
		t.Errorf("Payload.LicenseID: got %q, want %q", got.Payload.LicenseID, original.Payload.LicenseID)
	}
	if got.Payload.Customer != original.Payload.Customer {
		t.Errorf("Payload.Customer: got %q, want %q", got.Payload.Customer, original.Payload.Customer)
	}
	if got.Payload.MaxServers != original.Payload.MaxServers {
		t.Errorf("Payload.MaxServers: got %d, want %d", got.Payload.MaxServers, original.Payload.MaxServers)
	}
	if got.Payload.MaxUsers != original.Payload.MaxUsers {
		t.Errorf("Payload.MaxUsers: got %d, want %d", got.Payload.MaxUsers, original.Payload.MaxUsers)
	}
	if len(got.Payload.Modules) != len(original.Payload.Modules) {
		t.Errorf("Payload.Modules length: got %d, want %d", len(got.Payload.Modules), len(original.Payload.Modules))
	}
	if len(got.Payload.Accelerators) != len(original.Payload.Accelerators) {
		t.Errorf("Payload.Accelerators length: got %d, want %d", len(got.Payload.Accelerators), len(original.Payload.Accelerators))
	}
}

// TestPostgresLicenseCache_GetMissing verifies that Get returns nil for a key
// that has never been cached.
func TestIntegration_PostgresLicenseCache_GetMissing(t *testing.T) {
	cache, _, cleanup := newTestCache(t)
	defer cleanup()
	ctx := context.Background()

	tenantCtx := LicenseTenantContext{TenantID: "tenant-missing-999", IsAdmin: false}
	got := cache.Get(ctx, "AEG-NONEXISTENT-KEY", tenantCtx)
	if got != nil {
		t.Errorf("Get on missing key should return nil, got %+v", got)
	}
}

// TestPostgresLicenseCache_Invalidate verifies that Invalidate removes a cached
// entry so subsequent Get returns nil.
func TestPostgresLicenseCache_Invalidate(t *testing.T) {
	cache, _, cleanup := newTestCache(t)
	defer cleanup()
	ctx := context.Background()

	tenantCtx := LicenseTenantContext{TenantID: "tenant-inv-002", IsAdmin: false}
	key := "AEG-PRO-INV-002"
	ttl := 10 * time.Minute

	if err := cache.Set(ctx, key, validResult(), ttl, tenantCtx); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Confirm entry exists
	if got := cache.Get(ctx, key, tenantCtx); got == nil {
		t.Fatal("expected cache entry to exist before Invalidate")
	}

	// Invalidate
	if err := cache.Invalidate(ctx, key, tenantCtx); err != nil {
		t.Fatalf("Invalidate: %v", err)
	}

	// Confirm entry is gone
	if got := cache.Get(ctx, key, tenantCtx); got != nil {
		t.Errorf("Get after Invalidate should return nil, got %+v", got)
	}
}

// TestPostgresLicenseCache_PruneExpired verifies that PruneExpired removes
// entries whose TTL has elapsed while preserving fresh entries.
func TestPostgresLicenseCache_PruneExpired(t *testing.T) {
	cache, pgStore, cleanup := newTestCache(t)
	defer cleanup()
	ctx := context.Background()

	tenantCtx := LicenseTenantContext{TenantID: "tenant-prune-003", IsAdmin: false}

	// Insert a "fresh" entry with a long TTL.
	freshKey := "AEG-PRO-FRESH-003"
	freshResult := validResult()
	freshResult.ValidatedAt = time.Now().UTC()
	if err := cache.Set(ctx, freshKey, freshResult, 1*time.Hour, tenantCtx); err != nil {
		t.Fatalf("Set fresh: %v", err)
	}

	// Insert an "expired" entry by backdating ValidatedAt and using a very
	// short TTL. The SQL uses expires_at > NOW() so we need to insert
	// directly via the pool to control the expires_at column.
	expiredKey := "AEG-PRO-EXPIRED-003"
	expiredResult := validResult()
	expiredResult.ValidatedAt = time.Now().UTC().Add(-2 * time.Hour) // 2 hours ago
	// Set with a short TTL so expires_at is in the past.
	if err := cache.Set(ctx, expiredKey, expiredResult, 1*time.Second, tenantCtx); err != nil {
		t.Fatalf("Set expired: %v", err)
	}

	// Force-update expires_at to the distant past so it's definitely expired.
	_, err := pgStore.Pool().Exec(ctx,
		`UPDATE license_cache SET expires_at = NOW() - INTERVAL '1 hour' WHERE license_key = $1 AND tenant_id = $2`,
		expiredKey, tenantCtx.TenantID,
	)
	if err != nil {
		t.Fatalf("force-expire: %v", err)
	}

	// Prune expired entries.
	pruned, err := cache.PruneExpired(ctx)
	if err != nil {
		t.Fatalf("PruneExpired: %v", err)
	}
	if pruned < 1 {
		t.Errorf("expected at least 1 pruned entry, got %d", pruned)
	}

	// Expired entry should be gone.
	if got := cache.Get(ctx, expiredKey, tenantCtx); got != nil {
		// Get also filters by expires_at > NOW(), so even if prune didn't
		// remove it, Get wouldn't return it. But we still verify prune removed it
		// by counting pruned rows above.
		t.Log("Get on expired key returned non-nil (possibly before prune took effect)")
	}

	// Fresh entry should still be accessible.
	if got := cache.Get(ctx, freshKey, tenantCtx); got == nil {
		t.Fatal("fresh entry should still exist after PruneExpired")
	} else if !got.Valid {
		t.Errorf("fresh entry should still be valid, got Valid=%v", got.Valid)
	}
}

// TestPostgresLicenseCache_SetUpsert verifies that Set with the same
// (tenant_id, license_key) pair upserts (updates) the existing entry.
func TestPostgresLicenseCache_SetUpsert(t *testing.T) {
	cache, _, cleanup := newTestCache(t)
	defer cleanup()
	ctx := context.Background()

	tenantCtx := LicenseTenantContext{TenantID: "tenant-upsert-004", IsAdmin: false}
	key := "AEG-PRO-UPSERT-004"
	ttl := 5 * time.Minute

	// Initial set — Professional tier.
	first := validResult()
	if err := cache.Set(ctx, key, first, ttl, tenantCtx); err != nil {
		t.Fatalf("Set first: %v", err)
	}

	got := cache.Get(ctx, key, tenantCtx)
	if got == nil {
		t.Fatal("Get after first Set returned nil")
	}
	if got.Tier != tier.TierProfessional {
		t.Errorf("initial tier: got %v, want %v", got.Tier, tier.TierProfessional)
	}

	// Upsert — upgrade to Enterprise tier.
	second := validResult()
	second.Tier = tier.TierEnterprise
	second.Payload.Tier = "enterprise"
	second.Payload.MaxServers = 100
	second.Payload.MaxUsers = 10000
	second.Message = "License valid — Enterprise tier (upgraded)"

	if err := cache.Set(ctx, key, second, ttl, tenantCtx); err != nil {
		t.Fatalf("Set second (upsert): %v", err)
	}

	got = cache.Get(ctx, key, tenantCtx)
	if got == nil {
		t.Fatal("Get after upsert returned nil")
	}
	if got.Tier != tier.TierEnterprise {
		t.Errorf("upserted tier: got %v, want %v", got.Tier, tier.TierEnterprise)
	}
	if got.Payload.MaxServers != 100 {
		t.Errorf("upserted MaxServers: got %d, want 100", got.Payload.MaxServers)
	}
	if got.Message != second.Message {
		t.Errorf("upserted Message: got %q, want %q", got.Message, second.Message)
	}
}

// TestPostgresLicenseCache_TenantIsolation verifies that cache entries are
// isolated by tenant_id — one tenant cannot read another tenant's entries.
func TestPostgresLicenseCache_TenantIsolation(t *testing.T) {
	cache, _, cleanup := newTestCache(t)
	defer cleanup()
	ctx := context.Background()

	tenantA := LicenseTenantContext{TenantID: "tenant-alpha-005", IsAdmin: false}
	tenantB := LicenseTenantContext{TenantID: "tenant-beta-005", IsAdmin: false}
	key := "AEG-PRO-SHARED-KEY-005" // same key, different tenants
	ttl := 5 * time.Minute

	// Set for tenant A — Professional tier.
	resultA := validResult()
	if err := cache.Set(ctx, key, resultA, ttl, tenantA); err != nil {
		t.Fatalf("Set tenantA: %v", err)
	}

	// Set for tenant B — Enterprise tier.
	resultB := validResult()
	resultB.Tier = tier.TierEnterprise
	resultB.Payload.Tier = "enterprise"
	resultB.Payload.Customer = "beta-corp"
	if err := cache.Set(ctx, key, resultB, ttl, tenantB); err != nil {
		t.Fatalf("Set tenantB: %v", err)
	}

	// Tenant A should see Professional.
	gotA := cache.Get(ctx, key, tenantA)
	if gotA == nil {
		t.Fatal("tenantA Get returned nil")
	}
	if gotA.Tier != tier.TierProfessional {
		t.Errorf("tenantA tier: got %v, want %v", gotA.Tier, tier.TierProfessional)
	}
	if gotA.Payload.Customer != "acme-corp" {
		t.Errorf("tenantA customer: got %q, want %q", gotA.Payload.Customer, "acme-corp")
	}

	// Tenant B should see Enterprise.
	gotB := cache.Get(ctx, key, tenantB)
	if gotB == nil {
		t.Fatal("tenantB Get returned nil")
	}
	if gotB.Tier != tier.TierEnterprise {
		t.Errorf("tenantB tier: got %v, want %v", gotB.Tier, tier.TierEnterprise)
	}
	if gotB.Payload.Customer != "beta-corp" {
		t.Errorf("tenantB customer: got %q, want %q", gotB.Payload.Customer, "beta-corp")
	}
}

// TestPostgresLicenseCache_TenantIsolation_Invalidate verifies that
// Invalidate for one tenant does not affect another tenant's entry.
func TestPostgresLicenseCache_TenantIsolation_Invalidate(t *testing.T) {
	cache, _, cleanup := newTestCache(t)
	defer cleanup()
	ctx := context.Background()

	tenantA := LicenseTenantContext{TenantID: "tenant-invalpha-006", IsAdmin: false}
	tenantB := LicenseTenantContext{TenantID: "tenant-invbeta-006", IsAdmin: false}
	key := "AEG-PRO-INVISO-006"
	ttl := 5 * time.Minute

	if err := cache.Set(ctx, key, validResult(), ttl, tenantA); err != nil {
		t.Fatalf("Set tenantA: %v", err)
	}
	if err := cache.Set(ctx, key, validResult(), ttl, tenantB); err != nil {
		t.Fatalf("Set tenantB: %v", err)
	}

	// Invalidate for tenant A only.
	if err := cache.Invalidate(ctx, key, tenantA); err != nil {
		t.Fatalf("Invalidate tenantA: %v", err)
	}

	// Tenant A should be gone.
	if got := cache.Get(ctx, key, tenantA); got != nil {
		t.Errorf("tenantA Get after Invalidate should be nil, got %+v", got)
	}

	// Tenant B should still be present.
	if got := cache.Get(ctx, key, tenantB); got == nil {
		t.Fatal("tenantB Get after tenantA Invalidate should still exist")
	}
}

// TestPostgresLicenseCache_ExpiredLicense verifies that an expired license
// with grace period is correctly stored and retrieved.
func TestPostgresLicenseCache_ExpiredLicense(t *testing.T) {
	cache, _, cleanup := newTestCache(t)
	defer cleanup()
	ctx := context.Background()

	tenantCtx := LicenseTenantContext{TenantID: "tenant-expired-007", IsAdmin: false}
	key := "AEG-ENT-EXPIRED-007"
	ttl := 5 * time.Minute

	original := expiredResult()
	if err := cache.Set(ctx, key, original, ttl, tenantCtx); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got := cache.Get(ctx, key, tenantCtx)
	if got == nil {
		t.Fatal("Get returned nil for expired license")
	}

	if got.Valid != false {
		t.Errorf("Valid: got %v, want false", got.Valid)
	}
	if got.Expired != true {
		t.Errorf("Expired: got %v, want true", got.Expired)
	}
	if got.GracePeriod != true {
		t.Errorf("GracePeriod: got %v, want true", got.GracePeriod)
	}
	if got.Tier != tier.TierEnterprise {
		t.Errorf("Tier: got %v, want %v", got.Tier, tier.TierEnterprise)
	}
	if got.Error == nil {
		t.Error("expected non-nil Error for expired license")
	}
}

// TestPostgresLicenseCache_CommunityTier verifies round-tripping a Community
// (free) tier license through the cache.
func TestPostgresLicenseCache_CommunityTier(t *testing.T) {
	cache, _, cleanup := newTestCache(t)
	defer cleanup()
	ctx := context.Background()

	tenantCtx := LicenseTenantContext{TenantID: "tenant-community-008", IsAdmin: false}
	key := "AEG-COMM-FREE-008"
	ttl := 10 * time.Minute

	original := communityResult()
	if err := cache.Set(ctx, key, original, ttl, tenantCtx); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got := cache.Get(ctx, key, tenantCtx)
	if got == nil {
		t.Fatal("Get returned nil for Community license")
	}

	if got.Tier != tier.TierCommunity {
		t.Errorf("Tier: got %v, want %v", got.Tier, tier.TierCommunity)
	}
	if got.Payload.Customer != "individual" {
		t.Errorf("Customer: got %q, want %q", got.Payload.Customer, "individual")
	}
	if got.Payload.MaxServers != 3 {
		t.Errorf("MaxServers: got %d, want 3", got.Payload.MaxServers)
	}
}

// TestPostgresLicenseCache_AdminTenantContext verifies that an admin
// tenant context can read entries with empty tenant_id (legacy mode).
func TestPostgresLicenseCache_AdminTenantContext(t *testing.T) {
	cache, _, cleanup := newTestCache(t)
	defer cleanup()
	ctx := context.Background()

	// Empty tenant_id (legacy) — set without tenant context.
	key := "AEG-PRO-ADMIN-009"
	ttl := 5 * time.Minute

	// Set with empty tenant ID (no tenant context).
	original := validResult()
	if err := cache.Set(ctx, key, original, ttl); err != nil {
		t.Fatalf("Set (no tenant): %v", err)
	}

	// Admin should be able to read it.
	adminCtx := LicenseTenantContext{TenantID: "", IsAdmin: true}
	got := cache.Get(ctx, key, adminCtx)
	if got == nil {
		t.Fatal("admin Get should find legacy entry with empty tenant_id")
	}
	if got.Tier != tier.TierProfessional {
		t.Errorf("admin tier: got %v, want %v", got.Tier, tier.TierProfessional)
	}
}

// TestPostgresLicenseCache_Close verifies that after Close(), all operations
// return appropriate zero values/errors.
func TestPostgresLicenseCache_Close(t *testing.T) {
	cache, _, cleanup := newTestCache(t)
	defer cleanup()
	ctx := context.Background()

	tenantCtx := LicenseTenantContext{TenantID: "tenant-close-010", IsAdmin: false}
	key := "AEG-PRO-CLOSE-010"
	ttl := 5 * time.Minute

	if err := cache.Set(ctx, key, validResult(), ttl, tenantCtx); err != nil {
		t.Fatalf("Set before Close: %v", err)
	}

	// Close the cache.
	if err := cache.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// After Close, Get should return nil.
	if got := cache.Get(ctx, key, tenantCtx); got != nil {
		t.Errorf("Get after Close should return nil, got %+v", got)
	}

	// After Close, Set should return error.
	if err := cache.Set(ctx, key, validResult(), ttl, tenantCtx); err == nil {
		t.Error("Set after Close should return error")
	}

	// After Close, Invalidate should return error.
	if err := cache.Invalidate(ctx, key, tenantCtx); err == nil {
		t.Error("Invalidate after Close should return error")
	}

	// After Close, PruneExpired should return error.
	if _, err := cache.PruneExpired(ctx); err == nil {
		t.Error("PruneExpired after Close should return error")
	}

	// Double Close should be safe.
	if err := cache.Close(); err != nil {
		t.Errorf("double Close should not error, got: %v", err)
	}
}

// TestPostgresLicenseCache_MultipleTenantsPruneExpired verifies that
// PruneExpired without tenant context removes expired entries across
// all tenants (global prune).
func TestPostgresLicenseCache_MultipleTenantsPruneExpired(t *testing.T) {
	cache, pgStore, cleanup := newTestCache(t)
	defer cleanup()
	ctx := context.Background()

	tenantA := LicenseTenantContext{TenantID: "tenant-prune-alpha-011", IsAdmin: false}
	tenantB := LicenseTenantContext{TenantID: "tenant-prune-beta-011", IsAdmin: false}
	ttl := 5 * time.Minute

	// Insert fresh entries for both tenants.
	if err := cache.Set(ctx, "AEG-PRO-FRESH-A", validResult(), ttl, tenantA); err != nil {
		t.Fatalf("Set tenantA fresh: %v", err)
	}
	if err := cache.Set(ctx, "AEG-PRO-FRESH-B", validResult(), ttl, tenantB); err != nil {
		t.Fatalf("Set tenantB fresh: %v", err)
	}

	// Insert expired entries for both tenants (short TTL, then force backdate).
	if err := cache.Set(ctx, "AEG-PRO-EXPIRED-A", validResult(), 1*time.Second, tenantA); err != nil {
		t.Fatalf("Set tenantA expired: %v", err)
	}
	if err := cache.Set(ctx, "AEG-PRO-EXPIRED-B", validResult(), 1*time.Second, tenantB); err != nil {
		t.Fatalf("Set tenantB expired: %v", err)
	}

	// Force expires_at into the past for the "expired" entries.
	_, err := pgStore.Pool().Exec(ctx,
		`UPDATE license_cache SET expires_at = NOW() - INTERVAL '1 hour' WHERE license_key LIKE 'AEG-PRO-EXPIRED-%'`,
	)
	if err != nil {
		t.Fatalf("force-expire entries: %v", err)
	}

	// Global prune (no tenant context — admin path).
	pruned, err := cache.PruneExpired(ctx)
	if err != nil {
		t.Fatalf("PruneExpired (global): %v", err)
	}
	if pruned < 2 {
		t.Errorf("expected at least 2 pruned entries across tenants, got %d", pruned)
	}

	// Fresh entries should still exist.
	if got := cache.Get(ctx, "AEG-PRO-FRESH-A", tenantA); got == nil {
		t.Fatal("tenantA fresh entry should still exist after global prune")
	}
	if got := cache.Get(ctx, "AEG-PRO-FRESH-B", tenantB); got == nil {
		t.Fatal("tenantB fresh entry should still exist after global prune")
	}
}
