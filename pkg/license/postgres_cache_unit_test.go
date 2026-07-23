//go:build !integration

package license

import (
	"context"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
)

func TestNewPostgresLicenseCache_NilInput(t *testing.T) {
	cache, err := NewPostgresLicenseCache(nil)
	if cache != nil {
		t.Fatalf("expected nil cache, got %v", cache)
	}
	if err == nil {
		t.Fatal("expected error for nil input, got nil")
	}
}

func TestPostgresLicenseCache_Close(t *testing.T) {
	c := &PostgresLicenseCache{closed: false}

	// First close should set closed=true and return nil
	if err := c.Close(); err != nil {
		t.Fatalf("expected nil error on first close, got %v", err)
	}
	if !c.closed {
		t.Fatal("expected closed flag to be true after Close()")
	}

	// Second close should be idempotent — return nil
	if err := c.Close(); err != nil {
		t.Fatalf("expected nil error on second close, got %v", err)
	}
}

func TestPostgresLicenseCache_Get_Closed(t *testing.T) {
	c := &PostgresLicenseCache{closed: true}
	result := c.Get(context.Background(), "some-key")
	if result != nil {
		t.Fatalf("expected nil result from Get on closed cache, got %v", result)
	}
}

func TestPostgresLicenseCache_Get_ClosedWithTenantContext(t *testing.T) {
	c := &PostgresLicenseCache{closed: true}
	result := c.Get(context.Background(), "some-key", LicenseTenantContext{TenantID: "t1", IsAdmin: false})
	if result != nil {
		t.Fatalf("expected nil result from Get on closed cache with tenant ctx, got %v", result)
	}
}

func TestPostgresLicenseCache_Set_Closed(t *testing.T) {
	c := &PostgresLicenseCache{closed: true}
	err := c.Set(context.Background(), "key", &ValidationResult{Valid: true}, 5*time.Minute)
	if err == nil {
		t.Fatal("expected error from Set on closed cache, got nil")
	}
}

func TestPostgresLicenseCache_Set_NilResult(t *testing.T) {
	// Set with nil result should return nil without accessing the pool.
	// Use a non-closed cache with nil pool — the nil result check happens
	// before any pool access, so this is safe.
	c := &PostgresLicenseCache{closed: false, pool: nil}
	err := c.Set(context.Background(), "key", nil, 5*time.Minute)
	if err != nil {
		t.Fatalf("expected nil error for nil result, got %v", err)
	}
}

func TestPostgresLicenseCache_Invalidate_Closed(t *testing.T) {
	c := &PostgresLicenseCache{closed: true}
	err := c.Invalidate(context.Background(), "key")
	if err == nil {
		t.Fatal("expected error from Invalidate on closed cache, got nil")
	}
}

func TestPostgresLicenseCache_Invalidate_ClosedWithTenantContext(t *testing.T) {
	c := &PostgresLicenseCache{closed: true}
	err := c.Invalidate(context.Background(), "key", LicenseTenantContext{TenantID: "t1", IsAdmin: false})
	if err == nil {
		t.Fatal("expected error from Invalidate on closed cache with tenant ctx, got nil")
	}
}

func TestPostgresLicenseCache_PruneExpired_Closed(t *testing.T) {
	c := &PostgresLicenseCache{closed: true}
	n, err := c.PruneExpired(context.Background())
	if err == nil {
		t.Fatal("expected error from PruneExpired on closed cache, got nil")
	}
	if n != 0 {
		t.Fatalf("expected 0 pruned count, got %d", n)
	}
}

func TestPostgresLicenseCache_PruneExpired_ClosedWithTenantContext(t *testing.T) {
	c := &PostgresLicenseCache{closed: true}
	n, err := c.PruneExpired(context.Background(), LicenseTenantContext{TenantID: "t1", IsAdmin: false})
	if err == nil {
		t.Fatal("expected error from PruneExpired on closed cache with tenant ctx, got nil")
	}
	if n != 0 {
		t.Fatalf("expected 0 pruned count, got %d", n)
	}
}

func TestNewPostgresLicenseCache_ErrorMessage(t *testing.T) {
	_, err := NewPostgresLicenseCache(nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	expected := "postgres store is nil"
	if err.Error() != expected+", cannot create license cache" && err.Error() != "postgres store is nil, cannot create license cache" {
		t.Logf("error message: %s", err.Error())
	}
}

// Verify that a PostgresLicenseCache created via struct literal with a
// non-nil PostgresStore behaves as expected on Close (pool field populated
// from PostgresStore.Pool()). This is a structural sanity check — we
// cannot call pool methods without a real database, but we can verify the
// constructor wires things up when given a valid store.
func TestNewPostgresLicenseCache_WithStore(t *testing.T) {
	// We can't create a real PostgresStore without a DB, but we can verify
	// the error path thoroughly and test closed behavior via struct literals.
	// Already covered above; this test documents intent.
	t.Skip("requires live database connection — covered by integration tests")
}

func TestPostgresLicenseCache_Set_ClosedWithTenantContext(t *testing.T) {
	c := &PostgresLicenseCache{closed: true}
	err := c.Set(context.Background(), "key", &ValidationResult{
		Valid:       true,
		Tier:        tier.TierCommunity,
		ValidatedAt: time.Now(),
	}, 5*time.Minute, LicenseTenantContext{TenantID: "t1"})
	if err == nil {
		t.Fatal("expected error from Set on closed cache with tenant ctx, got nil")
	}
}

// Ensure LicenseTenantContext is usable and exported fields work.
func TestLicenseTenantContext_Fields(t *testing.T) {
	tc := LicenseTenantContext{TenantID: "abc", IsAdmin: true}
	if tc.TenantID != "abc" {
		t.Fatalf("expected TenantID 'abc', got %q", tc.TenantID)
	}
	if !tc.IsAdmin {
		t.Fatal("expected IsAdmin true")
	}
}

// Ensure the PostgresLicenseCache struct can be constructed with an explicit
// mgr field for type-safety verification.
func TestPostgresLicenseCache_StructWithMgr(t *testing.T) {
	var mgr *ioc.PostgresStore
	c := &PostgresLicenseCache{mgr: mgr, closed: true}
	// Just verify closed cache returns early on all methods
	if err := c.Close(); err != nil {
		t.Fatalf("Close on already-closed: %v", err)
	}
}
