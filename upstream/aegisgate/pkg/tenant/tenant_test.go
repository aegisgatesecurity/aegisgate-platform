package tenant

import (
	"context"
	"testing"
)

// TestTenantCreation tests creating a new tenant
func TestTenantCreation(t *testing.T) {
	tenant := NewTenant("test-001", "Test Company", "test.example.com")

	if tenant.ID != "test-001" {
		t.Errorf("expected ID test-001, got %s", tenant.ID)
	}

	if tenant.Name != "Test Company" {
		t.Errorf("expected name 'Test Company', got %s", tenant.Name)
	}

	if tenant.Status != TenantStatusActive {
		t.Errorf("expected status active, got %s", tenant.Status)
	}

	if tenant.Plan != TenantPlanFree {
		t.Errorf("expected plan free, got %s", tenant.Plan)
	}
}

// TestTenantQuota tests tenant quota defaults
func TestTenantQuota(t *testing.T) {
	tenant := NewTenant("test-002", "Test", "test.com")

	if tenant.Quota.APIRequestsPerMinute != 100 {
		t.Errorf("expected 100 req/min, got %d", tenant.Quota.APIRequestsPerMinute)
	}

	if tenant.Quota.MaxConcurrentConnections != 10 {
		t.Errorf("expected 10 connections, got %d", tenant.Quota.MaxConcurrentConnections)
	}

	if tenant.Quota.MaxStorageMB != 1024 {
		t.Errorf("expected 1024MB storage, got %d", tenant.Quota.MaxStorageMB)
	}
}

// TestTenantSuspendActivate tests suspending and activating tenants
func TestTenantSuspendActivate(t *testing.T) {
	tenant := NewTenant("test-003", "Test", "test.com")

	// Test suspend
	if err := tenant.Suspend(); err != nil {
		t.Fatalf("failed to suspend: %v", err)
	}

	if tenant.Status != TenantStatusSuspended {
		t.Errorf("expected suspended status, got %s", tenant.Status)
	}

	// Test activate
	if err := tenant.Activate(); err != nil {
		t.Fatalf("failed to activate: %v", err)
	}

	if tenant.Status != TenantStatusActive {
		t.Errorf("expected active status, got %s", tenant.Status)
	}
}

// TestTenantFeatureCheck tests feature permission checking
func TestTenantFeatureCheck(t *testing.T) {
	tenant := NewTenant("test-004", "Test", "test.com")

	// Free tier should not have MTLS
	if tenant.CanUse("mtls") {
		t.Error("free tier should not have mtls")
	}

	// But should have webhooks
	if !tenant.CanUse("webhook") {
		t.Error("should have webhook")
	}

	// Enterprise should have everything
	tenant.Plan = TenantPlanEnterprise
	if !tenant.CanUse("mtls") {
		t.Error("enterprise should have mtls")
	}
}

// TestTenantQuotaCheck tests quota checking
func TestTenantQuotaCheck(t *testing.T) {
	tenant := NewTenant("test-005", "Test", "test.com")

	// Free tier should not exceed
	if tenant.CanExceed("concurrent_connections") {
		t.Error("free tier should not exceed connections")
	}

	// Enterprise can exceed
	tenant.Plan = TenantPlanEnterprise
	if !tenant.CanExceed("concurrent_connections") {
		t.Error("enterprise should exceed connections")
	}
}

// TestManager tests tenant manager
func TestManager(t *testing.T) {
	manager := NewManager()

	// Create tenant
	created, err := manager.CreateTenant("test-006", "Test", "test.com", "")
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	if created.ID != "test-006" {
		t.Errorf("expected ID test-006, got %s", created.ID)
	}

	// Get tenant
	retrieved, err := manager.GetTenant("test-006")
	if err != nil {
		t.Fatalf("failed to get tenant: %v", err)
	}

	if retrieved.Name != "Test" {
		t.Errorf("expected name Test, got %s", retrieved.Name)
	}

	// List tenants
	tenants := manager.ListTenants()
	if len(tenants) != 1 {
		t.Errorf("expected 1 tenant, got %d", len(tenants))
	}

	// Delete tenant
	if err := manager.DeleteTenant("test-006"); err != nil {
		t.Fatalf("failed to delete tenant: %v", err)
	}

	// Verify deleted
	_, err = manager.GetTenant("test-006")
	if err == nil {
		t.Error("expected error when getting deleted tenant")
	}
}

// TestRateLimiter tests the simple rate limiter
func TestRateLimiter(t *testing.T) {
	rl := NewSimpleRateLimiter(5) // 5 requests per minute

	// Should allow first 5
	for i := 0; i < 5; i++ {
		if !rl.Allow() {
			t.Errorf("request %d should be allowed", i+1)
		}
	}

	// 6th should be denied
	if rl.Allow() {
		t.Error("6th request should be denied")
	}
}

// TestContext tests tenant context propagation
func TestContext(t *testing.T) {
	ctx := WithTenant(context.Background(), "test-tenant-001")

	tenantID, ok := FromContext(ctx)
	if !ok {
		t.Fatal("failed to get tenant from context")
	}

	if tenantID != "test-tenant-001" {
		t.Errorf("expected test-tenant-001, got %s", tenantID)
	}
}

// TestTenantComplianceDefaults tests default compliance settings
func TestTenantComplianceDefaults(t *testing.T) {
	tenant := NewTenant("test-007", "Test", "test.com")

	if tenant.Compliance.RetentionPeriod != 365 {
		t.Errorf("expected 1 year retention, got %d", tenant.Compliance.RetentionPeriod)
	}

	if len(tenant.Compliance.EnabledFrameworks) == 0 {
		t.Error("should have at least one enabled framework")
	}

	if !tenant.Compliance.RequireEncryption {
		t.Error("should require encryption by default")
	}
}

// TestSearchTenants_BugFix verifies that SearchTenants matches by name
// or domain substring without the SQL-LIKE percent-wrapping bug.
func TestSearchTenants_BugFix(t *testing.T) {
	tmpDir := t.TempDir()
	fs, err := NewFileStorage(tmpDir)
	if err != nil {
		t.Fatalf("failed to create file storage: %v", err)
	}

	// Create tenants with distinct names and domains
	if _, err := fs.CreateTenant("t1", "Acme Corp", "acme.com", tmpDir); err != nil {
		t.Fatalf("create t1: %v", err)
	}
	if _, err := fs.CreateTenant("t2", "Beta Industries", "beta.io", tmpDir); err != nil {
		t.Fatalf("create t2: %v", err)
	}
	if _, err := fs.CreateTenant("t3", "Acme Labs", "acmelabs.org", tmpDir); err != nil {
		t.Fatalf("create t3: %v", err)
	}

	// Search for "acme" should match "Acme Corp" and "Acme Labs" by name
	results := fs.SearchTenants("acme")
	if len(results) != 2 {
		t.Errorf("expected 2 results for 'acme', got %d", len(results))
	}

	// Search for "beta" should match "Beta Industries" by name
	results = fs.SearchTenants("beta")
	if len(results) != 1 {
		t.Errorf("expected 1 result for 'beta', got %d", len(results))
	}

	// Search for "acme.com" should match by domain
	results = fs.SearchTenants("acme.com")
	if len(results) != 1 {
		t.Errorf("expected 1 result for 'acme.com', got %d", len(results))
	}

	// Search for "xyz" should return 0 results
	results = fs.SearchTenants("xyz")
	if len(results) != 0 {
		t.Errorf("expected 0 results for 'xyz', got %d", len(results))
	}
}

// TestFileStorage_LoadAllReinitializesResources verifies that tenants loaded
// from disk have their runtime resources (auditLog, rateLimiter, circuitBreaker)
// re-initialized, not left nil.
func TestFileStorage_LoadAllReinitializesResources(t *testing.T) {
	tmpDir := t.TempDir()
	fs, err := NewFileStorage(tmpDir)
	if err != nil {
		t.Fatalf("failed to create file storage: %v", err)
	}

	// Create a tenant — this initializes resources
	tenant, err := fs.CreateTenant("t-load", "Load Test", "load.com", tmpDir)
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	// Verify resources are initialized
	if tenant.GetAuditLog() == nil {
		t.Error("auditLog should be initialized after CreateTenant")
	}
	if tenant.GetRateLimiter() == nil {
		t.Error("rateLimiter should be initialized after CreateTenant")
	}
	if tenant.GetCircuitBreaker() == nil {
		t.Error("circuitBreaker should be initialized after CreateTenant")
	}

	// Simulate a restart by creating a new FileStorage from the same directory
	fs2, err := NewFileStorage(tmpDir)
	if err != nil {
		t.Fatalf("failed to create second file storage: %v", err)
	}

	// The loaded tenant must have resources re-initialized
	loaded, err := fs2.GetTenant("t-load")
	if err != nil {
		t.Fatalf("get tenant: %v", err)
	}

	if loaded.GetAuditLog() == nil {
		t.Error("auditLog should be re-initialized after loadAll")
	}
	if loaded.GetRateLimiter() == nil {
		t.Error("rateLimiter should be re-initialized after loadAll")
	}
	if loaded.GetCircuitBreaker() == nil {
		t.Error("circuitBreaker should be re-initialized after loadAll")
	}
}
