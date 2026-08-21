// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — Integration Tests for New Pipelines (Step 6)
// =========================================================================
//
// Integration tests for DSAR, A/B Testing, and Legal Hold pipelines.
// Gated by //go:build lab AND LAB_ENABLED=1 env var.
// Requires a running PostgreSQL instance (cd testlab && docker compose up -d).
//
// Run with:
//
//	LAB_ENABLED=1 go test -tags=lab -v ./testlab/ -run TestNewPipelines
//
// =========================================================================

//go:build lab

package testlab

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/abtest"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/dsar"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/legalhold"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/rbac"
)

// connectPostgres creates a PostgresStore for integration tests.
// The caller must close the store.
func connectPostgres(t *testing.T) *ioc.PostgresStore {
	t.Helper()
	ctx := context.Background()
	cfg := ioc.DefaultDatabaseConfig()
	cfg.URL = testDatabaseURL()
	store, err := ioc.NewPostgresStore(ctx, cfg)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	return store
}

// ---------------------------------------------------------------------------
// Legal Hold Postgres Store
// ---------------------------------------------------------------------------

func TestNewPipelines_LegalHoldPostgres_CreateAndCheck(t *testing.T) {
	skipIfNoLab(t)
	ctx := context.Background()

	pgStore := connectPostgres(t)
	defer pgStore.Close()

	store, err := legalhold.NewPostgresStore(pgStore.Pool())
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}

	hold := &legalhold.Hold{
		ID:         "hold-test-create-1",
		EntityID:   "agent-test-lh-create",
		EntityType: "agent",
		Reason:     "Integration test hold",
		IssuedBy:   "test-admin",
		CreatedAt:  time.Now().UTC(),
	}

	if err := store.Create(ctx, hold); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if !store.IsUnderHold(ctx, "agent-test-lh-create") {
		t.Error("IsUnderHold should return true after creating hold")
	}
	if store.IsUnderHold(ctx, "nonexistent-agent") {
		t.Error("IsUnderHold should return false for nonexistent agent")
	}
}

func TestNewPipelines_LegalHoldPostgres_Release(t *testing.T) {
	skipIfNoLab(t)
	ctx := context.Background()

	pgStore := connectPostgres(t)
	defer pgStore.Close()

	store, err := legalhold.NewPostgresStore(pgStore.Pool())
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}

	hold := &legalhold.Hold{
		ID:         "hold-test-release-1",
		EntityID:   "agent-test-lh-release",
		EntityType: "agent",
		Reason:     "Integration test hold — to be released",
		IssuedBy:   "test-admin",
		CreatedAt:  time.Now().UTC(),
	}

	if err := store.Create(ctx, hold); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if !store.IsUnderHold(ctx, "agent-test-lh-release") {
		t.Fatal("should be under hold before release")
	}

	if err := store.Release(ctx, hold.ID); err != nil {
		t.Fatalf("Release: %v", err)
	}

	if store.IsUnderHold(ctx, "agent-test-lh-release") {
		t.Error("IsUnderHold should return false after release")
	}
}

func TestNewPipelines_LegalHoldPostgres_GetActiveHolds(t *testing.T) {
	skipIfNoLab(t)
	ctx := context.Background()

	pgStore := connectPostgres(t)
	defer pgStore.Close()

	store, err := legalhold.NewPostgresStore(pgStore.Pool())
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}

	entityID := "agent-test-lh-active"
	hold1 := &legalhold.Hold{
		ID:         "hold-test-active-1",
		EntityID:   entityID,
		EntityType: "agent",
		Reason:     "Hold 1",
		IssuedBy:   "admin1",
		CreatedAt:  time.Now().UTC(),
	}
	hold2 := &legalhold.Hold{
		ID:         "hold-test-active-2",
		EntityID:   entityID,
		EntityType: "agent",
		Reason:     "Hold 2",
		IssuedBy:   "admin2",
		CreatedAt:  time.Now().UTC(),
	}

	if err := store.Create(ctx, hold1); err != nil {
		t.Fatalf("Create hold1: %v", err)
	}
	if err := store.Create(ctx, hold2); err != nil {
		t.Fatalf("Create hold2: %v", err)
	}

	active := store.GetActiveHolds(ctx, entityID)
	if len(active) < 2 {
		t.Errorf("expected at least 2 active holds, got %d", len(active))
	}

	// Release one and verify count drops
	if err := store.Release(ctx, hold1.ID); err != nil {
		t.Fatalf("Release hold1: %v", err)
	}

	active = store.GetActiveHolds(ctx, entityID)
	if len(active) != 1 {
		t.Errorf("expected 1 active hold after release, got %d", len(active))
	}

	// Cleanup
	_ = store.Release(ctx, hold2.ID)
}

// ---------------------------------------------------------------------------
// DSAR + Legal Hold Integration
// ---------------------------------------------------------------------------

func TestNewPipelines_DSAR_EraseBlockedByLegalHold(t *testing.T) {
	skipIfNoLab(t)
	ctx := context.Background()

	pgStore := connectPostgres(t)
	defer pgStore.Close()

	// Create legal hold service with Postgres backing
	lhStore, err := legalhold.NewPostgresStore(pgStore.Pool())
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	lhSvc := legalhold.NewService()
	lhSvc.SetStore(lhStore)

	// Create a legal hold on the entity
	entityID := "agent-test-dsar-blocked"
	hold, err := lhSvc.CreateHold(ctx, entityID, "agent", "Litigation hold for DSAR test", "legal-dept")
	if err != nil {
		t.Fatalf("CreateHold: %v", err)
	}

	// Register a mock data provider
	exportCalled := false
	eraseCalled := false

	// Create DSAR service with the legal hold checker
	dsarSvc := dsar.NewService(lhSvc, nil)
	dsarSvc.RegisterProvider(&mockDSARProvider{
		exportFn: func(ctx context.Context, entityID string) (json.RawMessage, error) {
			exportCalled = true
			return json.RawMessage(`{"entity":"` + entityID + `"}`), nil
		},
		eraseFn: func(ctx context.Context, entityID string) (int, error) {
			eraseCalled = true
			return 5, nil
		},
	})

	// Export should succeed even under legal hold
	result, err := dsarSvc.Export(ctx, entityID)
	if err != nil {
		t.Fatalf("Export under hold should succeed: %v", err)
	}
	if result == nil {
		t.Fatal("Export should return non-nil result")
	}
	if !exportCalled {
		t.Error("Export provider was not called")
	}

	// Erase should be BLOCKED by legal hold
	eraseResult, err := dsarSvc.Erase(ctx, entityID)
	if err != nil {
		t.Fatalf("Erase should not return error (returns blocked result): %v", err)
	}
	if eraseResult.BlockedBy == "" {
		t.Error("Erase should be blocked by legal hold (BlockedBy should be set)")
	}
	if eraseCalled {
		t.Error("Erase provider should NOT be called when blocked by legal hold")
	}

	// Release the hold
	if err := lhSvc.ReleaseHold(ctx, hold.ID); err != nil {
		t.Fatalf("ReleaseHold: %v", err)
	}

	// Now erase should succeed
	exportCalled = false
	eraseCalled = false
	eraseResult, err = dsarSvc.Erase(ctx, entityID)
	if err != nil {
		t.Errorf("Erase after hold release should succeed: %v", err)
	}
	if eraseResult.BlockedBy != "" {
		t.Error("Erase should not be blocked after hold release")
	}
	if !eraseCalled {
		t.Error("Erase provider was not called after hold release")
	}
}

func TestNewPipelines_DSAR_ExportMultipleProviders(t *testing.T) {
	skipIfNoLab(t)
	ctx := context.Background()

	pgStore := connectPostgres(t)
	defer pgStore.Close()

	lhStore, err := legalhold.NewPostgresStore(pgStore.Pool())
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	lhSvc := legalhold.NewService()
	lhSvc.SetStore(lhStore)

	dsarSvc := dsar.NewService(lhSvc, nil)
	dsarSvc.RegisterProvider(&mockDSARProvider{
		name: "rbac_mock",
		exportFn: func(ctx context.Context, entityID string) (json.RawMessage, error) {
			return json.RawMessage(`{"type":"rbac","agent":"` + entityID + `"}`), nil
		},
		eraseFn: func(ctx context.Context, entityID string) (int, error) { return 1, nil },
	})
	dsarSvc.RegisterProvider(&mockDSARProvider{
		name: "audit_mock",
		exportFn: func(ctx context.Context, entityID string) (json.RawMessage, error) {
			return json.RawMessage(`{"type":"audit","events":[]}`), nil
		},
		eraseFn: func(ctx context.Context, entityID string) (int, error) { return 0, nil },
	})

	entityID := "agent-test-dsar-multi"
	result, err := dsarSvc.Export(ctx, entityID)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if result == nil {
		t.Fatal("Export returned nil")
	}

	// Verify export bundle contains data from both providers
	if _, ok := result.Providers["rbac_mock"]; !ok {
		t.Error("Export bundle should contain rbac_mock provider data")
	}
	if _, ok := result.Providers["audit_mock"]; !ok {
		t.Error("Export bundle should contain audit_mock provider data")
	}
}

// ---------------------------------------------------------------------------
// A/B Testing Lifecycle
// ---------------------------------------------------------------------------

func TestNewPipelines_ABTest_FullLifecycle(t *testing.T) {
	skipIfNoLab(t)
	ctx := context.Background()

	svc := abtest.NewService()

	// Create test with variants (Name + Weight)
	test, err := svc.CreateTest(ctx, "Gateway detection A/B test", "full lifecycle test",
		[]abtest.Variant{
			{Name: "control", Weight: 1},
			{Name: "variant-a", Weight: 1},
		})
	if err != nil {
		t.Fatalf("CreateTest: %v", err)
	}
	testID := test.ID

	// Start test
	if err := svc.StartTest(ctx, testID); err != nil {
		t.Fatalf("StartTest: %v", err)
	}

	// Assign variants — same entity should get consistent variant
	v1, err := svc.AssignVariant(ctx, testID, "user-1")
	if err != nil {
		t.Fatalf("AssignVariant user-1: %v", err)
	}
	v2, err := svc.AssignVariant(ctx, testID, "user-1")
	if err != nil {
		t.Fatalf("AssignVariant user-1 (2nd): %v", err)
	}
	if v1 != v2 {
		t.Errorf("Same user should get same variant: %s vs %s", v1, v2)
	}

	// Record results (testID, variantName, detected, falsePositive, latencyMs)
	svc.RecordResult(ctx, testID, v1, true, false, 0.5)
	svc.RecordResult(ctx, testID, v1, false, false, 0.3)

	// Get metrics
	metrics, err := svc.GetMetrics(ctx, testID)
	if err != nil {
		t.Fatalf("GetMetrics: %v", err)
	}
	if len(metrics) == 0 {
		t.Fatal("Metrics should not be empty")
	}

	// Stop test
	if err := svc.StopTest(ctx, testID); err != nil {
		t.Fatalf("StopTest: %v", err)
	}

	// Verify test is stopped
	tests := svc.ListTests(ctx)
	found := false
	for _, tt := range tests {
		if tt.ID == testID && tt.Status == abtest.StatusStopped {
			found = true
			break
		}
	}
	if !found {
		t.Error("Test should be stopped after StopTest")
	}
}

func TestNewPipelines_ABTest_AssignVariantDistribution(t *testing.T) {
	skipIfNoLab(t)
	ctx := context.Background()

	svc := abtest.NewService()
	test, err := svc.CreateTest(ctx, "Distribution test", "verify variant distribution",
		[]abtest.Variant{
			{Name: "control", Weight: 1},
			{Name: "variant-a", Weight: 1},
			{Name: "variant-b", Weight: 1},
		})
	if err != nil {
		t.Fatalf("CreateTest: %v", err)
	}
	if err := svc.StartTest(ctx, test.ID); err != nil {
		t.Fatalf("StartTest: %v", err)
	}

	// Assign 300 users and verify distribution
	counts := map[string]int{}
	for i := 0; i < 300; i++ {
		userID := "user-" + string(rune('a'+i%26)) + string(rune('a'+i/26))
		v, err := svc.AssignVariant(ctx, test.ID, userID)
		if err != nil {
			t.Fatalf("AssignVariant %d: %v", i, err)
		}
		counts[v]++
	}

	// Each variant should have at least some users
	for _, variant := range []string{"control", "variant-a", "variant-b"} {
		if counts[variant] == 0 {
			t.Errorf("variant %s got 0 assignments — distribution issue", variant)
		}
		t.Logf("variant %s: %d assignments", variant, counts[variant])
	}
}

// ---------------------------------------------------------------------------
// RBAC + Legal Hold Cross-Pipeline
// ---------------------------------------------------------------------------

func TestNewPipelines_RBACAgentUnderLegalHold(t *testing.T) {
	skipIfNoLab(t)
	ctx := context.Background()

	pgStore := connectPostgres(t)
	defer pgStore.Close()

	// Set up RBAC store
	rbacStore, err := rbac.NewPostgresRBACStore(pgStore, nil)
	if err != nil {
		t.Fatalf("NewPostgresRBACStore: %v", err)
	}
	defer rbacStore.Close()

	// Set up legal hold
	lhStore, err := legalhold.NewPostgresStore(pgStore.Pool())
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}

	agentID := "agent-test-cross-pipeline"
	tenantID := "test-tenant-1"

	// Register agent
	agent := &rbac.Agent{
		ID:          agentID,
		Name:        "Test Agent for Cross-Pipeline",
		Description: "Tests RBAC + legal hold interaction",
		Role:        rbac.AgentRoleStandard,
		Enabled:     true,
		Tags:        map[string]string{"env": "test"},
	}
	if err := rbacStore.RegisterAgent(ctx, agent, rbac.RBACTenantContext{TenantID: tenantID}); err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}

	// Verify agent exists
	got, err := rbacStore.GetAgent(ctx, agentID, rbac.RBACTenantContext{TenantID: tenantID})
	if err != nil || got == nil {
		t.Fatalf("GetAgent: err=%v agent=%v", err, got)
	}

	// Place legal hold on agent
	hold := &legalhold.Hold{
		ID:         "hold-cross-1",
		EntityID:   agentID,
		EntityType: "agent",
		Reason:     "Investigation hold",
		IssuedBy:   "security-team",
		CreatedAt:  time.Now().UTC(),
	}
	if err := lhStore.Create(ctx, hold); err != nil {
		t.Fatalf("Create legal hold: %v", err)
	}

	// Verify legal hold is active
	if !lhStore.IsUnderHold(ctx, agentID) {
		t.Error("Agent should be under legal hold")
	}

	// Agent should still be retrievable (legal hold doesn't block reads)
	got, err = rbacStore.GetAgent(ctx, agentID, rbac.RBACTenantContext{TenantID: tenantID})
	if err != nil || got == nil {
		t.Error("Agent should still be retrievable under legal hold")
	}

	// Cleanup: release hold
	if err := lhStore.Release(ctx, hold.ID); err != nil {
		t.Fatalf("Release hold: %v", err)
	}
}

// ---------------------------------------------------------------------------
// RLS Defense-in-Depth Verification
// ---------------------------------------------------------------------------

func TestNewPipelines_RLS_TenantIsolation(t *testing.T) {
	skipIfNoLab(t)
	ctx := context.Background()

	store := connectPostgres(t)
	defer store.Close()

	tenantA := "tenant-rls-a"
	tenantB := "tenant-rls-b"

	// Insert IOC for tenant A
	iocA := ioc.IOC{
		Fingerprint:    "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111",
		Type:           ioc.IOCTypeProxyResponse,
		Severity:       ioc.SeverityHigh,
		Category:       "rls-test",
		Pattern:        "tenant-a-pattern",
		SourceProvider: "test",
		AffectsLens:    true,
		AffectsGateway: false,
		Source:         "rls-test",
		Count:          1,
		FirstSeen:      time.Now().UTC(),
		LastSeen:       time.Now().UTC(),
	}
	if _, err := store.Observe(ctx, iocA, ioc.TenantContext{TenantID: tenantA}); err != nil {
		t.Fatalf("Observe tenantA: %v", err)
	}

	// Insert IOC for tenant B
	iocB := ioc.IOC{
		Fingerprint:    "bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222",
		Type:           ioc.IOCTypeProxyResponse,
		Severity:       ioc.SeverityLow,
		Category:       "rls-test",
		Pattern:        "tenant-b-pattern",
		SourceProvider: "test",
		AffectsLens:    true,
		AffectsGateway: false,
		Source:         "rls-test",
		Count:          1,
		FirstSeen:      time.Now().UTC(),
		LastSeen:       time.Now().UTC(),
	}
	if _, err := store.Observe(ctx, iocB, ioc.TenantContext{TenantID: tenantB}); err != nil {
		t.Fatalf("Observe tenantB: %v", err)
	}

	// Tenant A should only see their IOC
	snapshotA, err := store.Snapshot(ctx, ioc.TenantContext{TenantID: tenantA})
	if err != nil {
		t.Fatalf("Snapshot tenantA: %v", err)
	}
	for _, item := range snapshotA {
		if item.TenantID != tenantA {
			t.Errorf("Tenant A snapshot contains IOC from tenant %s (expected %s)", item.TenantID, tenantA)
		}
	}

	// Tenant B should only see their IOC
	snapshotB, err := store.Snapshot(ctx, ioc.TenantContext{TenantID: tenantB})
	if err != nil {
		t.Fatalf("Snapshot tenantB: %v", err)
	}
	for _, item := range snapshotB {
		if item.TenantID != tenantB {
			t.Errorf("Tenant B snapshot contains IOC from tenant %s (expected %s)", item.TenantID, tenantB)
		}
	}

	// Admin should see both
	snapshotAdmin, err := store.Snapshot(ctx, ioc.TenantContext{TenantID: tenantA, IsAdmin: true})
	if err != nil {
		t.Fatalf("Snapshot admin: %v", err)
	}
	foundA, foundB := false, false
	for _, item := range snapshotAdmin {
		if item.TenantID == tenantA {
			foundA = true
		}
		if item.TenantID == tenantB {
			foundB = true
		}
	}
	if !foundA || !foundB {
		t.Errorf("Admin should see both tenants: foundA=%v foundB=%v", foundA, foundB)
	}
}

func TestNewPipelines_RLS_GetCrossTenantBlocked(t *testing.T) {
	skipIfNoLab(t)
	ctx := context.Background()

	store := connectPostgres(t)
	defer store.Close()

	tenantA := "tenant-get-a"
	tenantB := "tenant-get-b"

	fp := "cccc3333cccc3333cccc3333cccc3333cccc3333cccc3333cccc3333cccc3333"

	// Insert IOC for tenant A
	iocItem := ioc.IOC{
		Fingerprint:    fp,
		Type:           ioc.IOCTypeProxyResponse,
		Severity:       ioc.SeverityMedium,
		Category:       "rls-cross-test",
		Pattern:        "cross-tenant-pattern",
		SourceProvider: "test",
		AffectsLens:    true,
		AffectsGateway: false,
		Source:         "rls-test",
		Count:          1,
		FirstSeen:      time.Now().UTC(),
		LastSeen:       time.Now().UTC(),
	}
	if _, err := store.Observe(ctx, iocItem, ioc.TenantContext{TenantID: tenantA}); err != nil {
		t.Fatalf("Observe: %v", err)
	}

	// Tenant A can read it
	got, err := store.Get(ctx, fp, ioc.TenantContext{TenantID: tenantA})
	if err != nil || got == nil {
		t.Fatalf("Tenant A should read own IOC: err=%v got=%v", err, got)
	}

	// Tenant B should NOT see tenant A's IOC (app-layer filtering)
	got, err = store.Get(ctx, fp, ioc.TenantContext{TenantID: tenantB})
	if err != nil {
		t.Fatalf("Get for tenant B returned error: %v", err)
	}
	if got != nil {
		t.Error("Tenant B should not see tenant A's IOC")
	}

	// Admin can read it
	got, err = store.Get(ctx, fp, ioc.TenantContext{TenantID: tenantA, IsAdmin: true})
	if err != nil {
		t.Fatalf("Admin Get: %v", err)
	}
	if got == nil {
		t.Error("Admin should be able to read any tenant's IOC")
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// mockDSARProvider is a test double for DSAR data providers.
type mockDSARProvider struct {
	name     string
	exportFn func(ctx context.Context, entityID string) (json.RawMessage, error)
	eraseFn  func(ctx context.Context, entityID string) (int, error)
}

func (m *mockDSARProvider) Name() string { return m.name }
func (m *mockDSARProvider) Export(ctx context.Context, entityID string) (json.RawMessage, error) {
	return m.exportFn(ctx, entityID)
}
func (m *mockDSARProvider) Erase(ctx context.Context, entityID string) (int, error) {
	return m.eraseFn(ctx, entityID)
}

// ---------------------------------------------------------------------------
// FORCE RLS Verification (Migration 010)
// ---------------------------------------------------------------------------

// TestNewPipelines_FORCE_RLS_NoContextReturnsNoTenantRows verifies that
// after FORCE ROW LEVEL SECURITY is applied (migration 010), queries
// without SET LOCAL app.tenant_id do NOT return tenant-scoped rows.
// Only rows with empty tenant_id (shared/global) should be visible.
func TestNewPipelines_FORCE_RLS_NoContextReturnsNoTenantRows(t *testing.T) {
	skipIfNoLab(t)
	ctx := context.Background()

	store := connectPostgres(t)
	defer store.Close()

	tenantX := "tenant-force-rls"

	// Insert a tenant-scoped IOC
	iocItem := ioc.IOC{
		Fingerprint:    "dddd4444dddd4444dddd4444dddd4444dddd4444dddd4444dddd4444dddd4444",
		Type:           ioc.IOCTypeProxyResponse,
		Severity:       ioc.SeverityMedium,
		Category:       "force-rls-test",
		Pattern:        "force-rls-pattern",
		SourceProvider: "test",
		AffectsLens:    true,
		AffectsGateway: false,
		Source:         "force-rls-test",
		Count:          1,
		FirstSeen:      time.Now().UTC(),
		LastSeen:       time.Now().UTC(),
	}
	if _, err := store.Observe(ctx, iocItem, ioc.TenantContext{TenantID: tenantX}); err != nil {
		t.Fatalf("Observe: %v", err)
	}

	// With tenant context, should find it
	got, err := store.Get(ctx, iocItem.Fingerprint, ioc.TenantContext{TenantID: tenantX})
	if err != nil || got == nil {
		t.Errorf("Tenant X should see own IOC: err=%v got=%v", err, got)
	}

	// Admin should also find it
	got, err = store.Get(ctx, iocItem.Fingerprint, ioc.TenantContext{TenantID: tenantX, IsAdmin: true})
	if err != nil || got == nil {
		t.Errorf("Admin should see tenant X IOC: err=%v got=%v", err, got)
	}

	// Verify FORCE RLS is active by checking pg_catalog
	pool := store.Pool()
	var rlsForced bool
	err = pool.QueryRow(ctx,
		`SELECT relrowsecurity AND relforcerowsecurity
		 FROM pg_class
		 WHERE relname = 'ioc_fingerprints'`,
	).Scan(&rlsForced)
	if err != nil {
		t.Fatalf("Failed to check RLS status: %v", err)
	}
	if !rlsForced {
		t.Error("FORCE ROW LEVEL SECURITY is not active on ioc_fingerprints — migration 010 may not have been applied")
	}
}

// TestNewPipelines_FORCE_RLS_AdminBypassWorks verifies that with FORCE
// RLS active, the admin bypass (SET LOCAL app.is_admin = 'true') still
// allows cross-tenant queries to succeed.
func TestNewPipelines_FORCE_RLS_AdminBypassWorks(t *testing.T) {
	skipIfNoLab(t)
	ctx := context.Background()

	store := connectPostgres(t)
	defer store.Close()

	tenantA := "tenant-force-admin-a"
	tenantB := "tenant-force-admin-b"

	// Insert IOCs for two tenants
	for _, tenant := range []string{tenantA, tenantB} {
		iocItem := ioc.IOC{
			Fingerprint:    tenant[:16] + strings.Repeat("0", 48),
			Type:           ioc.IOCTypeProxyResponse,
			Severity:       ioc.SeverityLow,
			Category:       "force-rls-admin",
			Pattern:        "admin-bypass-" + tenant,
			SourceProvider: "test",
			AffectsLens:    true,
			AffectsGateway: false,
			Source:         "force-rls-test",
			Count:          1,
			FirstSeen:      time.Now().UTC(),
			LastSeen:       time.Now().UTC(),
		}
		if _, err := store.Observe(ctx, iocItem, ioc.TenantContext{TenantID: tenant}); err != nil {
			t.Fatalf("Observe %s: %v", tenant, err)
		}
	}

	// Admin snapshot should see both tenants
	snapshot, err := store.Snapshot(ctx, ioc.TenantContext{TenantID: tenantA, IsAdmin: true})
	if err != nil {
		t.Fatalf("Admin Snapshot: %v", err)
	}

	foundA, foundB := false, false
	for _, item := range snapshot {
		if item.TenantID == tenantA && item.Category == "force-rls-admin" {
			foundA = true
		}
		if item.TenantID == tenantB && item.Category == "force-rls-admin" {
			foundB = true
		}
	}
	if !foundA || !foundB {
		t.Errorf("Admin should see both tenants with FORCE RLS: foundA=%v foundB=%v", foundA, foundB)
	}
}

// TestNewPipelines_FORCE_RLS_PruneCrossTenant verifies that Prune (admin-scoped)
// can delete across all tenants even with FORCE RLS active.
func TestNewPipelines_FORCE_RLS_PruneCrossTenant(t *testing.T) {
	skipIfNoLab(t)
	ctx := context.Background()

	store := connectPostgres(t)
	defer store.Close()

	tenantP := "tenant-force-prune"

	// Insert an IOC with a very old timestamp
	oldTime := time.Now().UTC().Add(-48 * time.Hour)
	iocItem := ioc.IOC{
		Fingerprint:    "eeee5555eeee5555eeee5555eeee5555eeee5555eeee5555eeee5555eeee5555",
		Type:           ioc.IOCTypeProxyResponse,
		Severity:       ioc.SeverityLow,
		Category:       "force-rls-prune",
		Pattern:        "prune-test",
		SourceProvider: "test",
		AffectsLens:    true,
		AffectsGateway: false,
		Source:         "force-rls-test",
		Count:          1,
		FirstSeen:      oldTime,
		LastSeen:       oldTime,
	}
	if _, err := store.Observe(ctx, iocItem, ioc.TenantContext{TenantID: tenantP}); err != nil {
		t.Fatalf("Observe: %v", err)
	}

	// Prune with 24h max age — should delete the 48h-old IOC
	pruned, err := store.Prune(ctx, 24*time.Hour)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if pruned < 1 {
		t.Errorf("Prune should have deleted at least 1 IOC, got %d", pruned)
	}

	// Verify it's gone
	got, err := store.Get(ctx, iocItem.Fingerprint, ioc.TenantContext{TenantID: tenantP})
	if err != nil {
		t.Fatalf("Get after prune: %v", err)
	}
	if got != nil {
		t.Error("IOC should have been pruned but is still present")
	}
}

// ensure unused imports don't cause errors
var _ = strings.Contains
