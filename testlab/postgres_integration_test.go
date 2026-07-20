// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — PostgreSQL Integration Tests (D1 Phase 1D)
// =========================================================================
//
// Real-database tests that verify the PostgreSQL storage backend works
// end-to-end. These are gated by both the `//go:build lab` build tag
// AND the LAB_ENABLED=1 env var. They require a running PostgreSQL
// instance (started via `cd testlab && docker compose up -d`).
//
// Run with:
//
//	LAB_ENABLED=1 go test -tags=lab -v ./testlab/ -run TestPostgres
//
// =========================================================================

//go:build lab

package testlab

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/license"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/rbac"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
)

// testDatabaseURL returns the PostgreSQL connection URL for integration tests.
// Falls back to localhost if AEGISGATE_DATABASE_URL is not set (for local testing).
func testDatabaseURL() string {
	if u := os.Getenv("AEGISGATE_DATABASE_URL"); u != "" {
		return u
	}
	return "postgres://aegisgate:aegisgate_test_pass@localhost:5432/aegisgate_test?sslmode=disable"
}

// skipIfNoLab skips the test if LAB_ENABLED is not set.
func skipIfNoLab(t *testing.T) {
	t.Helper()
	if os.Getenv("LAB_ENABLED") != "1" {
		t.Skip("skipping: set LAB_ENABLED=1 to run PostgreSQL integration tests")
	}
}

// ============================================================================
// IOC Store Integration Tests (Phase 1A)
// ============================================================================

func TestPostgresIOCStore_ObserveAndGet(t *testing.T) {
	skipIfNoLab(t)
	ctx := context.Background()

	cfg := ioc.DefaultDatabaseConfig()
	cfg.URL = testDatabaseURL()

	store, err := ioc.NewPostgresStore(ctx, cfg)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	defer store.Close()

	// Observe an IOC
	testIOC := ioc.IOC{
		Fingerprint:    fmt.Sprintf("test-ioc-observe-%d", time.Now().UnixNano()),
		Type:           "domain",
		Severity:       "high",
		Category:       "phishing",
		Pattern:        "evil.example.com",
		SourceProvider: "integration-test",
		AffectsLens:    true,
		AffectsGateway: true,
	}

	observed, err := store.Observe(ctx, testIOC)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}

	if observed.Fingerprint != testIOC.Fingerprint {
		t.Errorf("Observed fingerprint = %q, want %q", observed.Fingerprint, testIOC.Fingerprint)
	}

	// Get it back
	got, err := store.Get(ctx, testIOC.Fingerprint)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil {
		t.Fatal("Get returned nil, want the observed IOC")
	}
	if got.Fingerprint != testIOC.Fingerprint {
		t.Errorf("Get fingerprint = %q, want %q", got.Fingerprint, testIOC.Fingerprint)
	}
	if got.Count < 1 {
		t.Errorf("Get count = %d, want >= 1", got.Count)
	}

	t.Logf("✅ IOC Observe+Get: fingerprint=%s, count=%d", got.Fingerprint, got.Count)
}

func TestPostgresIOCStore_Query(t *testing.T) {
	skipIfNoLab(t)
	ctx := context.Background()

	cfg := ioc.DefaultDatabaseConfig()
	cfg.URL = testDatabaseURL()

	store, err := ioc.NewPostgresStore(ctx, cfg)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	defer store.Close()

	// Observe multiple IOCs with different categories
	categories := []string{"malware", "phishing", "c2"}
	for _, cat := range categories {
		testIOC := ioc.IOC{
			Fingerprint:    fmt.Sprintf("test-ioc-query-%s-%d", cat, time.Now().UnixNano()),
			Type:           "domain",
			Severity:       "high",
			Category:       cat,
			Pattern:        cat + ".example.com",
			SourceProvider: "integration-test",
			AffectsLens:    true,
		}
		_, err := store.Observe(ctx, testIOC)
		if err != nil {
			t.Fatalf("Observe(%s): %v", cat, err)
		}
	}

	// Query by category
	results, err := store.Query(ctx, ioc.IOCQuery{Category: "phishing"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(results) == 0 {
		t.Error("Query returned 0 results, want >= 1")
	}

	t.Logf("✅ IOC Query by category: %d results for 'phishing'", len(results))
}

func TestPostgresIOCStore_Size(t *testing.T) {
	skipIfNoLab(t)
	ctx := context.Background()

	cfg := ioc.DefaultDatabaseConfig()
	cfg.URL = testDatabaseURL()

	store, err := ioc.NewPostgresStore(ctx, cfg)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	defer store.Close()

	size, err := store.Size(ctx)
	if err != nil {
		t.Fatalf("Size: %v", err)
	}
	t.Logf("✅ IOC Store Size: %d entries", size)
}

// ============================================================================
// RBAC Store Integration Tests (Phase 1C)
// ============================================================================

func TestPostgresRBAC_RegisterAndGetAgent(t *testing.T) {
	skipIfNoLab(t)
	ctx := context.Background()

	cfg := ioc.DefaultDatabaseConfig()
	cfg.URL = testDatabaseURL()

	pgStore, err := ioc.NewPostgresStore(ctx, cfg)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	defer pgStore.Close()

	rbacStore, err := rbac.NewPostgresRBACStore(pgStore, nil)
	if err != nil {
		t.Fatalf("NewPostgresRBACStore: %v", err)
	}
	defer rbacStore.Close()

	agent := &rbac.Agent{
		ID:          fmt.Sprintf("test-agent-%d", time.Now().UnixNano()),
		Name:        "Integration Test Agent",
		Description: "Agent created by PostgreSQL integration tests",
		Role:        rbac.AgentRoleStandard,
		Tools:       []rbac.ToolPermission{rbac.PermToolFileRead, rbac.PermToolWebSearch},
		Tags:        map[string]string{"env": "test", "source": "integration"},
		Metadata:    map[string]interface{}{"version": "1.0"},
		Enabled:     true,
	}

	// Register
	if err := rbacStore.RegisterAgent(ctx, agent); err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}

	// Get
	got, err := rbacStore.GetAgent(ctx, agent.ID)
	if err != nil {
		t.Fatalf("GetAgent: %v", err)
	}
	if got == nil {
		t.Fatal("GetAgent returned nil")
	}
	if got.ID != agent.ID {
		t.Errorf("GetAgent ID = %q, want %q", got.ID, agent.ID)
	}
	if got.Role != agent.Role {
		t.Errorf("GetAgent Role = %q, want %q", got.Role, agent.Role)
	}

	t.Logf("✅ RBAC Register+Get: agent_id=%s, role=%s", got.ID, got.Role)
}

func TestPostgresRBAC_CreateAndGetAgentSession(t *testing.T) {
	skipIfNoLab(t)
	ctx := context.Background()

	cfg := ioc.DefaultDatabaseConfig()
	cfg.URL = testDatabaseURL()

	pgStore, err := ioc.NewPostgresStore(ctx, cfg)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	defer pgStore.Close()

	rbacStore, err := rbac.NewPostgresRBACStore(pgStore, nil)
	if err != nil {
		t.Fatalf("NewPostgresRBACStore: %v", err)
	}
	defer rbacStore.Close()

	// Register agent first
	agent := &rbac.Agent{
		ID:      fmt.Sprintf("test-session-agent-%d", time.Now().UnixNano()),
		Name:    "Session Test Agent",
		Role:    rbac.AgentRoleStandard,
		Enabled: true,
	}
	if err := rbacStore.RegisterAgent(ctx, agent); err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}

	// Create session
	session := &rbac.AgentSession{
		ID:        fmt.Sprintf("test-session-%d", time.Now().UnixNano()),
		AgentID:   agent.ID,
		IPAddress: "10.0.0.1",
		Active:    true,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(time.Hour),
		Tags:      map[string]string{"source": "integration"},
	}
	session.SetLastActivity(time.Now().UTC())

	if err := rbacStore.CreateAgentSession(ctx, session); err != nil {
		t.Fatalf("CreateAgentSession: %v", err)
	}

	// Get session
	got, err := rbacStore.GetAgentSession(ctx, session.ID)
	if err != nil {
		t.Fatalf("GetAgentSession: %v", err)
	}
	if got == nil {
		t.Fatal("GetAgentSession returned nil")
	}
	if got.ID != session.ID {
		t.Errorf("GetAgentSession ID = %q, want %q", got.ID, session.ID)
	}
	if got.AgentID != agent.ID {
		t.Errorf("GetAgentSession AgentID = %q, want %q", got.AgentID, agent.ID)
	}

	t.Logf("✅ RBAC CreateSession+Get: session_id=%s, agent_id=%s", got.ID, got.AgentID)
}

func TestPostgresRBAC_InvalidateSession(t *testing.T) {
	skipIfNoLab(t)
	ctx := context.Background()

	cfg := ioc.DefaultDatabaseConfig()
	cfg.URL = testDatabaseURL()

	pgStore, err := ioc.NewPostgresStore(ctx, cfg)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	defer pgStore.Close()

	rbacStore, err := rbac.NewPostgresRBACStore(pgStore, nil)
	if err != nil {
		t.Fatalf("NewPostgresRBACStore: %v", err)
	}
	defer rbacStore.Close()

	// Register agent
	agent := &rbac.Agent{
		ID:      fmt.Sprintf("test-inval-agent-%d", time.Now().UnixNano()),
		Name:    "Invalidate Test Agent",
		Role:    rbac.AgentRoleStandard,
		Enabled: true,
	}
	if err := rbacStore.RegisterAgent(ctx, agent); err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}

	// Create session
	session := &rbac.AgentSession{
		ID:        fmt.Sprintf("test-inval-session-%d", time.Now().UnixNano()),
		AgentID:   agent.ID,
		Active:    true,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}
	session.SetLastActivity(time.Now().UTC())

	if err := rbacStore.CreateAgentSession(ctx, session); err != nil {
		t.Fatalf("CreateAgentSession: %v", err)
	}

	// Invalidate
	if err := rbacStore.InvalidateAgentSession(ctx, session.ID); err != nil {
		t.Fatalf("InvalidateAgentSession: %v", err)
	}

	// Verify session is no longer active
	got, err := rbacStore.GetAgentSession(ctx, session.ID)
	if err != nil {
		t.Fatalf("GetAgentSession after invalidate: %v", err)
	}
	if got != nil {
		t.Errorf("GetAgentSession returned non-nil after invalidation, want nil")
	}

	t.Logf("✅ RBAC InvalidateSession: session %s invalidated", session.ID[:8])
}

func TestPostgresRBAC_ListAgents(t *testing.T) {
	skipIfNoLab(t)
	ctx := context.Background()

	cfg := ioc.DefaultDatabaseConfig()
	cfg.URL = testDatabaseURL()

	pgStore, err := ioc.NewPostgresStore(ctx, cfg)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	defer pgStore.Close()

	rbacStore, err := rbac.NewPostgresRBACStore(pgStore, nil)
	if err != nil {
		t.Fatalf("NewPostgresRBACStore: %v", err)
	}
	defer rbacStore.Close()

	agents, err := rbacStore.ListAgents(ctx)
	if err != nil {
		t.Fatalf("ListAgents: %v", err)
	}
	t.Logf("✅ RBAC ListAgents: %d agents", len(agents))
}

func TestPostgresRBAC_PruneExpiredSessions(t *testing.T) {
	skipIfNoLab(t)
	ctx := context.Background()

	cfg := ioc.DefaultDatabaseConfig()
	cfg.URL = testDatabaseURL()

	pgStore, err := ioc.NewPostgresStore(ctx, cfg)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	defer pgStore.Close()

	rbacStore, err := rbac.NewPostgresRBACStore(pgStore, nil)
	if err != nil {
		t.Fatalf("NewPostgresRBACStore: %v", err)
	}
	defer rbacStore.Close()

	pruned, err := rbacStore.PruneExpiredSessions(ctx)
	if err != nil {
		t.Fatalf("PruneExpiredSessions: %v", err)
	}
	t.Logf("✅ RBAC PruneExpiredSessions: %d expired sessions pruned", pruned)
}

// ============================================================================
// License Cache Integration Tests (Phase 1C)
// ============================================================================

func TestPostgresLicenseCache_SetAndGet(t *testing.T) {
	skipIfNoLab(t)
	ctx := context.Background()

	cfg := ioc.DefaultDatabaseConfig()
	cfg.URL = testDatabaseURL()

	pgStore, err := ioc.NewPostgresStore(ctx, cfg)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	defer pgStore.Close()

	cache, err := license.NewPostgresLicenseCache(pgStore)
	if err != nil {
		t.Fatalf("NewPostgresLicenseCache: %v", err)
	}
	defer cache.Close()

	// Set a cache entry
	key := fmt.Sprintf("test-license-%d", time.Now().UnixNano())
	result := &license.ValidationResult{
		Valid:       true,
		Expired:     false,
		GracePeriod: false,
		Tier:        tier.TierProfessional,
		Message:     "License valid - Professional tier",
		ValidatedAt: time.Now().UTC(),
	}

	if err := cache.Set(ctx, key, result, 5*time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Get it back
	got := cache.Get(ctx, key)
	if got == nil {
		t.Fatal("Get returned nil, want the cached result")
	}
	if got.Tier != result.Tier {
		t.Errorf("Get Tier = %v, want %v", got.Tier, result.Tier)
	}
	if got.Valid != result.Valid {
		t.Errorf("Get Valid = %v, want %v", got.Valid, result.Valid)
	}

	t.Logf("✅ License Cache Set+Get: key=%s, tier=%s, valid=%v", key[:24], got.Tier.String(), got.Valid)
}

func TestPostgresLicenseCache_Invalidate(t *testing.T) {
	skipIfNoLab(t)
	ctx := context.Background()

	cfg := ioc.DefaultDatabaseConfig()
	cfg.URL = testDatabaseURL()

	pgStore, err := ioc.NewPostgresStore(ctx, cfg)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	defer pgStore.Close()

	cache, err := license.NewPostgresLicenseCache(pgStore)
	if err != nil {
		t.Fatalf("NewPostgresLicenseCache: %v", err)
	}
	defer cache.Close()

	// Set and then invalidate
	key := fmt.Sprintf("test-license-inval-%d", time.Now().UnixNano())
	result := &license.ValidationResult{
		Valid:       true,
		Tier:        tier.TierDeveloper,
		Message:     "Test",
		ValidatedAt: time.Now().UTC(),
	}

	if err := cache.Set(ctx, key, result, 5*time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}

	if err := cache.Invalidate(ctx, key); err != nil {
		t.Fatalf("Invalidate: %v", err)
	}

	// Verify it's gone
	got := cache.Get(ctx, key)
	if got != nil {
		t.Errorf("Get after invalidate returned non-nil, want nil")
	}

	t.Logf("✅ License Cache Invalidate: key %s invalidated", key[:24])
}

func TestPostgresLicenseCache_PruneExpired(t *testing.T) {
	skipIfNoLab(t)
	ctx := context.Background()

	cfg := ioc.DefaultDatabaseConfig()
	cfg.URL = testDatabaseURL()

	pgStore, err := ioc.NewPostgresStore(ctx, cfg)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	defer pgStore.Close()

	cache, err := license.NewPostgresLicenseCache(pgStore)
	if err != nil {
		t.Fatalf("NewPostgresLicenseCache: %v", err)
	}
	defer cache.Close()

	pruned, err := cache.PruneExpired(ctx)
	if err != nil {
		t.Fatalf("PruneExpired: %v", err)
	}
	t.Logf("✅ License Cache PruneExpired: %d entries pruned", pruned)
}

// ============================================================================
// Migration Verification Tests
// ============================================================================

func TestPostgresMigrations_AllApplied(t *testing.T) {
	skipIfNoLab(t)
	ctx := context.Background()

	cfg := ioc.DefaultDatabaseConfig()
	cfg.URL = testDatabaseURL()

	store, err := ioc.NewPostgresStore(ctx, cfg)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	defer store.Close()

	// Verify all migrations were applied by checking ioc_schema_migrations
	// The store's migrate() function runs on NewPostgresStore, so all
	// 3 migrations (001, 002, 003) should be present.
	pool := store.Pool()
	if pool == nil {
		t.Fatal("Pool() returned nil")
	}

	rows, err := pool.Query(ctx, "SELECT version FROM ioc_schema_migrations ORDER BY version")
	if err != nil {
		t.Fatalf("Query migrations: %v", err)
	}
	defer rows.Close()

	versions := []int{}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			t.Fatalf("Scan migration version: %v", err)
		}
		versions = append(versions, v)
	}

	if len(versions) < 3 {
		t.Errorf("Expected at least 3 migrations, got %d: %v", len(versions), versions)
	}

	t.Logf("✅ Migrations applied: %v", versions)
}
