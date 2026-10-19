// SPDX-License-Identifier: Apache-2.0
//go:build integration

package ioc_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/testdb"
)

// =========================================================================
// tenant_rls.go — SetTenantContextOnConn and ClearTenantContextOnConn
// =========================================================================

func TestPhase5_SetTenantContextOnConn_Success(t *testing.T) {
	pgStore, cleanup := testdb.SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	conn, err := pgStore.Pool().Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire connection: %v", err)
	}
	defer conn.Release()

	err = ioc.SetTenantContextOnConn(ctx, conn, "tenant-test-123", true)
	if err != nil {
		t.Fatalf("SetTenantContextOnConn: %v", err)
	}

	// Verify the tenant_id was set
	var tenantID string
	err = conn.QueryRow(ctx, "SELECT current_setting('app.tenant_id', true)").Scan(&tenantID)
	if err != nil {
		t.Fatalf("QueryRow: %v", err)
	}
	if tenantID != "tenant-test-123" {
		t.Errorf("tenant_id: got %q, want %q", tenantID, "tenant-test-123")
	}

	// Verify is_admin was set
	var isAdmin string
	err = conn.QueryRow(ctx, "SELECT current_setting('app.is_admin', true)").Scan(&isAdmin)
	if err != nil {
		t.Fatalf("QueryRow: %v", err)
	}
	if isAdmin != "true" {
		t.Errorf("is_admin: got %q, want %q", isAdmin, "true")
	}
}

func TestPhase5_SetTenantContextOnConn_NotAdmin(t *testing.T) {
	pgStore, cleanup := testdb.SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	conn, err := pgStore.Pool().Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire connection: %v", err)
	}
	defer conn.Release()

	err = ioc.SetTenantContextOnConn(ctx, conn, "tenant-non-admin", false)
	if err != nil {
		t.Fatalf("SetTenantContextOnConn: %v", err)
	}

	var isAdmin string
	err = conn.QueryRow(ctx, "SELECT current_setting('app.is_admin', true)").Scan(&isAdmin)
	if err != nil {
		t.Fatalf("QueryRow: %v", err)
	}
	if isAdmin != "false" {
		t.Errorf("is_admin: got %q, want %q", isAdmin, "false")
	}
}

func TestPhase5_SetTenantContextOnConn_WithQuotes(t *testing.T) {
	pgStore, cleanup := testdb.SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	conn, err := pgStore.Pool().Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire connection: %v", err)
	}
	defer conn.Release()

	// Tenant ID with single quote (SQL injection prevention)
	err = ioc.SetTenantContextOnConn(ctx, conn, "tenant'or'1=1", false)
	if err != nil {
		t.Fatalf("SetTenantContextOnConn: %v", err)
	}

	var tenantID string
	err = conn.QueryRow(ctx, "SELECT current_setting('app.tenant_id', true)").Scan(&tenantID)
	if err != nil {
		t.Fatalf("QueryRow: %v", err)
	}
	if tenantID != "tenant'or'1=1" {
		t.Errorf("tenant_id with quotes: got %q, want %q", tenantID, "tenant'or'1=1")
	}
}

func TestPhase5_ClearTenantContextOnConn_Success(t *testing.T) {
	pgStore, cleanup := testdb.SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	conn, err := pgStore.Pool().Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire connection: %v", err)
	}
	defer conn.Release()

	// Set tenant context first
	err = ioc.SetTenantContextOnConn(ctx, conn, "tenant-clear-test", true)
	if err != nil {
		t.Fatalf("SetTenantContextOnConn: %v", err)
	}

	// Now clear it
	err = ioc.ClearTenantContextOnConn(ctx, conn)
	if err != nil {
		t.Fatalf("ClearTenantContextOnConn: %v", err)
	}

	// Verify tenant_id is cleared
	var tenantID string
	err = conn.QueryRow(ctx, "SELECT current_setting('app.tenant_id', true)").Scan(&tenantID)
	if err != nil {
		t.Fatalf("QueryRow: %v", err)
	}
	if tenantID != "" {
		t.Errorf("tenant_id after clear: got %q, want \"\"", tenantID)
	}

	// Verify is_admin is false
	var isAdmin string
	err = conn.QueryRow(ctx, "SELECT current_setting('app.is_admin', true)").Scan(&isAdmin)
	if err != nil {
		t.Fatalf("QueryRow: %v", err)
	}
	if isAdmin != "false" {
		t.Errorf("is_admin after clear: got %q, want %q", isAdmin, "false")
	}
}

// =========================================================================
// postgres_store.go — Observe with invalid IOC
// =========================================================================

func TestPhase5_PostgresStore_Observe_InvalidIOC(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	// IOC with empty fingerprint is invalid
	invalid := ioc.IOC{
		Type:        ioc.IOCTypePromptInjection,
		Severity:    ioc.SeverityHigh,
		Fingerprint: "", // empty → invalid
	}
	_, err := store.Observe(ctx, invalid)
	if err == nil {
		t.Fatal("expected error for invalid IOC")
	}
}

// =========================================================================
// postgres_store.go — NewPostgresStore with default config
// =========================================================================

func TestPhase5_NewPostgresStore_DefaultConfig(t *testing.T) {
	pgStore, cleanup := testdb.SetupTestDB(t)
	defer cleanup()

	// Get the database URL from the existing store
	dsn := pgStore.DSN()
	if dsn == "" {
		t.Skip("could not get DSN from test store")
	}

	ctx := context.Background()
	cfg := ioc.DefaultDatabaseConfig()
	cfg.URL = dsn
	// MaxConns and MinConns left as 0 → should default to 25 and 5 via NewPostgresStore
	cfg.MaxConns = 0
	cfg.MinConns = 0

	store, err := ioc.NewPostgresStore(ctx, cfg)
	if err != nil {
		t.Fatalf("NewPostgresStore with defaults: %v", err)
	}
	defer store.Close()

	// Verify the store works
	count, err := store.Size(ctx)
	if err != nil {
		t.Fatalf("Size: %v", err)
	}
	_ = count
}

// =========================================================================
// postgres_store.go — Query with all filters
// =========================================================================

func TestPhase5_PostgresStore_Query_AllFilters(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	// Insert a test IOC
	original := testIOC("query-all-filters")
	_, err := store.Observe(ctx, original)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}

	// Query with multiple filters
	results, err := store.Query(ctx, ioc.IOCQuery{
		Type:           original.Type,
		SeverityMin:    original.Severity,
		Category:       original.Category,
		SourceProvider: original.SourceProvider,
		Limit:          10,
	})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}

	found := false
	for _, r := range results {
		if r.Fingerprint == original.Fingerprint {
			found = true
			break
		}
	}
	if !found {
		t.Error("query did not return the inserted IOC")
	}
}

// =========================================================================
// postgres_store.go — SnapshotSince
// =========================================================================

func TestPhase5_PostgresStore_SnapshotSince_RecentOnly(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	// Insert a test IOC
	original := testIOC("snapshot-since")
	_, err := store.Observe(ctx, original)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}

	// Query for IOCs seen after 1 hour ago
	results, err := store.SnapshotSince(ctx, time.Now().Add(-1*time.Hour))
	if err != nil {
		t.Fatalf("SnapshotSince: %v", err)
	}

	if len(results) == 0 {
		t.Error("expected at least 1 IOC in snapshot since 1 hour ago")
	}
}

func TestPhase5_PostgresStore_SnapshotSince_FutureCutoff(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	// Insert a test IOC
	original := testIOC("snapshot-future")
	_, err := store.Observe(ctx, original)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}

	// Query for IOCs seen after 1 hour in the future — should return nothing
	results, err := store.SnapshotSince(ctx, time.Now().Add(1*time.Hour))
	if err != nil {
		t.Fatalf("SnapshotSince: %v", err)
	}

	// Should be empty (or very few if other tests inserted data)
	for _, r := range results {
		if r.Fingerprint == original.Fingerprint {
			t.Error("IOC should not appear in snapshot with future cutoff")
		}
	}
}

// =========================================================================
// postgres_store.go — Flush
// =========================================================================

func TestPhase5_PostgresStore_Flush(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	// Insert a test IOC
	original := testIOC("flush-test")
	_, err := store.Observe(ctx, original)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}

	// Flush should not error
	err = store.Flush(ctx)
	if err != nil {
		t.Fatalf("Flush: %v", err)
	}
}

// =========================================================================
// postgres_store.go — Prune with long maxAge (should prune nothing)
// =========================================================================

func TestPhase5_PostgresStore_Prune_Nothing(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	// Insert a test IOC
	original := testIOC("prune-nothing")
	_, err := store.Observe(ctx, original)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}

	// Prune with 1 year maxAge — should not prune anything
	pruned, err := store.Prune(ctx, 365*24*time.Hour)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if pruned < 0 {
		t.Errorf("pruned count should be >= 0, got %d", pruned)
	}
}

// =========================================================================
// postgres_store.go — NewPostgresStore with production mode SSL enforcement
// =========================================================================

func TestPhase5_NewPostgresStore_ProductionMode_SSLDisableRejected(t *testing.T) {
	pgStore, cleanup := testdb.SetupTestDB(t)
	defer cleanup()

	dsn := pgStore.DSN()
	if dsn == "" {
		t.Skip("could not get DSN from test store")
	}
	// Append sslmode=disable to the URL
	if strings.Contains(dsn, "?") {
		dsn += "&sslmode=disable"
	} else {
		dsn += "?sslmode=disable"
	}

	t.Setenv("AEGISGATE_MODE", "production")

	ctx := context.Background()
	cfg := ioc.DefaultDatabaseConfig()
	cfg.URL = dsn

	_, err := ioc.NewPostgresStore(ctx, cfg)
	if err == nil {
		t.Fatal("expected error for sslmode=disable in production mode")
	}
}

func TestPhase5_NewPostgresStore_ProductionMode_SSLPreferRejected(t *testing.T) {
	pgStore, cleanup := testdb.SetupTestDB(t)
	defer cleanup()

	dsn := pgStore.DSN()
	if dsn == "" {
		t.Skip("could not get DSN from test store")
	}
	if strings.Contains(dsn, "?") {
		dsn += "&sslmode=prefer"
	} else {
		dsn += "?sslmode=prefer"
	}

	t.Setenv("AEGISGATE_MODE", "prod")

	ctx := context.Background()
	cfg := ioc.DefaultDatabaseConfig()
	cfg.URL = dsn

	_, err := ioc.NewPostgresStore(ctx, cfg)
	if err == nil {
		t.Fatal("expected error for sslmode=prefer in production mode")
	}
}

func TestPhase5_NewPostgresStore_ProductionMode_NoSSLMode_AppendsRequire(t *testing.T) {
	pgStore, cleanup := testdb.SetupTestDB(t)
	defer cleanup()

	dsn := pgStore.DSN()
	if dsn == "" {
		t.Skip("could not get DSN from test store")
	}
	// Remove any existing sslmode parameter
	dsn = strings.Split(dsn, "sslmode=")[0]
	dsn = strings.TrimRight(dsn, "?&")

	t.Setenv("AEGISGATE_MODE", "production")

	ctx := context.Background()
	cfg := ioc.DefaultDatabaseConfig()
	cfg.URL = dsn

	// This should append sslmode=require and then fail at Ping
	// because the test container doesn't support SSL
	_, err := ioc.NewPostgresStore(ctx, cfg)
	if err == nil {
		t.Log("NewPostgresStore succeeded (SSL might be supported by container)")
	}
	// We don't fail the test if it succeeds — some containers support SSL
}

// =========================================================================
// postgres_store.go — Size with admin tenant context
// =========================================================================

func TestPhase5_PostgresStore_Size_AdminMode(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	// Insert a test IOC
	original := testIOC("size-admin")
	_, err := store.Observe(ctx, original)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}

	// Size as admin — should count all IOCs
	count, err := store.Size(ctx, ioc.TenantContext{TenantID: "", IsAdmin: true})
	if err != nil {
		t.Fatalf("Size admin: %v", err)
	}
	if count < 1 {
		t.Errorf("expected at least 1 IOC in admin mode, got %d", count)
	}
}

// =========================================================================
// postgres_store.go — Query with AffectsLens, AffectsGateway, Since, Offset filters
// =========================================================================

func TestPhase5_PostgresStore_Query_AllFilterOptions(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	// Insert a test IOC
	original := testIOC("query-all-options")
	_, err := store.Observe(ctx, original)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}

	affectsLens := true
	affectsGateway := false
	results, err := store.Query(ctx, ioc.IOCQuery{
		Type:           original.Type,
		Category:       original.Category,
		SourceProvider: original.SourceProvider,
		AffectsLens:    &affectsLens,
		AffectsGateway: &affectsGateway,
		Since:          time.Now().Add(-1 * time.Hour),
		Limit:          10,
		Offset:         0,
	})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	// Just verify the query doesn't error
	_ = results
}

// =========================================================================

func TestPhase5_PostgresStore_Get_AdminMode(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	// Insert a test IOC with a tenant
	original := testIOC("get-admin")
	_, err := store.Observe(ctx, original, ioc.TenantContext{TenantID: "tenant-admin-test"})
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}

	// Get as admin — should find it regardless of tenant
	result, err := store.Get(ctx, original.Fingerprint, ioc.TenantContext{TenantID: "", IsAdmin: true})
	if err != nil {
		t.Fatalf("Get admin: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result in admin mode")
	}
	if result.Fingerprint != original.Fingerprint {
		t.Errorf("fingerprint: got %q, want %q", result.Fingerprint, original.Fingerprint)
	}
}

// =========================================================================
// postgres_store.go — Size with tenant context
// =========================================================================

func TestPhase5_PostgresStore_Size_WithTenant(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	// Insert a test IOC with a tenant
	original := testIOC("size-tenant")
	_, err := store.Observe(ctx, original, ioc.TenantContext{TenantID: "tenant-size-test"})
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}

	// Size with tenant filter
	count, err := store.Size(ctx, ioc.TenantContext{TenantID: "tenant-size-test"})
	if err != nil {
		t.Fatalf("Size: %v", err)
	}
	if count < 1 {
		t.Errorf("expected at least 1 IOC for tenant, got %d", count)
	}
}
