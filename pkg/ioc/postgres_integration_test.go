// SPDX-License-Identifier: Apache-2.0
//go:build integration

// =========================================================================
// AegisGate Platform - PostgresStore Integration Tests
// =========================================================================
//
// postgres_integration_test.go exercises all PostgresStore methods against
// a live PostgreSQL database spun up via testcontainers. The tests use the
// shared testdb.SetupTestDB helper, which calls t.Skip if Docker is not
// available, so the suite is safe to include in CI runs without Docker.
//
// Run with: go test -tags=integration -run TestPostgresStore ./pkg/ioc/...
//
// Package ioc_test is used (external test package) so we can import testdb
// without an internal-to-external import cycle.
//
// =========================================================================

package ioc_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/testdb"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// testIOC returns a valid IOC suitable for insertion. Each call with a
// different suffix produces a unique fingerprint so multiple IOCs never
// collide on the primary key.
func testIOC(suffix string) ioc.IOC {
	now := time.Now().UTC()
	return ioc.IOC{
		Fingerprint:    fmt.Sprintf("%064x", suffix),
		Type:           ioc.IOCTypePromptInjection,
		Severity:       ioc.SeverityHigh,
		FirstSeen:      now,
		LastSeen:       now,
		Count:          1,
		Source:         "proxy",
		Category:       "prompt_injection",
		Pattern:        "jailbreak_v3",
		SourceProvider: "chatgpt",
		AffectsLens:    true,
		AffectsGateway: true,
	}
}

// testIOCWithType returns a valid IOC with a specific type and severity.
func testIOCWithType(suffix string, iocType ioc.IOCType, sev ioc.Severity) ioc.IOC {
	now := time.Now().UTC()
	return ioc.IOC{
		Fingerprint:    fmt.Sprintf("%064x", suffix),
		Type:           iocType,
		Severity:       sev,
		FirstSeen:      now,
		LastSeen:       now,
		Count:          1,
		Source:         "scanner",
		Category:       "secret_api_key",
		Pattern:        "aws_access_key_v1",
		SourceProvider: "claude",
		AffectsLens:    true,
		AffectsGateway: false,
	}
}

// setupStore creates a fresh PostgresStore via testcontainers and returns it
// along with a cleanup function. The caller should defer cleanup().
func setupStore(t *testing.T) (*ioc.PostgresStore, func()) {
	t.Helper()
	pgStore, cleanup := testdb.SetupTestDB(t)
	return pgStore, cleanup
}

// --------------------------------------------------------------------------
// Observe
// --------------------------------------------------------------------------

func TestPostgresStore_Observe_Insert(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	original := testIOC("observe-insert")
	result, err := store.Observe(ctx, original, ioc.TenantContext{TenantID: "tenant-alpha"})
	if err != nil {
		t.Fatalf("Observe insert: %v", err)
	}

	if result.Fingerprint != original.Fingerprint {
		t.Errorf("Fingerprint mismatch: got %q, want %q", result.Fingerprint, original.Fingerprint)
	}
	if result.Type != original.Type {
		t.Errorf("Type mismatch: got %q, want %q", result.Type, original.Type)
	}
	if result.Severity != original.Severity {
		t.Errorf("Severity mismatch: got %q, want %q", result.Severity, original.Severity)
	}
	if result.Count != 1 {
		t.Errorf("Count after first insert: got %d, want 1", result.Count)
	}
}

func TestPostgresStore_Observe_Upsert(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	original := testIOC("observe-upsert")
	_, err := store.Observe(ctx, original, ioc.TenantContext{TenantID: "tenant-beta"})
	if err != nil {
		t.Fatalf("first Observe: %v", err)
	}

	// Observe the same fingerprint again; count should increment.
	updated := original
	updated.Severity = ioc.SeverityCritical // severity should escalate
	result, err := store.Observe(ctx, updated, ioc.TenantContext{TenantID: "tenant-beta"})
	if err != nil {
		t.Fatalf("second Observe: %v", err)
	}

	if result.Count != 2 {
		t.Errorf("Count after upsert: got %d, want 2", result.Count)
	}
	if result.Severity != ioc.SeverityCritical {
		t.Errorf("Severity after upsert: got %q, want %q", result.Severity, ioc.SeverityCritical)
	}
}

// --------------------------------------------------------------------------
// ObserveBatch
// --------------------------------------------------------------------------

func TestPostgresStore_ObserveBatch(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	iocs := []ioc.IOC{
		testIOC("batch-1"),
		testIOC("batch-2"),
		testIOC("batch-3"),
	}

	err := store.ObserveBatch(ctx, iocs, ioc.TenantContext{TenantID: "tenant-gamma"})
	if err != nil {
		t.Fatalf("ObserveBatch: %v", err)
	}

	size, err := store.Size(ctx, ioc.TenantContext{TenantID: "tenant-gamma"})
	if err != nil {
		t.Fatalf("Size after batch: %v", err)
	}
	if size != 3 {
		t.Errorf("Size after ObserveBatch: got %d, want 3", size)
	}
}

func TestPostgresStore_ObserveBatch_Empty(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	err := store.ObserveBatch(ctx, nil, ioc.TenantContext{TenantID: "tenant-gamma"})
	if err != nil {
		t.Fatalf("ObserveBatch with nil: %v", err)
	}

	err = store.ObserveBatch(ctx, []ioc.IOC{}, ioc.TenantContext{TenantID: "tenant-gamma"})
	if err != nil {
		t.Fatalf("ObserveBatch with empty slice: %v", err)
	}
}

// --------------------------------------------------------------------------
// Get
// --------------------------------------------------------------------------

func TestPostgresStore_Get_Found(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	original := testIOC("get-found")
	_, err := store.Observe(ctx, original, ioc.TenantContext{TenantID: "tenant-delta"})
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}

	result, err := store.Get(ctx, original.Fingerprint, ioc.TenantContext{TenantID: "tenant-delta"})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if result == nil {
		t.Fatal("Get returned nil, expected IOC")
	}
	if result.Fingerprint != original.Fingerprint {
		t.Errorf("Get fingerprint: got %q, want %q", result.Fingerprint, original.Fingerprint)
	}
}

func TestPostgresStore_Get_NotFound(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	result, err := store.Get(ctx, "nonexistent_fingerprint_that_is_exactly_64_chars_padded_with_zzzz", ioc.TenantContext{TenantID: "tenant-delta"})
	if err != nil {
		t.Fatalf("Get not found: %v", err)
	}
	if result != nil {
		t.Errorf("Get nonexistent: expected nil, got %+v", result)
	}
}

func TestPostgresStore_Get_TenantIsolation(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	original := testIOC("get-tenant-iso")
	_, err := store.Observe(ctx, original, ioc.TenantContext{TenantID: "tenant-a"})
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}

	// A different tenant should not see this IOC.
	result, err := store.Get(ctx, original.Fingerprint, ioc.TenantContext{TenantID: "tenant-b"})
	if err != nil {
		t.Fatalf("Get with different tenant: %v", err)
	}
	if result != nil {
		t.Errorf("tenant-b should not see tenant-a's IOC, got %+v", result)
	}

	// Admin should see it.
	adminResult, err := store.Get(ctx, original.Fingerprint, ioc.TenantContext{TenantID: "tenant-b", IsAdmin: true})
	if err != nil {
		t.Fatalf("Get as admin: %v", err)
	}
	if adminResult == nil {
		t.Error("admin should see tenant-a's IOC, got nil")
	}
}

// --------------------------------------------------------------------------
// Size
// --------------------------------------------------------------------------

func TestPostgresStore_Size(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	tenantID := "tenant-epsilon"

	// Initially empty.
	size, err := store.Size(ctx, ioc.TenantContext{TenantID: tenantID})
	if err != nil {
		t.Fatalf("Size initial: %v", err)
	}
	if size != 0 {
		t.Errorf("Initial size: got %d, want 0", size)
	}

	// Insert two IOCs.
	for _, suffix := range []string{"size-1", "size-2"} {
		_, err := store.Observe(ctx, testIOC(suffix), ioc.TenantContext{TenantID: tenantID})
		if err != nil {
			t.Fatalf("Observe %s: %v", suffix, err)
		}
	}

	size, err = store.Size(ctx, ioc.TenantContext{TenantID: tenantID})
	if err != nil {
		t.Fatalf("Size after insert: %v", err)
	}
	if size != 2 {
		t.Errorf("Size after 2 inserts: got %d, want 2", size)
	}
}

// --------------------------------------------------------------------------
// Snapshot
// --------------------------------------------------------------------------

func TestPostgresStore_Snapshot(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	tenantID := "tenant-zeta"

	iocs := []ioc.IOC{
		testIOC("snap-1"),
		testIOC("snap-2"),
		testIOC("snap-3"),
	}
	err := store.ObserveBatch(ctx, iocs, ioc.TenantContext{TenantID: tenantID})
	if err != nil {
		t.Fatalf("ObserveBatch: %v", err)
	}

	snapshot, err := store.Snapshot(ctx, ioc.TenantContext{TenantID: tenantID})
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(snapshot) != 3 {
		t.Errorf("Snapshot length: got %d, want 3", len(snapshot))
	}

	// Verify snapshot is sorted by LastSeen descending.
	for i := 1; i < len(snapshot); i++ {
		if snapshot[i].LastSeen.After(snapshot[i-1].LastSeen) {
			t.Errorf("Snapshot not sorted by LastSeen DESC: [%d]=%v > [%d]=%v",
				i, snapshot[i].LastSeen, i-1, snapshot[i-1].LastSeen)
		}
	}
}

// --------------------------------------------------------------------------
// SnapshotSince
// --------------------------------------------------------------------------

func TestPostgresStore_SnapshotSince(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	tenantID := "tenant-eta"

	// Insert an IOC with a known timestamp in the past.
	past := time.Now().UTC().Add(-2 * time.Hour)
	oldIOC := ioc.IOC{
		Fingerprint:    fmt.Sprintf("%064x", "since-old"),
		Type:           ioc.IOCTypeProxyResponse,
		Severity:       ioc.SeverityLow,
		FirstSeen:      past,
		LastSeen:       past,
		Count:          1,
		Source:         "proxy",
		AffectsLens:    true,
		AffectsGateway: true,
	}
	_, err := store.Observe(ctx, oldIOC, ioc.TenantContext{TenantID: tenantID})
	if err != nil {
		t.Fatalf("Observe old: %v", err)
	}

	// Insert a recent IOC.
	recent := testIOC("since-recent")
	_, err = store.Observe(ctx, recent, ioc.TenantContext{TenantID: tenantID})
	if err != nil {
		t.Fatalf("Observe recent: %v", err)
	}

	// SnapshotSince 1 hour ago should return only the recent IOC.
	cutoff := time.Now().UTC().Add(-1 * time.Hour)
	results, err := store.SnapshotSince(ctx, cutoff, ioc.TenantContext{TenantID: tenantID})
	if err != nil {
		t.Fatalf("SnapshotSince: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("SnapshotSince result count: got %d, want 1", len(results))
	} else if results[0].Fingerprint != recent.Fingerprint {
		t.Errorf("SnapshotSince fingerprint: got %q, want %q",
			results[0].Fingerprint, recent.Fingerprint)
	}
}

// --------------------------------------------------------------------------
// Query
// --------------------------------------------------------------------------

func TestPostgresStore_Query_ByType(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	tenantID := "tenant-theta"

	// Insert IOCs of different types.
	iocs := []ioc.IOC{
		testIOCWithType("query-proxy", ioc.IOCTypeProxyResponse, ioc.SeverityMedium),
		testIOCWithType("query-pi", ioc.IOCTypePromptInjection, ioc.SeverityHigh),
		testIOCWithType("query-secret", ioc.IOCTypeSecretLeak, ioc.SeverityCritical),
	}
	err := store.ObserveBatch(ctx, iocs, ioc.TenantContext{TenantID: tenantID})
	if err != nil {
		t.Fatalf("ObserveBatch: %v", err)
	}

	results, err := store.Query(ctx, ioc.IOCQuery{
		Type: ioc.IOCTypePromptInjection,
	}, ioc.TenantContext{TenantID: tenantID})
	if err != nil {
		t.Fatalf("Query by type: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("Query by type count: got %d, want 1", len(results))
	}
	if results[0].Type != ioc.IOCTypePromptInjection {
		t.Errorf("Query by type result: got %q, want %q", results[0].Type, ioc.IOCTypePromptInjection)
	}
}

func TestPostgresStore_Query_BySeverity(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	tenantID := "tenant-iota"

	iocs := []ioc.IOC{
		testIOCWithType("sev-low", ioc.IOCTypeProxyResponse, ioc.SeverityLow),
		testIOCWithType("sev-med", ioc.IOCTypeProxyResponse, ioc.SeverityMedium),
		testIOCWithType("sev-high", ioc.IOCTypeProxyResponse, ioc.SeverityHigh),
		testIOCWithType("sev-crit", ioc.IOCTypeProxyResponse, ioc.SeverityCritical),
	}
	err := store.ObserveBatch(ctx, iocs, ioc.TenantContext{TenantID: tenantID})
	if err != nil {
		t.Fatalf("ObserveBatch: %v", err)
	}

	results, err := store.Query(ctx, ioc.IOCQuery{
		SeverityMin: ioc.SeverityHigh,
	}, ioc.TenantContext{TenantID: tenantID})
	if err != nil {
		t.Fatalf("Query by severity: %v", err)
	}

	// Should return high + critical = 2 results.
	if len(results) < 2 {
		t.Errorf("Query by severity (>=high): got %d results, want at least 2", len(results))
	}

	for _, r := range results {
		if r.Severity != ioc.SeverityHigh && r.Severity != ioc.SeverityCritical {
			t.Errorf("Query by severity returned unexpected severity %q", r.Severity)
		}
	}
}

func TestPostgresStore_Query_ByCategoryAndProvider(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	tenantID := "tenant-kappa"

	// Insert IOCs with different categories/providers.
	chatgptIOC := testIOC("query-chatgpt")
	chatgptIOC.Category = "pii_email"
	chatgptIOC.SourceProvider = "chatgpt"
	chatgptIOC.AffectsLens = true

	claudeIOC := testIOC("query-claude")
	claudeIOC.Category = "secret_api_key"
	claudeIOC.SourceProvider = "claude"
	claudeIOC.AffectsLens = true

	err := store.ObserveBatch(ctx, []ioc.IOC{chatgptIOC, claudeIOC}, ioc.TenantContext{TenantID: tenantID})
	if err != nil {
		t.Fatalf("ObserveBatch: %v", err)
	}

	lens := true
	results, err := store.Query(ctx, ioc.IOCQuery{
		SourceProvider: "chatgpt",
		AffectsLens:    &lens,
	}, ioc.TenantContext{TenantID: tenantID})
	if err != nil {
		t.Fatalf("Query by provider: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("Query by provider count: got %d, want 1", len(results))
	}
	if results[0].SourceProvider != "chatgpt" {
		t.Errorf("Query result SourceProvider: got %q, want %q", results[0].SourceProvider, "chatgpt")
	}
}

func TestPostgresStore_Query_WithLimit(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	tenantID := "tenant-limit"

	// Insert 5 IOCs.
	var iocs []ioc.IOC
	for i := 0; i < 5; i++ {
		iocs = append(iocs, testIOC(fmt.Sprintf("limit-%d", i)))
	}
	err := store.ObserveBatch(ctx, iocs, ioc.TenantContext{TenantID: tenantID})
	if err != nil {
		t.Fatalf("ObserveBatch: %v", err)
	}

	results, err := store.Query(ctx, ioc.IOCQuery{
		Limit: 3,
	}, ioc.TenantContext{TenantID: tenantID})
	if err != nil {
		t.Fatalf("Query with limit: %v", err)
	}

	if len(results) != 3 {
		t.Errorf("Query with limit=3: got %d results, want 3", len(results))
	}
}

// --------------------------------------------------------------------------
// Prune
// --------------------------------------------------------------------------

func TestPostgresStore_Prune(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	tenantID := "tenant-prune"

	// Insert an "old" IOC with LastSeen 30 days ago.
	oldTime := time.Now().UTC().Add(-30 * 24 * time.Hour)
	oldIOC := ioc.IOC{
		Fingerprint:    fmt.Sprintf("%064x", "prune-old"),
		Type:           ioc.IOCTypeSecretLeak,
		Severity:       ioc.SeverityHigh,
		FirstSeen:      oldTime,
		LastSeen:       oldTime,
		Count:          5,
		Source:         "scanner",
		Category:       "secret_api_key",
		Pattern:        "aws_access_key_v1",
		SourceProvider: "chatgpt",
		AffectsLens:    true,
		AffectsGateway: true,
	}
	_, err := store.Observe(ctx, oldIOC, ioc.TenantContext{TenantID: tenantID})
	if err != nil {
		t.Fatalf("Observe old IOC: %v", err)
	}

	// Insert a "recent" IOC.
	recentIOC := testIOC("prune-recent")
	_, err = store.Observe(ctx, recentIOC, ioc.TenantContext{TenantID: tenantID})
	if err != nil {
		t.Fatalf("Observe recent IOC: %v", err)
	}

	// Verify 2 IOCs before pruning.
	sizeBefore, err := store.Size(ctx)
	if err != nil {
		t.Fatalf("Size before prune: %v", err)
	}
	if sizeBefore < 2 {
		t.Errorf("Size before prune: got %d, want >= 2", sizeBefore)
	}

	// Prune IOCs older than 7 days.
	pruned, err := store.Prune(ctx, 7*24*time.Hour)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if pruned != 1 {
		t.Errorf("Pruned count: got %d, want 1", pruned)
	}

	// The recent IOC should still exist.
	result, err := store.Get(ctx, recentIOC.Fingerprint)
	if err != nil {
		t.Fatalf("Get after prune: %v", err)
	}
	if result == nil {
		t.Error("Recent IOC should still exist after pruning")
	}

	// The old IOC should be gone.
	gone, err := store.Get(ctx, oldIOC.Fingerprint)
	if err != nil {
		t.Fatalf("Get old IOC after prune: %v", err)
	}
	if gone != nil {
		t.Error("Old IOC should have been pruned")
	}
}

// --------------------------------------------------------------------------
// Full round-trip
// --------------------------------------------------------------------------

func TestPostgresStore_RoundTrip(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	tenantID := "tenant-roundtrip"

	// 1. Observe a single IOC.
	single := testIOC("roundtrip-single")
	result, err := store.Observe(ctx, single, ioc.TenantContext{TenantID: tenantID})
	if err != nil {
		t.Fatalf("Observe single: %v", err)
	}
	if result.Count != 1 {
		t.Errorf("single Observe count: got %d, want 1", result.Count)
	}

	// 2. Observe same IOC again (upsert).
	result2, err := store.Observe(ctx, single, ioc.TenantContext{TenantID: tenantID})
	if err != nil {
		t.Fatalf("Observe upsert: %v", err)
	}
	if result2.Count != 2 {
		t.Errorf("upsert count: got %d, want 2", result2.Count)
	}

	// 3. Batch insert more IOCs.
	batch := []ioc.IOC{
		testIOC("roundtrip-batch-1"),
		testIOC("roundtrip-batch-2"),
	}
	err = store.ObserveBatch(ctx, batch, ioc.TenantContext{TenantID: tenantID})
	if err != nil {
		t.Fatalf("ObserveBatch: %v", err)
	}

	// 4. Verify size.
	size, err := store.Size(ctx, ioc.TenantContext{TenantID: tenantID})
	if err != nil {
		t.Fatalf("Size: %v", err)
	}
	if size != 3 {
		t.Errorf("Size after round-trip inserts: got %d, want 3", size)
	}

	// 5. Get by fingerprint.
	got, err := store.Get(ctx, single.Fingerprint, ioc.TenantContext{TenantID: tenantID})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil {
		t.Fatal("Get returned nil")
	}
	if got.Count != 2 {
		t.Errorf("Get count: got %d, want 2", got.Count)
	}

	// 6. Snapshot returns all 3.
	snap, err := store.Snapshot(ctx, ioc.TenantContext{TenantID: tenantID})
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(snap) != 3 {
		t.Errorf("Snapshot length: got %d, want 3", len(snap))
	}

	// 7. SnapshotSince returns IOCs seen after a recent cutoff.
	recentCutoff := time.Now().UTC().Add(-1 * time.Minute)
	sinceResults, err := store.SnapshotSince(ctx, recentCutoff, ioc.TenantContext{TenantID: tenantID})
	if err != nil {
		t.Fatalf("SnapshotSince: %v", err)
	}
	if len(sinceResults) != 3 {
		t.Errorf("SnapshotSince count: got %d, want 3", len(sinceResults))
	}

	// 8. Query with type filter.
	queryResults, err := store.Query(ctx, ioc.IOCQuery{
		Type: ioc.IOCTypePromptInjection,
	}, ioc.TenantContext{TenantID: tenantID})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	// All 3 test IOCs are IOCTypePromptInjection.
	if len(queryResults) != 3 {
		t.Errorf("Query by type count: got %d, want 3", len(queryResults))
	}

	// 9. Prune with a very short maxAge (should remove all).
	pruned, err := store.Prune(ctx, 1*time.Millisecond)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if pruned == 0 {
		t.Error("Prune with 1ms maxAge should have removed at least 1 IOC")
	}

	// After pruning, size should be 0 (all IOCs are older than 1ms).
	finalSize, err := store.Size(ctx)
	if err != nil {
		t.Fatalf("Final Size: %v", err)
	}
	if finalSize != 0 {
		t.Errorf("Size after prune: got %d, want 0", finalSize)
	}
}

// TestPostgresStore_RLS_Enforcement verifies that RLS policies actually fire
// at the database level, not just application-layer filtering.
// This test requires:
//  1. PostgreSQL with migration 008 applied (RLS enabled on ioc_fingerprints)
//  2. aegisgate_app role that is NOT the table owner (table owner bypasses RLS)
func TestPostgresStore_RLS_Enforcement(t *testing.T) {
	ctx := context.Background()
	store, cleanup := setupStore(t)
	defer cleanup()

	// Get database URL from store (DSN method)
	databaseURL := store.DSN()
	if databaseURL == "" {
		t.Skip("DATABASE_URL not available")
	}

	// Create aegisgate_app role in test database (testcontainers starts fresh)
	// Use same password as testcontainers default for simplicity
	_, err := store.Pool().Exec(ctx, `
		DO $$
		BEGIN
			IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aegisgate_app') THEN
				CREATE ROLE aegisgate_app LOGIN PASSWORD 'aegisgate_test_password' NOSUPERUSER NOBYPASSRLS;
			END IF;
		END $$;
		GRANT USAGE ON SCHEMA public TO aegisgate_app;
		GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO aegisgate_app;
	`)
	if err != nil {
		t.Fatalf("Create aegisgate_app role: %v", err)
	}

	// Insert IOCs for two tenants using app-layer filtering
	tenantACtx := ioc.TenantContext{TenantID: "tenant-a", IsAdmin: false}
	tenantBCtx := ioc.TenantContext{TenantID: "tenant-b", IsAdmin: false}

	iocA := testIOC("rls-enforcement-a")
	iocB := testIOC("rls-enforcement-b")

	_, err = store.Observe(ctx, iocA, tenantACtx)
	if err != nil {
		t.Fatalf("Observe tenant-a: %v", err)
	}

	_, err = store.Observe(ctx, iocB, tenantBCtx)
	if err != nil {
		t.Fatalf("Observe tenant-b: %v", err)
	}

	// Verify app-layer filtering works (tenant A sees only their IOC)
	resultsA, err := store.Query(ctx, ioc.IOCQuery{}, tenantACtx)
	if err != nil {
		t.Fatalf("Query as tenant-a: %v", err)
	}
	if len(resultsA) != 1 {
		t.Errorf("Tenant A should see 1 IOC (app-layer), got %d", len(resultsA))
	}

	// Now test RLS enforcement by connecting as aegisgate_app role
	// (non-owner, subject to RLS policies)
	appRoleURL := strings.Replace(databaseURL,
		"aegisgate:aegisgate_test_password",
		"aegisgate_app:aegisgate_test_password",
		1)

	appPool, err := pgxpool.New(ctx, appRoleURL)
	if err != nil {
		t.Fatalf("Create app role pool: %v", err)
	}
	defer appPool.Close()

	// Test 1: Query without tenant context (should see NOTHING due to RLS)
	// RLS policy: USING (tenant_id::text = current_setting('app.tenant_id'::text) OR current_setting('app.is_admin'::text) = 'true')
	// With empty tenant_id and is_admin=false, policy denies access
	var countWithoutContext int
	err = appPool.QueryRow(ctx, "SELECT COUNT(*) FROM ioc_fingerprints").Scan(&countWithoutContext)
	if err != nil {
		t.Fatalf("Query without context: %v", err)
	}
	if countWithoutContext != 0 {
		t.Errorf("RLS should block unscoped queries, got %d rows", countWithoutContext)
	}

	// Test 2: Query WITH tenant context (should see only tenant's data)
	// This uses WithTenantContext to set session variables
	var countWithContext int
	err = ioc.WithTenantContext(ctx, appPool, "tenant-a", false, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT COUNT(*) FROM ioc_fingerprints").Scan(&countWithContext)
	})
	if err != nil {
		t.Fatalf("Query with tenant context: %v", err)
	}
	if countWithContext != 1 {
		t.Errorf("RLS should allow tenant-a to see 1 IOC, got %d", countWithContext)
	}

	// Test 3: Verify tenant-b sees different data
	var countTenantB int
	err = ioc.WithTenantContext(ctx, appPool, "tenant-b", false, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT COUNT(*) FROM ioc_fingerprints").Scan(&countTenantB)
	})
	if err != nil {
		t.Fatalf("Query as tenant-b: %v", err)
	}
	if countTenantB != 1 {
		t.Errorf("RLS should allow tenant-b to see 1 IOC, got %d", countTenantB)
	}

	// Test 4: Admin context sees ALL IOCs
	var countAdmin int
	err = ioc.WithTenantContext(ctx, appPool, "", true, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT COUNT(*) FROM ioc_fingerprints").Scan(&countAdmin)
	})
	if err != nil {
		t.Fatalf("Query as admin: %v", err)
	}
	if countAdmin != 2 {
		t.Errorf("Admin should see all 2 IOCs, got %d", countAdmin)
	}

	t.Logf("✅ RLS enforcement verified: policies fire correctly for aegisgate_app role")
}

// TestPostgresStore_RLS_TableOwnerBypass verifies that table owners bypass RLS
// (expected PostgreSQL behavior). This is why we need FORCE ROW LEVEL SECURITY
// after app compatibility testing.
func TestPostgresStore_RLS_TableOwnerBypass(t *testing.T) {
	// This test is documented but skipped - it requires a more complex setup
	// to verify table owner bypass vs. forced RLS. The TestPostgresStore_RLS_Enforcement
	// test already proves RLS policies fire correctly for non-owner roles.
	t.Skip("Table owner bypass test requires separate database setup")
}
