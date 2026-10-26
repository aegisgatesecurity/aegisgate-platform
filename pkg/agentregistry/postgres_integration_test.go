// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — Agent Registry PostgreSQL Store Integration Tests
// =========================================================================
//
// Integration tests that verify PostgresStore and PostgresPolicyStore
// persist data correctly against a real PostgreSQL database spun up
// via testcontainers.
//
// Run:
//
//	go test -v -tags=integration ./pkg/agentregistry/
//
// Requires Docker for testcontainers.
// =========================================================================

//go:build integration

package agentregistry

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/auth"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/testdb"
)

// =====================================================================
// Helpers
// =====================================================================

func setupPostgresStore(t *testing.T) (*PostgresStore, *PostgresPolicyStore, func()) {
	t.Helper()
	pgStore, cleanup := testdb.SetupTestDB(t)
	store, err := NewPostgresStore(pgStore.Pool())
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	policyStore, err := NewPostgresPolicyStore(pgStore.Pool())
	if err != nil {
		t.Fatalf("NewPostgresPolicyStore: %v", err)
	}
	return store, policyStore, cleanup
}

func newTestRecord(suffix string) *AgentRecord {
	now := time.Now().UTC()
	return &AgentRecord{
		ID:               fmt.Sprintf("agent-%s", suffix),
		Name:             fmt.Sprintf("Agent %s", suffix),
		Description:      fmt.Sprintf("Test agent %s", suffix),
		Role:             "standard",
		Tools:            []string{"tool:file:read", "tool:web:search"},
		Enabled:          true,
		TenantID:         fmt.Sprintf("tenant-%s", suffix),
		Status:           StatusActive,
		StatusSince:      now,
		Owner:            "security-team",
		Tags:             map[string]string{"env": "test", "team": "sec"},
		Protocols:        []Protocol{ProtocolMCP, ProtocolA2A},
		LastActivity:     now,
		ActiveSessions:   3,
		TotalEvents:      42,
		InAIBOM:          true,
		AIBOMDrift:       "",
		DiscoverySources: []string{"rbac", "mcp", "a2a"},
		FirstSeen:        now,
		LastSeen:         now,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
}

func newTestPolicy(suffix string) *LifecyclePolicy {
	return &LifecyclePolicy{
		ID:                fmt.Sprintf("pol-%s", suffix),
		Name:              fmt.Sprintf("Policy %s", suffix),
		Description:       fmt.Sprintf("Test policy %s", suffix),
		Enabled:           true,
		DormancyThreshold: 24 * time.Hour,
		OnDormant: []PolicyAction{
			{Type: "notify", Target: "soc-channel"},
			{Type: "tag", Target: "status=dormant"},
		},
		OnQuarantine: []PolicyAction{
			{Type: "playbook", Target: "dormant_agent"},
		},
		Filters: &PolicyFilters{
			Protocols: []Protocol{ProtocolMCP},
			Roles:     []string{"standard", "privileged"},
		},
		TenantID:  fmt.Sprintf("tenant-%s", suffix),
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
}

// =====================================================================
// PostgresStore — CRUD
// =====================================================================

func TestPostgresStore_CRUD(t *testing.T) {
	store, _, cleanup := setupPostgresStore(t)
	defer cleanup()
	ctx := context.Background()

	// Create
	record := newTestRecord("crud")
	if err := store.Upsert(ctx, record); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	// Read
	got, err := store.Get(ctx, record.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != record.Name {
		t.Errorf("Name: got %q, want %q", got.Name, record.Name)
	}
	if got.Status != record.Status {
		t.Errorf("Status: got %q, want %q", got.Status, record.Status)
	}
	if len(got.Tools) != len(record.Tools) {
		t.Errorf("Tools length: got %d, want %d", len(got.Tools), len(record.Tools))
	}
	if got.Tags["env"] != "test" {
		t.Errorf("Tags[env]: got %q, want %q", got.Tags["env"], "test")
	}
	if len(got.Protocols) != 2 {
		t.Errorf("Protocols length: got %d, want %d", len(got.Protocols), 2)
	}
	if len(got.DiscoverySources) != 3 {
		t.Errorf("DiscoverySources length: got %d, want %d", len(got.DiscoverySources), 3)
	}
	if got.TotalEvents != 42 {
		t.Errorf("TotalEvents: got %d, want %d", got.TotalEvents, 42)
	}

	// Update
	record.Status = StatusDormant
	record.UpdatedAt = time.Now().UTC()
	if err := store.Upsert(ctx, record); err != nil {
		t.Fatalf("Upsert (update): %v", err)
	}
	got, err = store.Get(ctx, record.ID)
	if err != nil {
		t.Fatalf("Get after update: %v", err)
	}
	if got.Status != StatusDormant {
		t.Errorf("Status after update: got %q, want %q", got.Status, StatusDormant)
	}

	// Delete
	if err := store.Delete(ctx, record.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	_, err = store.Get(ctx, record.ID)
	if err != ErrNotFound {
		t.Errorf("Get after delete: got %v, want ErrNotFound", err)
	}
}

func TestPostgresStore_List(t *testing.T) {
	store, _, cleanup := setupPostgresStore(t)
	defer cleanup()
	ctx := context.Background()

	// Seed multiple agents
	for _, suffix := range []string{"list-1", "list-2", "list-3"} {
		record := newTestRecord(suffix)
		if err := store.Upsert(ctx, record); err != nil {
			t.Fatalf("Upsert(%s): %v", suffix, err)
		}
	}

	// List all
	records, err := store.List(ctx, nil)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(records) != 3 {
		t.Errorf("List count: got %d, want 3", len(records))
	}

	// List with status filter
	filter := &ListFilter{Status: StatusActive}
	filtered, err := store.List(ctx, filter)
	if err != nil {
		t.Fatalf("List with filter: %v", err)
	}
	if len(filtered) != 3 {
		t.Errorf("Filtered count (all active): got %d, want 3", len(filtered))
	}
}

func TestPostgresStore_Get_NotFound(t *testing.T) {
	store, _, cleanup := setupPostgresStore(t)
	defer cleanup()
	ctx := context.Background()

	_, err := store.Get(ctx, "nonexistent")
	if err != ErrNotFound {
		t.Errorf("Get nonexistent: got %v, want ErrNotFound", err)
	}
}

func TestPostgresStore_Delete_NotFound(t *testing.T) {
	store, _, cleanup := setupPostgresStore(t)
	defer cleanup()
	ctx := context.Background()

	err := store.Delete(ctx, "nonexistent")
	if err != ErrNotFound {
		t.Errorf("Delete nonexistent: got %v, want ErrNotFound", err)
	}
}

// =====================================================================
// PostgresPolicyStore — CRUD
// =====================================================================

func TestPostgresPolicyStore_CRUD(t *testing.T) {
	_, policyStore, cleanup := setupPostgresStore(t)
	defer cleanup()
	ctx := context.Background()

	// Create
	policy := newTestPolicy("crud")
	if err := policyStore.UpsertPolicy(ctx, policy); err != nil {
		t.Fatalf("UpsertPolicy: %v", err)
	}

	// Read
	got, err := policyStore.GetPolicy(ctx, policy.ID)
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if got.Name != policy.Name {
		t.Errorf("Name: got %q, want %q", got.Name, policy.Name)
	}
	if got.DormancyThreshold != policy.DormancyThreshold {
		t.Errorf("DormancyThreshold: got %v, want %v", got.DormancyThreshold, policy.DormancyThreshold)
	}
	if len(got.OnDormant) != 2 {
		t.Errorf("OnDormant length: got %d, want 2", len(got.OnDormant))
	}
	if got.Filters == nil {
		t.Fatal("Filters should not be nil")
	}
	if len(got.Filters.Protocols) != 1 {
		t.Errorf("Filters.Protocols length: got %d, want 1", len(got.Filters.Protocols))
	}

	// List
	policies, err := policyStore.ListPolicies(ctx)
	if err != nil {
		t.Fatalf("ListPolicies: %v", err)
	}
	if len(policies) != 1 {
		t.Errorf("ListPolicies count: got %d, want 1", len(policies))
	}

	// Update
	policy.Enabled = false
	policy.UpdatedAt = time.Now().UTC()
	if err := policyStore.UpsertPolicy(ctx, policy); err != nil {
		t.Fatalf("UpsertPolicy (update): %v", err)
	}
	got, err = policyStore.GetPolicy(ctx, policy.ID)
	if err != nil {
		t.Fatalf("GetPolicy after update: %v", err)
	}
	if got.Enabled != false {
		t.Errorf("Enabled after update: got %v, want false", got.Enabled)
	}

	// Delete
	if err := policyStore.DeletePolicy(ctx, policy.ID); err != nil {
		t.Fatalf("DeletePolicy: %v", err)
	}
	_, err = policyStore.GetPolicy(ctx, policy.ID)
	if err != ErrNotFound {
		t.Errorf("GetPolicy after delete: got %v, want ErrNotFound", err)
	}
}

// =====================================================================
// PostgresStore — List with filters (owner, tenant, protocol, multi)
// =====================================================================

func TestPostgresStore_List_FilterByOwner(t *testing.T) {
	store, _, cleanup := setupPostgresStore(t)
	defer cleanup()
	ctx := context.Background()

	// Seed agents with different owners
	r1 := newTestRecord("owner-a")
	r1.Owner = "team-a"
	r2 := newTestRecord("owner-b")
	r2.Owner = "team-b"
	for _, r := range []*AgentRecord{r1, r2} {
		if err := store.Upsert(ctx, r); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
	}

	filtered, err := store.List(ctx, &ListFilter{Owner: "team-a"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(filtered) != 1 {
		t.Fatalf("Expected 1 agent with owner team-a; got %d", len(filtered))
	}
	if filtered[0].Owner != "team-a" {
		t.Errorf("Owner = %s; want team-a", filtered[0].Owner)
	}
}

func TestPostgresStore_List_FilterByTenant(t *testing.T) {
	store, _, cleanup := setupPostgresStore(t)
	defer cleanup()
	ctx := context.Background()

	r1 := newTestRecord("tenant-x")
	r1.TenantID = "tenant-x"
	r2 := newTestRecord("tenant-y")
	r2.TenantID = "tenant-y"
	for _, r := range []*AgentRecord{r1, r2} {
		if err := store.Upsert(ctx, r); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
	}

	filtered, err := store.List(ctx, &ListFilter{TenantID: "tenant-x"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(filtered) != 1 {
		t.Fatalf("Expected 1 agent with tenant-x; got %d", len(filtered))
	}
}

func TestPostgresStore_List_FilterByProtocol(t *testing.T) {
	store, _, cleanup := setupPostgresStore(t)
	defer cleanup()
	ctx := context.Background()

	r1 := newTestRecord("proto-mcp")
	r1.Protocols = []Protocol{ProtocolMCP}
	r2 := newTestRecord("proto-a2a")
	r2.Protocols = []Protocol{ProtocolA2A}
	for _, r := range []*AgentRecord{r1, r2} {
		if err := store.Upsert(ctx, r); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
	}

	filtered, err := store.List(ctx, &ListFilter{Protocol: ProtocolMCP})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(filtered) != 1 {
		t.Fatalf("Expected 1 agent with MCP protocol; got %d", len(filtered))
	}
}

func TestPostgresStore_List_MultiFilter(t *testing.T) {
	store, _, cleanup := setupPostgresStore(t)
	defer cleanup()
	ctx := context.Background()

	r1 := newTestRecord("multi-1")
	r1.Owner = "team-a"
	r1.TenantID = "tenant-x"
	r1.Status = StatusActive
	r1.Protocols = []Protocol{ProtocolMCP}

	r2 := newTestRecord("multi-2")
	r2.Owner = "team-b"
	r2.TenantID = "tenant-x"
	r2.Status = StatusActive
	r2.Protocols = []Protocol{ProtocolMCP}

	for _, r := range []*AgentRecord{r1, r2} {
		if err := store.Upsert(ctx, r); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
	}

	// Filter by status + owner + tenant + protocol — exercises joinStrings with >1 condition
	filtered, err := store.List(ctx, &ListFilter{
		Status:   StatusActive,
		Owner:    "team-a",
		TenantID: "tenant-x",
		Protocol: ProtocolMCP,
	})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(filtered) != 1 {
		t.Fatalf("Expected 1 agent matching all filters; got %d", len(filtered))
	}
	if filtered[0].ID != "agent-multi-1" {
		t.Errorf("ID = %s; want agent-multi-1", filtered[0].ID)
	}
}

func TestPostgresStore_List_EmptyResult(t *testing.T) {
	store, _, cleanup := setupPostgresStore(t)
	defer cleanup()
	ctx := context.Background()

	// No records inserted — should return empty slice, not nil
	records, err := store.List(ctx, nil)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if records == nil {
		t.Fatal("Expected non-nil empty slice; got nil")
	}
	if len(records) != 0 {
		t.Errorf("Expected 0 records; got %d", len(records))
	}
}

// =====================================================================
// PostgresStore — Get with nullable/optional fields
// =====================================================================

func TestPostgresStore_Get_WithNullableFields(t *testing.T) {
	store, _, cleanup := setupPostgresStore(t)
	defer cleanup()
	ctx := context.Background()

	// Record with many optional fields unset (zero time)
	record := &AgentRecord{
		ID:               "minimal-agent",
		Name:             "Minimal Agent",
		Role:             "restricted",
		Enabled:          true,
		Status:           StatusProvisioned,
		StatusSince:      time.Now().UTC(),
		Protocols:        []Protocol{},
		Tools:            []string{},
		Tags:             map[string]string{},
		DiscoverySources: []string{},
		// LastActivity, DormantSince, CredentialExpiry, LastIntentAt,
		// FirstSeen, LastSeen all zero (will be stored as NULL)
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	if err := store.Upsert(ctx, record); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	got, err := store.Get(ctx, record.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != "Minimal Agent" {
		t.Errorf("Name = %s; want Minimal Agent", got.Name)
	}
	// Nullable timestamps should be zero (not nil-panicked)
	if !got.LastActivity.IsZero() {
		t.Errorf("LastActivity = %v; want zero", got.LastActivity)
	}
	if !got.DormantSince.IsZero() {
		t.Errorf("DormantSince = %v; want zero", got.DormantSince)
	}
	if !got.CredentialExpiry.IsZero() {
		t.Errorf("CredentialExpiry = %v; want zero", got.CredentialExpiry)
	}
	if !got.LastIntentAt.IsZero() {
		t.Errorf("LastIntentAt = %v; want zero", got.LastIntentAt)
	}
}

func TestPostgresStore_Get_AllNullableFieldsSet(t *testing.T) {
	store, _, cleanup := setupPostgresStore(t)
	defer cleanup()
	ctx := context.Background()

	now := time.Now().UTC()
	record := &AgentRecord{
		ID:               "full-agent",
		Name:             "Full Agent",
		Role:             "standard",
		Enabled:          true,
		Status:           StatusDormant,
		StatusSince:      now,
		Protocols:        []Protocol{ProtocolMCP, ProtocolHTTP, ProtocolA2A},
		Tools:            []string{"tool:file:read", "tool:web:search"},
		Tags:             map[string]string{"env": "prod", "region": "us-east"},
		DiscoverySources: []string{"rbac", "mcp", "a2a", "correlation"},
		LastActivity:     now.Add(-48 * time.Hour),
		DormantSince:     now.Add(-24 * time.Hour),
		CredentialExpiry: now.Add(30 * 24 * time.Hour),
		LastIntentAt:     now.Add(-12 * time.Hour),
		LastIntent:       "scan",
		IntentCount:      5,
		ActiveSessions:   2,
		TotalEvents:      100,
		InAIBOM:          true,
		AIBOMDrift:       "version mismatch",
		Owner:            "sec-team",
		TenantID:         "tenant-1",
		FirstSeen:        now.Add(-90 * 24 * time.Hour),
		LastSeen:         now,
		CreatedAt:        now.Add(-90 * 24 * time.Hour),
		UpdatedAt:        now,
	}

	if err := store.Upsert(ctx, record); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	got, err := store.Get(ctx, record.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	// Verify all nullable fields are populated
	if got.DormantSince.IsZero() {
		t.Error("DormantSince should not be zero")
	}
	if got.CredentialExpiry.IsZero() {
		t.Error("CredentialExpiry should not be zero")
	}
	if got.LastIntentAt.IsZero() {
		t.Error("LastIntentAt should not be zero")
	}
	if got.FirstSeen.IsZero() {
		t.Error("FirstSeen should not be zero")
	}
	if got.LastSeen.IsZero() {
		t.Error("LastSeen should not be zero")
	}
	if got.LastIntent != "scan" {
		t.Errorf("LastIntent = %s; want scan", got.LastIntent)
	}
	if got.IntentCount != 5 {
		t.Errorf("IntentCount = %d; want 5", got.IntentCount)
	}
	if got.AIBOMDrift != "version mismatch" {
		t.Errorf("AIBOMDrift = %s; want version mismatch", got.AIBOMDrift)
	}
}

// =====================================================================
// PostgresStore — List with nullable fields roundtrip
// =====================================================================

func TestPostgresStore_List_WithNullableFields(t *testing.T) {
	store, _, cleanup := setupPostgresStore(t)
	defer cleanup()
	ctx := context.Background()

	// Insert record with nullable fields set
	now := time.Now().UTC()
	record := &AgentRecord{
		ID:               "nullable-list-agent",
		Name:             "Nullable List Agent",
		Role:             "standard",
		Enabled:          true,
		Status:           StatusActive,
		StatusSince:      now,
		Protocols:        []Protocol{ProtocolMCP},
		Tools:            []string{"tool:file:read"},
		Tags:             map[string]string{"env": "prod"},
		DiscoverySources: []string{"rbac"},
		LastActivity:     now.Add(-1 * time.Hour),
		DormantSince:     now.Add(-30 * time.Minute),
		CredentialExpiry: now.Add(60 * 24 * time.Hour),
		LastIntentAt:     now.Add(-15 * time.Minute),
		LastIntent:       "execute",
		IntentCount:      3,
		ActiveSessions:   1,
		TotalEvents:      10,
		InAIBOM:          false,
		AIBOMDrift:       "",
		Owner:            "team-x",
		TenantID:         "tenant-y",
		FirstSeen:        now.Add(-10 * 24 * time.Hour),
		LastSeen:         now,
		CreatedAt:        now.Add(-10 * 24 * time.Hour),
		UpdatedAt:        now,
	}
	if err := store.Upsert(ctx, record); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	records, err := store.List(ctx, nil)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("Expected 1 record; got %d", len(records))
	}
	r := records[0]
	if r.DormantSince.IsZero() {
		t.Error("DormantSince should not be zero in List result")
	}
	if r.CredentialExpiry.IsZero() {
		t.Error("CredentialExpiry should not be zero in List result")
	}
	if r.LastIntentAt.IsZero() {
		t.Error("LastIntentAt should not be zero in List result")
	}
	if r.LastIntent != "execute" {
		t.Errorf("LastIntent = %s; want execute", r.LastIntent)
	}
	if r.IntentCount != 3 {
		t.Errorf("IntentCount = %d; want 3", r.IntentCount)
	}
}

// =====================================================================
// PostgresPolicyStore — additional edge cases
// =====================================================================

func TestPostgresPolicyStore_GetPolicy_NotFound(t *testing.T) {
	_, policyStore, cleanup := setupPostgresStore(t)
	defer cleanup()
	ctx := context.Background()

	_, err := policyStore.GetPolicy(ctx, "nonexistent-policy")
	if err != ErrNotFound {
		t.Errorf("GetPolicy nonexistent: got %v, want ErrNotFound", err)
	}
}

func TestPostgresPolicyStore_DeletePolicy_NotFound(t *testing.T) {
	_, policyStore, cleanup := setupPostgresStore(t)
	defer cleanup()
	ctx := context.Background()

	err := policyStore.DeletePolicy(ctx, "nonexistent-policy")
	if err != ErrNotFound {
		t.Errorf("DeletePolicy nonexistent: got %v, want ErrNotFound", err)
	}
}

func TestPostgresPolicyStore_ListPolicies_Empty(t *testing.T) {
	_, policyStore, cleanup := setupPostgresStore(t)
	defer cleanup()
	ctx := context.Background()

	policies, err := policyStore.ListPolicies(ctx)
	if err != nil {
		t.Fatalf("ListPolicies: %v", err)
	}
	if policies == nil {
		t.Fatal("Expected non-nil empty slice; got nil")
	}
	if len(policies) != 0 {
		t.Errorf("Expected 0 policies; got %d", len(policies))
	}
}

func TestPostgresPolicyStore_ListPolicies_Multiple(t *testing.T) {
	_, policyStore, cleanup := setupPostgresStore(t)
	defer cleanup()
	ctx := context.Background()

	for _, suffix := range []string{"multi-1", "multi-2", "multi-3"} {
		policy := newTestPolicy(suffix)
		if err := policyStore.UpsertPolicy(ctx, policy); err != nil {
			t.Fatalf("UpsertPolicy(%s): %v", suffix, err)
		}
	}

	policies, err := policyStore.ListPolicies(ctx)
	if err != nil {
		t.Fatalf("ListPolicies: %v", err)
	}
	if len(policies) != 3 {
		t.Errorf("Expected 3 policies; got %d", len(policies))
	}
}

// =====================================================================
// JSONB corruption tests — exercise json.Unmarshal error paths in
// PostgresStore.Get and PostgresPolicyStore queries. These cover lines
// 177, 180, 183, 186 in postgres_store.go (and the List/Policy
// equivalents) by inserting wrong-type JSONB via raw SQL.
// =====================================================================

func adminCtx(ctx context.Context) context.Context {
	return context.WithValue(ctx, auth.ContextKeyIsAdmin, true)
}

// corruptJSONB updates a JSONB column with wrong-type JSON so that
// json.Unmarshal into the expected Go type fails.
func corruptJSONB(t *testing.T, pool *pgxpool.Pool, agentID, column, badJSON string) {
	t.Helper()
	ctx := adminCtx(context.Background())
	_, err := pool.Exec(ctx,
		fmt.Sprintf("UPDATE agent_registry SET %s = $1::jsonb WHERE id = $2", column),
		badJSON, agentID)
	if err != nil {
		t.Fatalf("corrupt %s: %v", column, err)
	}
}

func TestPostgresStore_Get_CorruptTools(t *testing.T) {
	store, pool, cleanup := setupPostgresStoreWithPool(t)
	defer cleanup()
	ctx := adminCtx(context.Background())

	rec := newTestRecord("corrupt-tools")
	if err := store.Upsert(ctx, rec); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	// tools expects []string — inject a JSON object instead.
	corruptJSONB(t, pool, rec.ID, "tools", `{"not":"an_array"}`)

	_, err := store.Get(ctx, rec.ID)
	if err == nil {
		t.Fatal("Get with corrupt tools: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "unmarshal tools") {
		t.Errorf("Get error = %v; want 'unmarshal tools'", err)
	}
}

func TestPostgresStore_Get_CorruptTags(t *testing.T) {
	store, pool, cleanup := setupPostgresStoreWithPool(t)
	defer cleanup()
	ctx := adminCtx(context.Background())

	rec := newTestRecord("corrupt-tags")
	if err := store.Upsert(ctx, rec); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	// tags expects map[string]string — inject a JSON array instead.
	corruptJSONB(t, pool, rec.ID, "tags", `["not","an_object"]`)

	_, err := store.Get(ctx, rec.ID)
	if err == nil {
		t.Fatal("Get with corrupt tags: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "unmarshal tags") {
		t.Errorf("Get error = %v; want 'unmarshal tags'", err)
	}
}

func TestPostgresStore_Get_CorruptProtocols(t *testing.T) {
	store, pool, cleanup := setupPostgresStoreWithPool(t)
	defer cleanup()
	ctx := adminCtx(context.Background())

	rec := newTestRecord("corrupt-protos")
	if err := store.Upsert(ctx, rec); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	// protocols expects []Protocol (string slice) — inject a JSON number.
	corruptJSONB(t, pool, rec.ID, "protocols", `123`)

	_, err := store.Get(ctx, rec.ID)
	if err == nil {
		t.Fatal("Get with corrupt protocols: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "unmarshal protocols") {
		t.Errorf("Get error = %v; want 'unmarshal protocols'", err)
	}
}

func TestPostgresStore_Get_CorruptDiscoverySources(t *testing.T) {
	store, pool, cleanup := setupPostgresStoreWithPool(t)
	defer cleanup()
	ctx := adminCtx(context.Background())

	rec := newTestRecord("corrupt-disc")
	if err := store.Upsert(ctx, rec); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	// discovery_sources expects []string — inject a JSON object.
	corruptJSONB(t, pool, rec.ID, "discovery_sources", `{"not":"an_array"}`)

	_, err := store.Get(ctx, rec.ID)
	if err == nil {
		t.Fatal("Get with corrupt discovery_sources: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "unmarshal discovery_sources") {
		t.Errorf("Get error = %v; want 'unmarshal discovery_sources'", err)
	}
}

// setupPostgresStoreWithPool is like setupPostgresStore but also returns
// the underlying *pgxpool.Pool for raw SQL operations (e.g. corrupting
// JSONB columns to trigger unmarshal error paths).
func setupPostgresStoreWithPool(t *testing.T) (*PostgresStore, *pgxpool.Pool, func()) {
	t.Helper()
	pgStore, cleanup := testdb.SetupTestDB(t)
	pool := pgStore.Pool()
	store, err := NewPostgresStore(pool)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	return store, pool, cleanup
}

// =====================================================================
// Cancelled-context tests — exercise query/exec error paths in
// PostgresStore.List, Delete, ListPolicies, and DeletePolicy.
// An already-cancelled context causes the query to fail immediately,
// triggering the error return branches (lines 266, 407, 541, 636).
// =====================================================================

func TestPostgresStore_List_CancelledContext(t *testing.T) {
	store, _, cleanup := setupPostgresStore(t)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := store.List(ctx, nil)
	if err == nil {
		t.Fatal("List with cancelled context: expected error, got nil")
	}
}

func TestPostgresStore_Delete_CancelledContext(t *testing.T) {
	store, _, cleanup := setupPostgresStore(t)
	defer cleanup()

	// Insert a record first so the delete has something to target.
	ctx := adminCtx(context.Background())
	rec := newTestRecord("cancel-delete")
	if err := store.Upsert(ctx, rec); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	// Cancel context before delete — exec should fail.
	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel()

	err := store.Delete(cancelCtx, rec.ID)
	if err == nil {
		t.Fatal("Delete with cancelled context: expected error, got nil")
	}
}

func TestPostgresPolicyStore_ListPolicies_CancelledContext(t *testing.T) {
	_, policyStore, cleanup := setupPostgresStore(t)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := policyStore.ListPolicies(ctx)
	if err == nil {
		t.Fatal("ListPolicies with cancelled context: expected error, got nil")
	}
}

func TestPostgresPolicyStore_DeletePolicy_CancelledContext(t *testing.T) {
	_, policyStore, cleanup := setupPostgresStore(t)
	defer cleanup()

	// Insert a policy first.
	ctx := adminCtx(context.Background())
	pol := newTestPolicy("cancel-del-pol")
	if err := policyStore.UpsertPolicy(ctx, pol); err != nil {
		t.Fatalf("UpsertPolicy: %v", err)
	}

	// Cancel context before delete — exec should fail.
	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel()

	err := policyStore.DeletePolicy(cancelCtx, pol.ID)
	if err == nil {
		t.Fatal("DeletePolicy with cancelled context: expected error, got nil")
	}
}

// =====================================================================
// Scan error tests — exercise rows.Scan error paths in List and
// ListPolicies (lines 286, 556). We ALTER a column type after inserting
// data so the scan into the expected Go type fails.
// =====================================================================

func TestPostgresStore_List_ScanError(t *testing.T) {
	store, pool, cleanup := setupPostgresStoreWithPool(t)
	defer cleanup()

	ctx := adminCtx(context.Background())
	rec := newTestRecord("scan-err")
	if err := store.Upsert(ctx, rec); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	// Alter active_sessions from INTEGER to TEXT so scanning into
	// &record.ActiveSessions (int) fails.
	_, err := pool.Exec(ctx,
		"ALTER TABLE agent_registry ALTER COLUMN active_sessions TYPE TEXT USING active_sessions::TEXT")
	if err != nil {
		t.Fatalf("ALTER TABLE: %v", err)
	}

	_, err = store.List(ctx, nil)
	if err == nil {
		t.Fatal("List with altered schema: expected scan error, got nil")
	}
	if !strings.Contains(err.Error(), "scan row") {
		t.Errorf("List error = %v; want 'scan row'", err)
	}
}

func TestPostgresPolicyStore_ListPolicies_ScanError(t *testing.T) {
	_, pool, cleanup := setupPostgresStoreWithPool(t)
	defer cleanup()

	ctx := adminCtx(context.Background())
	policyStore, err := NewPostgresPolicyStore(pool)
	if err != nil {
		t.Fatalf("NewPostgresPolicyStore: %v", err)
	}
	pol := newTestPolicy("scan-err-pol")
	if err := policyStore.UpsertPolicy(ctx, pol); err != nil {
		t.Fatalf("UpsertPolicy: %v", err)
	}

	// Alter enabled from BOOLEAN to TEXT so scanning into
	// &policy.Enabled (bool) fails.
	_, err = pool.Exec(ctx,
		"ALTER TABLE agent_lifecycle_policies ALTER COLUMN enabled TYPE TEXT USING enabled::TEXT")
	if err != nil {
		t.Fatalf("ALTER TABLE: %v", err)
	}

	_, err = policyStore.ListPolicies(ctx)
	if err == nil {
		t.Fatal("ListPolicies with altered schema: expected scan error, got nil")
	}
	if !strings.Contains(err.Error(), "scan policy row") {
		t.Errorf("ListPolicies error = %v; want 'scan policy row'", err)
	}
}
