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
	"testing"
	"time"

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