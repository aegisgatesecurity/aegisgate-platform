package agentregistry

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestInMemoryStoreCRUD verifies basic Create-Read-Update-Delete
// operations on the in-memory store.
func TestInMemoryStoreCRUD(t *testing.T) {
	store := NewInMemoryStore()
	ctx := context.Background()

	// Create
	record := &AgentRecord{
		ID:       "agent-1",
		Name:     "Test Agent",
		Role:     "standard",
		Enabled:  true,
		Status:   StatusActive,
		Tags:     map[string]string{"env": "prod"},
	}
	if err := store.Upsert(ctx, record); err != nil {
		t.Fatalf("Upsert failed: %v", err)
	}

	// Read
	got, err := store.Get(ctx, "agent-1")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got.Name != "Test Agent" {
		t.Errorf("Name = %q, want %q", got.Name, "Test Agent")
	}
	if got.Status != StatusActive {
		t.Errorf("Status = %q, want %q", got.Status, StatusActive)
	}

	// Verify it's a copy (mutating should not affect store)
	got.Name = "Modified"
	got2, _ := store.Get(ctx, "agent-1")
	if got2.Name != "Test Agent" {
		t.Error("Get returned a reference, not a copy")
	}

	// Update
	record.Name = "Updated Agent"
	record.Status = StatusDormant
	if err := store.Upsert(ctx, record); err != nil {
		t.Fatalf("Upsert (update) failed: %v", err)
	}
	got3, _ := store.Get(ctx, "agent-1")
	if got3.Name != "Updated Agent" {
		t.Errorf("Name after update = %q, want %q", got3.Name, "Updated Agent")
	}
	if got3.Status != StatusDormant {
		t.Errorf("Status after update = %q, want %q", got3.Status, StatusDormant)
	}

	// List
	record2 := &AgentRecord{ID: "agent-2", Name: "Agent 2", Status: StatusActive, Tags: map[string]string{"env": "dev"}}
	_ = store.Upsert(ctx, record2)

	all, err := store.List(ctx, nil)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("List returned %d records, want 2", len(all))
	}

	// List with filter
	filtered, _ := store.List(ctx, &ListFilter{Status: StatusDormant})
	if len(filtered) != 1 {
		t.Errorf("Filtered list returned %d, want 1", len(filtered))
	}

	// List with tag filter
	tagFiltered, _ := store.List(ctx, &ListFilter{Tag: map[string]string{"env": "prod"}})
	if len(tagFiltered) != 1 {
		t.Errorf("Tag filtered list returned %d, want 1", len(tagFiltered))
	}

	// Delete
	if err := store.Delete(ctx, "agent-1"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	_, err = store.Get(ctx, "agent-1")
	if err == nil {
		t.Error("Get after delete should fail")
	}

	// Delete non-existent
	if err := store.Delete(ctx, "nonexistent"); err == nil {
		t.Error("Delete non-existent should return ErrNotFound")
	}

	// Close
	if err := store.Close(); err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

// TestInMemoryPolicyStoreCRUD verifies policy store operations.
func TestInMemoryPolicyStoreCRUD(t *testing.T) {
	store := NewInMemoryPolicyStore()
	ctx := context.Background()

	policy := &LifecyclePolicy{
		ID:                "policy-1",
		Name:              "Default Dormancy",
		Enabled:           true,
		DormancyThreshold: 60 * 24 * time.Hour,
		OnDormant: []PolicyAction{
			{Type: "notify", Target: "email"},
		},
	}

	if err := store.UpsertPolicy(ctx, policy); err != nil {
		t.Fatalf("UpsertPolicy failed: %v", err)
	}

	got, err := store.GetPolicy(ctx, "policy-1")
	if err != nil {
		t.Fatalf("GetPolicy failed: %v", err)
	}
	if got.Name != "Default Dormancy" {
		t.Errorf("Name = %q, want %q", got.Name, "Default Dormancy")
	}
	if got.DormancyThreshold != 60*24*time.Hour {
		t.Errorf("DormancyThreshold = %v, want %v", got.DormancyThreshold, 60*24*time.Hour)
	}

	// Verify clone
	got.Name = "Modified"
	got2, _ := store.GetPolicy(ctx, "policy-1")
	if got2.Name != "Default Dormancy" {
		t.Error("GetPolicy returned a reference, not a copy")
	}

	// List
	all, _ := store.ListPolicies(ctx)
	if len(all) != 1 {
		t.Errorf("ListPolicies returned %d, want 1", len(all))
	}

	// Delete
	_ = store.DeletePolicy(ctx, "policy-1")
	_, err = store.GetPolicy(ctx, "policy-1")
	if err == nil {
		t.Error("GetPolicy after delete should fail")
	}
}

// TestListFilterMatching verifies that ListFilter correctly matches
// and filters records.
func TestListFilterMatching(t *testing.T) {
	records := []*AgentRecord{
		{ID: "1", Status: StatusActive, Owner: "team-a", Protocols: []Protocol{ProtocolMCP}, Tags: map[string]string{"env": "prod"}},
		{ID: "2", Status: StatusDormant, Owner: "team-b", Protocols: []Protocol{ProtocolA2A}, Tags: map[string]string{"env": "dev"}},
		{ID: "3", Status: StatusActive, Owner: "team-a", Protocols: []Protocol{ProtocolMCP, ProtocolA2A}, Tags: map[string]string{"env": "prod"}},
	}

	tests := []struct {
		name     string
		filter   *ListFilter
		wantLen  int
	}{
		{"nil filter", nil, 3},
		{"status active", &ListFilter{Status: StatusActive}, 2},
		{"status dormant", &ListFilter{Status: StatusDormant}, 1},
		{"owner team-a", &ListFilter{Owner: "team-a"}, 2},
		{"protocol mcp", &ListFilter{Protocol: ProtocolMCP}, 2},
		{"protocol a2a", &ListFilter{Protocol: ProtocolA2A}, 2},
		{"tag env=prod", &ListFilter{Tag: map[string]string{"env": "prod"}}, 2},
		{"tag env=dev", &ListFilter{Tag: map[string]string{"env": "dev"}}, 1},
		{"combined status+owner", &ListFilter{Status: StatusActive, Owner: "team-a"}, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched := 0
			for _, r := range records {
				if tt.filter.matches(r) {
					matched++
				}
			}
			if matched != tt.wantLen {
				t.Errorf("got %d matches, want %d", matched, tt.wantLen)
			}
		})
	}
}
// =====================================================================
// Close tests
// =====================================================================

// TestInMemoryStore_Close verifies that Close is a no-op and returns nil.
func TestInMemoryStore_Close(t *testing.T) {
	store := NewInMemoryStore()
	if err := store.Close(); err != nil {
		t.Errorf("InMemoryStore.Close() = %v, want nil", err)
	}
}

// TestInMemoryPolicyStore_Close verifies that Close is a no-op and returns nil.
func TestInMemoryPolicyStore_Close(t *testing.T) {
	store := NewInMemoryPolicyStore()
	if err := store.Close(); err != nil {
		t.Errorf("InMemoryPolicyStore.Close() = %v, want nil", err)
	}
}

// =====================================================================
// clonePolicy tests — verify all optional fields are deep-copied
// =====================================================================

// TestClonePolicy_Full verifies deep cloning of a policy with all fields set.
func TestClonePolicy_Full(t *testing.T) {
	original := &LifecyclePolicy{
		ID:                  "clone-test",
		Name:                "Clone Test",
		Enabled:             true,
		DormancyThreshold:   24 * time.Hour,
		QuarantineThreshold: 7 * 24 * time.Hour,
		AutoRevokeThreshold: 30 * 24 * time.Hour,
		OnDormant: []PolicyAction{
			{Type: "notify", Target: "email"},
			{Type: "tag", Target: "flagged=true"},
		},
		OnQuarantine: []PolicyAction{
			{Type: "quarantine"},
		},
		OnRevoke: []PolicyAction{
			{Type: "revoke"},
			{Type: "notify", Target: "pagerduty"},
		},
		Filters: &PolicyFilters{
			Protocols: []Protocol{ProtocolMCP, ProtocolA2A},
			Roles:     []string{"standard", "privileged"},
			Tags:      map[string]string{"env": "prod", "team": "sec"},
			TenantIDs: []string{"tenant-1", "tenant-2"},
		},
	}

	cloned := clonePolicy(original)

	// Verify basic fields
	if cloned.ID != original.ID {
		t.Errorf("ID = %q, want %q", cloned.ID, original.ID)
	}
	if cloned.Name != original.Name {
		t.Errorf("Name = %q, want %q", cloned.Name, original.Name)
	}
	if cloned.Enabled != original.Enabled {
		t.Errorf("Enabled = %v, want %v", cloned.Enabled, original.Enabled)
	}

	// Verify action slices are deep-copied (modifying clone shouldn't affect original)
	cloned.OnDormant[0].Type = "modified"
	if original.OnDormant[0].Type == "modified" {
		t.Error("OnDormant slice was not deep-copied")
	}

	cloned.OnQuarantine[0].Type = "modified"
	if original.OnQuarantine[0].Type == "modified" {
		t.Error("OnQuarantine slice was not deep-copied")
	}

	cloned.OnRevoke[0].Type = "modified"
	if original.OnRevoke[0].Type == "modified" {
		t.Error("OnRevoke slice was not deep-copied")
	}

	// Verify Filters deep copy
	if cloned.Filters == nil {
		t.Fatal("Filters should not be nil")
	}

	// Protocols
	cloned.Filters.Protocols[0] = ProtocolHTTP
	if original.Filters.Protocols[0] == ProtocolHTTP {
		t.Error("Filters.Protocols was not deep-copied")
	}

	// Roles
	cloned.Filters.Roles[0] = "modified"
	if original.Filters.Roles[0] == "modified" {
		t.Error("Filters.Roles was not deep-copied")
	}

	// Tags
	cloned.Filters.Tags["env"] = "modified"
	if original.Filters.Tags["env"] == "modified" {
		t.Error("Filters.Tags was not deep-copied")
	}

	// TenantIDs
	cloned.Filters.TenantIDs[0] = "modified"
	if original.Filters.TenantIDs[0] == "modified" {
		t.Error("Filters.TenantIDs was not deep-copied")
	}
}

// TestClonePolicy_Nil verifies that clonePolicy(nil) returns nil.
func TestClonePolicy_Nil(t *testing.T) {
	if clonePolicy(nil) != nil {
		t.Error("clonePolicy(nil) should return nil")
	}
}

// TestClonePolicy_EmptyActions verifies cloning a policy with no action slices.
func TestClonePolicy_EmptyActions(t *testing.T) {
	original := &LifecyclePolicy{
		ID:      "empty-actions",
		Name:    "Empty",
		Enabled: true,
	}

	cloned := clonePolicy(original)
	if cloned.ID != "empty-actions" {
		t.Errorf("ID = %q, want %q", cloned.ID, "empty-actions")
	}
	if cloned.OnDormant != nil {
		t.Error("OnDormant should be nil")
	}
	if cloned.OnQuarantine != nil {
		t.Error("OnQuarantine should be nil")
	}
	if cloned.OnRevoke != nil {
		t.Error("OnRevoke should be nil")
	}
	if cloned.Filters != nil {
		t.Error("Filters should be nil")
	}
}

// TestClonePolicy_PartialFilters verifies cloning with partially populated filters.
func TestClonePolicy_PartialFilters(t *testing.T) {
	original := &LifecyclePolicy{
		ID:      "partial-filters",
		Name:    "Partial",
		Enabled: true,
		Filters: &PolicyFilters{
			Protocols: []Protocol{ProtocolMCP},
			// Roles, Tags, TenantIDs are nil
		},
	}

	cloned := clonePolicy(original)
	if cloned.Filters == nil {
		t.Fatal("Filters should not be nil")
	}
	if len(cloned.Filters.Protocols) != 1 || cloned.Filters.Protocols[0] != ProtocolMCP {
		t.Errorf("Protocols = %v, want [mcp]", cloned.Filters.Protocols)
	}
	if cloned.Filters.Roles != nil {
		t.Error("Roles should be nil")
	}
	if cloned.Filters.Tags != nil {
		t.Error("Tags should be nil")
	}
	if cloned.Filters.TenantIDs != nil {
		t.Error("TenantIDs should be nil")
	}
}

// TestCloneRecord_Nil verifies that cloneRecord(nil) returns nil.
func TestCloneRecord_Nil(t *testing.T) {
	if cloneRecord(nil) != nil {
		t.Error("cloneRecord(nil) should return nil")
	}
}

// =====================================================================
// Edge case tests for memory store error paths
// =====================================================================

// TestInMemoryStore_Upsert_NilRecord verifies that Upsert(nil) returns nil.
func TestInMemoryStore_Upsert_NilRecord(t *testing.T) {
	store := NewInMemoryStore()
	if err := store.Upsert(context.Background(), nil); err != nil {
		t.Errorf("Upsert(nil) = %v, want nil", err)
	}
}

// TestInMemoryPolicyStore_UpsertPolicy_NilPolicy verifies that UpsertPolicy(nil) returns nil.
func TestInMemoryPolicyStore_UpsertPolicy_NilPolicy(t *testing.T) {
	store := NewInMemoryPolicyStore()
	if err := store.UpsertPolicy(context.Background(), nil); err != nil {
		t.Errorf("UpsertPolicy(nil) = %v, want nil", err)
	}
}

// TestInMemoryPolicyStore_DeletePolicy_NotFound verifies that deleting
// a nonexistent policy returns ErrNotFound.
func TestInMemoryPolicyStore_DeletePolicy_NotFound(t *testing.T) {
	store := NewInMemoryPolicyStore()
	err := store.DeletePolicy(context.Background(), "nonexistent")
	if err == nil {
		t.Error("DeletePolicy(nonexistent) should return ErrNotFound")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("DeletePolicy(nonexistent) error = %v, want ErrNotFound", err)
	}
}
