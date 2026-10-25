package agentregistry

import (
	"context"
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