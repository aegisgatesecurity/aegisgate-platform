// SPDX-License-Identifier: Apache-2.0

package incident

import (
	"context"
	"testing"
)

// TestPhase3_MemoryStore_UpdateIncident_NilAndEmptyID covers error paths
// in the in-memory store's UpdateIncident function.
func TestPhase3_MemoryStore_UpdateIncident_NilAndEmptyID(t *testing.T) {
	store := NewInMemoryIncidentStore()

	if err := store.UpdateIncident(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil incident")
	}

	if err := store.UpdateIncident(context.Background(), &Incident{ID: ""}); err == nil {
		t.Fatal("expected error for empty ID")
	}
}

// TestPhase3_MemoryStore_UpdateIncident_NotFound covers the not-found path.
func TestPhase3_MemoryStore_UpdateIncident_NotFound(t *testing.T) {
	store := NewInMemoryIncidentStore()

	err := store.UpdateIncident(context.Background(), &Incident{ID: "nonexistent"})
	if err == nil {
		t.Fatal("expected error for nonexistent incident")
	}
}

// TestPhase3_MemoryStore_UpdateIncident_WithTenant covers the tenant index
// add/remove path in UpdateIncident.
func TestPhase3_MemoryStore_UpdateIncident_WithTenant(t *testing.T) {
	store := NewInMemoryIncidentStore()

	inc := NewIncident("Tenant Update Test", "desc", SeverityHigh, SourceSOC)
	inc.TenantID = "tenant-update"
	inc.AgentID = "agent-update"
	inc.SessionID = "session-update"
	if err := store.CreateIncident(context.Background(), inc); err != nil {
		t.Fatalf("CreateIncident: %v", err)
	}

	// Update with different tenant to exercise removeFromIndex + addToIndex
	inc.TenantID = "tenant-new"
	inc.AgentID = "agent-new"
	inc.SessionID = "session-new"
	if err := store.UpdateIncident(context.Background(), inc); err != nil {
		t.Fatalf("UpdateIncident: %v", err)
	}

	// Verify the update worked
	got, err := store.GetIncident(context.Background(), inc.ID)
	if err != nil {
		t.Fatalf("GetIncident: %v", err)
	}
	if got.TenantID != "tenant-new" {
		t.Fatalf("expected tenant_id=tenant-new, got %s", got.TenantID)
	}
}

// TestPhase3_MemoryStore_CreateIncident_NilAndEmptyID covers error paths.
func TestPhase3_MemoryStore_CreateIncident_NilAndEmptyID(t *testing.T) {
	store := NewInMemoryIncidentStore()

	if err := store.CreateIncident(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil incident")
	}

	if err := store.CreateIncident(context.Background(), &Incident{ID: ""}); err == nil {
		t.Fatal("expected error for empty ID")
	}
}

// TestPhase3_MemoryStore_ListIncidents_NilQuery covers the nil query path.
func TestPhase3_MemoryStore_ListIncidents_NilQuery(t *testing.T) {
	store := NewInMemoryIncidentStore()

	inc := NewIncident("Nil Query Test", "desc", SeverityMedium, SourceAPI)
	if err := store.CreateIncident(context.Background(), inc); err != nil {
		t.Fatalf("CreateIncident: %v", err)
	}

	// Nil query should return all incidents
	results, err := store.ListIncidents(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListIncidents nil query: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
}
