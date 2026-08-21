// SPDX-License-Identifier: Apache-2.0

// Package tenant provides CRUD management for multi-tenant isolation.
// See manager.go for the Tenant struct and Manager API.
package tenant

import (
	"testing"
)

func TestCreateTenant(t *testing.T) {
	m := NewManager()
	tnt, err := m.Create("Acme Corp", "Acme Corporation", "admin@acme.com", "professional", 50, 20)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if tnt.ID == "" {
		t.Error("expected non-empty tenant ID")
	}
	if tnt.Name != "Acme Corp" {
		t.Errorf("name: got %q, want %q", tnt.Name, "Acme Corp")
	}
	if !tnt.Active {
		t.Error("expected new tenant to be active")
	}
	if tnt.CreatedAt.IsZero() {
		t.Error("expected non-zero CreatedAt")
	}
}

func TestCreateTenantRequiresName(t *testing.T) {
	m := NewManager()
	_, err := m.Create("", "", "", "", 0, 0)
	if err == nil {
		t.Error("expected error for empty name")
	}
}

func TestGetTenant(t *testing.T) {
	m := NewManager()
	tnt, _ := m.Create("Test", "Test Co", "", "community", 10, 5)

	got, err := m.Get(tnt.ID)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got.Name != "Test" {
		t.Errorf("name: got %q, want %q", got.Name, "Test")
	}

	_, err = m.Get("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent tenant")
	}
}

func TestListTenants(t *testing.T) {
	m := NewManager()
	m.Create("A", "A Co", "", "community", 1, 1)
	m.Create("B", "B Co", "", "developer", 2, 2)

	list := m.List()
	if len(list) != 2 {
		t.Errorf("expected 2 tenants, got %d", len(list))
	}
}

func TestUpdateTenant(t *testing.T) {
	m := NewManager()
	tnt, _ := m.Create("Old", "Old Name", "", "community", 1, 1)

	updated, err := m.Update(tnt.ID, map[string]interface{}{
		"name":        "New",
		"displayName": "New Name",
		"active":      false,
	})
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	if updated.Name != "New" {
		t.Errorf("name: got %q, want %q", updated.Name, "New")
	}
	if updated.DisplayName != "New Name" {
		t.Errorf("displayName: got %q, want %q", updated.DisplayName, "New Name")
	}
	if updated.Active {
		t.Error("expected active=false")
	}
}

func TestDeleteTenant(t *testing.T) {
	m := NewManager()
	tnt, _ := m.Create("Delete", "Delete Me", "", "", 0, 0)

	err := m.Delete(tnt.ID)
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	if m.Count() != 0 {
		t.Errorf("expected 0 tenants after delete, got %d", m.Count())
	}

	err = m.Delete(tnt.ID)
	if err == nil {
		t.Error("expected error deleting nonexistent tenant")
	}
}

func TestCountTenants(t *testing.T) {
	m := NewManager()
	if m.Count() != 0 {
		t.Errorf("expected 0 tenants, got %d", m.Count())
	}
	m.Create("A", "A", "", "", 0, 0)
	m.Create("B", "B", "", "", 0, 0)
	if m.Count() != 2 {
		t.Errorf("expected 2 tenants, got %d", m.Count())
	}
}

func TestTenantIDFormat(t *testing.T) {
	m := NewManager()
	tnt, _ := m.Create("Test", "Test", "", "", 0, 0)
	if len(tnt.ID) < 10 {
		t.Errorf("tenant ID too short: %q", tnt.ID)
	}
	// Should start with "tnt_"
	if tnt.ID[:4] != "tnt_" {
		t.Errorf("expected 'tnt_' prefix, got %q", tnt.ID[:4])
	}
}
