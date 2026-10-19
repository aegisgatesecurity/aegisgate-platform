// SPDX-License-Identifier: Apache-2.0
//go:build integration

// Phase 4 integration tests for the PostgreSQL-backed Tenant Manager.
// Uses testcontainers to spin up an ephemeral PostgreSQL container.
// Run with: go test -tags=integration -count=1 ./pkg/tenant/...

package tenant

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/testdb"
)

func setupPostgresManager(t *testing.T) (*PostgresManager, func()) {
	t.Helper()
	pgStore, dbCleanup := testdb.SetupTestDB(t)
	pm, err := NewPostgresManager(pgStore)
	if err != nil {
		dbCleanup()
		t.Fatalf("NewPostgresManager: %v", err)
	}
	cleanup := func() {
		pm.Close()
		dbCleanup()
	}
	return pm, cleanup
}

// --- Create ---

func TestPhase4_PostgresManager_Create(t *testing.T) {
	pm, cleanup := setupPostgresManager(t)
	defer cleanup()
	ctx := context.Background()

	tnt, err := pm.Create(ctx, "Acme Corp", "Acme Corporation", "admin@acme.com", "professional", 50, 20)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if tnt.ID == "" {
		t.Fatal("expected non-empty tenant ID")
	}
	if tnt.Name != "Acme Corp" {
		t.Errorf("Name: got %q, want %q", tnt.Name, "Acme Corp")
	}
	if tnt.DisplayName != "Acme Corporation" {
		t.Errorf("DisplayName: got %q, want %q", tnt.DisplayName, "Acme Corporation")
	}
	if tnt.Email != "admin@acme.com" {
		t.Errorf("Email: got %q, want %q", tnt.Email, "admin@acme.com")
	}
	if tnt.LicenseTier != "professional" {
		t.Errorf("LicenseTier: got %q, want %q", tnt.LicenseTier, "professional")
	}
	if tnt.MaxUsers != 50 {
		t.Errorf("MaxUsers: got %d, want 50", tnt.MaxUsers)
	}
	if tnt.MaxAgents != 20 {
		t.Errorf("MaxAgents: got %d, want 20", tnt.MaxAgents)
	}
	if !tnt.Active {
		t.Error("expected new tenant to be active")
	}
	if tnt.CreatedAt.IsZero() {
		t.Error("expected non-zero CreatedAt")
	}
}

func TestPhase4_PostgresManager_Create_EmptyName(t *testing.T) {
	pm, cleanup := setupPostgresManager(t)
	defer cleanup()
	ctx := context.Background()

	_, err := pm.Create(ctx, "", "", "", "", 0, 0)
	if err == nil {
		t.Fatal("expected error for empty name")
	}
}

// --- Get ---

func TestPhase4_PostgresManager_Get(t *testing.T) {
	pm, cleanup := setupPostgresManager(t)
	defer cleanup()
	ctx := context.Background()

	tnt, _ := pm.Create(ctx, "Test Co", "Test Company", "", "community", 10, 5)
	got, err := pm.Get(ctx, tnt.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != tnt.ID {
		t.Errorf("ID: got %q, want %q", got.ID, tnt.ID)
	}
	if got.Name != "Test Co" {
		t.Errorf("Name: got %q, want %q", got.Name, "Test Co")
	}
}

func TestPhase4_PostgresManager_Get_NotFound(t *testing.T) {
	pm, cleanup := setupPostgresManager(t)
	defer cleanup()
	ctx := context.Background()

	_, err := pm.Get(ctx, "nonexistent-id")
	if err == nil {
		t.Fatal("expected error for nonexistent tenant")
	}
}

// --- List ---

func TestPhase4_PostgresManager_List(t *testing.T) {
	pm, cleanup := setupPostgresManager(t)
	defer cleanup()
	ctx := context.Background()

	// Start with empty list
	list, err := pm.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("expected 0 tenants, got %d", len(list))
	}

	// Add tenants
	pm.Create(ctx, "A", "A Co", "", "community", 1, 1)
	pm.Create(ctx, "B", "B Co", "", "developer", 2, 2)

	list, err = pm.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 tenants, got %d", len(list))
	}
}

// --- Update ---

func TestPhase4_PostgresManager_Update(t *testing.T) {
	pm, cleanup := setupPostgresManager(t)
	defer cleanup()
	ctx := context.Background()

	tnt, _ := pm.Create(ctx, "Old", "Old Name", "old@corp.com", "community", 1, 1)

	updated, err := pm.Update(ctx, tnt.ID, map[string]interface{}{
		"name":        "New",
		"displayName": "New Name",
		"email":       "new@corp.com",
		"licenseTier": "professional",
		"maxUsers":    float64(100),
		"maxAgents":   float64(50),
		"active":      false,
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.Name != "New" {
		t.Errorf("Name: got %q, want %q", updated.Name, "New")
	}
	if updated.DisplayName != "New Name" {
		t.Errorf("DisplayName: got %q, want %q", updated.DisplayName, "New Name")
	}
	if updated.Email != "new@corp.com" {
		t.Errorf("Email: got %q, want %q", updated.Email, "new@corp.com")
	}
	if updated.LicenseTier != "professional" {
		t.Errorf("LicenseTier: got %q, want %q", updated.LicenseTier, "professional")
	}
	if updated.MaxUsers != 100 {
		t.Errorf("MaxUsers: got %d, want 100", updated.MaxUsers)
	}
	if updated.MaxAgents != 50 {
		t.Errorf("MaxAgents: got %d, want 50", updated.MaxAgents)
	}
	if updated.Active {
		t.Error("expected active=false")
	}
}

func TestPhase4_PostgresManager_Update_EmptyMap(t *testing.T) {
	pm, cleanup := setupPostgresManager(t)
	defer cleanup()
	ctx := context.Background()

	tnt, _ := pm.Create(ctx, "NoChange", "No Change", "", "", 0, 0)
	updated, err := pm.Update(ctx, tnt.ID, map[string]interface{}{})
	if err != nil {
		t.Fatalf("Update with empty map: %v", err)
	}
	if updated.Name != "NoChange" {
		t.Errorf("Name: got %q, want %q", updated.Name, "NoChange")
	}
}

func TestPhase4_PostgresManager_Update_NotFound(t *testing.T) {
	pm, cleanup := setupPostgresManager(t)
	defer cleanup()
	ctx := context.Background()

	_, err := pm.Update(ctx, "nonexistent-id", map[string]interface{}{"name": "X"})
	if err == nil {
		t.Fatal("expected error for nonexistent tenant")
	}
}

func TestPhase4_PostgresManager_Update_EmptyNameSkipped(t *testing.T) {
	pm, cleanup := setupPostgresManager(t)
	defer cleanup()
	ctx := context.Background()

	tnt, _ := pm.Create(ctx, "Original", "Original Name", "", "", 0, 0)
	// Empty name in update should be skipped (name is required)
	updated, err := pm.Update(ctx, tnt.ID, map[string]interface{}{"name": ""})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.Name != "Original" {
		t.Errorf("Name: got %q, want %q (should not change to empty)", updated.Name, "Original")
	}
}

// --- Delete ---

func TestPhase4_PostgresManager_Delete(t *testing.T) {
	pm, cleanup := setupPostgresManager(t)
	defer cleanup()
	ctx := context.Background()

	tnt, _ := pm.Create(ctx, "Delete Me", "Delete Me Co", "", "", 0, 0)
	if err := pm.Delete(ctx, tnt.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// Verify it's gone
	_, err := pm.Get(ctx, tnt.ID)
	if err == nil {
		t.Fatal("tenant should not exist after delete")
	}
}

func TestPhase4_PostgresManager_Delete_NotFound(t *testing.T) {
	pm, cleanup := setupPostgresManager(t)
	defer cleanup()
	ctx := context.Background()

	err := pm.Delete(ctx, "nonexistent-id")
	if err == nil {
		t.Fatal("expected error for deleting nonexistent tenant")
	}
}

// --- Count ---

func TestPhase4_PostgresManager_Count(t *testing.T) {
	pm, cleanup := setupPostgresManager(t)
	defer cleanup()
	ctx := context.Background()

	count, err := pm.Count(ctx)
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 tenants, got %d", count)
	}

	pm.Create(ctx, "A", "", "", "", 0, 0)
	pm.Create(ctx, "B", "", "", "", 0, 0)

	count, err = pm.Count(ctx)
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected 2 tenants, got %d", count)
	}
}

// --- Close ---

func TestPhase4_PostgresManager_Close(t *testing.T) {
	pm, cleanup := setupPostgresManager(t)
	defer cleanup()
	ctx := context.Background()

	// Close the manager
	if err := pm.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Operations after close should return error
	_, err := pm.Create(ctx, "Should Fail", "", "", "", 0, 0)
	if err == nil {
		t.Fatal("expected error after Close")
	}

	_, err = pm.Get(ctx, "any-id")
	if err == nil {
		t.Fatal("expected error after Close")
	}

	_, err = pm.List(ctx)
	if err == nil {
		t.Fatal("expected error after Close")
	}

	err = pm.Delete(ctx, "any-id")
	if err == nil {
		t.Fatal("expected error after Close")
	}

	_, err = pm.Count(ctx)
	if err == nil {
		t.Fatal("expected error after Close")
	}

	// Double close should be safe
	if err := pm.Close(); err != nil {
		t.Fatalf("double Close should be safe: %v", err)
	}
}

// --- Handler (HTTP) ---

func TestPhase4_PostgresManager_Handler_CRUD(t *testing.T) {
	pm, cleanup := setupPostgresManager(t)
	defer cleanup()

	handler := pm.Handler()

	// Create via HTTP
	body := `{"name":"HTTP Tenant","displayName":"HTTP Co","email":"admin@http.com","licenseTier":"professional","maxUsers":100}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/tenants", strings.NewReader(body))
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("Create: status %d, want 201", rec.Code)
	}
	var created Tenant
	json.NewDecoder(rec.Body).Decode(&created)
	if created.Name != "HTTP Tenant" {
		t.Errorf("Name: got %q, want %q", created.Name, "HTTP Tenant")
	}

	// Get via HTTP
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/api/v1/tenants/"+created.ID, nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Get: status %d, want 200", rec.Code)
	}
	var got Tenant
	json.NewDecoder(rec.Body).Decode(&got)
	if got.ID != created.ID {
		t.Errorf("ID: got %q, want %q", got.ID, created.ID)
	}

	// List via HTTP
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/api/v1/tenants", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("List: status %d, want 200", rec.Code)
	}
	var listResp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&listResp)
	if int(listResp["count"].(float64)) != 1 {
		t.Errorf("count: got %v, want 1", listResp["count"])
	}

	// Update via HTTP
	updateBody := `{"name":"Updated Tenant","active":false}`
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("PUT", "/api/v1/tenants/"+created.ID, strings.NewReader(updateBody))
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Update: status %d, want 200", rec.Code)
	}
	var updated Tenant
	json.NewDecoder(rec.Body).Decode(&updated)
	if updated.Name != "Updated Tenant" {
		t.Errorf("Name: got %q, want %q", updated.Name, "Updated Tenant")
	}
	if updated.Active {
		t.Error("expected active=false")
	}

	// Delete via HTTP
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("DELETE", "/api/v1/tenants/"+created.ID, nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("Delete: status %d, want 204", rec.Code)
	}

	// Verify deleted
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/api/v1/tenants/"+created.ID, nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("Get after delete: status %d, want 404", rec.Code)
	}
}

func TestPhase4_PostgresManager_Handler_ErrorPaths(t *testing.T) {
	pm, cleanup := setupPostgresManager(t)
	defer cleanup()

	handler := pm.Handler()

	// Create with invalid JSON
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/tenants", strings.NewReader("bad json"))
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("invalid JSON: status %d, want 400", rec.Code)
	}

	// Create with empty name
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/api/v1/tenants", strings.NewReader(`{"name":""}`))
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("empty name: status %d, want 400", rec.Code)
	}

	// Get not found
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/api/v1/tenants/nonexistent", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("not found: status %d, want 404", rec.Code)
	}

	// Update not found
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("PUT", "/api/v1/tenants/nonexistent", strings.NewReader(`{"name":"X"}`))
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("update not found: status %d, want 404", rec.Code)
	}

	// Delete not found
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("DELETE", "/api/v1/tenants/nonexistent", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("delete not found: status %d, want 404", rec.Code)
	}

	// Method not allowed
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("PATCH", "/api/v1/tenants", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("method not allowed: status %d, want 405", rec.Code)
	}

	// Update with invalid JSON
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("PUT", "/api/v1/tenants/some-id", strings.NewReader("bad json"))
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("invalid JSON update: status %d, want 400", rec.Code)
	}
}

// --- joinStrings ---

func TestPhase4_JoinStrings(t *testing.T) {
	if got := joinStrings([]string{}, ", "); got != "" {
		t.Errorf("empty: got %q, want empty", got)
	}
	if got := joinStrings([]string{"a"}, ", "); got != "a" {
		t.Errorf("single: got %q, want %q", got, "a")
	}
	if got := joinStrings([]string{"a", "b", "c"}, ", "); got != "a, b, c" {
		t.Errorf("multiple: got %q, want %q", got, "a, b, c")
	}
}
