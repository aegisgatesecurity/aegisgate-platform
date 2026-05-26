// SPDX-License-Identifier: Apache-2.0
// Auth middleware coverage — targeting 95%+
// Covers: RequireRole forbidden path, RequirePermission wildcard matching paths

package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/rbac"
)

// ============================================================================
// RequireRole — 90% → 95%+ (forbidden response path)
// ============================================================================

func TestRequireRole_ForbiddenViewerRequiresAdmin(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-key-role-forbidden"),
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	token, err := m.GenerateToken("viewer-user", "viewer")
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	handler := m.RequireRole(rbac.UserRoleAdmin, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called for viewer requiring admin")
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("Expected 403 for viewer requiring admin, got %d", rr.Code)
	}
}

func TestRequireRole_ViewerCanAccessViewer(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-key-role-viewer-ok"),
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	token, err := m.GenerateToken("viewer-user", "viewer")
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	handler := m.RequireRole(rbac.UserRoleViewer, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected 200 for viewer accessing viewer resource, got %d", rr.Code)
	}
}

// ============================================================================
// RequirePermission — 70.4% → 95%+
// Tests hit the wildcard matching branches (resource*, action*, full*)
// ============================================================================

func TestRequirePermission_ViewerDefaultPermsWildcard(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-key-perm-viewer"),
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	// Create viewer token — viewer has dashboard:read by default
	token, err := m.GenerateToken("perm-viewer", "viewer")
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	handler := m.RequirePermission(rbac.Permission{Resource: "dashboard", Action: "read"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected 200 for viewer with dashboard:read, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestRequirePermission_ViewerDeniedWildcard(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-key-perm-denied"),
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	token, err := m.GenerateToken("perm-denied", "viewer")
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	handler := m.RequirePermission(rbac.Permission{Resource: "admin", Action: "delete"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("Expected 403 for viewer denied admin:delete, got %d", rr.Code)
	}
}

func TestRequirePermission_AdminAllPermissions(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-key-perm-admin"),
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	token, err := m.GenerateToken("perm-admin", "admin")
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	// Admin should have wildcard permissions ({Resource: "*", Action: "*"})
	// This tests the full wildcard branch
	permissions := []rbac.Permission{
		{Resource: "dashboard", Action: "read"},
		{Resource: "admin", Action: "delete"},
		{Resource: "metrics", Action: "read"},
	}

	for _, perm := range permissions {
		handler := m.RequirePermission(perm, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected 200 for admin with %s:%s, got %d: %s", perm.Resource, perm.Action, rr.Code, rr.Body.String())
		}
	}
}

func TestRequirePermission_AnalystPermsWildcard(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-key-perm-analyst"),
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	token, err := m.GenerateToken("perm-analyst", "analyst")
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	// Analyst should have specific permissions
	handler := m.RequirePermission(rbac.Permission{Resource: "metrics", Action: "read"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected 200 for analyst with metrics:read, got %d: %s", rr.Code, rr.Body.String())
	}
}
