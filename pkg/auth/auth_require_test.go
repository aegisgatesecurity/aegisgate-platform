// SPDX-License-Identifier: Apache-2.0
//go:build !race

package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/rbac"
)

// =============================================================================
// RequireRole — authenticated context via JWT bearer token
// All tests follow the existing middleware_test.go pattern exactly
// =============================================================================

// TestRequireRole_ComplianceOfficer tests compliance_officer role with valid JWT
func TestRequireRole_ComplianceOfficer(t *testing.T) {
	testKey := []byte("test-jwt-key-32bytes-long-key")
	cfg := &Config{
		JWTSigningKey:    testKey,
		APIAuthToken:     "test-api-token",
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	token, err := m.GenerateToken("compliance-user", "compliance_officer")
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	req := httptest.NewRequest("GET", "/compliance", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	m.RequireRole(rbac.UserRoleComplianceOfficer, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for compliance_officer, got %d", rr.Code)
	}
}

// TestRequireRole_AdminOnViewer_Alt tests admin role accessing viewer endpoint
func TestRequireRole_AdminOnViewer_Alt(t *testing.T) {
	testKey := []byte("test-jwt-key-32bytes-long-key")
	cfg := &Config{
		JWTSigningKey:    testKey,
		APIAuthToken:     "test-api-token",
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	token, err := m.GenerateToken("admin-user", "admin")
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	req := httptest.NewRequest("GET", "/viewer", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	m.RequireRole(rbac.UserRoleViewer, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for admin on viewer, got %d", rr.Code)
	}
}

// TestRequireRole_NoContext tests RequireRole without auth context
func TestRequireRole_NoContext(t *testing.T) {
	testKey := []byte("test-jwt-key-32bytes-long-key")
	cfg := &Config{
		JWTSigningKey:    testKey,
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	req := httptest.NewRequest("GET", "/admin", nil)
	rr := httptest.NewRecorder()
	m.RequireRole(rbac.UserRoleAdmin, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without context, got %d", rr.Code)
	}
}

// TestRequireRole_ViewerDeniedOnAdmin tests viewer role denied on admin endpoint
func TestRequireRole_ViewerDeniedOnAdmin(t *testing.T) {
	testKey := []byte("test-jwt-key-32bytes-long-key")
	cfg := &Config{
		JWTSigningKey:    testKey,
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	token, err := m.GenerateToken("viewer-user", "viewer")
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	req := httptest.NewRequest("GET", "/admin", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	m.RequireRole(rbac.UserRoleAdmin, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for viewer on admin, got %d", rr.Code)
	}
}

// =============================================================================
// RequirePermission via JWT bearer token
// =============================================================================

// TestRequirePermission_AdminReadAllowed tests admin:read permission via JWT
func TestRequirePermission_AdminReadAllowed(t *testing.T) {
	testKey := []byte("test-jwt-key-32bytes-long-key")
	cfg := &Config{
		JWTSigningKey:    testKey,
		APIAuthToken:     "test-api-token",
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	token, err := m.GenerateToken("admin-user", "admin")
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	req := httptest.NewRequest("GET", "/admin/read", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	m.RequirePermission(rbac.Permission{Resource: "admin", Action: "read"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for admin:read, got %d", rr.Code)
	}
}

// TestRequirePermission_ViewerDeniedDelete tests viewer denied admin:delete via JWT
func TestRequirePermission_ViewerDeniedDelete(t *testing.T) {
	testKey := []byte("test-jwt-key-32bytes-long-key")
	cfg := &Config{
		JWTSigningKey:    testKey,
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	token, err := m.GenerateToken("viewer-user", "viewer")
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	req := httptest.NewRequest("GET", "/admin/delete", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	m.RequirePermission(rbac.Permission{Resource: "admin", Action: "delete"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for viewer on admin:delete, got %d", rr.Code)
	}
}

// TestRequirePermission_CustomPerms tests custom permissions via JWT
func TestRequirePermission_CustomPerms(t *testing.T) {
	testKey := []byte("test-jwt-key-32bytes-long-key")
	cfg := &Config{
		JWTSigningKey:    testKey,
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	token, err := m.GenerateToken("custom-user", "viewer")
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	perms := []rbac.Permission{
		{Resource: "dashboard", Action: "read"},
		{Resource: "reports", Action: "generate"},
	}
	ctx := context.Background()
	ctx = context.WithValue(ctx, ContextKeyUserRole, rbac.UserRoleViewer)
	ctx = context.WithValue(ctx, ContextKeyPermissions, perms)
	ctx = context.WithValue(ctx, ContextKeyUserID, "custom-user")
	req := httptest.NewRequest("GET", "/dashboard", nil).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	m.RequirePermission(rbac.Permission{Resource: "dashboard", Action: "read"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for dashboard:read, got %d", rr.Code)
	}
}

// TestRequirePermission_MissingPerm tests missing permission denied
func TestRequirePermission_MissingPerm(t *testing.T) {
	testKey := []byte("test-jwt-key-32bytes-long-key")
	cfg := &Config{
		JWTSigningKey:    testKey,
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	token, err := m.GenerateToken("denied-user", "viewer")
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	perms := []rbac.Permission{{Resource: "dashboard", Action: "read"}}
	ctx := context.Background()
	ctx = context.WithValue(ctx, ContextKeyUserRole, rbac.UserRoleViewer)
	ctx = context.WithValue(ctx, ContextKeyPermissions, perms)
	ctx = context.WithValue(ctx, ContextKeyUserID, "denied-user")
	req := httptest.NewRequest("GET", "/admin/delete", nil).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	m.RequirePermission(rbac.Permission{Resource: "admin", Action: "delete"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for missing permission, got %d", rr.Code)
	}
}

// TestRequirePermission_DefaultRolePerms tests default permissions from role
func TestRequirePermission_DefaultRolePerms(t *testing.T) {
	testKey := []byte("test-jwt-key-32bytes-long-key")
	cfg := &Config{
		JWTSigningKey:    testKey,
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	token, err := m.GenerateToken("admin-user", "admin")
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	req := httptest.NewRequest("GET", "/admin/read", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	m.RequirePermission(rbac.Permission{Resource: "admin", Action: "read"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for admin with default permissions, got %d", rr.Code)
	}
}

// TestRequirePermission_WildcardAction tests wildcard (*,*) permission
func TestRequirePermission_WildcardAction(t *testing.T) {
	testKey := []byte("test-jwt-key-32bytes-long-key")
	cfg := &Config{
		JWTSigningKey:    testKey,
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	token, err := m.GenerateToken("admin-user", "admin")
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	req := httptest.NewRequest("GET", "/admin/logs", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	m.RequirePermission(rbac.Permission{Resource: "admin", Action: "logs"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for admin on admin:logs, got %d", rr.Code)
	}
}

// TestRequirePermission_WildcardResource tests wildcard (*,*) resource permission
func TestRequirePermission_WildcardResource(t *testing.T) {
	testKey := []byte("test-jwt-key-32bytes-long-key")
	cfg := &Config{
		JWTSigningKey:    testKey,
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	token, err := m.GenerateToken("admin-user", "admin")
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	req := httptest.NewRequest("GET", "/any-resource", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	m.RequirePermission(rbac.Permission{Resource: "admin", Action: "read"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for admin, got %d", rr.Code)
	}
}

// TestRequirePermission_AnalystRole tests analyst role permission (admin:read)
func TestRequirePermission_AnalystRole(t *testing.T) {
	testKey := []byte("test-jwt-key-32bytes-long-key")
	cfg := &Config{
		JWTSigningKey:    testKey,
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	token, err := m.GenerateToken("analyst-user", "analyst")
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	req := httptest.NewRequest("GET", "/dashboard", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	m.RequirePermission(rbac.Permission{Resource: "dashboard", Action: "read"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for analyst on dashboard:read, got %d", rr.Code)
	}
}

// TestRequirePermission_NoContext tests RequirePermission without auth context
func TestRequirePermission_NoContext(t *testing.T) {
	testKey := []byte("test-jwt-key-32bytes-long-key")
	cfg := &Config{
		JWTSigningKey:    testKey,
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	req := httptest.NewRequest("GET", "/admin/read", nil)
	rr := httptest.NewRecorder()
	m.RequirePermission(rbac.Permission{Resource: "admin", Action: "read"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without context, got %d", rr.Code)
	}
}
