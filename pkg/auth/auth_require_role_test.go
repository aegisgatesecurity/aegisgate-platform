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
// RequireRole — role hierarchy edge cases (AtLeast: viewer < analyst < compliance_officer < admin)
// =============================================================================

// TestRequireRole_ViewerOnCompliance tests viewer denied on compliance_officer endpoint
func TestRequireRole_ViewerOnCompliance(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	token, _ := m.GenerateToken("viewer-user", "viewer")

	req := httptest.NewRequest("GET", "/compliance", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	m.RequireRole(rbac.UserRoleComplianceOfficer, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for viewer on compliance_officer, got %d", rr.Code)
	}
}

// TestRequireRole_AnalystOnCompliance tests analyst denied on compliance_officer endpoint
func TestRequireRole_AnalystOnCompliance(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	token, _ := m.GenerateToken("analyst-user", "analyst")

	req := httptest.NewRequest("GET", "/compliance", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	m.RequireRole(rbac.UserRoleComplianceOfficer, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for analyst on compliance_officer, got %d", rr.Code)
	}
}

// TestRequireRole_ComplianceOnAnalyst tests compliance_officer ALLOWED on analyst endpoint
func TestRequireRole_ComplianceOnAnalyst(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	token, _ := m.GenerateToken("compliance-user", "compliance_officer")

	req := httptest.NewRequest("GET", "/analyst", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	m.RequireRole(rbac.UserRoleAnalyst, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for compliance_officer on analyst, got %d", rr.Code)
	}
}

// TestRequireRole_AdminOnCompliance tests admin ALLOWED on compliance_officer endpoint
func TestRequireRole_AdminOnCompliance(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	token, _ := m.GenerateToken("admin-user", "admin")

	req := httptest.NewRequest("GET", "/compliance", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	m.RequireRole(rbac.UserRoleComplianceOfficer, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for admin on compliance_officer, got %d", rr.Code)
	}
}

// TestRequireRole_ViewerOnAdmin tests viewer denied on admin endpoint
func TestRequireRole_ViewerOnAdmin(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	token, _ := m.GenerateToken("viewer-user", "viewer")

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

// TestRequireRole_SameLevelAllowed tests same level roles allowed (analyst on analyst)
func TestRequireRole_SameLevelAllowed(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	token, _ := m.GenerateToken("analyst-user", "analyst")

	req := httptest.NewRequest("GET", "/analyst", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	m.RequireRole(rbac.UserRoleAnalyst, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for analyst on analyst, got %d", rr.Code)
	}
}

// TestRequireRole_AdminOnAnalyst tests admin ALLOWED on analyst endpoint
func TestRequireRole_AdminOnAnalyst(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	token, _ := m.GenerateToken("admin-user", "admin")

	req := httptest.NewRequest("GET", "/analyst", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	m.RequireRole(rbac.UserRoleAnalyst, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for admin on analyst, got %d", rr.Code)
	}
}

// =============================================================================
// RequirePermission — specific resource:action permissions from role defaults
// =============================================================================

// TestRequirePermission_ViewerDefaultPerms tests viewer default permissions
func TestRequirePermission_ViewerDefaultPerms(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	token, _ := m.GenerateToken("viewer-user", "viewer")

	// viewer has dashboard:read, metrics:read, audit:read, license:read
	allowed := []rbac.Permission{
		{Resource: "dashboard", Action: "read"},
		{Resource: "metrics", Action: "read"},
		{Resource: "audit", Action: "read"},
		{Resource: "license", Action: "read"},
	}
	for _, perm := range allowed {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		m.RequirePermission(perm, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 for viewer on %s:%s, got %d", perm.Resource, perm.Action, rr.Code)
		}
	}
}

// TestRequirePermission_ViewerDeniedCompliance tests viewer denied on compliance:*
func TestRequirePermission_ViewerDeniedCompliance(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	token, _ := m.GenerateToken("viewer-user", "viewer")

	denied := []rbac.Permission{
		{Resource: "compliance", Action: "read"},
		{Resource: "compliance", Action: "execute"},
		{Resource: "compliance", Action: "write"},
	}
	for _, perm := range denied {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		m.RequirePermission(perm, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Errorf("expected 403 for viewer on %s:%s, got %d", perm.Resource, perm.Action, rr.Code)
		}
	}
}

// TestRequirePermission_AnalystHasComplianceRead tests analyst has compliance:read,execute
func TestRequirePermission_AnalystHasComplianceRead(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	token, _ := m.GenerateToken("analyst-user", "analyst")

	allowed := []rbac.Permission{
		{Resource: "compliance", Action: "read"},
		{Resource: "compliance", Action: "execute"},
	}
	for _, perm := range allowed {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		m.RequirePermission(perm, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 for analyst on %s:%s, got %d", perm.Resource, perm.Action, rr.Code)
		}
	}
}

// TestRequirePermission_ComplianceOfficerExtraPerms tests compliance_officer has policy:read
func TestRequirePermission_ComplianceOfficerExtraPerms(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	token, _ := m.GenerateToken("compliance-user", "compliance_officer")

	// compliance_officer has policy:read which analyst doesn't have
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	m.RequirePermission(rbac.Permission{Resource: "policy", Action: "read"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for compliance_officer on policy:read, got %d", rr.Code)
	}
}

// TestRequirePermission_WildcardResourceMatch tests action wildcard p.Resource=="*" && p.Action==perm.Action
func TestRequirePermission_WildcardResourceMatch(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	token, _ := m.GenerateToken("admin-user", "admin")

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	m.RequirePermission(rbac.Permission{Resource: "anything", Action: "read"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for admin with *:* wildcard, got %d", rr.Code)
	}
}

// =============================================================================
// RequireAuth — handleSSOToken edge cases (no SSO manager = skip SSO)
// =============================================================================

// TestRequireAuth_NoSSOManager_Continues tests RequireAuth skips SSO when no manager set
func TestRequireAuth_NoSSOManager_Continues(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		APIAuthToken:     "test-api-token",
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg) // No SSO manager

	// Should try JWT next (not SSO)
	token, _ := m.GenerateToken("test-user", "viewer")
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 when no SSO manager (JWT should work), got %d", rr.Code)
	}
}

// TestRequireAuth_SSOSchemeFallsThrough tests Bearer token not matching SSO falls to JWT/API
func TestRequireAuth_SSOSchemeFallsThrough(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		APIAuthToken:     "test-api-token",
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	token, _ := m.GenerateToken("test-user", "viewer")
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for Bearer JWT token, got %d", rr.Code)
	}
}

// =============================================================================
// GetUserRole / GetPermissions / GetTier / GetAuthType — edge cases
// =============================================================================

// TestGetUserRole_EmptyContext tests GetUserRole returns empty string for empty context
func TestGetUserRole_EmptyContext(t *testing.T) {
	ctx := context.Background()
	role := GetUserRole(ctx)
	if role != "" {
		t.Errorf("expected empty role for empty context, got %q", role)
	}
}

// TestGetPermissions_EmptyContext tests GetPermissions returns nil for empty context
func TestGetPermissions_EmptyContext(t *testing.T) {
	ctx := context.Background()
	perms := GetPermissions(ctx)
	if perms != nil {
		t.Errorf("expected nil permissions for empty context, got %v", perms)
	}
}

// TestGetTier_EmptyContext tests GetTier returns "community" as default for empty context
func TestGetTier_EmptyContext(t *testing.T) {
	ctx := context.Background()
	tier := GetTier(ctx)
	if tier != "community" {
		t.Errorf("expected 'community' for empty context, got %q", tier)
	}
}

// TestGetAuthType_EmptyContext tests GetAuthType returns empty string for empty context
func TestGetAuthType_EmptyContext(t *testing.T) {
	ctx := context.Background()
	authType := GetAuthType(ctx)
	if authType != "" {
		t.Errorf("expected empty authType for empty context, got %q", authType)
	}
}

// TestGetUserID_EmptyContext tests GetUserID returns empty string for empty context
func TestGetUserID_EmptyContext(t *testing.T) {
	ctx := context.Background()
	userID := GetUserID(ctx)
	if userID != "" {
		t.Errorf("expected empty userID for empty context, got %q", userID)
	}
}
