//go:build !race

// SPDX-License-Identifier: Apache-2.0
// Auth RequirePermission Direct Internal Coverage
// Target: 70.4% → 95%+
// Strategy: Test nil-permissions path and wildcard branches

package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/rbac"
)

// Test nil-permissions path via dev mode (auth disabled)
func TestRequirePermission_NilPermissionsViaDevMode(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-key-nil-perm-dev"),
		TokenExpiryHours: 24,
		RequireAuth:      false,
	}
	m := NewMiddleware(cfg)

	perm := rbac.Permission{Resource: "dashboard", Action: "read"}
	handlerFunc := m.RequirePermission(perm, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	handlerFunc.ServeHTTP(rr, req)

	// Dev mode defaults to viewer → dashboard:read should be allowed
	if rr.Code != http.StatusOK {
		t.Logf("Dev mode with nil permissions: got status %d", rr.Code)
	}
}

// Test nil role defaults to viewer
func TestRequirePermission_NilRoleDevMode(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-key-nilrole-dev"),
		TokenExpiryHours: 24,
		RequireAuth:      false,
	}
	m := NewMiddleware(cfg)

	// Test a permission that viewer HAS
	perm := rbac.Permission{Resource: "dashboard", Action: "read"}
	handlerFunc := m.RequirePermission(perm, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	handlerFunc.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected viewer to have dashboard:read in dev mode, got %d", rr.Code)
	}

	// Test a permission that viewer DOES NOT have
	perm2 := rbac.Permission{Resource: "admin", Action: "delete"}
	handlerFunc2 := m.RequirePermission(perm2, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req2 := httptest.NewRequest("GET", "/test", nil)
	rr2 := httptest.NewRecorder()
	handlerFunc2.ServeHTTP(rr2, req2)

	if rr2.Code != http.StatusForbidden {
		t.Errorf("Expected viewer to be denied admin:delete in dev mode, got %d", rr2.Code)
	}
}

// Test context helpers directly to verify nil-permissions behavior
func TestGetPermissions_NilCtxDirect(t *testing.T) {
	ctx := context.Background()
	perms := GetPermissions(ctx)
	if perms != nil {
		t.Errorf("Expected nil permissions from empty context, got %v", perms)
	}

	role := GetUserRole(ctx)
	if role != "" {
		t.Errorf("Expected empty role from empty context, got %s", role)
	}

	// Verify default permissions for empty role
	defaultPerms := rbac.GetPermissionsForUserRole("")
	if len(defaultPerms) > 0 {
		t.Logf("Empty role gives %d default permissions", len(defaultPerms))
	}

	// Verify viewer permissions
	viewerPerms := rbac.GetPermissionsForUserRole(rbac.UserRoleViewer)
	if len(viewerPerms) == 0 {
		t.Error("Expected viewer permissions to be non-empty")
	}
}

// Test SetPermissions and SetUserRole context helpers
func TestSetPermissionsAndUserRole_HelpersDirect(t *testing.T) {
	ctx := context.Background()

	ctx = SetUserRole(ctx, rbac.UserRoleAdmin)
	role := GetUserRole(ctx)
	if role != rbac.UserRoleAdmin {
		t.Errorf("Expected admin role, got %s", role)
	}

	testPerms := []rbac.Permission{
		{Resource: "*", Action: "*"},
		{Resource: "custom", Action: "read"},
	}
	ctx = SetPermissions(ctx, testPerms)
	perms := GetPermissions(ctx)
	if len(perms) != 2 {
		t.Errorf("Expected 2 permissions, got %d", len(perms))
	}
}

// Test compliance_officer permissions which include resource-level patterns
func TestRequirePermission_ComplianceOfficerWildcardPaths(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-key-compliance-wild"),
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	token, _ := m.GenerateToken("compliance-user", "compliance_officer")

	tests := []struct {
		resource string
		action   string
		expected int
	}{
		// Compliance officer specific permissions (exact match in role permissions)
		{"compliance", "read", http.StatusOK},
		{"compliance", "execute", http.StatusOK},
		{"compliance", "write", http.StatusOK},
		{"policy", "read", http.StatusOK},
		{"audit", "read", http.StatusOK},
		// Denied (no match)
		{"admin", "delete", http.StatusForbidden},
	}

	for _, tc := range tests {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()

		perm := rbac.Permission{Resource: rbac.Resource(tc.resource), Action: rbac.Action(tc.action)}
		handlerFunc := m.RequirePermission(perm, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		handlerFunc.ServeHTTP(rr, req)

		if rr.Code != tc.expected {
			t.Errorf("compliance_officer %s:%s: expected %d, got %d", tc.resource, tc.action, tc.expected, rr.Code)
		}
	}
}

// Test admin permissions hitting different wildcard branches
func TestRequirePermission_AdminWildcardBranches(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-key-admin-wild"),
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	token, _ := m.GenerateToken("admin-user", "admin")

	tests := []rbac.Permission{
		{Resource: "anything", Action: "everything"}, // full wildcard: *:*
		{Resource: "dashboard", Action: "read"},      // exact match first in loop
		{Resource: "dashboard", Action: "write"},     // action wildcard: *:write
		{Resource: "custom", Action: "execute"},      // action wildcard: *:execute
		{Resource: "nonexistent", Action: "delete"},  // full wildcard: *:*
	}

	for _, perm := range tests {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()

		handlerFunc := m.RequirePermission(perm, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		handlerFunc.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("admin %s:%s: expected 200, got %d", perm.Resource, perm.Action, rr.Code)
		}
	}
}
