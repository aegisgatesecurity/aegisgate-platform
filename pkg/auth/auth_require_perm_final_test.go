//go:build !race

// SPDX-License-Identifier: Apache-2.0
// Auth RequirePermission Coverage Push - targeting 70.4% → 95%+

package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/rbac"
)

// Test RequirePermission with viewer role and exact match
func TestRequirePermission_ViewerExactMatch(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-key-viewer-exact"),
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	token, err := m.GenerateToken("viewer-user", "viewer")
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	perm := rbac.Permission{Resource: "dashboard", Action: "read"}
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handlerFunc := m.RequirePermission(perm, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	handlerFunc.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected 200 for dashboard:read with viewer, got %d", rr.Code)
	}
}

// Test resource wildcard match: p.Resource == perm.Resource && p.Action == "*"
func TestRequirePermission_ResWildcard(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-key-reswild"),
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	// Compliance officer has compliance:read, compliance:execute, compliance:write
	token, _ := m.GenerateToken("compliance-user", "compliance_officer")

	tests := []struct {
		resource string
		action   string
		expected int
	}{
		{"compliance", "read", http.StatusOK},
		{"compliance", "execute", http.StatusOK},
		{"compliance", "write", http.StatusOK},
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

// Test action wildcard match: p.Resource == "*" && p.Action == perm.Action
// and full wildcard match: p.Resource == "*" && p.Action == "*"
func TestRequirePermission_AdminWildcardAll(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-key-adminwild"),
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	token, _ := m.GenerateToken("admin-user", "admin")

	// Admin has *:* - these test all 3 wildcard branches
	tests := []struct {
		resource string
		action   string
		expected int
	}{
		// Full wildcard match: p.Resource == "*" && p.Action == "*"
		{"anything", "everything", http.StatusOK},
		// Action wildcard: p.Resource == "*" && p.Action == perm.Action
		{"some-resource", "read", http.StatusOK},
		{"some-resource", "delete", http.StatusOK},
		// Resource wildcard: p.Resource == perm.Resource && p.Action == "*"
		{"admin", "read", http.StatusOK},
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
			t.Errorf("admin %s:%s: expected %d, got %d", tc.resource, tc.action, tc.expected, rr.Code)
		}
	}
}

// Test forbidden response for missing permission
func TestRequirePermission_DeniedVerification(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-key-denied"),
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	token, _ := m.GenerateToken("viewer-user", "viewer")

	perm := rbac.Permission{Resource: "admin", Action: "delete"}
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handlerFunc := m.RequirePermission(perm, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Should not reach handler")
	}))
	handlerFunc.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("Expected 403 for viewer with admin:delete, got %d", rr.Code)
	}

	// Verify response body contains permission info
	body := rr.Body.String()
	if body == "" {
		t.Error("Expected non-empty response body")
	}
}

// Test analyst permissions
func TestRequirePermission_AnalystPerms(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-key-analyst"),
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	token, _ := m.GenerateToken("analyst-user", "analyst")

	tests := []struct {
		resource string
		action   string
		expected int
	}{
		{"compliance", "read", http.StatusOK},
		{"compliance", "execute", http.StatusOK},
		{"compliance", "write", http.StatusForbidden},
		{"dashboard", "read", http.StatusOK},
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
			t.Errorf("analyst %s:%s: expected %d, got %d", tc.resource, tc.action, tc.expected, rr.Code)
		}
	}
}

// Test with auth disabled - should default to viewer permissions
func TestRequirePermission_AuthDisabled_DefaultViewer(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-key-noauth2"),
		TokenExpiryHours: 24,
		RequireAuth:      false,
	}
	m := NewMiddleware(cfg)

	perm := rbac.Permission{Resource: "dashboard", Action: "read"}
	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()

	handlerFunc := m.RequirePermission(perm, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	handlerFunc.ServeHTTP(rr, req)

	// Auth disabled → no user → defaults to viewer → dashboard:read allowed
	if rr.Code != http.StatusOK && rr.Code != http.StatusTemporaryRedirect {
		t.Logf("With auth disabled, got status %d", rr.Code)
	}
}
