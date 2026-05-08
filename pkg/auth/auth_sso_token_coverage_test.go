//go:build !race

// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform — auth RequireRole/RequirePermission coverage
// =========================================================================

package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/rbac"
)

// --------------------------------------------------------------------------
// RequireRole coverage
// --------------------------------------------------------------------------

func TestRequireRole_DeniedForViewer(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-key-for-role-testing"),
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)
	token, _ := m.GenerateToken("test-user", "viewer")

	handler := m.RequireRole(rbac.UserRoleAdmin, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("code=%d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestRequireRole_AdminSucceeds(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-key-for-role-testing"),
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)
	token, _ := m.GenerateToken("test-user", "admin")

	handler := m.RequireRole(rbac.UserRoleAdmin, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("code=%d, want %d", rec.Code, http.StatusOK)
	}
}

func TestRequireRole_OperatorDenied(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-key-for-role-testing"),
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)
	token, _ := m.GenerateToken("test-user", "operator")

	handler := m.RequireRole(rbac.UserRoleAdmin, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("code=%d, want %d", rec.Code, http.StatusForbidden)
	}
}

// --------------------------------------------------------------------------
// RequirePermission coverage
// --------------------------------------------------------------------------

func TestRequirePermission_DeniedViewer(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-key-for-perm-testing"),
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)
	token, _ := m.GenerateToken("test-user", "viewer")

	handler := m.RequirePermission(
		rbac.Permission{Resource: rbac.ResourceConfig, Action: rbac.ActionWrite},
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("code=%d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestRequirePermission_AdminSucceeds(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-key-for-perm-testing"),
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)
	token, _ := m.GenerateToken("test-user", "admin")

	handler := m.RequirePermission(
		rbac.Permission{Resource: rbac.ResourceConfig, Action: rbac.ActionWrite},
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("code=%d, want %d", rec.Code, http.StatusOK)
	}
}

// --------------------------------------------------------------------------
// RequirePermission with wildcard permissions
// --------------------------------------------------------------------------

func TestRequirePermission_ResourceWildcardDenied(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-key-for-perm-testing"),
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)
	token, _ := m.GenerateToken("test-user", "viewer")

	handler := m.RequirePermission(
		rbac.Permission{Resource: "dashboard", Action: rbac.ActionWrite},
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("code=%d, want %d", rec.Code, http.StatusForbidden)
	}
}
