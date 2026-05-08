//go:build !race

// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform — handleSSOToken coverage tests
// =========================================================================

package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/rbac"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/sso"
)

// --------------------------------------------------------------------------
// handleSSOToken — SSO ValidateSession "session not found" path
// Exercises line 231: "SSO validation failed" error from ValidateSession
// --------------------------------------------------------------------------

func TestHandleSSOToken_SSOValidationFails(t *testing.T) {
	mgr, _ := sso.NewManager(&sso.ManagerConfig{DefaultConfig: sso.DefaultSSOConfig()})

	cfg := &Config{
		JWTSigningKey:    []byte("dev-key-change-in-production"),
		APIAuthToken:     "dev-token-change-in-production",
		TokenExpiryHours: 24,
		RequireAuth:      true,
		SSOConfig:        sso.DefaultSSOConfig(),
	}
	m := NewMiddlewareWithSSO(cfg, mgr)

	handler := m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Valid bearer format but no SSO session exists → ValidateSession returns error
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer valid-format-but-no-session")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// SSO validation fails → 401
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("code=%d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

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
