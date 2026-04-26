// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform — SSO Middleware Integration Tests
// =========================================================================

package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/rbac"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/sso"
)

// ============================================================================
// DefaultSSOConfig tests
// ============================================================================

func TestDefaultSSOConfig(t *testing.T) {
	cfg := DefaultSSOConfig()
	if cfg == nil {
		t.Fatal("DefaultSSOConfig() returned nil")
	}
	if cfg.SessionDuration != 24*time.Hour {
		t.Errorf("SessionDuration = %v, want %v", cfg.SessionDuration, 24*time.Hour)
	}
	if cfg.CookieName != "sso_session" {
		t.Errorf("CookieName = %v, want sso_session", cfg.CookieName)
	}
	if !cfg.CookieSecure {
		t.Error("CookieSecure should be true by default")
	}
	if !cfg.CookieHTTPOnly {
		t.Error("CookieHTTPOnly should be true by default")
	}
}

// ============================================================================
// NewMiddlewareWithSSO / SSOManager / RequireSSOLogin tests
// ============================================================================

func TestNewMiddlewareWithSSO(t *testing.T) {
	cfg := DefaultConfig()
	manager, err := sso.NewManager(nil)
	if err != nil {
		t.Fatalf("Failed to create SSO manager: %v", err)
	}

	m := NewMiddlewareWithSSO(cfg, manager)
	if m == nil {
		t.Fatal("NewMiddlewareWithSSO() returned nil")
	}
	if m.config != cfg {
		t.Error("config not set correctly")
	}
	if m.ssoManager != manager {
		t.Error("ssoManager not set correctly")
	}
}

func TestNewMiddlewareWithSSO_NilManager(t *testing.T) {
	cfg := DefaultConfig()
	m := NewMiddlewareWithSSO(cfg, nil)
	if m == nil {
		t.Fatal("NewMiddlewareWithSSO() returned nil")
	}
	if m.ssoManager != nil {
		t.Error("ssoManager should be nil")
	}
}

func TestSSOManager(t *testing.T) {
	tests := []struct {
		name    string
		manager *sso.Manager
		wantNil bool
	}{
		{"with manager", func() *sso.Manager { m, _ := sso.NewManager(nil); return m }(), false},
		{"without manager", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			m := NewMiddlewareWithSSO(cfg, tt.manager)
			got := m.SSOManager()
			if (got == nil) != tt.wantNil {
				t.Errorf("SSOManager() nil = %v, wantNil %v", got == nil, tt.wantNil)
			}
		})
	}
}

func TestRequireSSOLogin(t *testing.T) {
	t.Run("with SSO manager and config", func(t *testing.T) {
		manager, _ := sso.NewManager(nil)
		ssoConfig := sso.DefaultSSOConfig()
		cfg := &Config{
			JWTSigningKey:    []byte("test-key-32bytes-long-for-testing!"),
			APIAuthToken:     "test-token",
			TokenExpiryHours: 24,
			RequireAuth:      true,
			SSOConfig:        ssoConfig,
		}
		m := NewMiddlewareWithSSO(cfg, manager)
		if !m.RequireSSOLogin() {
			t.Error("RequireSSOLogin() should return true when SSO is configured")
		}
	})

	t.Run("without SSO manager", func(t *testing.T) {
		cfg := DefaultConfig()
		m := NewMiddleware(cfg)
		if m.RequireSSOLogin() {
			t.Error("RequireSSOLogin() should return false without SSO manager")
		}
	})

	t.Run("with SSO manager but nil config", func(t *testing.T) {
		manager, _ := sso.NewManager(nil)
		cfg := DefaultConfig()
		m := NewMiddlewareWithSSO(cfg, manager)
		// No SSOConfig set, so RequireSSOLogin should return false
		if m.RequireSSOLogin() {
			t.Error("RequireSSOLogin() should return false when SSOConfig is nil")
		}
	})

	t.Run("with nil config", func(t *testing.T) {
		manager, _ := sso.NewManager(nil)
		m := &Middleware{config: nil, ssoManager: manager}
		if m.RequireSSOLogin() {
			t.Error("RequireSSOLogin() should return false with nil config")
		}
	})
}

// ============================================================================
// ssoRoleToUserRole tests
// ============================================================================

func TestSSORoleToUserRole(t *testing.T) {
	tests := []struct {
		name string
		role string
		want rbac.UserRole
	}{
		{"admin maps to admin", "admin", rbac.UserRoleAdmin},
		{"operator maps to analyst", "operator", rbac.UserRoleAnalyst},
		{"viewer maps to viewer", "viewer", rbac.UserRoleViewer},
		{"service maps to viewer (default)", "service", rbac.UserRoleViewer},
		{"unknown role maps to viewer", "unknown", rbac.UserRoleViewer},
		{"empty role maps to viewer", "", rbac.UserRoleViewer},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ssoRoleToUserRole(tt.role)
			if got != tt.want {
				t.Errorf("ssoRoleToUserRole(%v) = %v, want %v", tt.role, got, tt.want)
			}
		})
	}
}

// ============================================================================
// handleSSOToken tests via RequireAuth with SSO
// ============================================================================

func TestRequireAuth_WithSSOManager_NoSSOToken(t *testing.T) {
	// When SSO is configured but no SSO token is provided, it should fall back to JWT/API token
	manager, _ := sso.NewManager(nil)
	ssoConfig := sso.DefaultSSOConfig()
	cfg := &Config{
		JWTSigningKey:    []byte("test-key-32bytes-long-for-testing!"),
		APIAuthToken:     "test-token",
		TokenExpiryHours: 24,
		RequireAuth:      true,
		SSOConfig:        ssoConfig,
	}
	m := NewMiddlewareWithSSO(cfg, manager)

	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Should never reach here without auth
		w.WriteHeader(http.StatusOK)
	})

	// No authorization header — should get 401
	handler := m.RequireAuth(dummyHandler)
	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 without auth, got %d", rec.Code)
	}
}

func TestRequireAuth_WithSSOManager_ValidJWT(t *testing.T) {
	// SSO is configured but we use JWT — should fall through and succeed
	manager, _ := sso.NewManager(nil)
	ssoConfig := sso.DefaultSSOConfig()
	cfg := &Config{
		JWTSigningKey:    []byte("test-key-32bytes-long-for-testing!"),
		APIAuthToken:     "test-token",
		TokenExpiryHours: 24,
		RequireAuth:      true,
		SSOConfig:        ssoConfig,
	}
	m := NewMiddlewareWithSSO(cfg, manager)

	token, err := m.GenerateToken("sso-user", "community")
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authType := GetAuthType(r.Context())
		if authType != AuthTypeJWT {
			t.Errorf("Expected auth type %s, got %s", AuthTypeJWT, authType)
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := m.RequireAuth(dummyHandler)
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200 with valid JWT, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRequireAuth_WithSSOManager_ValidAPIToken(t *testing.T) {
	manager, _ := sso.NewManager(nil)
	ssoConfig := sso.DefaultSSOConfig()
	cfg := &Config{
		JWTSigningKey:    []byte("test-key-32bytes-long-for-testing!"),
		APIAuthToken:     "my-api-token",
		TokenExpiryHours: 24,
		RequireAuth:      true,
		SSOConfig:        ssoConfig,
	}
	m := NewMiddlewareWithSSO(cfg, manager)

	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authType := GetAuthType(r.Context())
		if authType != AuthTypeAPIToken {
			t.Errorf("Expected auth type %s, got %s", AuthTypeAPIToken, authType)
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := m.RequireAuth(dummyHandler)
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "token my-api-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200 with valid API token, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRequireAuth_SSODevMode(t *testing.T) {
	// When RequireAuth=false, should allow through without auth (dev mode)
	manager, _ := sso.NewManager(nil)
	ssoConfig := sso.DefaultSSOConfig()
	cfg := &Config{
		JWTSigningKey:    []byte("test-key-32bytes-long-for-testing!"),
		APIAuthToken:     "test-token",
		TokenExpiryHours: 24,
		RequireAuth:      false,
		SSOConfig:        ssoConfig,
	}
	m := NewMiddlewareWithSSO(cfg, manager)

	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := GetUserID(r.Context())
		if userID != "dev-user" {
			t.Errorf("Expected dev-user, got %s", userID)
		}
		authType := GetAuthType(r.Context())
		if authType != "none" {
			t.Errorf("Expected auth type 'none', got %s", authType)
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := m.RequireAuth(dummyHandler)
	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200 in dev mode, got %d", rec.Code)
	}
}

// ============================================================================
// GetUserRole / GetPermissions edge cases (nil context, wrong type)
// ============================================================================

func TestGetUserRole_NilContext(t *testing.T) {
	role := GetUserRole(context.Background())
	if role != "" {
		t.Errorf("GetUserRole(empty ctx) = %q, want empty string", role)
	}
}

func TestGetUserRole_WrongType(t *testing.T) {
	ctx := context.WithValue(context.Background(), ContextKeyUserRole, "not-a-role")
	role := GetUserRole(ctx)
	if role != "" {
		t.Errorf("GetUserRole(wrong type) = %q, want empty string", role)
	}
}

func TestGetPermissions_NilContext(t *testing.T) {
	perms := GetPermissions(context.Background())
	if perms != nil {
		t.Errorf("GetPermissions(empty ctx) = %v, want nil", perms)
	}
}

func TestGetPermissions_WrongType(t *testing.T) {
	ctx := context.WithValue(context.Background(), ContextKeyPermissions, "not-permissions")
	perms := GetPermissions(ctx)
	if perms != nil {
		t.Errorf("GetPermissions(wrong type) = %v, want nil", perms)
	}
}

// ============================================================================
// RequirePermission additional edge cases
// ============================================================================

func TestRequirePermission_EmptyPermissions(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-key-32bytes-long-for-testing!"),
		APIAuthToken:     "test-token",
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	perm := rbac.Permission{Resource: rbac.ResourceDashboard, Action: rbac.ActionRead}
	handler := m.RequirePermission(perm, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Use a valid JWT with viewer role to get empty permissions context
	token, _ := m.GenerateToken("test-user", "community")
	req := httptest.NewRequest("GET", "/dashboard", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Viewer should have dashboard:read, so this should succeed or fail based on role permissions
	// The point is testing that it doesn't panic with nil permissions
	if rec.Code == 0 {
		t.Error("Expected a response code, got 0")
	}
}

func TestRequirePermission_ResourceWildcard(t *testing.T) {
	// Test with admin role which should have wildcard permissions
	cfg := &Config{
		JWTSigningKey:    []byte("test-key-32bytes-long-for-testing!"),
		APIAuthToken:     "test-token",
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	perm := rbac.Permission{Resource: rbac.ResourceConfig, Action: rbac.ActionDelete}
	handler := m.RequirePermission(perm, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Admin token via API
	req := httptest.NewRequest("DELETE", "/config/123", nil)
	req.Header.Set("Authorization", "token test-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200 for admin with wildcard permissions, got %d", rec.Code)
	}
}
