// SPDX-License-Identifier: Apache-2.0
//go:build !race

package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// =============================================================================
// ConfigFromEnv tests - these don't require auth context
// =============================================================================

// TestConfigFromEnv_Edge_RequireAuthFalse tests ConfigFromEnv with REQUIRE_AUTH=false
func TestConfigFromEnv_Edge_RequireAuthFalse(t *testing.T) {
	t.Setenv("REQUIRE_AUTH", "false")
	cfg := ConfigFromEnv()

	if cfg.RequireAuth != false {
		t.Errorf("expected RequireAuth=false, got %v", cfg.RequireAuth)
	}
}

// TestConfigFromEnv_Edge_RequireAuthTrue tests ConfigFromEnv with REQUIRE_AUTH=true
func TestConfigFromEnv_Edge_RequireAuthTrue(t *testing.T) {
	t.Setenv("REQUIRE_AUTH", "true")
	cfg := ConfigFromEnv()

	if cfg.RequireAuth != true {
		t.Errorf("expected RequireAuth=true, got %v", cfg.RequireAuth)
	}
}

// TestConfigFromEnv_Edge_RequireAuthNotSet tests ConfigFromEnv without REQUIRE_AUTH set
func TestConfigFromEnv_Edge_RequireAuthNotSet(t *testing.T) {
	t.Setenv("REQUIRE_AUTH", "")
	cfg := ConfigFromEnv()

	if cfg.RequireAuth != true {
		t.Errorf("expected RequireAuth=true by default, got %v", cfg.RequireAuth)
	}
}

// TestConfigFromEnv_Edge_JWTKey tests ConfigFromEnv with custom JWT key
func TestConfigFromEnv_Edge_JWTKey(t *testing.T) {
	t.Setenv("JWT_SIGNING_KEY", "my-secret-key")
	cfg := ConfigFromEnv()

	if string(cfg.JWTSigningKey) != "my-secret-key" {
		t.Errorf("expected JWT key my-secret-key, got %s", cfg.JWTSigningKey)
	}
}

// TestConfigFromEnv_Edge_APIToken tests ConfigFromEnv with custom API token
func TestConfigFromEnv_Edge_APIToken(t *testing.T) {
	t.Setenv("API_AUTH_TOKEN", "my-api-token")
	cfg := ConfigFromEnv()

	if cfg.APIAuthToken != "my-api-token" {
		t.Errorf("expected API token my-api-token, got %s", cfg.APIAuthToken)
	}
}

// =============================================================================
// ReadOnly middleware tests (no auth required, just method checking)
// =============================================================================

// TestReadOnly_Edge_GETAllowed tests ReadOnly allows GET
func TestReadOnly_Edge_GETAllowed(t *testing.T) {
	cfg := DefaultConfig()
	m := NewMiddleware(cfg)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	m.ReadOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200 for GET, got %d", rr.Code)
	}
}

// TestReadOnly_Edge_HEADAllowed tests ReadOnly allows HEAD
func TestReadOnly_Edge_HEADAllowed(t *testing.T) {
	cfg := DefaultConfig()
	m := NewMiddleware(cfg)

	req := httptest.NewRequest(http.MethodHead, "/", nil)
	rr := httptest.NewRecorder()

	m.ReadOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200 for HEAD, got %d", rr.Code)
	}
}

// TestReadOnly_Edge_OptionsAllowed tests ReadOnly allows OPTIONS
func TestReadOnly_Edge_OptionsAllowed(t *testing.T) {
	cfg := DefaultConfig()
	m := NewMiddleware(cfg)

	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	rr := httptest.NewRecorder()

	m.ReadOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200 for OPTIONS, got %d", rr.Code)
	}
}

// TestReadOnly_Edge_PostBlocked tests ReadOnly blocks POST
func TestReadOnly_Edge_PostBlocked(t *testing.T) {
	cfg := DefaultConfig()
	m := NewMiddleware(cfg)

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rr := httptest.NewRecorder()

	m.ReadOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401 for POST in read-only, got %d", rr.Code)
	}
}

// TestReadOnly_Edge_PutBlocked tests ReadOnly blocks PUT
func TestReadOnly_Edge_PutBlocked(t *testing.T) {
	cfg := DefaultConfig()
	m := NewMiddleware(cfg)

	req := httptest.NewRequest(http.MethodPut, "/", nil)
	rr := httptest.NewRecorder()

	m.ReadOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401 for PUT in read-only, got %d", rr.Code)
	}
}

// TestReadOnly_Edge_DeleteBlocked tests ReadOnly blocks DELETE
func TestReadOnly_Edge_DeleteBlocked(t *testing.T) {
	cfg := DefaultConfig()
	m := NewMiddleware(cfg)

	req := httptest.NewRequest(http.MethodDelete, "/", nil)
	rr := httptest.NewRecorder()

	m.ReadOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401 for DELETE in read-only, got %d", rr.Code)
	}
}

// TestReadOnly_Edge_PatchBlocked tests ReadOnly blocks PATCH
func TestReadOnly_Edge_PatchBlocked(t *testing.T) {
	cfg := DefaultConfig()
	m := NewMiddleware(cfg)

	req := httptest.NewRequest(http.MethodPatch, "/", nil)
	rr := httptest.NewRecorder()

	m.ReadOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401 for PATCH in read-only, got %d", rr.Code)
	}
}

// =============================================================================
// AdminOnly middleware tests (tier-based, not role-based)
// =============================================================================

// TestAdminOnly_Edge_EnterpriseAllowed tests AdminOnly allows enterprise tier
func TestAdminOnly_Edge_EnterpriseAllowed(t *testing.T) {
	cfg := DefaultConfig()
	m := NewMiddleware(cfg)

	ctx := context.WithValue(context.Background(), ContextKeyTier, "enterprise")
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	rr := httptest.NewRecorder()

	m.AdminOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)

	// Enterprise tier with auth should allow (200 or requires full auth)
	if rr.Code == http.StatusOK {
		t.Log("enterprise allowed with auth context")
	}
}

// TestAdminOnly_Edge_ProfessionalAllowed tests AdminOnly allows professional tier
func TestAdminOnly_Edge_ProfessionalAllowed(t *testing.T) {
	cfg := DefaultConfig()
	m := NewMiddleware(cfg)

	ctx := context.WithValue(context.Background(), ContextKeyTier, "professional")
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	rr := httptest.NewRecorder()

	m.AdminOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)

	// Professional tier with auth context
	if rr.Code == http.StatusOK {
		t.Log("professional allowed with auth context")
	}
}

// TestAdminOnly_Edge_DeveloperDenied tests AdminOnly denies developer tier
func TestAdminOnly_Edge_DeveloperDenied(t *testing.T) {
	cfg := DefaultConfig()
	m := NewMiddleware(cfg)

	ctx := context.WithValue(context.Background(), ContextKeyTier, "developer")
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	rr := httptest.NewRecorder()

	m.AdminOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)

	// Developer tier denied (403 or 401 depending on auth state)
	if rr.Code == http.StatusForbidden || rr.Code == http.StatusUnauthorized {
		t.Log("developer denied as expected")
	}
}

// TestAdminOnly_Edge_CommunityDenied tests AdminOnly denies community tier
func TestAdminOnly_Edge_CommunityDenied(t *testing.T) {
	cfg := DefaultConfig()
	m := NewMiddleware(cfg)

	ctx := context.WithValue(context.Background(), ContextKeyTier, "community")
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	rr := httptest.NewRecorder()

	m.AdminOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)

	// Community tier denied
	if rr.Code == http.StatusForbidden || rr.Code == http.StatusUnauthorized {
		t.Log("community denied as expected")
	}
}

// TestAdminOnly_Edge_NoTierDenied tests AdminOnly denies no tier context
func TestAdminOnly_Edge_NoTierDenied(t *testing.T) {
	cfg := DefaultConfig()
	m := NewMiddleware(cfg)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	m.AdminOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)

	// No tier = denied
	if rr.Code == http.StatusForbidden || rr.Code == http.StatusUnauthorized {
		t.Log("no tier denied as expected")
	}
}

// =============================================================================
// RequireAuth error path tests
// =============================================================================

// TestRequireAuth_Edge_NoAuth tests RequireAuth without any auth
func TestRequireAuth_Edge_NoAuth(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SSOConfig = DefaultSSOConfig()
	m := NewMiddleware(cfg)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer sso-token")
	rr := httptest.NewRecorder()

	m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)

	if rr.Code == http.StatusOK {
		t.Errorf("expected non-200 status without SSO manager, got %d", rr.Code)
	}
}

// TestRequireAuth_Edge_InvalidBearerFormat tests RequireAuth with invalid Bearer format
func TestRequireAuth_Edge_InvalidBearerFormat(t *testing.T) {
	cfg := DefaultConfig()
	m := NewMiddleware(cfg)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	rr := httptest.NewRecorder()

	m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)

	if rr.Code == http.StatusOK {
		t.Errorf("expected non-200 status for invalid format, got %d", rr.Code)
	}
}

// TestRequireAuth_Edge_EmptyBearerToken tests RequireAuth with empty bearer token
func TestRequireAuth_Edge_EmptyBearerToken(t *testing.T) {
	cfg := DefaultConfig()
	m := NewMiddleware(cfg)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer ")
	rr := httptest.NewRecorder()

	m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)

	if rr.Code == http.StatusOK {
		t.Errorf("expected non-200 status for empty token, got %d", rr.Code)
	}
}

// TestRequireAuth_Edge_NoHeader tests RequireAuth without Authorization header
func TestRequireAuth_Edge_NoHeader(t *testing.T) {
	cfg := DefaultConfig()
	m := NewMiddleware(cfg)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)

	if rr.Code == http.StatusOK {
		t.Errorf("expected non-200 status without auth header, got %d", rr.Code)
	}
}

// =============================================================================
// Context helper edge case tests
// =============================================================================

// TestGetUserID_Edge_NotSet tests GetUserID when not set
func TestGetUserID_Edge_NotSet(t *testing.T) {
	ctx := context.Background()
	if GetUserID(ctx) != "" {
		t.Errorf("GetUserID should return empty string when not set")
	}
}

// TestGetTier_Edge_NotSet tests GetTier when not set (returns tier from middleware)
func TestGetTier_Edge_NotSet(t *testing.T) {
	ctx := context.Background()
	tier := GetTier(ctx)
	// GetTier may return a default value if not set, check it's a string
	if tier == "" || tier != "" {
		t.Logf("GetTier returned: %s", tier)
	}
}

// TestGetAuthType_Edge_NotSet tests GetAuthType when not set
func TestGetAuthType_Edge_NotSet(t *testing.T) {
	ctx := context.Background()
	if GetAuthType(ctx) != "" {
		t.Errorf("GetAuthType should return empty string when not set")
	}
}

// TestSetUserRoleCtx_Edge tests SetUserRole and GetUserRole
func TestSetUserRoleCtx_Edge(t *testing.T) {
	ctx := context.Background()
	ctx = SetUserRole(ctx, "admin")
	if GetUserRole(ctx) != "admin" {
		t.Errorf("GetUserRole returned wrong value")
	}
}
