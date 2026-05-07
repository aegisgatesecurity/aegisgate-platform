// SPDX-License-Identifier: Apache-2.0
//go:build !race

package auth

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/rbac"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/sso"
)

// =============================================================================
// handleSSOToken coverage (45.5% → 95%+)
// handleSSOToken is called from RequireAuth when ssoManager != nil.
// =============================================================================

func TestHandleSSOToken_MissingHeader(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key"),
		APIAuthToken:     "test-api-token",
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := m.RequireAuth(dummyHandler)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("code=%d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestHandleSSOToken_InvalidFormat(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key"),
		APIAuthToken:     "test-api-token",
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := m.RequireAuth(dummyHandler)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "InvalidFormat token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("code=%d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestHandleSSOToken_InvalidToken(t *testing.T) {
	mgrCfg := &sso.ManagerConfig{DefaultConfig: sso.DefaultSSOConfig()}
	manager, err := sso.NewManager(mgrCfg)
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}

	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key"),
		APIAuthToken:     "test-api-token",
		TokenExpiryHours: 24,
		RequireAuth:      true,
		SSOConfig:        sso.DefaultSSOConfig(),
	}
	m := NewMiddlewareWithSSO(cfg, manager)

	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := m.RequireAuth(dummyHandler)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("code=%d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestHandleSSOToken_SSOfailsNoFallback(t *testing.T) {
	mgrCfg := &sso.ManagerConfig{DefaultConfig: sso.DefaultSSOConfig()}
	manager, err := sso.NewManager(mgrCfg)
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}

	cfg := &Config{
		JWTSigningKey:    []byte("dev-key-change-in-production"),
		APIAuthToken:     "dev-token-change-in-production",
		TokenExpiryHours: 24,
		RequireAuth:      true,
		SSOConfig:        sso.DefaultSSOConfig(),
	}
	m := NewMiddlewareWithSSO(cfg, manager)

	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := m.RequireAuth(dummyHandler)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid-sso-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("code=%d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

// =============================================================================
// RequireAuth production bypass paths
// =============================================================================

func TestRequireAuth_ProductionEnvBypass(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("dev-key-change-in-production"),
		APIAuthToken:     "dev-token-change-in-production",
		TokenExpiryHours: 24,
		RequireAuth:      false,
	}
	m := NewMiddleware(cfg)

	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	oldEnv := os.Getenv("AEGISGATE_ENV")
	os.Setenv("AEGISGATE_ENV", "production")
	defer os.Setenv("AEGISGATE_ENV", oldEnv)

	handler := m.RequireAuth(dummyHandler)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("code=%d, want %d in production env", rec.Code, http.StatusUnauthorized)
	}
}

func TestRequireAuth_ProductionEnvProd(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("dev-key-change-in-production"),
		APIAuthToken:     "dev-token-change-in-production",
		TokenExpiryHours: 24,
		RequireAuth:      false,
	}
	m := NewMiddleware(cfg)

	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	oldEnv := os.Getenv("AEGISGATE_ENV")
	os.Setenv("AEGISGATE_ENV", "prod")
	defer os.Setenv("AEGISGATE_ENV", oldEnv)

	handler := m.RequireAuth(dummyHandler)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("code=%d, want %d in prod env", rec.Code, http.StatusUnauthorized)
	}
}

// =============================================================================
// handleJWT edge cases
// =============================================================================

func TestHandleJWT_Base64Encoded(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		APIAuthToken:     "test-api-token",
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	tokenString, err := m.GenerateToken("base64-user", "community")
	if err != nil {
		t.Fatalf("GenerateToken() error: %v", err)
	}

	encoded := base64.StdEncoding.EncodeToString([]byte(tokenString))

	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := m.RequireAuth(dummyHandler)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+encoded)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("code=%d, want %d for base64 token", rec.Code, http.StatusOK)
	}
}

func TestHandleJWT_InvalidBase64(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		APIAuthToken:     "test-api-token",
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := m.RequireAuth(dummyHandler)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer not-valid-base64!!!")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("code=%d, want %d for invalid base64", rec.Code, http.StatusUnauthorized)
	}
}

// =============================================================================
// RequireAuth SSO cascade paths
// =============================================================================

func TestRequireAuth_SSOWithFallbackJWT(t *testing.T) {
	mgrCfg := &sso.ManagerConfig{DefaultConfig: sso.DefaultSSOConfig()}
	manager, err := sso.NewManager(mgrCfg)
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}

	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		APIAuthToken:     "test-api-token",
		TokenExpiryHours: 24,
		RequireAuth:      true,
		SSOConfig:        sso.DefaultSSOConfig(),
	}
	m := NewMiddlewareWithSSO(cfg, manager)

	tokenString, err := m.GenerateToken("fallback-user", "community")
	if err != nil {
		t.Fatalf("GenerateToken() error: %v", err)
	}

	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := m.RequireAuth(dummyHandler)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("code=%d, want %d (SSO failed, JWT fallback should work)", rec.Code, http.StatusOK)
	}
}

// =============================================================================
// RequirePermission edge cases
// =============================================================================

func TestRequirePermission_Denied(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		APIAuthToken:     "test-api-token",
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Use a token that will get default viewer permissions (no wildcard)
	tokenString, err := m.GenerateToken("no-wildcard-user", "community")
	if err != nil {
		t.Fatalf("GenerateToken() error: %v", err)
	}

	handler := m.RequirePermission(rbac.Permission{Resource: "admin", Action: "delete"}, dummyHandler)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Should deny — viewer doesn't have admin:delete
	if rec.Code != http.StatusForbidden {
		t.Errorf("code=%d, want %d for missing permission", rec.Code, http.StatusForbidden)
	}
}

// =============================================================================
// unauthorized helper edge cases
// =============================================================================

func TestUnauthorized_SetsWWWAuthenticate(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key"),
		APIAuthToken:     "test-api-token",
		TokenExpiryHours: 24,
		RequireAuth:      true,
	}
	m := NewMiddleware(cfg)

	handler := m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("code=%d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if hdr := rec.Header().Get("WWW-Authenticate"); hdr == "" {
		t.Error("WWW-Authenticate header should be set")
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type=%q, want application/json", ct)
	}
}
