//go:build !race

// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform — handleSSOToken coverage tests
// Tests the SSO token authentication path in RequireAuth middleware
// =========================================================================

package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/rbac"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/sso"
)

// Mock SSOSessionStore for creating test sessions
type mockSessionStore struct {
	sessions map[string]*sso.SSOSession
}

func newMockStore() *mockSessionStore {
	return &mockSessionStore{sessions: make(map[string]*sso.SSOSession)}
}

func (s *mockSessionStore) Create(session *sso.SSOSession) error {
	s.sessions[session.ID] = session
	return nil
}

func (s *mockSessionStore) Get(id string) (*sso.SSOSession, error) {
	if session, ok := s.sessions[id]; ok {
		return session, nil
	}
	return nil, sso.NewSSOError(sso.ErrSessionExpired, "session not found")
}

func (s *mockSessionStore) Update(session *sso.SSOSession) error {
	s.sessions[session.ID] = session
	return nil
}

func (s *mockSessionStore) Delete(id string) error {
	delete(s.sessions, id)
	return nil
}

func (s *mockSessionStore) GetByUserID(userID string) ([]*sso.SSOSession, error) {
	return nil, nil
}

func (s *mockSessionStore) DeleteByUserID(userID string) error {
	return nil
}

func (s *mockSessionStore) Cleanup() error {
	return nil
}

// =========================================================================
// Tests: handleSSOToken error paths (expects 401)
// These use dev keys which trigger SSO-only fail-closed behavior
// =========================================================================

// TestSSOTokenHandle_MissingHeader: no auth header → handleSSOToken gets ""
func TestSSOTokenHandle_MissingHeader(t *testing.T) {
	store := newMockStore()
	manager, _ := sso.NewManager(&sso.ManagerConfig{SessionStore: store})
	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		TokenExpiryHours: 24,
		APIAuthToken:     "test-api-token",
		RequireAuth:      true,
		SSOConfig:        sso.DefaultSSOConfig(),
	}
	m := NewMiddlewareWithSSO(cfg, manager)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler := m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 without auth header, got %d", rec.Code)
	}
}

// TestSSOTokenHandle_InvalidFormat: Basic auth (not Bearer)
func TestSSOTokenHandle_InvalidFormat(t *testing.T) {
	store := newMockStore()
	manager, _ := sso.NewManager(&sso.ManagerConfig{SessionStore: store})
	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		TokenExpiryHours: 24,
		APIAuthToken:     "test-api-token",
		RequireAuth:      true,
		SSOConfig:        sso.DefaultSSOConfig(),
	}
	m := NewMiddlewareWithSSO(cfg, manager)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	rec := httptest.NewRecorder()

	handler := m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 with non-Bearer auth, got %d", rec.Code)
	}
}

// TestSSOTokenHandle_InvalidToken: Session not found
func TestSSOTokenHandle_InvalidToken(t *testing.T) {
	store := newMockStore()
	manager, _ := sso.NewManager(&sso.ManagerConfig{SessionStore: store})
	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		TokenExpiryHours: 24,
		APIAuthToken:     "test-api-token",
		RequireAuth:      true,
		SSOConfig:        sso.DefaultSSOConfig(),
	}
	m := NewMiddlewareWithSSO(cfg, manager)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer nonexistent-session")
	rec := httptest.NewRecorder()

	handler := m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 when session not found, got %d", rec.Code)
	}
}

// TestSSOTokenHandle_SSOfailsNoFallback: SSO-only mode (no JWT fallback)
func TestSSOTokenHandle_SSOfailsNoFallback(t *testing.T) {
	store := newMockStore()
	manager, _ := sso.NewManager(&sso.ManagerConfig{SessionStore: store})

	cfg := &Config{
		JWTSigningKey: nil, // No JWT fallback
		APIAuthToken:  "",
		RequireAuth:   true,
		SSOConfig:     sso.DefaultSSOConfig(),
	}
	m := NewMiddlewareWithSSO(cfg, manager)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer some-token")
	rec := httptest.NewRecorder()

	handler := m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 in SSO-only mode, got %d", rec.Code)
	}
}

// =========================================================================
// Tests: expired/inactive session → ValidateSession errors
// =========================================================================

// TestSSOTokenHandle_ExpiredSession: ValidateSession returns error
func TestSSOTokenHandle_ExpiredSession(t *testing.T) {
	store := newMockStore()

	expiredSession := &sso.SSOSession{
		ID:        "expired-session",
		User:      &sso.SSOUser{ID: "user-1", Email: "test@example.com", Role: "admin"},
		Active:    true,
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}
	store.Create(expiredSession)

	manager, _ := sso.NewManager(&sso.ManagerConfig{SessionStore: store})
	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		TokenExpiryHours: 24,
		APIAuthToken:     "test-api-token",
		RequireAuth:      true,
		SSOConfig:        sso.DefaultSSOConfig(),
	}
	m := NewMiddlewareWithSSO(cfg, manager)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer expired-session")
	rec := httptest.NewRecorder()

	handler := m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 when session expired, got %d", rec.Code)
	}
}

// TestSSOTokenHandle_InactiveSession: session.Active = false
func TestSSOTokenHandle_InactiveSession(t *testing.T) {
	store := newMockStore()

	inactiveSession := &sso.SSOSession{
		ID:        "inactive-session",
		User:      &sso.SSOUser{ID: "user-1", Email: "test@example.com", Role: "admin"},
		Active:    false,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	store.Create(inactiveSession)

	manager, _ := sso.NewManager(&sso.ManagerConfig{SessionStore: store})
	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		TokenExpiryHours: 24,
		APIAuthToken:     "test-api-token",
		RequireAuth:      true,
		SSOConfig:        sso.DefaultSSOConfig(),
	}
	m := NewMiddlewareWithSSO(cfg, manager)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer inactive-session")
	rec := httptest.NewRecorder()

	handler := m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 when session inactive, got %d", rec.Code)
	}
}

// TestSSOTokenHandle_NilUser: session has nil user
func TestSSOTokenHandle_NilUser(t *testing.T) {
	store := newMockStore()

	nilUserSession := &sso.SSOSession{
		ID:        "nil-user-session",
		User:      nil,
		Active:    true,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	store.Create(nilUserSession)

	manager, _ := sso.NewManager(&sso.ManagerConfig{SessionStore: store})
	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		TokenExpiryHours: 24,
		APIAuthToken:     "test-api-token",
		RequireAuth:      true,
		SSOConfig:        sso.DefaultSSOConfig(),
	}
	m := NewMiddlewareWithSSO(cfg, manager)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer nil-user-session")
	rec := httptest.NewRecorder()

	handler := m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 when session has nil user, got %d", rec.Code)
	}
}

// =========================================================================
// Tests: JWT error paths (expects 401)
// =========================================================================

// TestSSOTokenHandle_JWTInvalid: invalid JWT token
func TestSSOTokenHandle_JWTInvalid(t *testing.T) {
	store := newMockStore()
	manager, _ := sso.NewManager(&sso.ManagerConfig{SessionStore: store})
	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		TokenExpiryHours: 24,
		APIAuthToken:     "test-api-token",
		RequireAuth:      true,
		SSOConfig:        nil, // Skip SSO path
	}
	m := NewMiddlewareWithSSO(cfg, manager)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid-jwt-token")
	rec := httptest.NewRecorder()

	handler := m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 with invalid JWT, got %d", rec.Code)
	}
}

// TestSSOTokenHandle_JWTEmpty: empty bearer token
func TestSSOTokenHandle_JWTEmpty(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		TokenExpiryHours: 24,
		APIAuthToken:     "test-api-token",
		RequireAuth:      true,
		SSOConfig:        nil,
	}
	m := NewMiddleware(cfg)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer ")
	rec := httptest.NewRecorder()

	handler := m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 with empty JWT, got %d", rec.Code)
	}
}

// TestSSOTokenHandle_JWTExpired: expired JWT token
func TestSSOTokenHandle_JWTExpired(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		APIAuthToken:     "test-api-token",
		TokenExpiryHours: 0, // Already expired
		RequireAuth:      true,
		SSOConfig:        nil,
	}
	m := NewMiddleware(cfg)

	token, _ := m.GenerateToken("test-user", "admin")

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler := m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 with expired JWT, got %d", rec.Code)
	}
}

// =========================================================================
// Tests: API token error paths
// =========================================================================

// TestSSOTokenHandle_APITokenInvalid: invalid API token
func TestSSOTokenHandle_APITokenInvalid(t *testing.T) {
	cfg := &Config{
		JWTSigningKey: nil,
		APIAuthToken:  "correct-api-token",
		RequireAuth:   true,
		SSOConfig:     nil,
	}
	m := NewMiddleware(cfg)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Token wrong-token")
	rec := httptest.NewRecorder()

	handler := m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 with invalid API token, got %d", rec.Code)
	}
}

// =========================================================================
// Tests: role mapping via JWT (these test ssoRoleToUserRole coverage)
// =========================================================================

// TestSSOTokenHandle_AdminRole: admin role maps correctly
func TestSSOTokenHandle_AdminRole(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		TokenExpiryHours: 24,
		APIAuthToken:     "test-api-token",
		RequireAuth:      true,
		SSOConfig:        nil,
	}
	m := NewMiddleware(cfg)

	token, _ := m.GenerateToken("admin-user", "admin")

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler := m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		role := GetUserRole(r.Context())
		if role != rbac.UserRoleAdmin {
			t.Errorf("Expected %s, got %s", rbac.UserRoleAdmin, role)
		}
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", rec.Code)
	}
}

// TestSSOTokenHandle_AnalystRole: operator role maps to analyst
func TestSSOTokenHandle_AnalystRole(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		TokenExpiryHours: 24,
		APIAuthToken:     "test-api-token",
		RequireAuth:      true,
		SSOConfig:        nil,
	}
	m := NewMiddleware(cfg)

	token, _ := m.GenerateToken("analyst-user", "analyst")

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler := m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		role := GetUserRole(r.Context())
		if role != rbac.UserRoleAnalyst {
			t.Errorf("Expected %s (operator→analyst), got %s", rbac.UserRoleAnalyst, role)
		}
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", rec.Code)
	}
}

// TestSSOTokenHandle_ViewerRole: viewer role maps correctly
func TestSSOTokenHandle_ViewerRole(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		TokenExpiryHours: 24,
		APIAuthToken:     "test-api-token",
		RequireAuth:      true,
		SSOConfig:        nil,
	}
	m := NewMiddleware(cfg)

	token, _ := m.GenerateToken("viewer-user", "viewer")

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler := m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		role := GetUserRole(r.Context())
		if role != rbac.UserRoleViewer {
			t.Errorf("Expected %s, got %s", rbac.UserRoleViewer, role)
		}
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", rec.Code)
	}
}

// TestSSOTokenHandle_ComplianceOfficerRole
func TestSSOTokenHandle_ComplianceOfficerRole(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		TokenExpiryHours: 24,
		APIAuthToken:     "test-api-token",
		RequireAuth:      true,
		SSOConfig:        nil,
	}
	m := NewMiddleware(cfg)

	token, _ := m.GenerateToken("compliance-user", "compliance_officer")

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler := m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		role := GetUserRole(r.Context())
		if role != rbac.UserRoleComplianceOfficer {
			t.Errorf("Expected %s, got %s", rbac.UserRoleComplianceOfficer, role)
		}
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", rec.Code)
	}
}

// =========================================================================
// Tests: permissions are set based on role
// =========================================================================

// TestSSOTokenHandle_PermissionsByRole
func TestSSOTokenHandle_PermissionsByRole(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		APIAuthToken:     "test-api-token",
		TokenExpiryHours: 24,
		RequireAuth:      true,
		SSOConfig:        nil,
	}
	m := NewMiddleware(cfg)

	token, _ := m.GenerateToken("admin-perms", "admin")

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler := m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		perms := GetPermissions(r.Context())
		// Admin should have permissions
		if len(perms) == 0 {
			t.Error("Expected admin to have permissions")
		}
		// Check for wildcard permission (admin has Resource="*" Action="*")
		hasWildcard := false
		for _, p := range perms {
			if p.Resource == "*" && p.Action == "*" {
				hasWildcard = true
				break
			}
		}
		if !hasWildcard {
			t.Error("Expected admin to have wildcard permission")
		}
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", rec.Code)
	}
}

// =========================================================================
// Tests: lowercase bearer scheme
// =========================================================================

// TestSSOTokenHandle_LowercaseBearer
func TestSSOTokenHandle_LowercaseBearer(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		TokenExpiryHours: 24,
		APIAuthToken:     "test-api-token",
		RequireAuth:      true,
		SSOConfig:        nil,
	}
	m := NewMiddleware(cfg)

	token, _ := m.GenerateToken("test-user", "admin")

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "bearer "+token) // lowercase
	rec := httptest.NewRecorder()

	handler := m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200 with lowercase bearer, got %d", rec.Code)
	}
}

// =========================================================================
// Tests: auth type is set correctly
// =========================================================================

// TestSSOTokenHandle_AuthTypeJWT
func TestSSOTokenHandle_AuthTypeJWT(t *testing.T) {
	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		TokenExpiryHours: 24,
		APIAuthToken:     "test-api-token",
		RequireAuth:      true,
		SSOConfig:        nil,
	}
	m := NewMiddleware(cfg)

	token, _ := m.GenerateToken("jwt-type-test", "admin")

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler := m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authType := GetAuthType(r.Context())
		if authType != AuthTypeJWT {
			t.Errorf("Expected auth type %s, got %s", AuthTypeJWT, authType)
		}
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", rec.Code)
	}
}
