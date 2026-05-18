//go:build !race

// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform — handleSSOToken coverage tests
// Tests the SSO token authentication path in RequireAuth middleware
// =========================================================================

package auth

import (
	"errors"
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

// mockSSOProvider implements sso.SSOProviderInterface for handleSSOToken testing
// Key: ValidateSession returns nil for valid sessions, enabling the success path
type mockSSOProvider struct {
	name string
	typ  sso.SSOProvider
}

func (m *mockSSOProvider) Name() string          { return m.name }
func (m *mockSSOProvider) Type() sso.SSOProvider { return m.typ }
func (m *mockSSOProvider) InitiateLogin(s string) (string, *sso.SSORequest, error) {
	return "", nil, errors.New("not implemented")
}
func (m *mockSSOProvider) HandleCallback(req *sso.SSORequest, params map[string]string) (*sso.SSOResponse, error) {
	return nil, errors.New("not implemented")
}
func (m *mockSSOProvider) ValidateSession(sess *sso.SSOSession) error {
	return nil // Always valid - enables success path testing
}
func (m *mockSSOProvider) Logout(sess *sso.SSOSession) (string, error) {
	return "", nil
}
func (m *mockSSOProvider) Metadata() ([]byte, error) {
	return []byte(`{"info":"mock"}`), nil
}

// newMockSSOManagerWithProvider creates an SSO manager with a mock provider injected
// This allows testing handleSSOToken success path without needing real OIDC/SAML
func newMockSSOManagerWithProvider(t *testing.T) (*sso.Manager, *mockSessionStore) {
	store := newMockStore()
	mgr, err := sso.NewManager(&sso.ManagerConfig{SessionStore: store})
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	// Inject mock provider directly into providers map (bypasses OIDC/SAML network requirements)
	mp := &mockSSOProvider{name: "test-provider", typ: sso.ProviderOIDC}
	mgrCfg := &sso.SSOConfig{Provider: sso.ProviderOIDC, Name: "test-provider", Enabled: true}
	mgr.Mu().Lock()
	mgr.SetProvidersForTest(map[string]sso.SSOProviderInterface{"test-provider": mp})
	mgr.SetConfigsForTest(map[string]*sso.SSOConfig{"test-provider": mgrCfg})
	mgr.Mu().Unlock()

	return mgr, store
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
// Tests: SSO success path (valid session)
// =========================================================================

// TestSSOTokenHandle_ValidSSOSession: successful SSO authentication
func TestSSOTokenHandle_ValidSSOSession(t *testing.T) {
	mgr, store := newMockSSOManagerWithProvider(t)

	validSession := &sso.SSOSession{
		ID:           "valid-session",
		User:         &sso.SSOUser{ID: "user-123", Email: "admin@example.com", Role: "admin"},
		ProviderName: "test-provider",
		Active:       true,
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	}
	store.Create(validSession)

	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		TokenExpiryHours: 24,
		APIAuthToken:     "test-api-token",
		RequireAuth:      true,
		SSOConfig:        sso.DefaultSSOConfig(),
	}
	m := NewMiddlewareWithSSO(cfg, mgr)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer valid-session")
	rec := httptest.NewRecorder()

	var userID, authType, role string
	handler := m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID = GetUserID(r.Context())
		authType = GetAuthType(r.Context())
		role = string(GetUserRole(r.Context()))
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200 for valid SSO session, got %d", rec.Code)
	}
	if userID != "user-123" {
		t.Errorf("Expected userID=user-123, got %s", userID)
	}
	if authType != "sso" {
		t.Errorf("Expected authType=sso, got %s", authType)
	}
	if role != string(rbac.UserRoleAdmin) {
		t.Errorf("Expected role=admin, got %s", role)
	}
}

// TestSSOTokenHandle_SSOEmailFallback: session.User.ID empty → uses Email
func TestSSOTokenHandle_SSOEmailFallback(t *testing.T) {
	mgr, store := newMockSSOManagerWithProvider(t)

	// Session where User.ID is empty but Email is set
	emailOnlySession := &sso.SSOSession{
		ID:           "email-only-session",
		User:         &sso.SSOUser{Email: "email-user@example.com", Role: "viewer"},
		ProviderName: "test-provider",
		Active:       true,
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	}
	store.Create(emailOnlySession)

	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		TokenExpiryHours: 24,
		APIAuthToken:     "test-api-token",
		RequireAuth:      true,
		SSOConfig:        sso.DefaultSSOConfig(),
	}
	m := NewMiddlewareWithSSO(cfg, mgr)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer email-only-session")
	rec := httptest.NewRecorder()

	var userID string
	handler := m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID = GetUserID(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", rec.Code)
	}
	// Should fall back to Email when ID is empty
	if userID != "email-user@example.com" {
		t.Errorf("Expected userID fallback to email, got %s", userID)
	}
}

// TestSSOTokenHandle_SSOSuccessWithFallbackAuth: SSO succeeds, JWT fallback if SSO fails
func TestSSOTokenHandle_SSOSuccessWithFallbackAuth(t *testing.T) {
	mgr, store := newMockSSOManagerWithProvider(t)

	validSession := &sso.SSOSession{
		ID:           "valid-session",
		User:         &sso.SSOUser{ID: "sso-user", Email: "sso@example.com", Role: "analyst"},
		ProviderName: "test-provider",
		Active:       true,
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	}
	store.Create(validSession)

	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		TokenExpiryHours: 24,
		APIAuthToken:     "test-api-token",
		RequireAuth:      true,
		SSOConfig:        sso.DefaultSSOConfig(),
	}
	m := NewMiddlewareWithSSO(cfg, mgr)

	// SSO session is valid
	req1 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req1.Header.Set("Authorization", "Bearer valid-session")
	rec1 := httptest.NewRecorder()

	handler := m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusOK {
		t.Errorf("Expected 200 for valid SSO, got %d", rec1.Code)
	}

	// Different token falls to JWT
	jwtToken, _ := m.GenerateToken("jwt-user", "admin")
	req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req2.Header.Set("Authorization", "Bearer "+jwtToken)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Errorf("Expected 200 for JWT fallback, got %d", rec2.Code)
	}
}

// TestSSOTokenHandle_SSOProviderValidateError: provider returns validation error
func TestSSOTokenHandle_SSOProviderValidateError(t *testing.T) {
	store := newMockStore()
	mgr, err := sso.NewManager(&sso.ManagerConfig{SessionStore: store})
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	// Create a mock provider that always returns error
	failProvider := &mockFailProvider{name: "fail-provider", typ: sso.ProviderOIDC}
	mgrCfg := &sso.SSOConfig{Provider: sso.ProviderOIDC, Name: "fail-provider", Enabled: true}
	mgr.Mu().Lock()
	mgr.SetProvidersForTest(map[string]sso.SSOProviderInterface{"fail-provider": failProvider})
	mgr.SetConfigsForTest(map[string]*sso.SSOConfig{"fail-provider": mgrCfg})
	mgr.Mu().Unlock()

	sessionWithFailProvider := &sso.SSOSession{
		ID:           "fail-session",
		User:         &sso.SSOUser{ID: "user-1", Email: "test@example.com", Role: "admin"},
		ProviderName: "fail-provider",
		Active:       true,
	}
	store.Create(sessionWithFailProvider)

	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		TokenExpiryHours: 24,
		APIAuthToken:     "test-api-token",
		RequireAuth:      true,
		SSOConfig:        sso.DefaultSSOConfig(),
	}
	m := NewMiddlewareWithSSO(cfg, mgr)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer fail-session")
	rec := httptest.NewRecorder()

	handler := m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 when provider validation fails, got %d", rec.Code)
	}
}

// mockFailProvider always returns an error on ValidateSession
type mockFailProvider struct {
	name string
	typ  sso.SSOProvider
}

func (m *mockFailProvider) Name() string          { return m.name }
func (m *mockFailProvider) Type() sso.SSOProvider { return m.typ }
func (m *mockFailProvider) InitiateLogin(s string) (string, *sso.SSORequest, error) {
	return "", nil, errors.New("not implemented")
}
func (m *mockFailProvider) HandleCallback(req *sso.SSORequest, params map[string]string) (*sso.SSOResponse, error) {
	return nil, errors.New("not implemented")
}
func (m *mockFailProvider) ValidateSession(sess *sso.SSOSession) error {
	return errors.New("provider validation failed")
}
func (m *mockFailProvider) Logout(sess *sso.SSOSession) (string, error) {
	return "", nil
}
func (m *mockFailProvider) Metadata() ([]byte, error) {
	return []byte(`{}`), nil
}

// TestSSOTokenHandle_UppercaseBearer: uppercase BEARER scheme
func TestSSOTokenHandle_UppercaseBearer(t *testing.T) {
	mgr, store := newMockSSOManagerWithProvider(t)

	validSession := &sso.SSOSession{
		ID:           "valid-uppercase",
		User:         &sso.SSOUser{ID: "user-upper", Email: "upper@example.com", Role: "admin"},
		ProviderName: "test-provider",
		Active:       true,
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	}
	store.Create(validSession)

	cfg := &Config{
		JWTSigningKey:    []byte("test-jwt-key-32bytes-long-key"),
		TokenExpiryHours: 24,
		APIAuthToken:     "test-api-token",
		RequireAuth:      true,
		SSOConfig:        sso.DefaultSSOConfig(),
	}
	m := NewMiddlewareWithSSO(cfg, mgr)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "BEARER valid-uppercase") // Uppercase BEARER
	rec := httptest.NewRecorder()

	handler := m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200 with uppercase BEARER, got %d", rec.Code)
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
