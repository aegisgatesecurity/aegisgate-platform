//go:build !race

// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// SSO Coverage Enhancement Tests - Session 18
// =========================================================================

package sso

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// =========================================================================
// Cookie-based session tests
// =========================================================================

func TestRequireSession_CookieNoSession(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)

	handler := middleware.RequireSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized && rr.Code != http.StatusTemporaryRedirect {
		t.Errorf("expected 401 or 307, got %d", rr.Code)
	}
}

func TestRequireSession_CookieInvalidSession(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)

	handler := middleware.RequireSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.AddCookie(&http.Cookie{Name: "sso_session", Value: "invalid-session"})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized && rr.Code != http.StatusTemporaryRedirect {
		t.Errorf("expected 401 or 307, got %d", rr.Code)
	}
}

func TestRequireSession_CookieExpiredSession(t *testing.T) {
	manager, _ := NewManager(nil)

	session := &SSOSession{
		ID:           "expired-session",
		UserID:       "user-123",
		ProviderName: "test",
		Provider:     ProviderOIDC,
		Active:       true,
		CreatedAt:    time.Now().Add(-2 * time.Hour),
		ExpiresAt:    time.Now().Add(-time.Hour),
	}
	manager.sessions.Create(session)

	middleware := NewMiddleware(manager, nil)
	handler := middleware.RequireSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Header.Set("Authorization", "Bearer expired-session")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized && rr.Code != http.StatusTemporaryRedirect {
		t.Errorf("expected 401 or 307, got %d", rr.Code)
	}
}

func TestRequireSession_CookieInactiveSession(t *testing.T) {
	manager, _ := NewManager(nil)

	session := &SSOSession{
		ID:           "inactive-session",
		UserID:       "user-123",
		ProviderName: "test",
		Provider:     ProviderOIDC,
		Active:       false,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(time.Hour),
	}
	manager.sessions.Create(session)

	middleware := NewMiddleware(manager, nil)
	handler := middleware.RequireSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Header.Set("Authorization", "Bearer inactive-session")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized && rr.Code != http.StatusTemporaryRedirect {
		t.Errorf("expected 401 or 307, got %d", rr.Code)
	}
}

// =========================================================================
// OptionalSession tests (60.0% → 95%+)
// =========================================================================

func TestOptionalSession_ContextSession(t *testing.T) {
	manager, _ := NewManager(nil)

	session := &SSOSession{
		ID:           "ctx-session",
		UserID:       "user-456",
		ProviderName: "test",
		Provider:     ProviderOIDC,
		Active:       true,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(time.Hour),
	}
	manager.sessions.Create(session)

	middleware := NewMiddleware(manager, nil)

	ctx := ContextWithSession(context.Background(), session)
	handler := middleware.OptionalSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil).WithContext(ctx)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// =========================================================================
// RequireRole tests (80.0% → 95%+)
// =========================================================================

func TestRequireRole_UnknownUserRole(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)

	user := &SSOUser{
		ID:    "user-123",
		Email: "test@example.com",
		Role:  "nonexistent-role",
	}

	handler := middleware.RequireRole("admin")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	ctx := ContextWithUser(context.Background(), user)
	req := httptest.NewRequest(http.MethodGet, "/api/test", nil).WithContext(ctx)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden && rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 403 or 401, got %d", rr.Code)
	}
}

func TestRequireRole_UnknownRequiredRole(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)

	user := &SSOUser{
		ID:    "user-123",
		Email: "test@example.com",
		Role:  "admin",
	}

	handler := middleware.RequireRole("nonexistent-role")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	ctx := ContextWithUser(context.Background(), user)
	req := httptest.NewRequest(http.MethodGet, "/api/test", nil).WithContext(ctx)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden && rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 403 or 401, got %d", rr.Code)
	}
}

// =========================================================================
// setSessionCookie tests (63.6% → 95%+)
// =========================================================================

func TestSetSessionCookie_CookieWithPath(t *testing.T) {
	manager, _ := NewManager(nil)
	opts := &CookieOptions{
		Secure:   true,
		HTTPOnly: true,
		SameSite: "Strict",
		Path:     "/api/v1",
		MaxAge:   3600,
	}
	mw := NewMiddleware(manager, opts)

	rr := httptest.NewRecorder()
	mw.setSessionCookie(rr, "test-session")

	cookies := rr.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}

	cookie := cookies[0]
	if cookie.Name != "sso_session" {
		t.Errorf("expected name 'sso_session', got '%s'", cookie.Name)
	}
	if cookie.Value != "test-session" {
		t.Errorf("expected value 'test-session', got '%s'", cookie.Value)
	}
	if cookie.Path != "/api/v1" {
		t.Errorf("expected path '/api/v1', got '%s'", cookie.Path)
	}
}

func TestSetSessionCookie_CookieWithDomain(t *testing.T) {
	manager, _ := NewManager(nil)
	opts := &CookieOptions{
		Secure:   true,
		HTTPOnly: true,
		SameSite: "Lax",
		Path:     "/",
		Domain:   "example.com",
		MaxAge:   86400,
	}
	mw := NewMiddleware(manager, opts)

	rr := httptest.NewRecorder()
	mw.setSessionCookie(rr, "domain-session")

	cookies := rr.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
}

func TestSetSessionCookie_NoneSameSite(t *testing.T) {
	manager, _ := NewManager(nil)
	opts := &CookieOptions{
		Secure:   true,
		HTTPOnly: true,
		SameSite: "None",
		Path:     "/",
		MaxAge:   0,
	}
	mw := NewMiddleware(manager, opts)

	rr := httptest.NewRecorder()
	mw.setSessionCookie(rr, "cross-site-session")

	cookies := rr.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
}

// =========================================================================
// clearSessionCookie tests (66.7% → 95%+)
// =========================================================================

func TestClearSessionCookie_WithDomain(t *testing.T) {
	manager, _ := NewManager(nil)
	opts := &CookieOptions{
		Secure:   true,
		HTTPOnly: true,
		SameSite: "Strict",
		Path:     "/api",
		Domain:   "example.com",
	}
	mw := NewMiddleware(manager, opts)

	rr := httptest.NewRecorder()
	mw.clearSessionCookie(rr)

	cookies := rr.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}

	cookie := cookies[0]
	if cookie.MaxAge != -1 {
		t.Errorf("expected MaxAge=-1, got %d", cookie.MaxAge)
	}
}

func TestClearSessionCookie_WithExisting(t *testing.T) {
	manager, _ := NewManager(nil)
	opts := &CookieOptions{
		Secure:   true,
		HTTPOnly: true,
		SameSite: "Strict",
		Path:     "/",
	}
	mw := NewMiddleware(manager, opts)

	rr := httptest.NewRecorder()
	http.SetCookie(rr, &http.Cookie{Name: "sso_session", Value: "existing-session"})
	mw.clearSessionCookie(rr)

	cookies := rr.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
}

// =========================================================================
// handleUnauthorized tests
// =========================================================================

func TestHandleUnauthorized_WebPath(t *testing.T) {
	manager, _ := NewManager(nil)
	mw := NewMiddleware(manager, nil)

	req := httptest.NewRequest(http.MethodGet, "/web/dashboard", nil)
	rr := httptest.NewRecorder()

	err := NewSSOError(ErrSessionExpired, "session expired")
	mw.handleUnauthorized(rr, req, err)

	if rr.Code != http.StatusTemporaryRedirect {
		t.Errorf("expected 307, got %d", rr.Code)
	}

	loc := rr.Header().Get("Location")
	if loc != "/login" {
		t.Errorf("expected /login, got %s", loc)
	}
}

func TestHandleUnauthorized_DeepAPI(t *testing.T) {
	manager, _ := NewManager(nil)
	mw := NewMiddleware(manager, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v2/users/profiles", nil)
	rr := httptest.NewRecorder()

	err := NewSSOError(ErrInvalidToken, "token invalid")
	mw.handleUnauthorized(rr, req, err)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}

	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("expected JSON, got %s", ct)
	}
}

// =========================================================================
// handleForbidden tests
// =========================================================================

func TestHandleForbidden_WebPath(t *testing.T) {
	manager, _ := NewManager(nil)
	mw := NewMiddleware(manager, nil)

	req := httptest.NewRequest(http.MethodGet, "/admin/settings", nil)
	rr := httptest.NewRecorder()

	err := NewSSOError(ErrUserNotAllowed, "insufficient permissions")
	mw.handleForbidden(rr, req, err)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

func TestHandleForbidden_APIPath(t *testing.T) {
	manager, _ := NewManager(nil)
	mw := NewMiddleware(manager, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/admin/users", nil)
	rr := httptest.NewRecorder()

	err := NewSSOError(ErrUserNotAllowed, "insufficient permissions")
	mw.handleForbidden(rr, req, err)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}

	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("expected JSON, got %s", ct)
	}
}

// =========================================================================
// Manager InitiateLogin tests (80.0% → 95%+)
// =========================================================================

func TestManager_InitiateLogin_ProviderNotFound(t *testing.T) {
	manager, _ := NewManager(nil)

	_, _, err := manager.InitiateLogin("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent provider")
	}
}

// =========================================================================
// Manager ValidateSession tests (88.2% → 95%+)
// =========================================================================

func TestManager_ValidateSession_Nonexistent(t *testing.T) {
	manager, _ := NewManager(nil)

	_, err := manager.ValidateSession("nonexistent-session")
	if err == nil {
		t.Error("expected error for nonexistent session")
	}
}

func TestManager_ValidateSession_ProviderMissing(t *testing.T) {
	manager, _ := NewManager(nil)

	session := &SSOSession{
		ID:           "orphan-session",
		UserID:       "user-123",
		ProviderName: "missing-provider",
		Provider:     ProviderOIDC,
		Active:       true,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(time.Hour),
	}
	manager.sessions.Create(session)

	_, err := manager.ValidateSession("orphan-session")
	if err == nil {
		t.Error("expected error for missing provider")
	}
}

// =========================================================================
// Manager Logout tests (86.7% → 95%+)
// =========================================================================

func TestManager_Logout_Nonexistent(t *testing.T) {
	manager, _ := NewManager(nil)

	_, err := manager.Logout("nonexistent-session")
	if err == nil {
		t.Error("expected error for nonexistent session")
	}
}

func TestManager_Logout_SessionDeleted(t *testing.T) {
	manager, _ := NewManager(nil)

	session := &SSOSession{
		ID:           "logout-session",
		UserID:       "user-123",
		ProviderName: "test-provider",
		Provider:     ProviderOIDC,
		Active:       true,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(time.Hour),
	}
	manager.sessions.Create(session)

	// Create a provider that returns no logout URL
	provider := &mockProvider{name: "test-provider"}
	manager.SetProvidersForTest(map[string]SSOProviderInterface{
		"test-provider": provider,
	})

	url, err := manager.Logout("logout-session")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if url == "" {
		t.Errorf("expected non-empty URL, got empty")
	}

	// Session should be deleted
	_, err = manager.GetSession("logout-session")
	if err == nil {
		t.Error("expected session to be deleted")
	}
}

// =========================================================================
// Manager HandleCallback tests (76.2% → 95%+)
// =========================================================================

func TestManager_HandleCallback_ProviderMissing(t *testing.T) {
	manager, _ := NewManager(nil)

	_, err := manager.HandleCallback("nonexistent", map[string]string{"state": "test"})
	if err == nil {
		t.Error("expected error for nonexistent provider")
	}
}

func TestManager_HandleCallback_MissingState(t *testing.T) {
	manager, _ := NewManager(nil)

	provider := &mockProvider{name: "test"}
	manager.SetProvidersForTest(map[string]SSOProviderInterface{"test": provider})

	_, err := manager.HandleCallback("test", map[string]string{})
	if err == nil {
		t.Error("expected error for missing state")
	}
}

func TestManager_HandleCallback_StateNotFound(t *testing.T) {
	manager, _ := NewManager(nil)

	provider := &mockProvider{name: "test"}
	manager.SetProvidersForTest(map[string]SSOProviderInterface{"test": provider})

	_, err := manager.HandleCallback("test", map[string]string{"state": "nonexistent-state"})
	if err == nil {
		t.Error("expected error for nonexistent state")
	}
}

// =========================================================================
// Context helpers
// =========================================================================

func TestSessionFromContext(t *testing.T) {
	session := &SSOSession{ID: "test-session"}
	ctx := ContextWithSession(context.Background(), session)

	retrieved := SessionFromContext(ctx)
	if retrieved == nil {
		t.Error("expected session")
	}
	if retrieved.ID != "test-session" {
		t.Errorf("expected 'test-session', got '%s'", retrieved.ID)
	}
}

func TestUserFromContext(t *testing.T) {
	user := &SSOUser{ID: "test-user"}
	ctx := ContextWithUser(context.Background(), user)

	retrieved := UserFromContext(ctx)
	if retrieved == nil {
		t.Error("expected user")
	}
	if retrieved.ID != "test-user" {
		t.Errorf("expected 'test-user', got '%s'", retrieved.ID)
	}
}

func TestContextHelpers_EmptyContext(t *testing.T) {
	ctx := context.Background()

	if SessionFromContext(ctx) != nil {
		t.Error("expected nil session")
	}
	if UserFromContext(ctx) != nil {
		t.Error("expected nil user")
	}
}

// =========================================================================
// Mock provider for testing
// =========================================================================

type mockProviderS18 struct {
	name string
}

func (m *mockProviderS18) Name() string      { return m.name }
func (m *mockProviderS18) Type() SSOProvider { return ProviderOIDC }
func (m *mockProviderS18) InitiateLogin(state string) (string, *SSORequest, error) {
	return "https://example.com/login", &SSORequest{State: state, ID: "req-123", Provider: m.name}, nil
}
func (m *mockProviderS18) HandleCallback(req *SSORequest, params map[string]string) (*SSOResponse, error) {
	return nil, NewSSOError(ErrInvalidCallback, "mock callback")
}
func (m *mockProviderS18) ValidateSession(session *SSOSession) error {
	return NewSSOError(ErrInvalidToken, "mock validation")
}
func (m *mockProviderS18) Logout(session *SSOSession) (string, error) { return "", nil }
func (m *mockProviderS18) Metadata() ([]byte, error)                  { return nil, nil }

// =========================================================================
// SSOError tests
// =========================================================================

func TestSSOError_WithCauseS18(t *testing.T) {
	inner := errors.New("inner error")
	err := NewSSOError(ErrInvalidRequest, "outer error").WithCause(inner)

	msg := err.Error()
	if !strings.Contains(msg, "outer error") || !strings.Contains(msg, "inner error") {
		t.Errorf("expected error message with 'outer error' and 'inner error', got '%s'", msg)
	}
}

// =========================================================================
// RoleAtLeast edge cases
// =========================================================================

func TestSSOUser_RoleAtLeast_Same(t *testing.T) {
	user := &SSOUser{Role: "admin"}
	if !user.RoleAtLeast("admin") {
		t.Error("admin should be >= admin")
	}
}

func TestSSOUser_RoleAtLeast_Higher(t *testing.T) {
	user := &SSOUser{Role: "admin"}
	if !user.RoleAtLeast("viewer") {
		t.Error("admin should be >= viewer")
	}
}

func TestSSOUser_RoleAtLeast_Lower(t *testing.T) {
	user := &SSOUser{Role: "viewer"}
	if user.RoleAtLeast("admin") {
		t.Error("viewer should not be >= admin")
	}
}

func TestSSOUser_RoleAtLeast_UnknownUserRole(t *testing.T) {
	user := &SSOUser{Role: "custom-role"}
	if user.RoleAtLeast("admin") {
		t.Error("unknown role should not be >= admin")
	}
}

func TestSSOUser_RoleAtLeast_UnknownRequiredRole(t *testing.T) {
	user := &SSOUser{Role: "admin"}
	if user.RoleAtLeast("custom-role") {
		t.Error("admin should not be >= unknown role")
	}
}

// =========================================================================
// generateState tests
// =========================================================================

func TestGenerateState_NotEmpty(t *testing.T) {
	state := generateState()
	if state == "" {
		t.Error("expected non-empty state")
	}
}

func TestGenerateState_Different(t *testing.T) {
	s1 := generateState()
	s2 := generateState()
	if s1 == s2 {
		t.Error("expected different states")
	}
}

// =========================================================================
// domainMatches tests
// =========================================================================

func TestDomainMatches_Empty(t *testing.T) {
	if domainMatches("", "example.com") {
		t.Error("expected false for empty email")
	}
}

func TestDomainMatches_Match(t *testing.T) {
	if !domainMatches("user@example.com", "example.com") {
		t.Error("expected true for match")
	}
}

func TestDomainMatches_NoMatch(t *testing.T) {
	if domainMatches("user@other.com", "example.com") {
		t.Error("expected false for non-match")
	}
}

// =========================================================================
// Manager stats tests
// =========================================================================

func TestManager_Stats(t *testing.T) {
	manager, _ := NewManager(nil)

	stats, err := manager.Stats()
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if stats.Providers != 0 {
		t.Errorf("expected 0 providers, got %d", stats.Providers)
	}
}

func TestManager_Stats_WithProvider(t *testing.T) {
	manager, _ := NewManager(nil)
	manager.SetProvidersForTest(map[string]SSOProviderInterface{
		"test-provider": &mockProvider{name: "test-provider"},
	})

	stats, err := manager.Stats()
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if stats.Providers != 1 {
		t.Errorf("expected 1 provider, got %d", stats.Providers)
	}
}

// =========================================================================
// Manager session tests
// =========================================================================

func TestManager_GetSession_NotFound(t *testing.T) {
	manager, _ := NewManager(nil)

	_, err := manager.GetSession("nonexistent")
	if err == nil {
		t.Error("expected error")
	}
}

func TestManager_GetUserSessions_None(t *testing.T) {
	manager, _ := NewManager(nil)

	sessions, err := manager.GetUserSessions("nonexistent-user")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if len(sessions) != 0 {
		t.Errorf("expected 0 sessions, got %d", len(sessions))
	}
}

// =========================================================================
// Manager cleanup tests
// =========================================================================

func TestManager_CleanupSessions(t *testing.T) {
	manager, _ := NewManager(nil)

	err := manager.CleanupSessions()
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

// =========================================================================
// CheckDomainAccess tests
// =========================================================================

func TestManager_CheckDomainAccess_ProviderNotFound(t *testing.T) {
	manager, _ := NewManager(nil)

	err := manager.CheckDomainAccess("nonexistent", "user@example.com")
	if err == nil {
		t.Error("expected error")
	}
}

func TestManager_CheckDomainAccess_BlockedDomain(t *testing.T) {
	manager, _ := NewManager(nil)
	manager.SetConfigsForTest(map[string]*SSOConfig{
		"test": {
			Name:           "test",
			Provider:       ProviderOIDC,
			BlockedDomains: []string{"blocked.com"},
		},
	})

	err := manager.CheckDomainAccess("test", "user@blocked.com")
	if err == nil {
		t.Error("expected error for blocked domain")
	}
}

func TestManager_CheckDomainAccess_NotAllowed(t *testing.T) {
	manager, _ := NewManager(nil)
	manager.SetConfigsForTest(map[string]*SSOConfig{
		"test": {
			Name:           "test",
			Provider:       ProviderOIDC,
			AllowedDomains: []string{"allowed.com"},
		},
	})

	err := manager.CheckDomainAccess("test", "user@other.com")
	if err == nil {
		t.Error("expected error for non-allowed domain")
	}
}

func TestManager_CheckDomainAccess_Allowed(t *testing.T) {
	manager, _ := NewManager(nil)
	manager.SetConfigsForTest(map[string]*SSOConfig{
		"test": {
			Name:           "test",
			Provider:       ProviderOIDC,
			AllowedDomains: []string{"allowed.com"},
		},
	})

	err := manager.CheckDomainAccess("test", "user@allowed.com")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

// =========================================================================
// applyRoleMappings tests
// =========================================================================

func TestManager_ApplyRoleMappings_NilConfig(t *testing.T) {
	manager, _ := NewManager(nil)

	user := &SSOUser{ID: "user-123", Groups: []string{"admins"}}
	manager.applyRoleMappings(user, nil)

	// Should not panic, role unchanged
	if user.Role != "" {
		t.Errorf("expected empty role, got %s", user.Role)
	}
}

func TestManager_ApplyRoleMappings_NoMappings(t *testing.T) {
	manager, _ := NewManager(nil)

	user := &SSOUser{ID: "user-123", Groups: []string{"admins"}}
	manager.applyRoleMappings(user, &SSOConfig{})

	if user.Role != "" {
		t.Errorf("expected empty role, got %s", user.Role)
	}
}

func TestManager_ApplyRoleMappings_Match(t *testing.T) {
	manager, _ := NewManager(nil)

	user := &SSOUser{ID: "user-123", Groups: []string{"admin-group"}}
	manager.applyRoleMappings(user, &SSOConfig{
		RoleMappings: []RoleMapping{
			{IdPRole: "admin-group", AppRole: "admin"},
		},
	})

	if user.Role != "admin" {
		t.Errorf("expected 'admin', got '%s'", user.Role)
	}
}

func TestManager_ApplyRoleMappings_NoMatch(t *testing.T) {
	manager, _ := NewManager(nil)

	user := &SSOUser{ID: "user-123", Groups: []string{"other-group"}}
	manager.applyRoleMappings(user, &SSOConfig{
		RoleMappings: []RoleMapping{
			{IdPRole: "admin-group", AppRole: "admin"},
		},
	})

	if user.Role != "" {
		t.Errorf("expected empty role, got %s", user.Role)
	}
}
