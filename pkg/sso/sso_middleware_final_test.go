//go:build !race

// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// SSO Middleware Final Coverage Tests
// Target: push middleware.go from ~73% to 95%+ and manager.go key functions
// =========================================================================

package sso

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// mockProviderFinal is a mock provider for final coverage tests.
type mockProviderFinal struct {
	name         string
	typ          SSOProvider
	loginURL     string
	session      *SSOSession
	user         *SSOUser
	failInit     bool
	failCallback bool
	failValidate bool
	failLogout   bool
	metadata     []byte
	logoutURL    string
}

func (m *mockProviderFinal) Name() string      { return m.name }
func (m *mockProviderFinal) Type() SSOProvider { return m.typ }

func (m *mockProviderFinal) InitiateLogin(state string) (string, *SSORequest, error) {
	if m.failInit {
		return "", nil, newTestSSOError("init error")
	}
	req := &SSORequest{ID: "mock-req-" + state, Provider: m.name, State: state}
	return m.loginURL, req, nil
}

func (m *mockProviderFinal) HandleCallback(req *SSORequest, params map[string]string) (*SSOResponse, error) {
	if m.failCallback {
		return nil, newTestSSOError("callback error")
	}
	return &SSOResponse{
		Success: true,
		User:    m.user,
		Session: m.session,
	}, nil
}

func (m *mockProviderFinal) ValidateSession(sess *SSOSession) error {
	if m.failValidate {
		return newTestSSOError("validate error")
	}
	return nil
}

func (m *mockProviderFinal) Logout(sess *SSOSession) (string, error) {
	if m.failLogout {
		return "", newTestSSOError("logout error")
	}
	return m.logoutURL, nil
}

func (m *mockProviderFinal) Metadata() ([]byte, error) {
	if m.metadata == nil {
		return []byte("<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\">mock</md:EntityDescriptor>"), nil
	}
	return m.metadata, nil
}

func newTestSSOError(msg string) *SSOError {
	return &SSOError{Code: ErrInvalidRequest, Message: msg}
}

// setupManagerWithProvider creates a Manager with a mock provider registered.
func setupManagerWithProvider() (*Manager, *mockProviderFinal) {
	manager, _ := NewManager(nil)
	mp := &mockProviderFinal{
		name:      "test-provider",
		typ:       ProviderOIDC,
		loginURL:  "https://idp.example.com/login",
		logoutURL: "https://idp.example.com/logout",
	}
	manager.SetProvidersForTest(map[string]SSOProviderInterface{
		"test-provider": mp,
	})
	manager.SetConfigsForTest(map[string]*SSOConfig{
		"test-provider": {
			Name:     "test-provider",
			Provider: ProviderOIDC,
			OIDC: &OIDCConfig{
				ClientID: "test-client",
			},
			RoleMappings: []RoleMapping{
				{IdPRole: "admins", AppRole: "admin"},
			},
		},
	})
	return manager, mp
}

// createValidSession creates a valid session in the manager's store.
func createValidSession(manager *Manager, id, providerName string) *SSOSession {
	session := &SSOSession{
		ID:           id,
		UserID:       "user-" + id,
		Provider:     ProviderOIDC,
		ProviderName: providerName,
		Active:       true,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(24 * time.Hour),
		User: &SSOUser{
			ID:     "user-" + id,
			Email:  "user@example.com",
			Name:   "Test User",
			Role:   "admin",
			Groups: []string{"admins"},
		},
	}
	_ = manager.sessions.Create(session)
	return session
}

// =========================================================================
// OptionalSession (60.0% → 95%+)
// Test the full happy path: cookie → session lookup → validate → set context
// =========================================================================

func TestFinal_OptionalSession_ValidSessionViaCookie(t *testing.T) {
	manager, _ := setupManagerWithProvider()
	middleware := NewMiddleware(manager, nil)
	_ = createValidSession(manager, "opt-session-1", "test-provider")

	called := false
	handler := middleware.OptionalSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		sess := SessionFromContext(r.Context())
		if sess == nil || sess.ID != "opt-session-1" {
			t.Errorf("expected session in context, got %v", sess)
		}
		user := UserFromContext(r.Context())
		if user == nil || user.ID != "user-opt-session-1" {
			t.Errorf("expected user in context, got %v", user)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "sso_session", Value: "opt-session-1"})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !called {
		t.Error("expected next handler to be called")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestFinal_OptionalSession_ValidSessionViaBearer(t *testing.T) {
	manager, _ := setupManagerWithProvider()
	middleware := NewMiddleware(manager, nil)
	_ = createValidSession(manager, "opt-bearer-1", "test-provider")

	called := false
	handler := middleware.OptionalSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		sess := SessionFromContext(r.Context())
		if sess == nil || sess.ID != "opt-bearer-1" {
			t.Errorf("expected session in context, got %v", sess)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer opt-bearer-1")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !called {
		t.Error("expected next handler to be called")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestFinal_OptionalSession_InvalidSessionID(t *testing.T) {
	manager, _ := setupManagerWithProvider()
	middleware := NewMiddleware(manager, nil)

	called := false
	handler := middleware.OptionalSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		// Session should NOT be in context
		sess := SessionFromContext(r.Context())
		if sess != nil {
			t.Errorf("expected no session in context, got %v", sess)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "sso_session", Value: "nonexistent-session"})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !called {
		t.Error("expected next handler to be called even without valid session")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 (optional), got %d", rr.Code)
	}
}

func TestFinal_OptionalSession_SessionWithNilUser(t *testing.T) {
	manager, _ := setupManagerWithProvider()
	middleware := NewMiddleware(manager, nil)

	// Create session without a User
	session := &SSOSession{
		ID:           "opt-no-user",
		UserID:       "user-no-user",
		Provider:     ProviderOIDC,
		ProviderName: "test-provider",
		Active:       true,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(24 * time.Hour),
		User:         nil, // no user
	}
	_ = manager.sessions.Create(session)

	called := false
	handler := middleware.OptionalSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		sess := SessionFromContext(r.Context())
		if sess == nil || sess.ID != "opt-no-user" {
			t.Errorf("expected session in context, got %v", sess)
		}
		user := UserFromContext(r.Context())
		if user != nil {
			t.Errorf("expected nil user in context, got %v", user)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "sso_session", Value: "opt-no-user"})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !called {
		t.Error("expected next handler to be called")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// =========================================================================
// RequireSession (71.4% → 95%+)
// Test: valid session full path, validation failure, API path, web path
// =========================================================================

func TestFinal_RequireSession_ValidSessionViaCookie(t *testing.T) {
	manager, _ := setupManagerWithProvider()
	middleware := NewMiddleware(manager, nil)
	_ = createValidSession(manager, "req-session-1", "test-provider")

	called := false
	handler := middleware.RequireSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		sess := SessionFromContext(r.Context())
		if sess == nil || sess.ID != "req-session-1" {
			t.Errorf("expected session in context, got %v", sess)
		}
		user := UserFromContext(r.Context())
		if user == nil || user.ID != "user-req-session-1" {
			t.Errorf("expected user in context, got %v", user)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: "sso_session", Value: "req-session-1"})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !called {
		t.Error("expected next handler to be called")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestFinal_RequireSession_ValidationFails(t *testing.T) {
	manager, mp := setupManagerWithProvider()
	mp.failValidate = true
	middleware := NewMiddleware(manager, nil)
	_ = createValidSession(manager, "req-fail-session", "test-provider")

	handler := middleware.RequireSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not reach next handler")
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.AddCookie(&http.Cookie{Name: "sso_session", Value: "req-fail-session"})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// API path should get 401 JSON
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for failed validation, got %d", rr.Code)
	}
	// Should also clear the cookie
	found := false
	for _, c := range rr.Result().Cookies() {
		if c.Name == "sso_session" {
			found = true
			if c.MaxAge != -1 {
				t.Errorf("expected cleared cookie MaxAge=-1, got %d", c.MaxAge)
			}
		}
	}
	if !found {
		t.Error("expected session cookie to be cleared")
	}
}

func TestFinal_RequireSession_ValidationFails_WebPath(t *testing.T) {
	manager, mp := setupManagerWithProvider()
	mp.failValidate = true
	middleware := NewMiddleware(manager, nil)
	_ = createValidSession(manager, "req-fail-web", "test-provider")

	handler := middleware.RequireSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not reach next handler")
	}))

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: "sso_session", Value: "req-fail-web"})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Non-API path should redirect to /login
	if rr.Code != http.StatusTemporaryRedirect {
		t.Errorf("expected 307 redirect for web path, got %d", rr.Code)
	}
}

func TestFinal_RequireSession_ExpiredSession(t *testing.T) {
	manager, _ := setupManagerWithProvider()
	middleware := NewMiddleware(manager, nil)

	// Create an expired session
	session := &SSOSession{
		ID:           "req-expired",
		UserID:       "user-expired",
		Provider:     ProviderOIDC,
		ProviderName: "test-provider",
		Active:       true,
		CreatedAt:    time.Now().Add(-48 * time.Hour),
		ExpiresAt:    time.Now().Add(-24 * time.Hour),
	}
	_ = manager.sessions.Create(session)

	handler := middleware.RequireSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not reach next handler")
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.AddCookie(&http.Cookie{Name: "sso_session", Value: "req-expired"})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for expired session, got %d", rr.Code)
	}
}

// =========================================================================
// CallbackHandler (64.7% → 95%+)
// Test: successful callback with session, cookie setting, success/failure redirects
// =========================================================================

func TestFinal_CallbackHandler_SuccessWithSession(t *testing.T) {
	manager, mp := setupManagerWithProvider()
	mp.session = &SSOSession{
		ID:           "cb-session-1",
		UserID:       "user-cb",
		Provider:     ProviderOIDC,
		ProviderName: "test-provider",
		Active:       true,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(24 * time.Hour),
	}
	mp.user = &SSOUser{ID: "user-cb", Email: "user@example.com", Role: "admin", Groups: []string{"admins"}}
	middleware := NewMiddleware(manager, nil)

	// Create the request state
	ssoReq := &SSORequest{ID: "cb-req-1", Provider: "test-provider", State: "state-123"}
	_ = manager.requests.Create(ssoReq)

	handler := middleware.CallbackHandler("test-provider", "/dashboard", "/login?error")

	req := httptest.NewRequest(http.MethodGet, "/callback?state=state-123&code=auth-code", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Should redirect to onSuccess URL
	if rr.Code != http.StatusTemporaryRedirect {
		t.Errorf("expected 307 redirect, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if loc != "/dashboard" {
		t.Errorf("expected redirect to /dashboard, got %s", loc)
	}

	// Check session cookie was set
	found := false
	for _, c := range rr.Result().Cookies() {
		if c.Name == "sso_session" && c.Value == "cb-session-1" {
			found = true
		}
	}
	if !found {
		t.Error("expected session cookie to be set")
	}
}

func TestFinal_CallbackHandler_SuccessNoOnSuccess(t *testing.T) {
	manager, mp := setupManagerWithProvider()
	mp.session = &SSOSession{
		ID:           "cb-session-2",
		UserID:       "user-cb2",
		Provider:     ProviderOIDC,
		ProviderName: "test-provider",
		Active:       true,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(24 * time.Hour),
	}
	mp.user = &SSOUser{ID: "user-cb2", Email: "user2@example.com"}
	middleware := NewMiddleware(manager, nil)

	ssoReq := &SSORequest{ID: "cb-req-2", Provider: "test-provider", State: "state-456"}
	_ = manager.requests.Create(ssoReq)

	handler := middleware.CallbackHandler("test-provider", "", "/login?error")

	req := httptest.NewRequest(http.MethodGet, "/callback?state=state-456&code=auth-code", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Should return 200 OK with "Authentication successful"
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Authentication successful") {
		t.Errorf("expected body to contain 'Authentication successful', got %s", body)
	}
}

func TestFinal_CallbackHandler_SuccessNoSession(t *testing.T) {
	manager, mp := setupManagerWithProvider()
	mp.session = nil // no session in response
	mp.user = &SSOUser{ID: "user-cb3", Email: "user3@example.com"}
	middleware := NewMiddleware(manager, nil)

	ssoReq := &SSORequest{ID: "cb-req-3", Provider: "test-provider", State: "state-789"}
	_ = manager.requests.Create(ssoReq)

	handler := middleware.CallbackHandler("test-provider", "/home", "/login?error")

	req := httptest.NewRequest(http.MethodGet, "/callback?state=state-789&code=code", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Should redirect to onSuccess even without session
	if rr.Code != http.StatusTemporaryRedirect {
		t.Errorf("expected 307 redirect, got %d", rr.Code)
	}
	// No session cookie should be set with value
	for _, c := range rr.Result().Cookies() {
		if c.Name == "sso_session" {
			t.Error("expected no session cookie when response has no session")
		}
	}
}

func TestFinal_CallbackHandler_ErrorNoOnFailure(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)

	// nonexistent provider → error, no onFailure URL
	handler := middleware.CallbackHandler("nonexistent", "/success", "")

	req := httptest.NewRequest(http.MethodGet, "/callback?error=access_denied", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Should return 401 Unauthorized as plain error
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized, got %d", rr.Code)
	}
}

func TestFinal_CallbackHandler_ParamsFromQuery(t *testing.T) {
	manager, mp := setupManagerWithProvider()
	mp.session = &SSOSession{
		ID: "cb-session-params", UserID: "user-params", Provider: ProviderOIDC,
		ProviderName: "test-provider", Active: true,
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	mp.user = &SSOUser{ID: "user-params"}
	middleware := NewMiddleware(manager, nil)

	ssoReq := &SSORequest{ID: "cb-req-params", Provider: "test-provider", State: "state-params"}
	_ = manager.requests.Create(ssoReq)

	handler := middleware.CallbackHandler("test-provider", "/home", "/error")

	req := httptest.NewRequest(http.MethodGet, "/callback?state=state-params&code=abc123&foo=bar", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusTemporaryRedirect {
		t.Errorf("expected 307 redirect, got %d", rr.Code)
	}
}

// =========================================================================
// setSessionCookie (81.8% → 95%+)
// Test: SameSite modes, Secure/HttpOnly enforcement
// =========================================================================

func TestFinal_SetSessionCookie_SameSiteLax(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, &CookieOptions{
		SameSite: "Lax",
		Secure:   true,
		HTTPOnly: true,
		Path:     "/",
		MaxAge:   3600,
	})

	rr := httptest.NewRecorder()
	middleware.setSessionCookie(rr, "session-lax")

	cookies := rr.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	if cookies[0].SameSite != http.SameSiteLaxMode {
		t.Errorf("expected SameSiteLaxMode, got %v", cookies[0].SameSite)
	}
}

func TestFinal_SetSessionCookie_SameSiteNone(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, &CookieOptions{
		SameSite: "None",
		Secure:   true,
		HTTPOnly: true,
		Path:     "/",
		MaxAge:   3600,
	})

	rr := httptest.NewRecorder()
	middleware.setSessionCookie(rr, "session-none")

	cookies := rr.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	if cookies[0].SameSite != http.SameSiteNoneMode {
		t.Errorf("expected SameSiteNoneMode, got %v", cookies[0].SameSite)
	}
}

func TestFinal_SetSessionCookie_SameSiteDefault(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, &CookieOptions{
		SameSite: "unknown", // falls through to default
		Secure:   true,
		HTTPOnly: true,
		Path:     "/",
		MaxAge:   3600,
	})

	rr := httptest.NewRecorder()
	middleware.setSessionCookie(rr, "session-default")

	cookies := rr.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	if cookies[0].SameSite != http.SameSiteStrictMode {
		t.Errorf("expected SameSiteStrictMode (default), got %v", cookies[0].SameSite)
	}
}

func TestFinal_SetSessionCookie_EnforceSecure(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, &CookieOptions{
		Secure:   false, // should be enforced to true
		HTTPOnly: true,
		SameSite: "Strict",
		Path:     "/",
		MaxAge:   3600,
	})

	rr := httptest.NewRecorder()
	middleware.setSessionCookie(rr, "session-insecure")

	cookies := rr.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	if !cookies[0].Secure {
		t.Error("expected Secure to be enforced to true")
	}
}

func TestFinal_SetSessionCookie_EnforceHttpOnly(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, &CookieOptions{
		Secure:   true,
		HTTPOnly: false, // should be enforced to true
		SameSite: "Strict",
		Path:     "/",
		MaxAge:   3600,
	})

	rr := httptest.NewRecorder()
	middleware.setSessionCookie(rr, "session-no-httponly")

	cookies := rr.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	if !cookies[0].HttpOnly {
		t.Error("expected HttpOnly to be enforced to true")
	}
}

func TestFinal_SetSessionCookie_Domain(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, &CookieOptions{
		Secure:   true,
		HTTPOnly: true,
		SameSite: "Strict",
		Path:     "/auth",
		Domain:   "example.com",
		MaxAge:   7200,
	})

	rr := httptest.NewRecorder()
	middleware.setSessionCookie(rr, "session-domain")

	cookies := rr.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	if cookies[0].Domain != "example.com" {
		t.Errorf("expected Domain example.com, got %s", cookies[0].Domain)
	}
	if cookies[0].Path != "/auth" {
		t.Errorf("expected Path /auth, got %s", cookies[0].Path)
	}
}

// =========================================================================
// clearSessionCookie (66.7% → 95%+)
// Test: enforce Secure and HttpOnly flags
// =========================================================================

func TestFinal_ClearSessionCookie_EnforcesSecure(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, &CookieOptions{
		Secure:   false, // should be enforced to true
		HTTPOnly: true,
		SameSite: "Strict",
		Path:     "/",
	})

	rr := httptest.NewRecorder()
	middleware.clearSessionCookie(rr)

	cookies := rr.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	c := cookies[0]
	if !c.Secure {
		t.Error("expected Secure to be enforced to true on clear")
	}
	if c.MaxAge != -1 {
		t.Errorf("expected MaxAge=-1, got %d", c.MaxAge)
	}
	if c.Value != "" {
		t.Errorf("expected empty Value, got %q", c.Value)
	}
}

func TestFinal_ClearSessionCookie_EnforcesHttpOnly(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, &CookieOptions{
		Secure:   true,
		HTTPOnly: false, // should be enforced to true
		SameSite: "Strict",
		Path:     "/",
	})

	rr := httptest.NewRecorder()
	middleware.clearSessionCookie(rr)

	cookies := rr.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	c := cookies[0]
	if !c.HttpOnly {
		t.Error("expected HttpOnly to be enforced to true on clear")
	}
}

func TestFinal_ClearSessionCookie_VerifyAllFields(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, &CookieOptions{
		Secure:   true,
		HTTPOnly: true,
		SameSite: "Strict",
		Path:     "/",
		Domain:   "example.com",
	})

	rr := httptest.NewRecorder()
	middleware.clearSessionCookie(rr)

	cookies := rr.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	c := cookies[0]
	if c.Name != "sso_session" {
		t.Errorf("expected Name sso_session, got %s", c.Name)
	}
	if c.Value != "" {
		t.Errorf("expected empty Value, got %q", c.Value)
	}
	if c.MaxAge != -1 {
		t.Errorf("expected MaxAge=-1, got %d", c.MaxAge)
	}
	if !c.Secure {
		t.Error("expected Secure=true")
	}
	if !c.HttpOnly {
		t.Error("expected HttpOnly=true")
	}
	if c.Path != "/" {
		t.Errorf("expected Path=/, got %s", c.Path)
	}
	if c.Domain != "example.com" {
		t.Errorf("expected Domain=example.com, got %s", c.Domain)
	}
}

// =========================================================================
// handleUnauthorized (85.7% → 95%+)
// Test: web path redirect to /login
// =========================================================================

func TestFinal_HandleUnauthorized_WebPath(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	rr := httptest.NewRecorder()
	middleware.handleUnauthorized(rr, req, NewSSOError(ErrSessionExpired, "session expired"))

	if rr.Code != http.StatusTemporaryRedirect {
		t.Errorf("expected 307 redirect for web path, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if loc != "/login" {
		t.Errorf("expected redirect to /login, got %s", loc)
	}
}

func TestFinal_HandleUnauthorized_APIPath(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/data", nil)
	rr := httptest.NewRecorder()
	middleware.handleUnauthorized(rr, req, NewSSOError(ErrInvalidToken, "bad token"))

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `"error":"unauthorized"`) {
		t.Errorf("expected JSON error in body, got %s", body)
	}
	if !strings.Contains(body, "bad token") {
		t.Errorf("expected error message in body, got %s", body)
	}
	ct := rr.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", ct)
	}
}

// =========================================================================
// handleForbidden (85.7% → 95%+)
// Test: web path → plain 403, API path → JSON 403
// =========================================================================

func TestFinal_HandleForbidden_WebPath(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)

	req := httptest.NewRequest(http.MethodGet, "/settings", nil)
	rr := httptest.NewRecorder()
	middleware.handleForbidden(rr, req, NewSSOError(ErrUserNotAllowed, "insufficient role"))

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
	body := rr.Body.String()
	if body != "Forbidden\n" {
		t.Errorf("expected 'Forbidden', got %q", body)
	}
}

func TestFinal_HandleForbidden_APIPath(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin", nil)
	rr := httptest.NewRecorder()
	middleware.handleForbidden(rr, req, NewSSOError(ErrUserNotAllowed, "insufficient role"))

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `"error":"forbidden"`) {
		t.Errorf("expected JSON error in body, got %s", body)
	}
	if !strings.Contains(body, "insufficient role") {
		t.Errorf("expected error message in body, got %s", body)
	}
	ct := rr.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", ct)
	}
}

// =========================================================================
// MetadataHandler (71.4% → 95%+)
// Test: success path returning XML metadata
// =========================================================================

func TestFinal_MetadataHandler_Success(t *testing.T) {
	manager, mp := setupManagerWithProvider()
	mp.metadata = []byte("<EntityDescriptor>mock-saml-metadata</EntityDescriptor>")
	middleware := NewMiddleware(manager, nil)

	handler := middleware.MetadataHandler("test-provider")
	req := httptest.NewRequest(http.MethodGet, "/sso/metadata", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/xml" {
		t.Errorf("expected Content-Type application/xml, got %s", ct)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "mock-saml-metadata") {
		t.Errorf("expected metadata in body, got %s", body)
	}
}

func TestFinal_MetadataHandler_DefaultMetadata(t *testing.T) {
	manager, _ := setupManagerWithProvider()
	// mp.metadata is nil, so Metadata() returns default mock data
	middleware := NewMiddleware(manager, nil)

	handler := middleware.MetadataHandler("test-provider")
	req := httptest.NewRequest(http.MethodGet, "/sso/metadata", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/xml" {
		t.Errorf("expected Content-Type application/xml, got %s", ct)
	}
}

// =========================================================================
// LoginHandler (83.3% → 95%+)
// Test: success path with redirect
// =========================================================================

func TestFinal_LoginHandler_Success(t *testing.T) {
	manager, mp := setupManagerWithProvider()
	mp.loginURL = "https://idp.example.com/login?state=abc"
	middleware := NewMiddleware(manager, nil)

	handler := middleware.LoginHandler("test-provider")
	req := httptest.NewRequest(http.MethodGet, "/sso/login", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusTemporaryRedirect {
		t.Errorf("expected 307 redirect, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "idp.example.com") {
		t.Errorf("expected redirect to idp login URL, got %s", loc)
	}
}

// =========================================================================
// LogoutHandler (88.2% → 95%+)
// Test: session from cookie, logout URL from provider
// =========================================================================

func TestFinal_LogoutHandler_SessionFromCookie(t *testing.T) {
	manager, mp := setupManagerWithProvider()
	mp.logoutURL = "https://idp.example.com/logout"
	middleware := NewMiddleware(manager, nil)
	_ = createValidSession(manager, "logout-session-1", "test-provider")

	handler := middleware.LogoutHandler("/after-logout")

	req := httptest.NewRequest(http.MethodGet, "/logout", nil)
	req.AddCookie(&http.Cookie{Name: "sso_session", Value: "logout-session-1"})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Should redirect to provider logout URL
	if rr.Code != http.StatusTemporaryRedirect {
		t.Errorf("expected 307 redirect, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if loc != "https://idp.example.com/logout" {
		t.Errorf("expected redirect to provider logout URL, got %s", loc)
	}

	// Cookie should be cleared
	for _, c := range rr.Result().Cookies() {
		if c.Name == "sso_session" && c.MaxAge == -1 {
			// Found cleared cookie - good
			return
		}
	}
}

func TestFinal_LogoutHandler_SessionFromContext(t *testing.T) {
	manager, mp := setupManagerWithProvider()
	mp.logoutURL = "https://idp.example.com/logout"
	middleware := NewMiddleware(manager, nil)
	session := createValidSession(manager, "logout-ctx-session", "test-provider")

	handler := middleware.LogoutHandler("/after-logout")

	req := httptest.NewRequest(http.MethodGet, "/logout", nil)
	ctx := ContextWithSession(req.Context(), session)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req.WithContext(ctx))

	if rr.Code != http.StatusTemporaryRedirect {
		t.Errorf("expected 307 redirect, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if loc != "https://idp.example.com/logout" {
		t.Errorf("expected redirect to provider logout, got %s", loc)
	}
}

func TestFinal_LogoutHandler_NoProviderLogoutURL(t *testing.T) {
	manager, mp := setupManagerWithProvider()
	mp.logoutURL = "" // no logout URL
	middleware := NewMiddleware(manager, nil)
	_ = createValidSession(manager, "logout-nourl", "test-provider")

	handler := middleware.LogoutHandler("/after-logout")

	req := httptest.NewRequest(http.MethodGet, "/logout", nil)
	req.AddCookie(&http.Cookie{Name: "sso_session", Value: "logout-nourl"})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// No provider logout URL → redirect to /after-logout
	if rr.Code != http.StatusTemporaryRedirect {
		t.Errorf("expected 307 redirect to after-logout, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if loc != "/after-logout" {
		t.Errorf("expected redirect to /after-logout, got %s", loc)
	}
}

func TestFinal_LogoutHandler_NoRedirectURL(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)

	handler := middleware.LogoutHandler("") // no redirect URL, no session

	req := httptest.NewRequest(http.MethodGet, "/logout", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Logged out successfully") {
		t.Errorf("expected 'Logged out successfully', got %s", body)
	}
}

// =========================================================================
// Manager: InitiateLogin (80.0% → 95%+)
// Test: success path with a registered provider
// =========================================================================

func TestFinal_InitiateLogin_Success(t *testing.T) {
	manager, _ := NewManager(nil)
	mp := &mockProviderFinal{
		name:     "login-provider",
		typ:      ProviderOIDC,
		loginURL: "https://idp.example.com/auth?state=xyz",
	}
	manager.SetProvidersForTest(map[string]SSOProviderInterface{
		"login-provider": mp,
	})
	manager.SetConfigsForTest(map[string]*SSOConfig{
		"login-provider": {Name: "login-provider", Provider: ProviderOIDC, OIDC: &OIDCConfig{ClientID: "test"}},
	})

	loginURL, req, err := manager.InitiateLogin("login-provider")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if loginURL == "" {
		t.Error("expected non-empty login URL")
	}
	if req == nil {
		t.Error("expected non-nil request")
	}
	if req.Provider != "login-provider" {
		t.Errorf("expected provider login-provider, got %s", req.Provider)
	}

	// Verify request was stored
	stored, err := manager.requests.Get(req.ID)
	if err != nil {
		t.Fatalf("expected request to be stored, got error: %v", err)
	}
	if stored.ID != req.ID {
		t.Errorf("expected stored request ID %s, got %s", req.ID, stored.ID)
	}
}

func TestFinal_InitiateLogin_FailInit(t *testing.T) {
	manager, _ := NewManager(nil)
	mp := &mockProviderFinal{
		name:     "fail-init-provider",
		typ:      ProviderOIDC,
		failInit: true,
	}
	manager.SetProvidersForTest(map[string]SSOProviderInterface{
		"fail-init-provider": mp,
	})

	_, _, err := manager.InitiateLogin("fail-init-provider")
	if err == nil {
		t.Error("expected error from failed init")
	}
}

// =========================================================================
// Manager: HandleCallback (85.7% → 95%+)
// Test: missing state, state mismatch, success path, session creation
// =========================================================================

func TestFinal_HandleCallback_MissingState(t *testing.T) {
	manager, mp := setupManagerWithProvider()
	mp.user = &SSOUser{ID: "user-cb-missing-state"}
	mp.session = &SSOSession{
		ID: "cb-session-missing-state", UserID: "user-cb-missing-state", Provider: ProviderOIDC,
		ProviderName: "test-provider", Active: true,
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	// With a registered provider, missing state parameter should return ErrInvalidCallback
	_, err := manager.HandleCallback("test-provider", map[string]string{"code": "abc"})
	if err == nil {
		t.Error("expected error for missing state parameter")
	}
	ssoErr, ok := err.(*SSOError)
	if !ok {
		t.Fatalf("expected SSOError, got %T", err)
	}
	if ssoErr.Code != ErrInvalidCallback {
		t.Errorf("expected error code %s, got %s", ErrInvalidCallback, ssoErr.Code)
	}
}

func TestFinal_HandleCallback_StateMismatch(t *testing.T) {
	manager, _ := NewManager(nil)

	_, err := manager.HandleCallback("test-provider", map[string]string{"state": "unknown-state"})
	if err == nil {
		t.Error("expected error for unknown state")
	}
}

func TestFinal_HandleCallback_ProviderMismatch(t *testing.T) {
	manager, mp := setupManagerWithProvider()
	mp.user = &SSOUser{ID: "user-cb"}
	mp.session = &SSOSession{
		ID: "cb-session", UserID: "user-cb", Provider: ProviderOIDC,
		ProviderName: "test-provider", Active: true,
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	// Create request with a DIFFERENT provider name
	ssoReq := &SSORequest{ID: "cb-req-mismatch", Provider: "other-provider", State: "state-mismatch"}
	_ = manager.requests.Create(ssoReq)

	_, err := manager.HandleCallback("test-provider", map[string]string{"state": "state-mismatch", "code": "abc"})
	if err == nil {
		t.Error("expected error for provider mismatch")
	}
	ssoErr, ok := err.(*SSOError)
	if !ok {
		t.Fatalf("expected SSOError, got %T", err)
	}
	if ssoErr.Code != ErrInvalidCallback {
		t.Errorf("expected error code %s, got %s", ErrInvalidCallback, ssoErr.Code)
	}
}

func TestFinal_HandleCallback_Success(t *testing.T) {
	manager, mp := setupManagerWithProvider()
	mp.user = &SSOUser{ID: "user-cb-success", Email: "user@example.com", Groups: []string{"admins"}}
	mp.session = &SSOSession{
		ID: "cb-session-success", UserID: "user-cb-success", Provider: ProviderOIDC,
		ProviderName: "test-provider", Active: true,
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	ssoReq := &SSORequest{ID: "cb-req-success", Provider: "test-provider", State: "state-success"}
	_ = manager.requests.Create(ssoReq)

	resp, err := manager.HandleCallback("test-provider", map[string]string{"state": "state-success", "code": "auth-code"})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !resp.Success {
		t.Error("expected successful response")
	}
	if resp.Session == nil {
		t.Error("expected session in response")
	}
	if resp.User == nil {
		t.Error("expected user in response")
	}

	// Verify request was deleted
	_, err = manager.requests.Get("cb-req-success")
	if err == nil {
		t.Error("expected request to be deleted after callback")
	}
}

func TestFinal_HandleCallback_CallbackError(t *testing.T) {
	manager, mp := setupManagerWithProvider()
	mp.failCallback = true

	ssoReq := &SSORequest{ID: "cb-req-error", Provider: "test-provider", State: "state-error"}
	_ = manager.requests.Create(ssoReq)

	_, err := manager.HandleCallback("test-provider", map[string]string{"state": "state-error", "code": "abc"})
	if err == nil {
		t.Error("expected error from failed callback")
	}
}

// =========================================================================
// Manager: TerminateUserSessions (85.7% → 95%+)
// Test: with actual sessions for the user
// =========================================================================

func TestFinal_TerminateUserSessions_WithSessions(t *testing.T) {
	manager, _ := NewManager(nil)

	// Create sessions for user
	session1 := &SSOSession{
		ID: "term-sess-1", UserID: "user-term", Active: true,
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	session2 := &SSOSession{
		ID: "term-sess-2", UserID: "user-term", Active: true,
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	_ = manager.sessions.Create(session1)
	_ = manager.sessions.Create(session2)

	err := manager.TerminateUserSessions("user-term")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify sessions are now inactive
	s1, _ := manager.sessions.Get("term-sess-1")
	if s1.Active {
		t.Error("expected session 1 to be inactive after termination")
	}
	s2, _ := manager.sessions.Get("term-sess-2")
	if s2.Active {
		t.Error("expected session 2 to be inactive after termination")
	}
}

func TestFinal_TerminateUserSessions_NoSessions(t *testing.T) {
	manager, _ := NewManager(nil)

	err := manager.TerminateUserSessions("nonexistent-user")
	if err != nil {
		t.Fatalf("expected no error for nonexistent user, got %v", err)
	}
}

// =========================================================================
// RequireSession: session found via Bearer token
// =========================================================================

func TestFinal_RequireSession_BearerToken(t *testing.T) {
	manager, _ := setupManagerWithProvider()
	middleware := NewMiddleware(manager, nil)
	_ = createValidSession(manager, "req-bearer-1", "test-provider")

	called := false
	handler := middleware.RequireSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		sess := SessionFromContext(r.Context())
		if sess == nil || sess.ID != "req-bearer-1" {
			t.Errorf("expected session in context, got %v", sess)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.Header.Set("Authorization", "Bearer req-bearer-1")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !called {
		t.Error("expected next handler to be called")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// =========================================================================
// RequireSession: session with nil user in context
// =========================================================================

func TestFinal_RequireSession_SessionWithNilUser(t *testing.T) {
	manager, _ := setupManagerWithProvider()
	middleware := NewMiddleware(manager, nil)

	session := &SSOSession{
		ID:           "req-nil-user",
		UserID:       "user-nil",
		Provider:     ProviderOIDC,
		ProviderName: "test-provider",
		Active:       true,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(24 * time.Hour),
		User:         nil,
	}
	_ = manager.sessions.Create(session)

	called := false
	handler := middleware.RequireSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		sess := SessionFromContext(r.Context())
		if sess == nil || sess.ID != "req-nil-user" {
			t.Errorf("expected session in context, got %v", sess)
		}
		user := UserFromContext(r.Context())
		if user != nil {
			t.Errorf("expected nil user in context, got %v", user)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: "sso_session", Value: "req-nil-user"})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !called {
		t.Error("expected next handler to be called")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// =========================================================================
// Manager: Logout (86.7% → 95%+)
// Test: provider not found (just clears local session), success path
// =========================================================================

func TestFinal_Logout_ProviderNotFound(t *testing.T) {
	manager, _ := NewManager(nil)

	session := &SSOSession{
		ID:           "logout-no-provider",
		UserID:       "user-logout",
		Provider:     ProviderOIDC,
		ProviderName: "nonexistent",
		Active:       true,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(24 * time.Hour),
	}
	_ = manager.sessions.Create(session)

	logoutURL, err := manager.Logout("logout-no-provider")
	if err != nil {
		t.Errorf("expected no error when provider not found, got %v", err)
	}
	if logoutURL != "" {
		t.Errorf("expected empty logout URL when provider not found, got %s", logoutURL)
	}

	// Verify session was deleted
	_, err = manager.sessions.Get("logout-no-provider")
	if err == nil {
		t.Error("expected session to be deleted after logout")
	}
}

func TestFinal_Logout_WithProvider(t *testing.T) {
	manager, mp := setupManagerWithProvider()
	mp.logoutURL = "https://idp.example.com/logout?id_token_hint=xxx"

	session := &SSOSession{
		ID:           "logout-with-provider",
		UserID:       "user-logout-prov",
		Provider:     ProviderOIDC,
		ProviderName: "test-provider",
		Active:       true,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(24 * time.Hour),
		IDToken:      "some-id-token",
	}
	_ = manager.sessions.Create(session)

	logoutURL, err := manager.Logout("logout-with-provider")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if logoutURL == "" {
		t.Error("expected non-empty logout URL")
	}

	// Verify session was deleted
	_, err = manager.sessions.Get("logout-with-provider")
	if err == nil {
		t.Error("expected session to be deleted after logout")
	}
}
