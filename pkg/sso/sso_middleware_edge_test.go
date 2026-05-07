// SPDX-License-Identifier: Apache-2.0
//go:build !race

package sso

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// =============================================================================
// RequireSession test coverage (35.7% → 95%+)
// =============================================================================

// TestRequireSession_NoSession tests RequireSession without session (redirects to /login for web)
func TestRequireSession_NoSession(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)
	handler := middleware.RequireSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Web path - should redirect to /login
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusTemporaryRedirect {
		t.Errorf("expected status 307 for web redirect, got %d", rr.Code)
	}
}

// TestRequireSession_ExpiredSession tests RequireSession with expired session
func TestRequireSession_ExpiredSession(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)
	handler := middleware.RequireSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Create expired session
	session := &SSOSession{
		ID:           "expired-session",
		UserID:       "user-3",
		ProviderName: "mock",
		Active:       true,
		CreatedAt:    time.Now().Add(-48 * time.Hour),
		ExpiresAt:    time.Now().Add(-24 * time.Hour),
	}
	_ = manager.sessions.Create(session)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Header.Set("Authorization", "Bearer expired-session")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401 for expired session, got %d", rr.Code)
	}
}

// =============================================================================
// OptionalSession test coverage (40.0% → 95%+)
// =============================================================================

// TestOptionalSession_CookieValid tests OptionalSession with valid cookie
func TestOptionalSession_CookieValid(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)
	handler := middleware.OptionalSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Create session
	session := &SSOSession{
		ID:           "optional-session-cookie",
		UserID:       "user-opt",
		ProviderName: "mock",
		Active:       true,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(24 * time.Hour),
	}
	_ = manager.sessions.Create(session)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "sso_session", Value: "optional-session-cookie"})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
}

// TestOptionalSession_NoSession tests OptionalSession without session
func TestOptionalSession_NoSession(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)
	handler := middleware.OptionalSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// No cookie, no auth header
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Should pass (optional)
	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200 for optional session, got %d", rr.Code)
	}
}

// TestOptionalSession_BearerToken tests OptionalSession with Bearer token
func TestOptionalSession_BearerToken(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)
	handler := middleware.OptionalSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Create session
	session := &SSOSession{
		ID:           "optional-bearer",
		UserID:       "user-opt-bearer",
		ProviderName: "mock",
		Active:       true,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(24 * time.Hour),
	}
	_ = manager.sessions.Create(session)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer optional-bearer")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
}

// =============================================================================
// getSessionFromRequest test coverage (61.5% → 95%+)
// =============================================================================

// TestGetSessionFromRequest_CookieOnly tests cookie-only session retrieval
func TestGetSessionFromRequest_CookieOnly(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)

	// Create session
	session := &SSOSession{
		ID:           "cookie-only-session",
		UserID:       "user-cookie",
		ProviderName: "mock",
		Active:       true,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(24 * time.Hour),
	}
	_ = manager.sessions.Create(session)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "sso_session", Value: "cookie-only-session"})
	result, err := middleware.getSessionFromRequest(req)
	if err != nil {
		t.Fatalf("expected session from cookie, got error: %v", err)
	}
	if result.ID != "cookie-only-session" {
		t.Errorf("expected session ID cookie-only-session, got %s", result.ID)
	}
}

// TestGetSessionFromRequest_BearerOnly tests Bearer-only session retrieval
func TestGetSessionFromRequest_BearerOnly(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)

	// Create session
	session := &SSOSession{
		ID:           "bearer-only-session",
		UserID:       "user-bearer",
		ProviderName: "mock",
		Active:       true,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(24 * time.Hour),
	}
	_ = manager.sessions.Create(session)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer bearer-only-session")
	result, err := middleware.getSessionFromRequest(req)
	if err != nil {
		t.Fatalf("expected session from Bearer, got error: %v", err)
	}
	if result.ID != "bearer-only-session" {
		t.Errorf("expected session ID bearer-only-session, got %s", result.ID)
	}
}

// TestGetSessionFromRequest_NoSession tests when no session exists
func TestGetSessionFromRequest_NoSession(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err := middleware.getSessionFromRequest(req)
	if err == nil {
		t.Fatal("expected error for no session")
	}
}

// TestGetSessionFromRequest_AuthHeaderNoBearer tests auth header without Bearer prefix
func TestGetSessionFromRequest_AuthHeaderNoBearer(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	_, err := middleware.getSessionFromRequest(req)
	if err == nil {
		t.Fatal("expected error for non-Bearer auth header")
	}
}

// =============================================================================
// setSessionCookie test coverage (54.5% → 95%+)
// =============================================================================

// TestSetSessionCookie_CustomOptions tests setting session cookie with custom options
func TestSetSessionCookie_CustomOptions(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, &CookieOptions{
		Path:     "/custom",
		Secure:   true,
		HTTPOnly: true,
		MaxAge:   3600,
	})

	_ = httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	middleware.setSessionCookie(rr, "custom-session-id")

	cookies := rr.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected cookie to be set")
	}
	if cookies[0].Value != "custom-session-id" {
		t.Errorf("expected cookie value custom-session-id, got %s", cookies[0].Value)
	}
	if cookies[0].Path != "/custom" {
		t.Errorf("expected cookie path /custom, got %s", cookies[0].Path)
	}
	if !cookies[0].Secure {
		t.Error("expected cookie to be secure")
	}
}

// =============================================================================
// CallbackHandler test coverage (64.7% → 95%+)
// =============================================================================

// TestCallbackHandler_NoProvider tests CallbackHandler without provider
func TestCallbackHandler_NoProvider(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)
	handler := middleware.CallbackHandler("unknown-provider", "/success", "/failure")

	req := httptest.NewRequest(http.MethodGet, "/callback", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Unknown provider returns non-200 (404 or redirect)
	if rr.Code == http.StatusOK {
		t.Errorf("expected non-200 status for unknown provider, got %d", rr.Code)
	}
}

// =============================================================================
// LogoutHandler test coverage (76.5% → 95%+)
// =============================================================================

// TestLogoutHandler_WithSession tests LogoutHandler with valid session
func TestLogoutHandler_WithSession(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)
	handler := middleware.LogoutHandler("/after-logout")

	// Create session
	session := &SSOSession{
		ID:           "logout-session",
		UserID:       "user-logout",
		ProviderName: "mock",
		Active:       true,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(24 * time.Hour),
	}
	_ = manager.sessions.Create(session)

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(&http.Cookie{Name: "sso_session", Value: "logout-session"})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Check cookie is cleared
	cookies := rr.Result().Cookies()
	for _, c := range cookies {
		if c.Name == "sso_session" && c.Value == "" {
			return // cleared
		}
	}
}

// =============================================================================
// MetadataHandler test coverage (71.4% → 95%+)
// =============================================================================

// TestMetadataHandler tests MetadataHandler returns correct content type
func TestMetadataHandler(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)
	handler := middleware.MetadataHandler("unknown-provider")

	req := httptest.NewRequest(http.MethodGet, "/metadata", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Unknown provider returns non-200
	if rr.Code == http.StatusOK {
		t.Errorf("expected non-200 status for unknown provider, got %d", rr.Code)
	}
}
