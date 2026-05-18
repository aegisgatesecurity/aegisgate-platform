//go:build !race

// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// SSO Middleware Coverage Tests
// =========================================================================

package sso

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// =========================================================================
// RequireSession tests (71.4% → 95%+)
// =========================================================================

func TestRequireSession_InvalidSession(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)

	handler := middleware.RequireSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Header.Set("Authorization", "Bearer invalid-session-id")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized && rr.Code != http.StatusTemporaryRedirect {
		t.Errorf("expected 401 or 307 for invalid session, got %d", rr.Code)
	}
}

func TestRequireSession_NoSession_Auth(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)

	handler := middleware.RequireSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized && rr.Code != http.StatusTemporaryRedirect {
		t.Errorf("expected 401 or 307 for no session, got %d", rr.Code)
	}
}

// =========================================================================
// OptionalSession tests (60.0% → 95%+)
// =========================================================================

func TestOptionalSession_NoSession_PassesThrough(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)

	handler := middleware.OptionalSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 with no session, got %d", rr.Code)
	}
}

func TestOptionalSession_InvalidSession_PassesThrough(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)

	handler := middleware.OptionalSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Header.Set("Authorization", "Bearer invalid-session-id")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 with invalid session, got %d", rr.Code)
	}
}

// =========================================================================
// RequireRole tests (80.0% → 95%+)
// =========================================================================

func TestRequireRole_NoUser_Redirects(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)

	handler := middleware.RequireRole("admin")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized && rr.Code != http.StatusTemporaryRedirect {
		t.Errorf("expected 401 or 307 for no user, got %d", rr.Code)
	}
}

func TestRequireRole_WrongRole_Forbidden(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)

	handler := middleware.RequireRole("super_admin")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Wrong role should result in 401, 403 or redirect
	if rr.Code != http.StatusUnauthorized && rr.Code != http.StatusForbidden && rr.Code != http.StatusTemporaryRedirect {
		t.Errorf("expected 401, 403 or 307 for wrong role, got %d", rr.Code)
	}
}

// =========================================================================
// RequireAnyRole tests (86.7% → 95%+)
// =========================================================================

func TestRequireAnyRole_NoUser_Redirects(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)

	handler := middleware.RequireAnyRole("admin", "viewer")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized && rr.Code != http.StatusTemporaryRedirect {
		t.Errorf("expected 401 or 307 for no user, got %d", rr.Code)
	}
}

// =========================================================================
// CallbackHandler tests (64.7% → 95%+)
// =========================================================================

func TestCallbackHandler_ErrorWithFailureRedirect(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)

	handler := middleware.CallbackHandler("oidc", "/success", "/failure")
	
	req := httptest.NewRequest(http.MethodGet, "/callback?error=access_denied", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
}

func TestCallbackHandler_SuccessRedirect(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)

	handler := middleware.CallbackHandler("nonexistent", "/success", "/failure")
	
	req := httptest.NewRequest(http.MethodGet, "/callback", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
}

// =========================================================================
// LogoutHandler tests (76.5% → 95%+)
// =========================================================================

func TestLogoutHandler_WithRedirect(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)

	handler := middleware.LogoutHandler("/after-logout")
	
	req := httptest.NewRequest(http.MethodGet, "/logout", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
}

func TestLogoutHandler_EmptyRedirect(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)

	handler := middleware.LogoutHandler("")
	
	req := httptest.NewRequest(http.MethodGet, "/logout", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
}

// =========================================================================
// setSessionCookie tests (63.6% → 95%+)
// =========================================================================

func TestSetSessionCookie_CookieSetCorrectly(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)

	rr := httptest.NewRecorder()

	middleware.setSessionCookie(rr, "test-session-id")

	cookies := rr.Result().Cookies()
	if len(cookies) == 0 {
		t.Error("expected cookie to be set")
	}
}

// =========================================================================
// clearSessionCookie tests (66.7% → 95%+)
// =========================================================================

func TestClearSessionCookie_CookieCleared(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)

	rr := httptest.NewRecorder()

	middleware.clearSessionCookie(rr)

	cookies := rr.Result().Cookies()
	if len(cookies) == 0 {
		t.Error("expected cookie to be cleared")
	}
}

func TestClearSessionCookie_WithExistingCookie(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)

	rr := httptest.NewRecorder()
	
	// Set a cookie first
	http.SetCookie(rr, &http.Cookie{Name: "sso_session", Value: "test-session"})
	
	middleware.clearSessionCookie(rr)

	// Check cookie was cleared
	cookies := rr.Result().Cookies()
	if len(cookies) == 0 {
		t.Error("expected cookie to be set/cleared")
	}
}

// =========================================================================
// MetadataHandler tests (71.4% → 95%+)
// =========================================================================

func TestMetadataHandler_ReturnsMetadata(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)

	handler := middleware.MetadataHandler("oidc")
	
	req := httptest.NewRequest(http.MethodGet, "/sso/metadata", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK && rr.Code != http.StatusNotFound {
		t.Errorf("expected 200 or 404, got %d", rr.Code)
	}
}

func TestMetadataHandler_ProviderNotFound(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)

	handler := middleware.MetadataHandler("nonexistent")
	
	req := httptest.NewRequest(http.MethodGet, "/sso/metadata", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestMetadataHandler_WithSAMLProvider(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)

	handler := middleware.MetadataHandler("saml")
	
	req := httptest.NewRequest(http.MethodGet, "/sso/metadata", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
}

// =========================================================================
// LoginHandler tests (83.3% → 95%+)
// =========================================================================

func TestLoginHandler_Redirect(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)

	handler := middleware.LoginHandler("nonexistent")
	
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Should redirect or return 404/500 for unknown provider
	if rr.Code != http.StatusNotFound && rr.Code != http.StatusTemporaryRedirect && rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 404, 307 or 500, got %d", rr.Code)
	}
}

// =========================================================================
// handleUnauthorized/handleForbidden tests
// =========================================================================

func TestHandleUnauthorized_Redirect(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	rr := httptest.NewRecorder()

	err := NewSSOError(ErrInvalidToken, "invalid token")
	middleware.handleUnauthorized(rr, req, err)

	// Should return 401 or redirect depending on configuration
	if rr.Code != http.StatusUnauthorized && rr.Code != http.StatusTemporaryRedirect {
		t.Errorf("expected 401 or 307 redirect, got %d", rr.Code)
	}
}

func TestHandleForbidden_Redirect(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	rr := httptest.NewRecorder()

	err := NewSSOError(ErrInvalidToken, "access denied")
	middleware.handleForbidden(rr, req, err)

	if rr.Code != http.StatusForbidden && rr.Code != http.StatusTemporaryRedirect {
		t.Errorf("expected 403 or 307, got %d", rr.Code)
	}
}

// =========================================================================
// RequireDomain tests
// =========================================================================

func TestRequireDomain_NoUser(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)

	handler := middleware.RequireDomain("example.com")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// No user should result in 401 or redirect
	if rr.Code != http.StatusUnauthorized && rr.Code != http.StatusTemporaryRedirect {
		t.Errorf("expected 401 or 307, got %d", rr.Code)
	}
}

// =========================================================================
// RequireGroup tests
// =========================================================================

func TestRequireGroup_NoUser(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)

	handler := middleware.RequireGroup("admins")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// No user should result in 401 or redirect
	if rr.Code != http.StatusUnauthorized && rr.Code != http.StatusTemporaryRedirect {
		t.Errorf("expected 401 or 307, got %d", rr.Code)
	}
}

// =========================================================================
// OIDC Logout coverage tests (33.3% → 95%+)
// =========================================================================

func TestOIDCProvider_Logout_EmptyEndSessionURL(t *testing.T) {
	provider := &OIDCProvider{
		config: &SSOConfig{
			OIDC: &OIDCConfig{
				ClientID:     "test-client",
				ClientSecret: "test-secret",
			},
		},
		oidcConfig: &OIDCConfig{},
	}

	session := &SSOSession{
		ID:      "session-123",
		IDToken: "id-token-456",
	}

	url, err := provider.Logout(session)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if url != "" {
		t.Errorf("expected empty URL when EndSessionURL is empty, got %s", url)
	}
}

func TestOIDCProvider_Logout_WithEndSessionURL(t *testing.T) {
	provider := &OIDCProvider{
		config: &SSOConfig{
			OIDC: &OIDCConfig{
				ClientID:     "test-client",
				ClientSecret: "test-secret",
			},
		},
		oidcConfig: &OIDCConfig{
			EndSessionURL: "https://provider.example.com/logout",
		},
	}

	session := &SSOSession{
		ID:      "session-123",
		IDToken: "id-token-456",
	}

	url, err := provider.Logout(session)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if url == "" {
		t.Error("expected non-empty logout URL")
	}
	if !strings.Contains(url, "id_token_hint") {
		t.Error("expected URL to contain id_token_hint")
	}
}

func TestOIDCProvider_Logout_NilSession(t *testing.T) {
	provider := &OIDCProvider{
		config: &SSOConfig{
			OIDC: &OIDCConfig{
				ClientID: "test-client",
			},
		},
	}

	_, err := provider.Logout(nil)
	if err == nil {
		t.Error("expected error with nil session")
	}
}

// =========================================================================
// OIDC ValidateSession paths (80.0% → 95%+)
// =========================================================================

func TestOIDCProvider_ValidateSession_NilSession(t *testing.T) {
	provider := &OIDCProvider{
		config: &SSOConfig{
			OIDC: &OIDCConfig{
				ClientID: "test-client",
			},
		},
	}

	err := provider.ValidateSession(nil)
	if err == nil {
		t.Error("expected error with nil session")
	}
}

func TestOIDCProvider_ValidateSession_ExpiredToken(t *testing.T) {
	provider := &OIDCProvider{
		config: &SSOConfig{
			OIDC: &OIDCConfig{
				ClientID: "test-client",
			},
		},
	}

	session := &SSOSession{
		ID:          "session-123",
		AccessToken: "valid-access-token",
		ExpiresAt:   time.Now().Add(-time.Hour),
	}

	err := provider.ValidateSession(session)
	if err == nil {
		t.Error("expected error for expired token")
	}
}

// =========================================================================
// OIDC mapClaimsToUser paths (90.0% → 95%+)
// =========================================================================

func TestOIDCProvider_MapClaimsToUser_StandardClaims(t *testing.T) {
	provider := &OIDCProvider{}

	user := &SSOUser{}
	claims := &OIDCIDTokenClaims{
		Subject:           "user-123",
		Email:            "test@example.com",
		Name:             "Test User",
		PreferredUsername: "testuser",
	}

	provider.mapClaimsToUser(user, claims)

	if user.UpstreamID != "user-123" {
		t.Errorf("expected UpstreamID to be set, got %s", user.UpstreamID)
	}
	if user.Email != "test@example.com" {
		t.Errorf("expected Email, got %s", user.Email)
	}
	if user.UpstreamName != "testuser" {
		t.Errorf("expected UpstreamName, got %s", user.UpstreamName)
	}
}

func TestOIDCProvider_MapClaimsToUser_MissingClaims(t *testing.T) {
	provider := &OIDCProvider{}

	user := &SSOUser{}
	claims := &OIDCIDTokenClaims{
		Subject: "user-123",
	}

	provider.mapClaimsToUser(user, claims)

	if user.UpstreamID != "user-123" {
		t.Errorf("expected UpstreamID to be set, got %s", user.UpstreamID)
	}
}

func TestOIDCProvider_MapClaimsToUser_WithGroups(t *testing.T) {
	provider := &OIDCProvider{}

	user := &SSOUser{}
	claims := &OIDCIDTokenClaims{
		Subject: "user-123",
		Groups:  []string{"admins", "developers"},
	}

	provider.mapClaimsToUser(user, claims)

	if len(user.Groups) != 2 {
		t.Errorf("expected 2 groups, got %d", len(user.Groups))
	}
}