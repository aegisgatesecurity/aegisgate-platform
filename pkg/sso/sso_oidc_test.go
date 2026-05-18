//go:build !race

// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// SSO OIDC Coverage Tests - Session 15
// =========================================================================

package sso

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// =========================================================================
// OIDC ValidateSession tests (80.0% → 95%+)
// =========================================================================

func TestOIDCValidateSession_NilSession(t *testing.T) {
	provider := &OIDCProvider{
		config: &SSOConfig{
			OIDC: &OIDCConfig{
				ClientID: "test-client",
			},
		},
	}

	err := provider.ValidateSession(nil)
	if err == nil {
		t.Error("expected error for nil session")
	}
}

func TestOIDCProvider_ValidateSession_Expired(t *testing.T) {
	provider := &OIDCProvider{
		config: &SSOConfig{
			OIDC: &OIDCConfig{
				ClientID:     "test-client",
				ClientSecret: "test-secret",
			},
		},
	}

	session := &SSOSession{
		ID:          "expired-session",
		AccessToken: "expired-access-token",
		ExpiresAt:   time.Now().Add(-1 * time.Hour),
	}

	err := provider.ValidateSession(session)
	if err == nil {
		t.Error("expected error for expired session")
	}
}

// =========================================================================
// OIDC Logout tests (91.7% → 95%+)
// =========================================================================

func TestOIDCLogout_NilSession(t *testing.T) {
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
// OIDC discover error tests (78.1% → 95%+)
// =========================================================================

func TestOIDCProvider_Discover_MissingIssuerURL(t *testing.T) {
	provider := &OIDCProvider{
		config: &SSOConfig{
			OIDC: &OIDCConfig{
				ClientID:  "test-client",
				IssuerURL: "", // Missing
			},
		},
		oidcConfig: &OIDCConfig{},
	}

	err := provider.discover()
	if err == nil {
		t.Error("expected error for missing issuer URL")
	}
}

func TestOIDCProvider_Discover_404Issuer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Not Found", http.StatusNotFound)
	}))
	defer server.Close()

	provider := &OIDCProvider{
		config: &SSOConfig{
			OIDC: &OIDCConfig{
				ClientID:  "test-client",
				IssuerURL: server.URL,
			},
		},
		oidcConfig: &OIDCConfig{},
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}

	err := provider.discover()
	if err == nil {
		t.Error("expected error for 404 issuer")
	}
}

func TestOIDCProvider_Discover_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{not valid json`))
	}))
	defer server.Close()

	provider := &OIDCProvider{
		config: &SSOConfig{
			OIDC: &OIDCConfig{
				ClientID:  "test-client",
				IssuerURL: server.URL,
			},
		},
		oidcConfig: &OIDCConfig{},
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}

	err := provider.discover()
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestOIDCProvider_Discover_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Server Error", http.StatusInternalServerError)
	}))
	defer server.Close()

	provider := &OIDCProvider{
		config: &SSOConfig{
			OIDC: &OIDCConfig{
				ClientID:  "test-client",
				IssuerURL: server.URL,
			},
		},
		oidcConfig: &OIDCConfig{},
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}

	err := provider.discover()
	if err == nil {
		t.Error("expected error for HTTP error")
	}
}

// =========================================================================
// OIDC getUserInfo tests (75.0% → 95%+)
// =========================================================================

func TestOIDCProvider_GetUserInfo_MissingURL(t *testing.T) {
	provider := &OIDCProvider{
		config: &SSOConfig{
			OIDC: &OIDCConfig{
				ClientID: "test-client",
			},
		},
		oidcConfig: &OIDCConfig{
			UserInfoURL: "", // Missing
		},
	}

	_, err := provider.getUserInfo("test-token")
	if err == nil {
		t.Error("expected error for missing userinfo URL")
	}
}

func TestOIDCProvider_GetUserInfo_Success(t *testing.T) {
	mockServer := NewMockOIDCServer()
	defer mockServer.Close()

	provider, err := mockServer.NewOIDCProvider()
	if err != nil {
		t.Fatalf("failed to create OIDC provider: %v", err)
	}

	userInfo, err := provider.getUserInfo("valid-access-token")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if userInfo == nil {
		t.Error("expected user info")
	}
	if userInfo["sub"] != "test-user" {
		t.Errorf("expected sub test-user, got %v", userInfo["sub"])
	}
}

func TestOIDCProvider_GetUserInfo_Unauthorized(t *testing.T) {
	mockServer := NewMockOIDCServer()
	defer mockServer.Close()

	provider, err := mockServer.NewOIDCProvider()
	if err != nil {
		t.Fatalf("failed to create OIDC provider: %v", err)
	}

	// Test with no/invalid token
	_, err = provider.getUserInfo("")
	if err == nil {
		t.Error("expected error for empty token")
	}
}

// =========================================================================
// OIDC parseIDToken tests (85.7% → 95%+)
// =========================================================================

func TestOIDCParseIDToken_Empty(t *testing.T) {
	provider := &OIDCProvider{
		config: &SSOConfig{
			OIDC: &OIDCConfig{
				ClientID:     "test-client",
				ClientSecret: "test-secret",
			},
		},
	}

	_, err := provider.parseIDToken("")
	if err == nil {
		t.Error("expected error for empty token")
	}
}

func TestOIDCProvider_ParseIDToken_InvalidFormat(t *testing.T) {
	provider := &OIDCProvider{
		config: &SSOConfig{
			OIDC: &OIDCConfig{
				ClientID:     "test-client",
				ClientSecret: "test-secret",
			},
		},
	}

	_, err := provider.parseIDToken("not-a-jwt")
	if err == nil {
		t.Error("expected error for invalid format")
	}
}

func TestOIDCProvider_ParseIDToken_InvalidBase64(t *testing.T) {
	provider := &OIDCProvider{
		config: &SSOConfig{
			OIDC: &OIDCConfig{
				ClientID:     "test-client",
				ClientSecret: "test-secret",
			},
		},
	}

	_, err := provider.parseIDToken("part1.part2.!!!")
	if err == nil {
		t.Error("expected error for invalid base64")
	}
}

// =========================================================================
// MockOIDCServer isAllowedRedirect tests (44.4% → 95%+)
// =========================================================================

func TestMockOIDCServer_IsAllowedRedirect_Empty(t *testing.T) {
	mock := NewMockOIDCServer()
	defer mock.Close()

	// Empty redirect should be allowed (same origin default)
	if !mock.isAllowedRedirect("") {
		t.Error("expected empty redirect to be allowed")
	}
}

func TestMockOIDCServer_IsAllowedRedirect_SameOrigin(t *testing.T) {
	mock := NewMockOIDCServer()
	defer mock.Close()

	// Same origin should be allowed
	if !mock.isAllowedRedirect(mock.Server.URL + "/callback") {
		t.Error("expected same-origin redirect to be allowed")
	}
}

func TestMockOIDCServer_IsAllowedRedirect_Configured(t *testing.T) {
	mock := NewMockOIDCServer()
	defer mock.Close()

	// Set allowed redirect URIs
	mock.AllowedRedirectURIs = []string{"https://app.example.com/callback"}

	// Configured redirect should be allowed
	if !mock.isAllowedRedirect("https://app.example.com/callback") {
		t.Error("expected configured redirect to be allowed")
	}

	// Unconfigured redirect should be denied
	if mock.isAllowedRedirect("https://evil.example.com/callback") {
		t.Error("expected unconfigured redirect to be denied")
	}
}

func TestMockOIDCServer_IsAllowedRedirect_Invalid(t *testing.T) {
	mock := NewMockOIDCServer()
	defer mock.Close()

	// Invalid URL should be denied
	if mock.isAllowedRedirect("://invalid") {
		t.Error("expected invalid URL to be denied")
	}
}

// =========================================================================
// Manager InitiateLogin tests (80.0% → 95%+)
// =========================================================================

func TestManager_InitiateLogin_WithMockProvider(t *testing.T) {
	manager, _ := NewManager(nil)
	mockServer := NewMockOIDCServer()
	defer mockServer.Close()

	provider, err := mockServer.NewOIDCProvider()
	if err != nil {
		t.Fatalf("failed to create OIDC provider: %v", err)
	}

	// Register provider using internal map
	manager.mu.Lock()
	manager.providers["test-oidc"] = provider
	manager.mu.Unlock()

	_, _, err = manager.InitiateLogin("test-oidc")
	if err != nil {
		t.Errorf("expected no error with valid provider, got %v", err)
	}
}

// =========================================================================
// OIDC InitiateLogin tests (64.3% → 95%+)
// =========================================================================

func TestOIDCProvider_InitiateLogin_WithStore(t *testing.T) {
	mockServer := NewMockOIDCServer()
	defer mockServer.Close()

	provider, err := mockServer.NewOIDCProvider()
	if err != nil {
		t.Fatalf("failed to create OIDC provider: %v", err)
	}

	// Use the store from the provider
	loginURL, ssoReq, err := provider.InitiateLogin("test-state")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if loginURL == "" {
		t.Error("expected login URL")
	}
	if ssoReq == nil {
		t.Error("expected SSO request")
	}
}

// =========================================================================
// CallbackHandler error tests (64.7% → 95%+)
// =========================================================================

func TestCallbackHandler_OIDCErrorNoRedirect(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)

	// No failure redirect URL - should return 401
	handler := middleware.CallbackHandler("nonexistent", "", "")

	req := httptest.NewRequest(http.MethodGet, "/callback?error=access_denied", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for error without failure redirect, got %d", rr.Code)
	}
}

func TestCallbackHandler_OIDCErrorWithRedirect(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)

	// Error with failure redirect - should redirect
	handler := middleware.CallbackHandler("nonexistent", "/success", "/failure")

	req := httptest.NewRequest(http.MethodGet, "/callback?error=access_denied&error_description=user_denied", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusTemporaryRedirect {
		t.Errorf("expected 307 redirect for error with failure URL, got %d", rr.Code)
	}
}

// =========================================================================
// handleUnauthorized/handleForbidden API tests (85.7% → 95%+)
// =========================================================================

func TestHandleUnauthorized_APIRequest(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/resource", nil)
	rr := httptest.NewRecorder()

	err := NewSSOError(ErrInvalidToken, "token expired")
	middleware.handleUnauthorized(rr, req, err)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for API request, got %d", rr.Code)
	}

	if rr.Header().Get("Content-Type") != "application/json" {
		t.Errorf("expected JSON content type, got %s", rr.Header().Get("Content-Type"))
	}
}

func TestHandleForbidden_APIRequest(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin", nil)
	rr := httptest.NewRecorder()

	err := NewSSOError(ErrUserNotAllowed, "insufficient role")
	middleware.handleForbidden(rr, req, err)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for API request, got %d", rr.Code)
	}

	if rr.Header().Get("Content-Type") != "application/json" {
		t.Errorf("expected JSON content type, got %s", rr.Header().Get("Content-Type"))
	}
}

// =========================================================================
// OptionalSession tests (60.0% → 95%+)
// =========================================================================

func TestOptionalSession_InvalidCookie_PassesThrough(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)

	handler := middleware.OptionalSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Invalid session cookie - should pass through
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "sso_session", Value: "invalid-session-id"})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 with invalid session cookie, got %d", rr.Code)
	}
}

func TestOptionalSession_ValidSessionFromCookie(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)

	// Create valid session
	session := &SSOSession{
		ID:           "valid-optional-session",
		UserID:       "user-optional",
		ProviderName: "mock",
		Active:       true,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(24 * time.Hour),
	}
	_ = manager.sessions.Create(session)

	handler := middleware.OptionalSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "sso_session", Value: "valid-optional-session"})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 with valid session, got %d", rr.Code)
	}
}

func TestOptionalSession_ExpiredSession_PassesThrough(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)

	// Create expired session
	session := &SSOSession{
		ID:           "expired-optional-session",
		UserID:       "user-optional",
		ProviderName: "mock",
		Active:       false,
		CreatedAt:    time.Now().Add(-48 * time.Hour),
		ExpiresAt:    time.Now().Add(-24 * time.Hour),
	}
	_ = manager.sessions.Create(session)

	handler := middleware.OptionalSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "sso_session", Value: "expired-optional-session"})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Expired session should still pass through (optional)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 with expired session (optional), got %d", rr.Code)
	}
}

// =========================================================================
// LoginHandler error tests (83.3% → 95%+)
// =========================================================================

func TestLoginHandler_ProviderError(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)

	handler := middleware.LoginHandler("nonexistent")

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound && rr.Code != http.StatusInternalServerError {
		t.Errorf("expected error status for unknown provider, got %d", rr.Code)
	}
}

// =========================================================================
// LogoutHandler tests (88.2% → 95%+)
// =========================================================================

func TestLogoutHandler_SessionFromCookie(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)

	// Create session
	session := &SSOSession{
		ID:           "logout-cookie-session",
		UserID:       "user-cookie-logout",
		ProviderName: "mock",
		Active:       true,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(24 * time.Hour),
	}
	_ = manager.sessions.Create(session)

	handler := middleware.LogoutHandler("/after-logout")

	req := httptest.NewRequest(http.MethodGet, "/logout", nil)
	req.AddCookie(&http.Cookie{Name: "sso_session", Value: "logout-cookie-session"})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusTemporaryRedirect && rr.Code != http.StatusOK {
		t.Errorf("expected redirect or OK, got %d", rr.Code)
	}
}

// =========================================================================
// MetadataHandler tests (71.4% → 95%+)
// =========================================================================

func TestMetadataHandler_ServiceError(t *testing.T) {
	manager, _ := NewManager(nil)
	middleware := NewMiddleware(manager, nil)

	handler := middleware.MetadataHandler("nonexistent")

	req := httptest.NewRequest(http.MethodGet, "/sso/metadata", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unknown provider, got %d", rr.Code)
	}
}
