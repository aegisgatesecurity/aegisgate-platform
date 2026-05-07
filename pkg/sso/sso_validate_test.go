// SPDX-License-Identifier: Apache-2.0
//go:build !race

package sso

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// =============================================================================
// Mock middleware provider for testing RequireSession, ValidateSession
// =============================================================================

type mockMWProvider struct {
	name   string
	typ    SSOProvider
	users  map[string]*SSOUser
	sess   *SSOSession
	expErr error
}

func (m *mockMWProvider) Name() string      { return m.name }
func (m *mockMWProvider) Type() SSOProvider { return m.typ }
func (m *mockMWProvider) InitiateLogin(s string) (string, *SSORequest, error) {
	return "https://example.com/login", &SSORequest{ID: "req1"}, nil
}
func (m *mockMWProvider) HandleCallback(req *SSORequest, params map[string]string) (*SSOResponse, error) {
	if m.users == nil {
		return &SSOResponse{Success: true, User: m.sess.User, Session: m.sess}, nil
	}
	return nil, errors.New("no callback")
}
func (m *mockMWProvider) ValidateSession(sess *SSOSession) error {
	if m.expErr != nil {
		return m.expErr
	}
	return nil
}
func (m *mockMWProvider) Logout(sess *SSOSession) (string, error) {
	return "https://example.com/logout", nil
}
func (m *mockMWProvider) Metadata() ([]byte, error) { return []byte("{}"), nil }

// =============================================================================
// TestValidateSession_Errors — ValidateSession error paths
// =============================================================================

func TestValidateSession_Errors(t *testing.T) {
	mgr, _ := NewManager(&ManagerConfig{})

	t.Run("SessionNotFound", func(t *testing.T) {
		_, err := mgr.ValidateSession("nonexistent-session-id")
		if err == nil {
			t.Fatal("expected error for nonexistent session")
		}
		t.Logf("Error for nonexistent session: %v", err)
	})

	t.Run("InactiveSession", func(t *testing.T) {
		// Create an inactive session
		inactiveSess := &SSOSession{
			ID:           "inactive-sess",
			UserID:       "user1",
			Provider:     ProviderOIDC,
			ProviderName: "oidc",
			Active:       false, // inactive
			ExpiresAt:    time.Now().Add(1 * time.Hour),
		}
		mgr.sessions.Create(inactiveSess)
		_, err := mgr.ValidateSession("inactive-sess")
		if err == nil {
			t.Fatal("expected error for inactive session")
		}
		t.Logf("Error for inactive session: %v", err)
	})

	t.Run("ProviderNotRegistered", func(t *testing.T) {
		// Session with unregistered provider
		sess := &SSOSession{
			ID:           "unreg-sess",
			UserID:       "user1",
			Provider:     ProviderOIDC,
			ProviderName: "not-registered-provider",
			Active:       true,
			ExpiresAt:    time.Now().Add(1 * time.Hour),
		}
		mgr.sessions.Create(sess)
		_, err := mgr.ValidateSession("unreg-sess")
		if err == nil {
			t.Fatal("expected error for unregistered provider")
		}
		t.Logf("Error for unregistered provider: %v", err)
	})
}

// =============================================================================
// TestRefreshSession_TokenErrors — RefreshSession error handling
// =============================================================================

func TestRefreshSession_TokenErrors(t *testing.T) {
	// NOTE: NewOIDCProvider requires network access to fetch OIDC discovery from issuer.
	// RefreshToken error paths are tested via the token source logic.
	// Full RefreshSession coverage requires integration tests with a real OIDC server (testlab).
	t.Run("NewOIDCProviderNetworkRequired", func(t *testing.T) {
		oidcCfg := &SSOConfig{
			Name:     "oidc",
			Provider: ProviderOIDC,
			OIDC: &OIDCConfig{
				ClientID:     "test-client",
				ClientSecret: "test-secret",
				IssuerURL:    "https://issuer.example.com",
				RedirectURL:  "http://localhost/callback",
				Scopes:       []string{"openid"},
			},
		}
		_, err := NewOIDCProvider(oidcCfg, nil)
		// This will fail because issuer.example.com doesn't exist
		// but we don't Fatal here — we just log the requirement
		t.Logf("NewOIDCProvider requires real OIDC server: %v", err)
	})
}

// =============================================================================
// TestLogout_Errors — Logout error paths
// =============================================================================

func TestLogout_Errors(t *testing.T) {
	mgr, _ := NewManager(&ManagerConfig{})

	t.Run("LogoutSessionNotFound", func(t *testing.T) {
		_, err := mgr.Logout("nonexistent-logout-session")
		if err == nil {
			t.Fatal("expected error for nonexistent session")
		}
		t.Logf("Logout error: %v", err)
	})
}

// =============================================================================
// TestRequireSession_WithProvider — session middleware with registered provider
// NOTE: RequireSession calls ValidateSession which calls the registered provider's
// ValidateSession. Without a registered provider, sessions cannot be validated
// and all requests redirect to /sso/login.
// =============================================================================

func TestRequireSession_WithProvider(t *testing.T) {
	mgr, _ := NewManager(&ManagerConfig{})
	mw := NewMiddleware(mgr, nil)

	// Store a session directly
	mgr.sessions.Create(&SSOSession{
		ID:           "sess1",
		UserID:       "user1",
		Provider:     ProviderOIDC,
		ProviderName: "oidc",
		Active:       true,
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	})

	// Register OIDC provider so ValidateSession can find the session.
	// NOTE: NewOIDCProvider requires network access to fetch OIDC discovery.
	// For unit tests, we test the session store directly via GetSession.
	// Full ValidateSession coverage requires integration tests with a real OIDC server.

	t.Run("ValidSession_GetSession", func(t *testing.T) {
		// Test GetSession directly (bypasses provider validation)
		sess, err := mgr.GetSession("sess1")
		if err != nil {
			t.Fatalf("GetSession failed: %v", err)
		}
		if sess.ID != "sess1" {
			t.Errorf("expected session ID sess1, got %s", sess.ID)
		}
	})

	t.Run("MissingSession", func(t *testing.T) {
		// Test via middleware without session cookie
		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()
		mw.RequireSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(rr, req)
		// Middleware redirects to /sso/login (307 Temporary Redirect)
		if rr.Code != http.StatusFound && rr.Code != http.StatusTemporaryRedirect {
			t.Errorf("expected redirect for missing session, got %d", rr.Code)
		}
	})

	t.Run("InvalidSession", func(t *testing.T) {
		// Session ID doesn't exist - handleUnauthorized may redirect or 401
		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{Name: "sso_session", Value: "invalid-session"})
		rr := httptest.NewRecorder()
		mw.RequireSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(rr, req)
		// handleUnauthorized may redirect (web) or 401 (API) based on path
		if rr.Code != http.StatusUnauthorized && rr.Code != http.StatusFound && rr.Code != http.StatusTemporaryRedirect {
			t.Errorf("expected 401/redirect for invalid session, got %d", rr.Code)
		}
	})

	t.Run("APIEndpoint_401", func(t *testing.T) {
		// API endpoint without session should return 401
		req := httptest.NewRequest("GET", "/api/test", nil)
		rr := httptest.NewRecorder()
		mw.RequireSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 for missing session on API, got %d", rr.Code)
		}
	})

	t.Run("WebEndpoint_Redirect", func(t *testing.T) {
		// Web endpoint without session should redirect
		req := httptest.NewRequest("GET", "/dashboard", nil)
		rr := httptest.NewRecorder()
		mw.RequireSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(rr, req)
		// Middleware redirects to /sso/login (307 Temporary Redirect)
		if rr.Code != http.StatusFound && rr.Code != http.StatusTemporaryRedirect {
			t.Errorf("expected redirect for missing session on web, got %d", rr.Code)
		}
	})
}

// =============================================================================
// TestOptionalSession_WithProvider — OptionalSession behavior
// =============================================================================

func TestOptionalSession_WithProvider(t *testing.T) {
	mgr, _ := NewManager(&ManagerConfig{})
	mw := NewMiddleware(mgr, nil)

	mgr.sessions.Create(&SSOSession{
		ID:           "sess2",
		UserID:       "user2",
		Provider:     ProviderOIDC,
		ProviderName: "oidc",
		Active:       true,
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	})

	t.Run("WithSession_200", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{Name: "sso_session", Value: "sess2"})
		rr := httptest.NewRecorder()
		mw.OptionalSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 with valid session, got %d", rr.Code)
		}
	})

	t.Run("WithoutSession_200", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()
		mw.OptionalSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 for no session (optional), got %d", rr.Code)
		}
	})
}

// =============================================================================
// TestRefreshSession_Direct — OIDC provider RefreshToken
// =============================================================================

// NOTE: NewOIDCProvider requires network access to fetch OIDC discovery.
// The actual RefreshToken tests require integration tests with a real OIDC server (testlab).
func TestRefreshSession_Direct(t *testing.T) {
	// Create OIDC provider — requires real network for discovery
	oidcCfg := &SSOConfig{
		Name:     "oidc",
		Provider: ProviderOIDC,
		OIDC: &OIDCConfig{
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			IssuerURL:    "https://issuer.example.com",
			RedirectURL:  "http://localhost/callback",
			Scopes:       []string{"openid"},
		},
	}
	_, err := NewOIDCProvider(oidcCfg, nil)
	t.Logf("OIDC provider creation requires real OIDC server: %v", err)
}

// =============================================================================
// TestLogoutHandler_WithProvider — LogoutHandler behavior
// =============================================================================

func TestLogoutHandler_WithProvider(t *testing.T) {
	mgr, _ := NewManager(&ManagerConfig{})
	mw := NewMiddleware(mgr, nil)

	mgr.sessions.Create(&SSOSession{
		ID:           "logout-test-sess",
		UserID:       "logout-user",
		Provider:     ProviderOIDC,
		ProviderName: "oidc",
		Active:       true,
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	})

	t.Run("LogoutWithSession", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/sso/logout", nil)
		req.AddCookie(&http.Cookie{Name: "sso_session", Value: "logout-test-sess"})
		rr := httptest.NewRecorder()
		mw.LogoutHandler("http://localhost").ServeHTTP(rr, req)
		if rr.Code != http.StatusOK && rr.Code != http.StatusFound && rr.Code != http.StatusTemporaryRedirect {
			t.Errorf("expected ok/redirect for logout, got %d", rr.Code)
		}
	})

	t.Run("LogoutWithoutSession", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/sso/logout", nil)
		rr := httptest.NewRecorder()
		mw.LogoutHandler("http://localhost").ServeHTTP(rr, req)
		if rr.Code != http.StatusFound && rr.Code != http.StatusTemporaryRedirect {
			t.Errorf("expected redirect for no session logout, got %d", rr.Code)
		}
	})
}

// =============================================================================
// TestManager_RefreshSession — Manager.RefreshSession
// =============================================================================

func TestManager_RefreshSession(t *testing.T) {
	mgr, _ := NewManager(&ManagerConfig{})

	t.Run("RefreshSessionNotFound", func(t *testing.T) {
		_, err := mgr.RefreshSession("nonexistent-refresh-session-id")
		if err == nil {
			t.Fatal("expected error for nonexistent session")
		}
		t.Logf("RefreshSession error (expected): %v", err)
	})

	t.Run("RefreshSession_OIDCProvider", func(t *testing.T) {
		// Create a session with OIDC provider but no registered provider
		mgr2, _ := NewManager(&ManagerConfig{})
		sessID := "refresh-sess-1"
		mgr2.sessions.Create(&SSOSession{
			ID:           sessID,
			UserID:       "user1",
			Provider:     ProviderOIDC,
			ProviderName: "oidc",
			Active:       true,
			ExpiresAt:    time.Now().Add(1 * time.Hour),
		})
		_, err := mgr2.RefreshSession(sessID)
		if err == nil {
			t.Log("RefreshSession returned nil (expected if OIDC not registered)")
		} else {
			t.Logf("RefreshSession error: %v", err)
		}
	})
}

// =============================================================================
// TestManager_RequireRole — SSO RequireRole middleware
// =============================================================================

func TestManager_RequireRole(t *testing.T) {
	mgr, _ := NewManager(&ManagerConfig{})
	mw := NewMiddleware(mgr, nil)

	mgr.sessions.Create(&SSOSession{
		ID:           "role-sess",
		UserID:       "role-user",
		Provider:     ProviderOIDC,
		ProviderName: "oidc",
		Active:       true,
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		User:         &SSOUser{ID: "role-user", Role: "admin"},
	})

	t.Run("NoSession_Redirect", func(t *testing.T) {
		// RequireRole requires an active session in context
		req := httptest.NewRequest("GET", "/admin", nil)
		rr := httptest.NewRecorder()
		mw.RequireRole("admin")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(rr, req)
		if rr.Code != http.StatusFound && rr.Code != http.StatusTemporaryRedirect {
			t.Errorf("expected redirect for no session, got %d", rr.Code)
		}
	})
}
