package sso

import (
	"encoding/json"
	"net/http"
	"testing"
)

// =============================================================================
// Manager.RefreshSession Coverage Tests
// =============================================================================

func TestManagerRefreshSession_Paths(t *testing.T) {
	t.Run("session not found", func(t *testing.T) {
		manager, _ := NewManager(nil)
		_, err := manager.RefreshSession("non-existent")
		if err == nil {
			t.Error("RefreshSession should fail for non-existent session")
		}
	})

	t.Run("not OIDC or OAuth provider", func(t *testing.T) {
		manager, _ := NewManager(nil)
		session := &SSOSession{
			ID:       "sess-saml",
			Provider: ProviderSAML,
		}
		store := NewMemorySessionStore()
		store.Create(session)
		manager.sessions = store

		_, err := manager.RefreshSession("sess-saml")
		if err == nil {
			t.Error("RefreshSession should fail for SAML sessions")
		}
	})

	t.Run("missing refresh token", func(t *testing.T) {
		manager, _ := NewManager(nil)
		session := &SSOSession{
			ID:           "sess-oidc",
			Provider:     ProviderOIDC,
			RefreshToken: "",
		}
		store := NewMemorySessionStore()
		store.Create(session)
		manager.sessions = store

		_, err := manager.RefreshSession("sess-oidc")
		if err == nil {
			t.Error("RefreshSession should fail when refresh token is missing")
		}
	})

	t.Run("provider not found", func(t *testing.T) {
		manager, _ := NewManager(nil)
		session := &SSOSession{
			ID:           "sess-oidc",
			Provider:     ProviderOIDC,
			ProviderName: "missing-provider",
			RefreshToken: "rt-123",
		}
		store := NewMemorySessionStore()
		store.Create(session)
		manager.sessions = store

		_, err := manager.RefreshSession("sess-oidc")
		if err == nil {
			t.Error("RefreshSession should fail when provider is not registered")
		}
	})

	t.Run("provider not OIDC type", func(t *testing.T) {
		manager, _ := NewManager(nil)

		// Set up a mock provider that is NOT *OIDCProvider
		mp := &mockProvider{name: "mock-non-oidc", typ: ProviderOIDC}
		// Note: mockProvider implements SSOProviderInterface but is not *OIDCProvider

		cfg := &SSOConfig{Provider: ProviderOIDC, Name: "mock-non-oidc"}
		manager.mu.Lock()
		manager.providers[mp.name] = mp
		manager.configs[mp.name] = cfg
		manager.mu.Unlock()

		session := &SSOSession{
			ID:           "sess-oidc",
			Provider:     ProviderOIDC,
			ProviderName: "mock-non-oidc",
			RefreshToken: "rt-123",
		}
		store := NewMemorySessionStore()
		store.Create(session)
		manager.sessions = store

		_, err := manager.RefreshSession("sess-oidc")
		if err == nil {
			t.Error("RefreshSession should fail when provider is not an OIDCProvider pointer")
		}
	})
}

func TestManagerRefreshSession_Success(t *testing.T) {
	// We need a real OIDCProvider with a mock server to test the successful path
	mockServer := NewMockOIDCServer()
	defer mockServer.Close()

	provider, err := mockServer.NewOIDCProvider()
	if err != nil {
		t.Fatalf("Failed to create OIDC provider: %v", err)
	}

	manager, _ := NewManager(nil)
	manager.mu.Lock()
	manager.providers[provider.Name()] = provider
	manager.configs[provider.Name()] = provider.config
	manager.mu.Unlock()

	sessionID := "test-session-success"
	session := &SSOSession{
		ID:           sessionID,
		UserID:       "test-user",
		Provider:     ProviderOIDC,
		ProviderName: provider.Name(),
		RefreshToken: "mock-refresh-token",
		Active:       true,
	}
	store := NewMemorySessionStore()
	store.Create(session)
	manager.sessions = store

	// Define what the token server returns on refresh
	mockServer.CustomTokenHandler = func(w http.ResponseWriter, r *http.Request) {
		token := map[string]interface{}{
			"access_token":  "new-access-token",
			"token_type":    "Bearer",
			"refresh_token": "new-refresh-token",
			"id_token":      "new-id-token",
			"expires_in":    3600,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(token)
	}

	updatedSess, err := manager.RefreshSession(sessionID)
	if err != nil {
		t.Fatalf("RefreshSession unexpected error: %v", err)
	}

	if updatedSess.AccessToken != "new-access-token" {
		t.Errorf("expected access token 'new-access-token', got %s", updatedSess.AccessToken)
	}
	if updatedSess.RefreshToken != "new-refresh-token" {
		t.Errorf("expected refresh token 'new-refresh-token', got %s", updatedSess.RefreshToken)
	}
	if updatedSess.IDToken != "new-id-token" {
		t.Errorf("expected id token 'new-id-token', got %s", updatedSess.IDToken)
	}
}

func TestManagerRefreshSession_ProviderError(t *testing.T) {
	mockServer := NewMockOIDCServer()
	defer mockServer.Close()

	provider, err := mockServer.NewOIDCProvider()
	if err != nil {
		t.Fatalf("Failed to create OIDC provider: %v", err)
	}

	manager, _ := NewManager(nil)
	manager.mu.Lock()
	manager.providers[provider.Name()] = provider
	manager.configs[provider.Name()] = provider.config
	manager.mu.Unlock()

	sessionID := "test-session-fail"
	session := &SSOSession{
		ID:           sessionID,
		Provider:     ProviderOIDC,
		ProviderName: provider.Name(),
		RefreshToken: "bad-refresh-token",
		Active:       true,
	}
	store := NewMemorySessionStore()
	store.Create(session)
	manager.sessions = store

	// Server returns error
	mockServer.CustomTokenHandler = func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "invalid_grant", http.StatusBadRequest)
	}

	_, err = manager.RefreshSession(sessionID)
	if err == nil {
		t.Error("RefreshSession should fail when provider returns error")
	}
}
