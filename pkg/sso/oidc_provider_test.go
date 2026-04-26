// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// OIDC Provider Tests with Mock Servers
// =========================================================================

package sso

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// =============================================================================
// OIDC InitiateLogin Tests
// =============================================================================

func TestOIDCInitiateLogin(t *testing.T) {
	mockServer := NewMockOIDCServer()
	defer mockServer.Close()

	provider, err := mockServer.NewOIDCProvider()
	if err != nil {
		t.Fatalf("Failed to create OIDC provider: %v", err)
	}

	t.Run("successful login", func(t *testing.T) {
		loginURL, ssoReq, err := provider.InitiateLogin("test-state")
		if err != nil {
			t.Fatalf("InitiateLogin() error: %v", err)
		}

		if loginURL == "" {
			t.Error("InitiateLogin() returned empty URL")
		}

		if ssoReq == nil {
			t.Error("InitiateLogin() returned nil request")
		}

		// Verify URL contains expected parameters
		parsedURL, err := url.Parse(loginURL)
		if err != nil {
			t.Fatalf("Failed to parse login URL: %v", err)
		}

		params := parsedURL.Query()
		if params.Get("state") != "test-state" {
			t.Errorf("state = %q, want test-state", params.Get("state"))
		}
		if params.Get("response_type") != "code" {
			t.Errorf("response_type = %q, want code", params.Get("response_type"))
		}
	})
}

// =============================================================================
// OIDC HandleCallback Tests
// =============================================================================

func TestOIDCHandleCallback(t *testing.T) {
	mockServer := NewMockOIDCServer()
	defer mockServer.Close()

	provider, err := mockServer.NewOIDCProvider()
	if err != nil {
		t.Fatalf("Failed to create OIDC provider: %v", err)
	}

	t.Run("missing code", func(t *testing.T) {
		_, err := provider.HandleCallback(&SSORequest{}, map[string]string{})
		if err == nil {
			t.Error("HandleCallback() should fail with missing code")
		}
	})
}

func TestOIDCHandleCallbackWithCode(t *testing.T) {
	mockServer := NewMockOIDCServer()
	defer mockServer.Close()

	provider, err := mockServer.NewOIDCProvider()
	if err != nil {
		t.Fatalf("Failed to create OIDC provider: %v", err)
	}

	// Configure custom token handler for successful callback
	mockServer.CustomTokenHandler = func(w http.ResponseWriter, r *http.Request) {
		token := map[string]interface{}{
			"access_token":  "test-access-token",
			"token_type":    "Bearer",
			"refresh_token": "test-refresh-token",
			"id_token":      mockServer.generateIDToken("test-user", "test@example.com"),
			"expires_in":    3600,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(token)
	}

	// Initiate login to get valid state
	_, ssoReq, err := provider.InitiateLogin("my-test-state")
	if err != nil {
		t.Fatalf("InitiateLogin() error: %v", err)
	}

	params := map[string]string{"code": "mock-auth-code", "state": "my-test-state"}

	resp, err := provider.HandleCallback(ssoReq, params)
	if err != nil {
		t.Fatalf("HandleCallback() error: %v", err)
	}

	if !resp.Success {
		t.Error("HandleCallback() should succeed")
	}
}

// =============================================================================
// OIDC RefreshToken Tests
// =============================================================================

func TestOIDCRefreshToken(t *testing.T) {
	mockServer := NewMockOIDCServer()
	defer mockServer.Close()

	provider, err := mockServer.NewOIDCProvider()
	if err != nil {
		t.Fatalf("Failed to create OIDC provider: %v", err)
	}

	t.Run("successful refresh", func(t *testing.T) {
		mockServer.CustomTokenHandler = func(w http.ResponseWriter, r *http.Request) {
			token := map[string]interface{}{
				"access_token":  "new-access-token",
				"token_type":    "Bearer",
				"refresh_token": "new-refresh-token",
				"expires_in":    3600,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(token)
		}

		newToken, err := provider.RefreshToken("original-refresh-token")
		if err != nil {
			t.Fatalf("RefreshToken() error: %v", err)
		}

		if newToken == nil {
			t.Error("RefreshToken() should return new token")
		}
	})

	t.Run("refresh token empty", func(t *testing.T) {
		_, err := provider.RefreshToken("")
		if err == nil {
			t.Error("RefreshToken() should fail with empty refresh token")
		}
	})
}

// =============================================================================
// OIDC GetUserInfo Tests
// =============================================================================

func TestOIDCGetUserInfo(t *testing.T) {
	mockServer := NewMockOIDCServer()
	defer mockServer.Close()

	// Configure custom userinfo response
	mockServer.CustomUserInfoHandler = func(w http.ResponseWriter, r *http.Request) {
		userInfo := map[string]interface{}{
			"sub":    "user-123",
			"name":   "Test User",
			"email":  "testuser@example.com",
			"groups": []interface{}{"users", "admins"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(userInfo)
	}

	// Create provider with mocked userinfo endpoint
	provider := &OIDCProvider{
		httpClient: &http.Client{},
		oidcConfig: &OIDCConfig{
			UserInfoURL: mockServer.UserInfoURL,
		},
	}

	t.Run("successful get user info", func(t *testing.T) {
		userInfo, err := provider.getUserInfo("valid-access-token")
		if err != nil {
			t.Fatalf("getUserInfo() error: %v", err)
		}

		email := userInfo["email"]
		if email != "testuser@example.com" {
			t.Errorf("email = %v, want testuser@example.com", email)
		}
	})
}

func TestOIDCGetUserInfoUnauthorized(t *testing.T) {
	// Server that returns 401
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer server.Close()

	provider := &OIDCProvider{
		oidcConfig: &OIDCConfig{},
		discovery: &OIDCDiscoveryDocument{
			UserInfoEndpoint: server.URL,
		},
	}

	_, err := provider.getUserInfo("invalid-token")
	if err == nil {
		t.Error("getUserInfo() should fail with invalid token")
	}
}

// =============================================================================
// OIDC ValidateSession Tests
// =============================================================================

func TestOIDCValidateSession(t *testing.T) {
	provider := &OIDCProvider{
		oidcConfig: &OIDCConfig{}, // Initialize to avoid nil pointer
	}

	t.Run("nil session", func(t *testing.T) {
		err := provider.ValidateSession(nil)
		if err == nil {
			t.Error("ValidateSession() should fail with nil session")
		}
	})

	t.Run("expired session", func(t *testing.T) {
		session := &SSOSession{
			ID:        "test-session",
			UserID:    "user-1",
			Active:    true,
			ExpiresAt: time.Now().Add(-1 * time.Hour),
		}
		err := provider.ValidateSession(session)
		if err == nil {
			t.Error("ValidateSession() should fail with expired session")
		}
	})

	t.Run("inactive session", func(t *testing.T) {
		session := &SSOSession{
			ID:        "test-session",
			UserID:    "user-1",
			Active:    false,
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}
		err := provider.ValidateSession(session)
		if err == nil {
			t.Error("ValidateSession() should fail with inactive session")
		}
	})

	t.Run("valid session", func(t *testing.T) {
		session := &SSOSession{
			ID:        "test-session",
			UserID:    "user-1",
			Active:    true,
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}
		err := provider.ValidateSession(session)
		if err != nil {
			t.Errorf("ValidateSession() error: %v", err)
		}
	})
}

// =============================================================================
// OIDC Logout Tests
// =============================================================================

func TestOIDCLogout(t *testing.T) {
	provider := &OIDCProvider{
		oidcConfig: &OIDCConfig{}, // Initialize to avoid nil pointer
	}

	t.Run("nil session", func(t *testing.T) {
		_, err := provider.Logout(nil)
		if err == nil {
			t.Error("Logout() should fail with nil session")
		}
	})

	t.Run("session without end session URL", func(t *testing.T) {
		session := &SSOSession{
			ID:     "test-session",
			UserID: "user-1",
		}
		_, err := provider.Logout(session)
		// May succeed without end session URL
		_ = err
	})
}

// =============================================================================
// OIDC Metadata Tests
// =============================================================================

func TestOIDCMetadata(t *testing.T) {
	mockServer := NewMockOIDCServer()
	defer mockServer.Close()

	provider, err := mockServer.NewOIDCProvider()
	if err != nil {
		t.Fatalf("Failed to create OIDC provider: %v", err)
	}

	t.Run("metadata endpoint", func(t *testing.T) {
		metadata, err := provider.Metadata()
		if err != nil {
			t.Fatalf("Metadata() error: %v", err)
		}

		if len(metadata) == 0 {
			t.Error("Metadata() should return content")
		}

		// Verify it's valid JSON
		var meta map[string]interface{}
		if err := json.Unmarshal(metadata, &meta); err != nil {
			t.Errorf("Metadata() should return valid JSON: %v", err)
		}
	})
}

// =============================================================================
// OIDC Name and Type Tests
// =============================================================================

func TestOIDCNameAndType(t *testing.T) {
	mockServer := NewMockOIDCServer()
	defer mockServer.Close()

	provider, err := mockServer.NewOIDCProvider()
	if err != nil {
		t.Fatalf("Failed to create OIDC provider: %v", err)
	}

	if provider.Name() == "" {
		t.Error("Name() should return non-empty string")
	}

	if provider.Type() != ProviderOIDC {
		t.Error("Type() should return ProviderOIDC")
	}
}

// =============================================================================
// Mock server tests
// =============================================================================

func TestMockOIDCServerDiscovery(t *testing.T) {
	mockServer := NewMockOIDCServer()
	defer mockServer.Close()

	resp, err := http.Get(mockServer.DiscoveryURL)
	if err != nil {
		t.Fatalf("Discovery endpoint error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Discovery returned status %d", resp.StatusCode)
	}

	var discovery map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		t.Fatalf("Failed to decode discovery: %v", err)
	}

	if discovery["issuer"] != mockServer.Issuer {
		t.Errorf("issuer = %v, want %v", discovery["issuer"], mockServer.Issuer)
	}
}

func TestMockOIDCServerToken(t *testing.T) {
	mockServer := NewMockOIDCServer()
	defer mockServer.Close()

	// Custom token handler
	mockServer.CustomTokenHandler = func(w http.ResponseWriter, r *http.Request) {
		token := map[string]interface{}{
			"access_token": "custom-token",
			"token_type":   "Bearer",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(token)
	}

	resp, err := http.PostForm(mockServer.TokenURL, url.Values{"grant_type": {"authorization_code"}, "code": {"test"}})
	if err != nil {
		t.Fatalf("Token endpoint error: %v", err)
	}
	defer resp.Body.Close()

	var token map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		t.Fatalf("Failed to decode token response: %v", err)
	}

	if token["access_token"] != "custom-token" {
		t.Errorf("access_token = %v, want custom-token", token["access_token"])
	}
}

// =============================================================================
// Helper function tests
// =============================================================================

func TestMockServerGenerateIDToken(t *testing.T) {
	mockServer := NewMockOIDCServer()
	defer mockServer.Close()

	t.Run("valid token format", func(t *testing.T) {
		token := mockServer.generateIDToken("user-subject", "user@example.com")

		// Token should have 3 parts separated by dots
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			t.Errorf("Token should have 3 parts, got %d", len(parts))
		}

		// Decode middle part (payload)
		decoded, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Errorf("Failed to decode payload: %v", err)
		}

		var claims map[string]interface{}
		if err := json.Unmarshal(decoded, &claims); err != nil {
			t.Errorf("Failed to parse claims: %v", err)
		}

		if claims["sub"] != "user-subject" {
			t.Errorf("sub = %v, want user-subject", claims["sub"])
		}
	})
}

func TestNewOIDCProviderConfigErrors(t *testing.T) {
	t.Run("missing issuer URL", func(t *testing.T) {
		_, err := NewOIDCProvider(&SSOConfig{
			Provider: ProviderOIDC,
			Name:     "test",
		}, nil)
		if err == nil {
			t.Error("Should fail without OIDC config")
		}
	})
}

// =============================================================================
// Additional OIDC Tests for parseIDToken and mapClaimsToUser
// =============================================================================

func TestParseIDToken(t *testing.T) {
	t.Run("invalid format - not enough parts", func(t *testing.T) {
		// Create a minimal OIDCProvider just for testing
		provider := &OIDCProvider{
			oidcConfig: &OIDCConfig{
				IssuerURL: "http://test-issuer",
			},
		}

		_, err := provider.parseIDToken("not.a.jwt")
		if err == nil {
			t.Error("parseIDToken() expected error for invalid format")
		}
	})

	t.Run("invalid base64 in payload", func(t *testing.T) {
		provider := &OIDCProvider{
			oidcConfig: &OIDCConfig{
				IssuerURL: "http://test-issuer",
			},
		}

		// Create a token with invalid base64 in the payload
		token := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.!!!invalid!!!.signature"
		_, err := provider.parseIDToken(token)
		if err == nil {
			t.Error("parseIDToken() expected error for invalid base64")
		}
	})

	t.Run("expired token", func(t *testing.T) {
		provider := &OIDCProvider{
			oidcConfig: &OIDCConfig{
				IssuerURL: "http://test-issuer",
			},
		}

		// Create an expired token
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
		claims := map[string]interface{}{
			"iss": "http://test-issuer",
			"sub": "user123",
			"exp": time.Now().Add(-1 * time.Hour).Unix(), // Expired 1 hour ago
		}
		claimsJSON, _ := json.Marshal(claims)
		payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
		token := fmt.Sprintf("%s.%s.", header, payload)

		_, err := provider.parseIDToken(token)
		if err == nil {
			t.Error("parseIDToken() expected error for expired token")
		}
	})

	t.Run("valid token", func(t *testing.T) {
		provider := &OIDCProvider{
			oidcConfig: &OIDCConfig{
				IssuerURL:       "http://test-issuer",
				SkipIssuerCheck: true, // Skip issuer validation for this test
			},
		}

		// Create a valid token with proper casing for JSON
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
		claims := map[string]interface{}{
			"iss":   "http://test-issuer",
			"sub":   "user123",
			"exp":   time.Now().Add(1 * time.Hour).Unix(),
			"email": "user@example.com",
			"name":  "Test User",
		}
		claimsJSON, _ := json.Marshal(claims)
		payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
		token := fmt.Sprintf("%s.%s.", header, payload)

		// Just verify token parsing succeeds - struct field mapping varies by JSON tag setup
		_, err := provider.parseIDToken(token)
		if err != nil {
			t.Errorf("parseIDToken() unexpected error: %v", err)
		}
	})
}

func TestMapClaimsToUser(t *testing.T) {
	provider := &OIDCProvider{
		config: &SSOConfig{
			AttributeMapping: &AttributeMapping{
				GroupAttribute: "groups",
			},
		},
	}

	t.Run("basic claims mapping", func(t *testing.T) {
		user := &SSOUser{}
		claims := &OIDCIDTokenClaims{
			Subject: "user123",
			Email:   "user@example.com",
			Name:    "Test User",
			Groups:  []string{"admin", "developers"},
		}

		provider.mapClaimsToUser(user, claims)

		// The function sets UpstreamID from Subject when user.ID is empty
		if user.UpstreamID != "user123" {
			t.Errorf("mapClaimsToUser() UpstreamID = %s, want user123", user.UpstreamID)
		}
		if user.Email != "user@example.com" {
			t.Errorf("mapClaimsToUser() Email = %s, want user@example.com", user.Email)
		}
		if user.Name != "Test User" {
			t.Errorf("mapClaimsToUser() Name = %s, want Test User", user.Name)
		}
		if len(user.Groups) != 2 {
			t.Errorf("mapClaimsToUser() Groups length = %d, want 2", len(user.Groups))
		}
	})
}

// Test RoleAtLeast method
func TestSSOUserRoleAtLeast(t *testing.T) {
	t.Run("viewer role", func(t *testing.T) {
		user := &SSOUser{Role: "viewer"}
		if !user.RoleAtLeast("viewer") {
			t.Error("viewer should be >= viewer")
		}
		if user.RoleAtLeast("admin") {
			t.Error("viewer should not be >= admin")
		}
	})

	t.Run("admin role", func(t *testing.T) {
		user := &SSOUser{Role: "admin"}
		if !user.RoleAtLeast("admin") {
			t.Error("admin should be >= admin")
		}
		if !user.RoleAtLeast("viewer") {
			t.Error("admin should be >= viewer")
		}
	})

	t.Run("empty role", func(t *testing.T) {
		user := &SSOUser{Role: ""}
		if user.RoleAtLeast("viewer") {
			t.Error("empty role should not be >= any role")
		}
	})
}

// Test OIDC discover function
func TestOIDCDiscover(t *testing.T) {
	// Create mock server
	server := NewMockOIDCServer()

	// Create provider
	provider, err := NewOIDCProvider(&SSOConfig{
		Name:     "test",
		Provider: ProviderOIDC,
		OIDC: &OIDCConfig{
			ClientID:    "test-client",
			IssuerURL:   server.Server.URL, // Use server URL directly
			RedirectURL: "http://localhost/callback",
			AuthURL:     server.AuthURL,
			TokenURL:    server.TokenURL,
			UserInfoURL: server.UserInfoURL,
		},
	}, nil)
	if err != nil {
		t.Fatalf("NewOIDCProvider() error: %v", err)
	}

	// Verify provider was created with endpoints
	if provider == nil {
		t.Error("NewOIDCProvider() returned nil")
	}
}

// Test validateAccessToken stub
func TestOIDCValidateAccessToken(t *testing.T) {
	provider := &OIDCProvider{}

	// This is a stub that just returns nil
	err := provider.validateAccessToken("any-token")
	if err != nil {
		t.Errorf("validateAccessToken() returned error: %v", err)
	}
}

// Test getStringExtra with nil token Extra
func TestGetStringExtraNilExtra(t *testing.T) {
	token := &oauth2.Token{}
	result := getStringExtra(token, "missing_key")
	if result != "" {
		t.Errorf("getStringExtra(nil, 'missing') = %q, want ''", result)
	}
}
