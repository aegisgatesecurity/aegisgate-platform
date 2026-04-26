// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// OIDC Mock HTTP Servers for Testing
// =========================================================================

package sso

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"
)

// MockOIDCServer creates a mock OIDC provider server
type MockOIDCServer struct {
	Server       *httptest.Server
	AuthURL      string
	TokenURL     string
	UserInfoURL  string
	DiscoveryURL string
	Issuer       string
	ClientID     string
	ClientSecret string

	// Custom handlers
	CustomAuthHandler     func(w http.ResponseWriter, r *http.Request)
	CustomTokenHandler    func(w http.ResponseWriter, r *http.Request)
	CustomUserInfoHandler func(w http.ResponseWriter, r *http.Request)
}

// NewMockOIDCServer creates a mock OIDC server with discovery endpoint
func NewMockOIDCServer() *MockOIDCServer {
	m := &MockOIDCServer{
		Issuer:       "https://mock-oidc.example.com",
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", m.handleDiscovery)
	mux.HandleFunc("/authorize", m.handleAuthorize)
	mux.HandleFunc("/token", m.handleToken)
	mux.HandleFunc("/userinfo", m.handleUserInfo)
	mux.HandleFunc("/.well-known/jwks.json", m.handleJWKS)

	m.Server = httptest.NewServer(mux)
	// Use server base URL as IssuerURL - code will append /.well-known/openid-configuration
	m.DiscoveryURL = m.Server.URL + "/.well-known/openid-configuration"
	m.AuthURL = m.Server.URL + "/authorize"
	m.TokenURL = m.Server.URL + "/token"
	m.UserInfoURL = m.Server.URL + "/userinfo"

	return m
}

// Close shuts down the mock server
func (m *MockOIDCServer) Close() {
	m.Server.Close()
}

// handleDiscovery returns OIDC discovery document
func (m *MockOIDCServer) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	discovery := map[string]interface{}{
		"issuer":                                m.Issuer,
		"authorization_endpoint":                m.AuthURL,
		"token_endpoint":                        m.TokenURL,
		"userinfo_endpoint":                     m.UserInfoURL,
		"jwks_uri":                              m.Server.URL + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code", "token", "id_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "email", "profile"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic"},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(discovery)
}

// handleAuthorize handles authorization requests
func (m *MockOIDCServer) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if m.CustomAuthHandler != nil {
		m.CustomAuthHandler(w, r)
		return
	}

	redirectURI := r.URL.Query().Get("redirect_uri")
	if redirectURI == "" {
		http.Error(w, "redirect_uri required", http.StatusBadRequest)
		return
	}

	code := "mock-auth-code-" + fmt.Sprintf("%d", time.Now().UnixNano())
	u, _ := url.Parse(redirectURI)
	q := u.Query()
	q.Set("code", code)
	q.Set("state", r.URL.Query().Get("state"))
	u.RawQuery = q.Encode()

	http.Redirect(w, r, u.String(), http.StatusFound)
}

// handleToken handles token exchange requests
func (m *MockOIDCServer) handleToken(w http.ResponseWriter, r *http.Request) {
	if m.CustomTokenHandler != nil {
		m.CustomTokenHandler(w, r)
		return
	}

	token := map[string]interface{}{
		"access_token":  "mock-access-token-" + fmt.Sprintf("%d", time.Now().UnixNano()),
		"token_type":    "Bearer",
		"refresh_token": "mock-refresh-token",
		"id_token":      m.generateIDToken("test-user", "test@example.com"),
		"expires_in":    3600,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(token)
}

// handleUserInfo returns user information
func (m *MockOIDCServer) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	if m.CustomUserInfoHandler != nil {
		m.CustomUserInfoHandler(w, r)
		return
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	userInfo := map[string]interface{}{
		"sub":            "test-user",
		"name":           "Test User",
		"email":          "test@example.com",
		"email_verified": true,
		"picture":        "https://example.com/photo.jpg",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userInfo)
}

// handleJWKS returns mock JWKS
func (m *MockOIDCServer) handleJWKS(w http.ResponseWriter, r *http.Request) {
	jwks := map[string]interface{}{
		"keys": []map[string]interface{}{
			{"kty": "RSA", "kid": "test-key-id", "use": "sig", "alg": "RS256", "n": "test-modulus", "e": "AQAB"},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}

// generateIDToken creates a mock ID token (unsigned for testing)
func (m *MockOIDCServer) generateIDToken(subject, email string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	claims := map[string]interface{}{
		"iss":   m.Issuer,
		"sub":   subject,
		"aud":   m.ClientID,
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"email": email,
		"nonce": "test-nonce",
	}
	claimsJSON, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
	return fmt.Sprintf("%s.%s.", header, payload)
}

// NewOIDCProviderWithMock creates an OIDC provider configured to use the mock server
func (m *MockOIDCServer) NewOIDCProvider() (*OIDCProvider, error) {
	cfg := &SSOConfig{
		Provider: ProviderOIDC,
		Name:     "test-oidc",
		OIDC: &OIDCConfig{
			ClientID:     m.ClientID,
			ClientSecret: m.ClientSecret,
			IssuerURL:    m.Server.URL, // Base URL for discovery
			RedirectURL:  "http://localhost/callback",
			Scopes:       []string{"openid", "email", "profile"},
			AuthURL:      m.AuthURL,  // Pre-configured endpoints
			TokenURL:     m.TokenURL, // to skip discovery
			UserInfoURL:  m.UserInfoURL,
			JWKSURL:      m.Server.URL + "/.well-known/jwks.json",
		},
	}
	return NewOIDCProvider(cfg, nil)
}

// CreateValidTokenResponse creates a valid token response
func (m *MockOIDCServer) CreateValidTokenResponse() map[string]interface{} {
	return map[string]interface{}{
		"access_token":  "valid-access-token",
		"token_type":    "Bearer",
		"refresh_token": "valid-refresh-token",
		"id_token":      m.generateIDToken("test-user", "test@example.com"),
		"expires_in":    3600,
	}
}

// Context returns a context with the mock server URL
func (m *MockOIDCServer) Context() context.Context {
	return context.WithValue(context.Background(), "mock_oidc_url", m.Server.URL)
}
