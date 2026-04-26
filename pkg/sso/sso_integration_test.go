// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// SSO Integration Tests
// These tests require real OIDC/SAML provider credentials and are excluded
// from standard coverage by the integration build tag.
// Run with: go test -tags=integration ./pkg/sso/...
// =========================================================================
//go:build integration
// +build integration

package sso

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/sso/stores"
)

// Test OIDC credentials - set via environment variables
func getOIDCConfig() *OIDCConfig {
	return &OIDCConfig{
		ClientID:     os.Getenv("OIDC_CLIENT_ID"),
		ClientSecret: os.Getenv("OIDC_CLIENT_SECRET"),
		IssuerURL:    os.Getenv("OIDC_ISSUER_URL"),
		RedirectURL:  os.Getenv("OIDC_REDIRECT_URL"),
		Scopes:       []string{"openid", "email", "profile"},
	}
}

// Test SAML credentials - set via environment variables
func getSAMLConfig() *SSOConfig {
	return &SSOConfig{
		Provider:    ProviderSAML,
		Name:        "test-saml",
		EntityID:    os.Getenv("SAML_ENTITY_ID"),
		ACSURL:      os.Getenv("SAML_ACS_URL"),
		IDPEntityID: os.Getenv("SAML_IDP_ENTITY_ID"),
		IDPSSOURL:   os.Getenv("SAML_IDP_SSO_URL"),
		IDPSLOURL:   os.Getenv("SAML_IDP_SLO_URL"),
	}
}

// =============================================================================
// OIDC Integration Tests
// =============================================================================

func TestOIDCIntegration_InitiateLogin(t *testing.T) {
	cfg := getOIDCConfig()
	if cfg.IssuerURL == "" || cfg.ClientID == "" {
		t.Skip("Skipping: OIDC credentials not configured")
	}

	provider, err := NewOIDCProvider(*cfg)
	if err != nil {
		t.Fatalf("NewOIDCProvider() error: %v", err)
	}

	loginURL, ssoReq, err := provider.InitiateLogin("test-state", "test-nonce")
	if err != nil {
		t.Fatalf("InitiateLogin() error: %v", err)
	}

	if loginURL == "" {
		t.Error("InitiateLogin() returned empty URL")
	}

	if ssoReq == nil {
		t.Error("InitiateLogin() returned nil request")
	}
}

func TestOIDCIntegration_HandleCallback(t *testing.T) {
	cfg := getOIDCConfig()
	if cfg.IssuerURL == "" || cfg.ClientID == "" {
		t.Skip("Skipping: OIDC credentials not configured")
	}

	// Start a mock server to handle the callback
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate token exchange response
		tokenResp := TokenResponse{
			AccessToken:  "test-access-token",
			TokenType:    "Bearer",
			RefreshToken: "test-refresh-token",
			IDToken:      createTestIDToken("test-subject", "test@example.com"),
			ExpiresIn:    3600,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tokenResp)
	}))
	defer server.Close()

	// Create provider with test server URL
	testCfg := *cfg
	testCfg.IssuerURL = server.URL
	testCfg.RedirectURL = server.URL + "/callback"

	provider, err := NewOIDCProvider(testCfg)
	if err != nil {
		t.Skipf("Skipping: cannot create provider: %v", err)
	}

	resp, err := provider.HandleCallback(context.Background(), &SSORequest{}, map[string]string{"code": "test-code"})
	if err != nil {
		t.Fatalf("HandleCallback() error: %v", err)
	}

	if !resp.Success {
		t.Error("HandleCallback() should succeed")
	}

	if resp.User == nil {
		t.Error("HandleCallback() should return user")
	}
}

func TestOIDCIntegration_RefreshToken(t *testing.T) {
	cfg := getOIDCConfig()
	if cfg.IssuerURL == "" || cfg.ClientID == "" {
		t.Skip("Skipping: OIDC credentials not configured")
	}

	// Start a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenResp := TokenResponse{
			AccessToken:  "new-access-token",
			TokenType:    "Bearer",
			RefreshToken: "new-refresh-token",
			ExpiresIn:    3600,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tokenResp)
	}))
	defer server.Close()

	testCfg := *cfg
	testCfg.IssuerURL = server.URL
	testCfg.RedirectURL = server.URL + "/callback"

	provider, err := NewOIDCProvider(testCfg)
	if err != nil {
		t.Skipf("Skipping: cannot create provider: %v", err)
	}

	session := &SSOSession{
		RefreshToken: "test-refresh-token",
		ExpiresAt:    time.Now().Add(-1 * time.Hour),
	}

	newSession, err := provider.RefreshToken(context.Background(), session)
	if err != nil {
		t.Fatalf("RefreshToken() error: %v", err)
	}

	if newSession == nil {
		t.Error("RefreshToken() should return new session")
	}
}

func TestOIDCIntegration_GetUserInfo(t *testing.T) {
	cfg := getOIDCConfig()
	if cfg.IssuerURL == "" {
		t.Skip("Skipping: OIDC credentials not configured")
	}

	// Start mock server with userinfo endpoint
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userInfo := UserInfo{
			Subject: "test-user",
			Email:   "test@example.com",
			Name:    "Test User",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(userInfo)
	}))
	defer server.Close()

	provider := &OIDCProvider{}
	provider.provider = &struct {
		AuthURL, TokenURL, UserInfoURL string
	}{UserInfoURL: server.URL}

	userInfo, err := provider.getUserInfo(context.Background(), "test-access-token")
	if err != nil {
		t.Fatalf("getUserInfo() error: %v", err)
	}

	if userInfo.Email != "test@example.com" {
		t.Errorf("getUserInfo() email = %q, want %q", userInfo.Email, "test@example.com")
	}
}

// =============================================================================
// SAML Integration Tests
// =============================================================================

func TestSAMLIntegration_NewSAMLProvider(t *testing.T) {
	cfg := getSAMLConfig()
	if cfg.EntityID == "" || cfg.ACSURL == "" {
		t.Skip("Skipping: SAML credentials not configured")
	}

	provider, err := NewSAMLProvider(cfg, stores.NewMemoryRequestStore())
	if err != nil {
		t.Fatalf("NewSAMLProvider() error: %v", err)
	}

	if provider == nil {
		t.Error("NewSAMLProvider() returned nil")
	}
}

func TestSAMLIntegration_InitiateLogin(t *testing.T) {
	cfg := getSAMLConfig()
	if cfg.EntityID == "" || cfg.IDPSSOURL == "" {
		t.Skip("Skipping: SAML credentials not configured")
	}

	provider, err := NewSAMLProvider(cfg, stores.NewMemoryRequestStore())
	if err != nil {
		t.Fatalf("NewSAMLProvider() error: %v", err)
	}

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
}

func TestSAMLIntegration_HandleCallback(t *testing.T) {
	cfg := getSAMLConfig()
	if cfg.EntityID == "" {
		t.Skip("Skipping: SAML credentials not configured")
	}

	provider, err := NewSAMLProvider(cfg, stores.NewMemoryRequestStore())
	if err != nil {
		t.Fatalf("NewSAMLProvider() error: %v", err)
	}

	// Create a valid SAML response for testing
	samlResponse := createTestSAMLResponse(cfg.EntityID, cfg.ACSURL)

	resp, err := provider.HandleCallback(&SSORequest{}, map[string]string{"SAMLResponse": samlResponse})
	if err != nil {
		t.Fatalf("HandleCallback() error: %v", err)
	}

	if !resp.Success {
		t.Error("HandleCallback() should succeed with valid response")
	}
}

func TestSAMLIntegration_LoadIDPMetadata(t *testing.T) {
	metadataURL := os.Getenv("SAML_IDP_METADATA_URL")
	if metadataURL == "" {
		t.Skip("Skipping: SAML IdP metadata URL not configured")
	}

	cfg := &SSOConfig{
		Provider:  ProviderSAML,
		Name:      "test",
		EntityID:  "test-sp",
		ACSURL:    "http://localhost/acs",
		IDPSSOURL: "http://localhost/sso",
	}

	provider, err := NewSAMLProvider(cfg, nil)
	if err != nil {
		t.Fatalf("NewSAMLProvider() error: %v", err)
	}

	err = provider.LoadIDPMetadata(metadataURL, nil)
	if err != nil {
		t.Fatalf("LoadIDPMetadata() error: %v", err)
	}
}

// =============================================================================
// Helper Functions
// =============================================================================

func createTestIDToken(subject, email string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims := map[string]interface{}{
		"iss":   "https://test-issuer.com",
		"sub":   subject,
		"aud":   "test-client",
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"email": email,
		"nonce": "test-nonce",
	}
	claimsJSON, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
	return fmt.Sprintf("%s.%s.SIGNATURE", header, payload)
}

func createTestSAMLResponse(entityID, acsURL string) string {
	now := time.Now().UTC().Format(time.RFC3339)
	response := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    ID="_%d" Version="2.0" IssueInstant="%s"
    Destination="%s">
    <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.example.com</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
    <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        ID="_%d" Version="2.0" IssueInstant="%s">
        <saml:Issuer>https://idp.example.com</saml:Issuer>
        <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">test@example.com</saml:NameID>
        </saml:Subject>
        <saml:AuthnStatement AuthnInstant="%s" SessionIndex="test-session">
            <saml:AuthnContext>
                <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
            </saml:AuthnContext>
        </saml:AuthnStatement>
    </saml:Assertion>
</samlp:Response>`, time.Now().UnixNano(), now, acsURL, time.Now().UnixNano(), now, now)
	return base64.StdEncoding.EncodeToString([]byte(response))
}
