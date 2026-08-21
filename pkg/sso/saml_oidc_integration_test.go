// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform — SAML Audience + OIDC Introspection Tests
// =========================================================================
//
// This file tests the v4.2.0+ security hardening:
//   - SAML audience restriction enforcement (StrictAudience=true)
//   - SAML destination validation (StrictAudience=true)
//   - OIDC access token introspection (RFC 7662)
//
// These tests use the existing mock SAML/OIDC servers (saml_mock_server.go,
// oidc_mock_server.go) to exercise the enforcement paths without requiring
// external services.
//
// =========================================================================

package sso

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// =========================================================================
// SAML Audience Restriction Tests
// =========================================================================

// TestSAMLAudienceRestrictionEnforced tests that when StrictAudience=true,
// a SAML response with a wrong audience is rejected.
func TestSAMLAudienceRestrictionEnforced(t *testing.T) {
	server, err := NewMockSAMLServer()
	if err != nil {
		t.Fatalf("failed to create mock SAML server: %v", err)
	}
	defer server.Close()

	cfg := server.NewSAMLConfig()
	cfg.StrictAudience = true
	// EntityID is the expected audience — set it to something specific
	cfg.SAML.EntityID = "https://my-sp.example.com"

	provider, err := NewSAMLProvider(cfg, nil)
	if err != nil {
		t.Fatalf("failed to create SAML provider: %v", err)
	}

	// Build a SAML response with WRONG audience
	samlResponse := buildSAMLResponseWithAudience(
		server.EntityID,                // issuer (IdP entity ID)
		cfg.SAML.ACSURL,                // destination (matches ACS URL)
		"https://wrong-sp.example.com", // WRONG audience
		"testuser@example.com",
	)

	// Parse and validate
	response := &Response{}
	decoded, _ := base64.StdEncoding.DecodeString(samlResponse)
	if err := xml.Unmarshal(decoded, response); err != nil {
		t.Fatalf("failed to parse SAML response: %v", err)
	}

	err = provider.validateResponse(response)
	if err == nil {
		t.Error("validateResponse() should reject wrong audience when StrictAudience=true")
	}
	if err != nil && !strings.Contains(err.Error(), "audience restriction failed") {
		t.Errorf("expected 'audience restriction failed' error, got: %v", err)
	}
}

// TestSAMLAudienceRestrictionCorrect tests that when StrictAudience=true,
// a SAML response with the correct audience is accepted.
func TestSAMLAudienceRestrictionCorrect(t *testing.T) {
	server, err := NewMockSAMLServer()
	if err != nil {
		t.Fatalf("failed to create mock SAML server: %v", err)
	}
	defer server.Close()

	cfg := server.NewSAMLConfig()
	cfg.StrictAudience = true
	cfg.SAML.EntityID = "https://my-sp.example.com"

	provider, err := NewSAMLProvider(cfg, nil)
	if err != nil {
		t.Fatalf("failed to create SAML provider: %v", err)
	}

	// Build a SAML response with CORRECT audience
	samlResponse := buildSAMLResponseWithAudience(
		server.EntityID,   // issuer
		cfg.SAML.ACSURL,   // destination (matches)
		cfg.SAML.EntityID, // CORRECT audience
		"testuser@example.com",
	)

	response := &Response{}
	decoded, _ := base64.StdEncoding.DecodeString(samlResponse)
	if err := xml.Unmarshal(decoded, response); err != nil {
		t.Fatalf("failed to parse SAML response: %v", err)
	}

	// This should pass audience check but may fail on signature check
	// (which is expected — we're only testing audience enforcement)
	err = provider.validateResponse(response)
	if err != nil && strings.Contains(err.Error(), "audience restriction") {
		t.Errorf("validateResponse() should not reject correct audience: %v", err)
	}
	// Other errors (e.g., signature) are OK — we're only testing audience
}

// TestSAMLAudienceRestrictionDisabled tests that when StrictAudience=false,
// a SAML response with a wrong audience is accepted (lenient mode).
func TestSAMLAudienceRestrictionDisabled(t *testing.T) {
	server, err := NewMockSAMLServer()
	if err != nil {
		t.Fatalf("failed to create mock SAML server: %v", err)
	}
	defer server.Close()

	cfg := server.NewSAMLConfig()
	cfg.StrictAudience = false // Lenient mode
	cfg.SAML.EntityID = "https://my-sp.example.com"

	provider, err := NewSAMLProvider(cfg, nil)
	if err != nil {
		t.Fatalf("failed to create SAML provider: %v", err)
	}

	// Build a SAML response with WRONG audience
	samlResponse := buildSAMLResponseWithAudience(
		server.EntityID,
		cfg.SAML.ACSURL,
		"https://wrong-sp.example.com", // WRONG audience
		"testuser@example.com",
	)

	response := &Response{}
	decoded, _ := base64.StdEncoding.DecodeString(samlResponse)
	if err := xml.Unmarshal(decoded, response); err != nil {
		t.Fatalf("failed to parse SAML response: %v", err)
	}

	err = provider.validateResponse(response)
	if err != nil && strings.Contains(err.Error(), "audience restriction") {
		t.Errorf("validateResponse() should not reject audience when StrictAudience=false: %v", err)
	}
}

// TestSAMLDestinationValidationEnforced tests that when StrictAudience=true,
// a SAML response with a wrong destination is rejected.
func TestSAMLDestinationValidationEnforced(t *testing.T) {
	server, err := NewMockSAMLServer()
	if err != nil {
		t.Fatalf("failed to create mock SAML server: %v", err)
	}
	defer server.Close()

	cfg := server.NewSAMLConfig()
	cfg.StrictAudience = true
	cfg.SAML.EntityID = server.Server.URL // Match audience in mock response

	provider, err := NewSAMLProvider(cfg, nil)
	if err != nil {
		t.Fatalf("failed to create SAML provider: %v", err)
	}

	// Build a SAML response with WRONG destination
	samlResponse := buildSAMLResponseWithAudience(
		server.EntityID,
		"https://wrong-destination.example.com/acs", // WRONG destination
		cfg.SAML.EntityID, // correct audience
		"testuser@example.com",
	)

	response := &Response{}
	decoded, _ := base64.StdEncoding.DecodeString(samlResponse)
	if err := xml.Unmarshal(decoded, response); err != nil {
		t.Fatalf("failed to parse SAML response: %v", err)
	}

	err = provider.validateResponse(response)
	if err == nil {
		t.Error("validateResponse() should reject wrong destination when StrictAudience=true")
	}
	if err != nil && !strings.Contains(err.Error(), "destination mismatch") {
		t.Errorf("expected 'destination mismatch' error, got: %v", err)
	}
}

// TestSAMLDestinationValidationCorrect tests that when StrictAudience=true,
// a SAML response with the correct destination passes destination check.
func TestSAMLDestinationValidationCorrect(t *testing.T) {
	server, err := NewMockSAMLServer()
	if err != nil {
		t.Fatalf("failed to create mock SAML server: %v", err)
	}
	defer server.Close()

	cfg := server.NewSAMLConfig()
	cfg.StrictAudience = true
	cfg.SAML.EntityID = server.Server.URL // Match audience in mock response

	provider, err := NewSAMLProvider(cfg, nil)
	if err != nil {
		t.Fatalf("failed to create SAML provider: %v", err)
	}

	// Build a SAML response with CORRECT destination
	samlResponse := buildSAMLResponseWithAudience(
		server.EntityID,
		cfg.SAML.ACSURL,   // CORRECT destination
		cfg.SAML.EntityID, // CORRECT audience
		"testuser@example.com",
	)

	response := &Response{}
	decoded, _ := base64.StdEncoding.DecodeString(samlResponse)
	if err := xml.Unmarshal(decoded, response); err != nil {
		t.Fatalf("failed to parse SAML response: %v", err)
	}

	err = provider.validateResponse(response)
	if err != nil && strings.Contains(err.Error(), "destination mismatch") {
		t.Errorf("validateResponse() should not reject correct destination: %v", err)
	}
}

// TestSAMLNoAudienceRestriction tests that a SAML response without
// AudienceRestriction element is accepted (no restriction = no enforcement).
func TestSAMLNoAudienceRestriction(t *testing.T) {
	server, err := NewMockSAMLServer()
	if err != nil {
		t.Fatalf("failed to create mock SAML server: %v", err)
	}
	defer server.Close()

	cfg := server.NewSAMLConfig()
	cfg.StrictAudience = true
	cfg.SAML.EntityID = "https://my-sp.example.com"

	provider, err := NewSAMLProvider(cfg, nil)
	if err != nil {
		t.Fatalf("failed to create SAML provider: %v", err)
	}

	// Build a SAML response WITHOUT AudienceRestriction
	samlResponse := buildSAMLResponseNoAudience(
		server.EntityID,
		cfg.SAML.ACSURL,
		"testuser@example.com",
	)

	response := &Response{}
	decoded, _ := base64.StdEncoding.DecodeString(samlResponse)
	if err := xml.Unmarshal(decoded, response); err != nil {
		t.Fatalf("failed to parse SAML response: %v", err)
	}

	err = provider.validateResponse(response)
	if err != nil && strings.Contains(err.Error(), "audience restriction") {
		t.Errorf("validateResponse() should not reject when no AudienceRestriction present: %v", err)
	}
}

// =========================================================================
// OIDC Access Token Introspection Tests (RFC 7662)
// =========================================================================

// TestOIDCIntrospectionActiveToken tests that validateAccessToken correctly
// calls the introspection endpoint and accepts an active token.
func TestOIDCIntrospectionActiveToken(t *testing.T) {
	mockServer := NewMockOIDCServer()
	defer mockServer.Close()

	// Add introspection endpoint to the mock server
	introspectionCalled := false
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/introspect", func(w http.ResponseWriter, r *http.Request) {
		introspectionCalled = true
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"active":true,"username":"test-user","scope":"openid email"}`)
	})
	introspectionServer := httptest.NewServer(mux)
	defer introspectionServer.Close()

	provider := &OIDCProvider{
		oidcConfig: &OIDCConfig{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			IssuerURL:    introspectionServer.URL,
		},
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}

	err := provider.validateAccessToken("valid-token-123")
	if err != nil {
		t.Errorf("validateAccessToken() with active token should return nil, got: %v", err)
	}
	if !introspectionCalled {
		t.Error("introspection endpoint was not called")
	}
}

// TestOIDCIntrospectionInactiveToken tests that validateAccessToken rejects
// an inactive/revoked token.
func TestOIDCIntrospectionInactiveToken(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/introspect", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"active":false}`)
	})
	introspectionServer := httptest.NewServer(mux)
	defer introspectionServer.Close()

	provider := &OIDCProvider{
		oidcConfig: &OIDCConfig{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			IssuerURL:    introspectionServer.URL,
		},
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}

	err := provider.validateAccessToken("revoked-token-456")
	if err == nil {
		t.Error("validateAccessToken() with inactive token should return error")
	}
	if err != nil && !strings.Contains(err.Error(), "not active") {
		t.Errorf("expected 'not active' error, got: %v", err)
	}
}

// TestOIDCIntrospectionDiscoveryEndpoint tests that validateAccessToken uses
// the introspection_endpoint from the OIDC discovery document when available.
func TestOIDCIntrospectionDiscoveryEndpoint(t *testing.T) {
	discoveryIntrospectionCalled := false

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"issuer": "https://test-oidc.example.com",
			"introspection_endpoint": "https://test-oidc.example.com/introspect",
			"token_endpoint": "https://test-oidc.example.com/token"
		}`)
	})
	mux.HandleFunc("/introspect", func(w http.ResponseWriter, r *http.Request) {
		discoveryIntrospectionCalled = true
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"active":true}`)
	})
	introspectionServer := httptest.NewServer(mux)
	defer introspectionServer.Close()

	// Create provider with discovery document that has introspection_endpoint
	provider := &OIDCProvider{
		oidcConfig: &OIDCConfig{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			IssuerURL:    introspectionServer.URL,
		},
		discovery: &OIDCDiscoveryDocument{
			IntrospectionEndpoint: introspectionServer.URL + "/introspect",
		},
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}

	err := provider.validateAccessToken("test-token")
	if err != nil {
		t.Errorf("validateAccessToken() with discovery endpoint should return nil, got: %v", err)
	}
	if !discoveryIntrospectionCalled {
		t.Error("discovery-specified introspection endpoint was not called")
	}
}

// TestOIDCIntrospectionNetworkError tests that validateAccessToken fails open
// (returns nil) on network errors, per the design decision.
func TestOIDCIntrospectionNetworkError(t *testing.T) {
	// Use a non-routable address to simulate network error
	provider := &OIDCProvider{
		oidcConfig: &OIDCConfig{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			IssuerURL:    "http://127.0.0.1:1", // port 1 is non-routable
		},
		httpClient: &http.Client{Timeout: 1 * time.Second},
	}

	err := provider.validateAccessToken("any-token")
	if err != nil {
		t.Errorf("validateAccessToken() should fail open on network error, got: %v", err)
	}
}

// TestOIDCIntrospectionNon200Response tests that validateAccessToken fails open
// (returns nil) when the introspection endpoint returns a non-200 status.
func TestOIDCIntrospectionNon200Response(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/introspect", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	introspectionServer := httptest.NewServer(mux)
	defer introspectionServer.Close()

	provider := &OIDCProvider{
		oidcConfig: &OIDCConfig{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			IssuerURL:    introspectionServer.URL,
		},
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}

	err := provider.validateAccessToken("test-token")
	if err != nil {
		t.Errorf("validateAccessToken() should fail open on non-200 response, got: %v", err)
	}
}

// TestOIDCIntrospectionBasicAuth tests that the introspection request includes
// HTTP Basic Authentication with client_id and client_secret.
func TestOIDCIntrospectionBasicAuth(t *testing.T) {
	var receivedAuthHeader string
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/introspect", func(w http.ResponseWriter, r *http.Request) {
		receivedAuthHeader = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"active":true}`)
	})
	introspectionServer := httptest.NewServer(mux)
	defer introspectionServer.Close()

	provider := &OIDCProvider{
		oidcConfig: &OIDCConfig{
			ClientID:     "my-client-id",
			ClientSecret: "my-client-secret",
			IssuerURL:    introspectionServer.URL,
		},
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}

	_ = provider.validateAccessToken("test-token")

	if receivedAuthHeader == "" {
		t.Error("introspection request should include Authorization header")
	}
	if !strings.HasPrefix(receivedAuthHeader, "Basic ") {
		t.Errorf("expected Basic auth, got: %s", receivedAuthHeader)
	}
}

// TestOIDCIntrospectionNoConfig tests that validateAccessToken returns nil
// (no error) when no OIDC config is available.
func TestOIDCIntrospectionNoConfig(t *testing.T) {
	provider := &OIDCProvider{}

	err := provider.validateAccessToken("any-token")
	if err != nil {
		t.Errorf("validateAccessToken() with no config should return nil, got: %v", err)
	}
}

// TestOIDCIntrospectionTokenFormParam tests that the introspection request
// sends the token as a form parameter named "token" per RFC 7662.
func TestOIDCIntrospectionTokenFormParam(t *testing.T) {
	var receivedToken string
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/introspect", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		receivedToken = r.FormValue("token")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"active":true}`)
	})
	introspectionServer := httptest.NewServer(mux)
	defer introspectionServer.Close()

	provider := &OIDCProvider{
		oidcConfig: &OIDCConfig{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			IssuerURL:    introspectionServer.URL,
		},
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}

	_ = provider.validateAccessToken("my-specific-token-value")

	if receivedToken != "my-specific-token-value" {
		t.Errorf("expected token form param 'my-specific-token-value', got: %q", receivedToken)
	}
}

// =========================================================================
// Helper: Build SAML Response with specific audience
// =========================================================================

// buildSAMLResponseWithAudience creates a base64-encoded SAML response
// with the specified audience restriction and destination.
func buildSAMLResponseWithAudience(issuer, destination, audience, nameID string) string {
	now := time.Now().UTC()
	instant := now.Format(time.RFC3339)
	responseID := fmt.Sprintf("_response_%d", now.UnixNano())
	assertionID := fmt.Sprintf("_assertion_%d", now.UnixNano())

	xmlStr := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="%s" Version="2.0" IssueInstant="%s" Destination="%s">
    <saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">%s</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
    <saml:Assertion ID="%s" Version="2.0" IssueInstant="%s">
        <saml:Issuer>%s</saml:Issuer>
        <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">%s</saml:NameID>
        </saml:Subject>
        <saml:Conditions NotBefore="%s" NotOnOrAfter="%s">
            <saml:AudienceRestriction><saml:Audience>%s</saml:Audience></saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AuthnStatement AuthnInstant="%s" SessionIndex="test-session">
            <saml:AuthnContext>
                <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
            </saml:AuthnContext>
        </saml:AuthnStatement>
    </saml:Assertion>
</samlp:Response>`,
		responseID, instant, destination, issuer,
		assertionID, instant, issuer,
		nameID,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		audience,
		instant)

	return base64.StdEncoding.EncodeToString([]byte(xmlStr))
}

// buildSAMLResponseNoAudience creates a base64-encoded SAML response
// without an AudienceRestriction element.
func buildSAMLResponseNoAudience(issuer, destination, nameID string) string {
	now := time.Now().UTC()
	instant := now.Format(time.RFC3339)
	responseID := fmt.Sprintf("_response_%d", now.UnixNano())
	assertionID := fmt.Sprintf("_assertion_%d", now.UnixNano())

	xmlStr := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="%s" Version="2.0" IssueInstant="%s" Destination="%s">
    <saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">%s</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
    <saml:Assertion ID="%s" Version="2.0" IssueInstant="%s">
        <saml:Issuer>%s</saml:Issuer>
        <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">%s</saml:NameID>
        </saml:Subject>
        <saml:Conditions NotBefore="%s" NotOnOrAfter="%s">
        </saml:Conditions>
        <saml:AuthnStatement AuthnInstant="%s" SessionIndex="test-session">
            <saml:AuthnContext>
                <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
            </saml:AuthnContext>
        </saml:AuthnStatement>
    </saml:Assertion>
</samlp:Response>`,
		responseID, instant, destination, issuer,
		assertionID, instant, issuer,
		nameID,
		now.Add(-5*time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339),
		instant)

	return base64.StdEncoding.EncodeToString([]byte(xmlStr))
}
