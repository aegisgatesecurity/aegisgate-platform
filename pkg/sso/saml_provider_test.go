// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// SAML Provider Tests with Mock Servers
// =========================================================================

package sso

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// =============================================================================
// SAML NewSAMLProvider Tests
// =============================================================================

func TestNewSAMLProviderErrors(t *testing.T) {
	t.Run("nil SAML config", func(t *testing.T) {
		_, err := NewSAMLProvider(&SSOConfig{
			Provider: ProviderSAML,
			Name:     "test",
		}, nil)
		if err == nil {
			t.Error("Should fail without SAML config")
		}
	})

	t.Run("missing EntityID", func(t *testing.T) {
		_, err := NewSAMLProvider(&SSOConfig{
			Provider: ProviderSAML,
			Name:     "test",
			SAML:     &SAMLConfig{},
		}, nil)
		if err == nil {
			t.Error("Should fail without EntityID")
		}
	})

	t.Run("missing ACSURL", func(t *testing.T) {
		_, err := NewSAMLProvider(&SSOConfig{
			Provider: ProviderSAML,
			Name:     "test",
			SAML: &SAMLConfig{
				EntityID: "http://localhost",
			},
		}, nil)
		if err == nil {
			t.Error("Should fail without ACSURL")
		}
	})
}

// =============================================================================
// SAML InitiateLogin Tests
// =============================================================================

func TestSAMLInitiateLogin(t *testing.T) {
	mockServer, err := NewMockSAMLServer()
	if err != nil {
		t.Fatalf("Failed to create mock SAML server: %v", err)
	}
	defer mockServer.Close()

	cfg := mockServer.NewSAMLConfig()
	provider, err := NewSAMLProvider(cfg, nil)
	if err != nil {
		t.Fatalf("Failed to create SAML provider: %v", err)
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

		// Verify request is stored
		if ssoReq.ID == "" {
			t.Error("SSORequest should have ID")
		}

		if ssoReq.RelayState != "test-state" {
			t.Errorf("RelayState = %q, want test-state", ssoReq.RelayState)
		}
	})

	t.Run("SAMLRequest in redirect", func(t *testing.T) {
		loginURL, _, err := provider.InitiateLogin("another-state")
		if err != nil {
			t.Fatalf("InitiateLogin() error: %v", err)
		}

		// Parse URL
		parsed, err := url.Parse(loginURL)
		if err != nil {
			t.Fatalf("Failed to parse URL: %v", err)
		}

		// Extract RelayState from parsed URL
		relayState := parsed.Query().Get("RelayState")
		if relayState != "another-state" {
			t.Errorf("RelayState in URL = %q, want another-state", relayState)
		}
	})
}

// =============================================================================
// SAML HandleCallback Tests
// =============================================================================

func TestSAMLHandleCallback(t *testing.T) {
	mockServer, err := NewMockSAMLServer()
	if err != nil {
		t.Fatalf("Failed to create mock SAML server: %v", err)
	}
	defer mockServer.Close()

	cfg := mockServer.NewSAMLConfig()
	cfg.SAML.ValidateSignature = false // Disable signature validation for tests
	provider, err := NewSAMLProvider(cfg, nil)
	if err != nil {
		t.Fatalf("Failed to create SAML provider: %v", err)
	}

	t.Run("missing SAMLResponse", func(t *testing.T) {
		_, err := provider.HandleCallback(&SSORequest{}, map[string]string{})
		if err == nil {
			t.Error("HandleCallback() should fail without SAMLResponse")
		}
	})

	t.Run("invalid base64", func(t *testing.T) {
		_, err := provider.HandleCallback(&SSORequest{}, map[string]string{
			"SAMLResponse": "not-valid-base64!!!",
		})
		if err == nil {
			t.Error("HandleCallback() should fail with invalid base64")
		}
	})
}

func TestSAMLHandleCallbackWithValidResponse(t *testing.T) {
	mockServer, err := NewMockSAMLServer()
	if err != nil {
		t.Fatalf("Failed to create mock SAML server: %v", err)
	}
	defer mockServer.Close()

	cfg := mockServer.NewSAMLConfig()
	cfg.SAML.ValidateSignature = false
	provider, err := NewSAMLProvider(cfg, nil)
	if err != nil {
		t.Fatalf("Failed to create SAML provider: %v", err)
	}

	// Create a valid SAML response
	samlResponse := mockServer.buildSAMLResponse("http://localhost/acs", "test-state")
	encodedResponse := base64.StdEncoding.EncodeToString([]byte(samlResponse))

	resp, err := provider.HandleCallback(&SSORequest{}, map[string]string{
		"SAMLResponse": encodedResponse,
	})
	if err != nil {
		t.Fatalf("HandleCallback() error: %v", err)
	}

	if !resp.Success {
		t.Error("HandleCallback() should succeed with valid response")
	}

	if resp.User == nil {
		t.Error("Should return user")
	}

	// Verify the NameID was extracted
	if resp.User.NameID == "" {
		t.Error("Should extract NameID from assertion")
	}

	// Verify UpstreamID was set (it's set in the SAML code)
	if resp.User.UpstreamID == "" {
		t.Error("Should extract UpstreamID from assertion")
	}
}

// =============================================================================
// SAML ValidateSession Tests
// =============================================================================

func TestSAMLValidateSession(t *testing.T) {
	mockServer, err := NewMockSAMLServer()
	if err != nil {
		t.Fatalf("Failed to create mock SAML server: %v", err)
	}
	defer mockServer.Close()

	cfg := mockServer.NewSAMLConfig()
	provider, err := NewSAMLProvider(cfg, nil)
	if err != nil {
		t.Fatalf("Failed to create SAML provider: %v", err)
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
// SAML Logout Tests
// =============================================================================

func TestSAMLLogout(t *testing.T) {
	mockServer, err := NewMockSAMLServer()
	if err != nil {
		t.Fatalf("Failed to create mock SAML server: %v", err)
	}
	defer mockServer.Close()

	cfg := mockServer.NewSAMLConfig()
	provider, err := NewSAMLProvider(cfg, nil)
	if err != nil {
		t.Fatalf("Failed to create SAML provider: %v", err)
	}

	t.Run("nil session", func(t *testing.T) {
		_, err := provider.Logout(nil)
		if err == nil {
			t.Error("Logout() should fail with nil session")
		}
	})

	t.Run("with SLO URL", func(t *testing.T) {
		session := &SSOSession{
			ID:     "test-session",
			UserID: "user-1",
			NameID: "testuser@example.com",
		}
		logoutURL, err := provider.Logout(session)
		if err != nil {
			t.Fatalf("Logout() error: %v", err)
		}

		if logoutURL == "" {
			t.Error("Logout() should return SLO URL")
		}
	})
}

// =============================================================================
// SAML Metadata Tests
// =============================================================================

func TestSAMLMetadata(t *testing.T) {
	mockServer, err := NewMockSAMLServer()
	if err != nil {
		t.Fatalf("Failed to create mock SAML server: %v", err)
	}
	defer mockServer.Close()

	cfg := mockServer.NewSAMLConfig()
	provider, err := NewSAMLProvider(cfg, nil)
	if err != nil {
		t.Fatalf("Failed to create SAML provider: %v", err)
	}

	t.Run("metadata generation", func(t *testing.T) {
		metadata, err := provider.Metadata()
		if err != nil {
			t.Fatalf("Metadata() error: %v", err)
		}

		if len(metadata) == 0 {
			t.Error("Metadata() should return content")
		}

		// Verify it's valid XML
		var entity EntityDescriptor
		if err := xml.Unmarshal(metadata, &entity); err != nil {
			t.Errorf("Metadata() should return valid XML: %v", err)
		}

		if entity.EntityID != cfg.SAML.EntityID {
			t.Errorf("EntityID = %q, want %q", entity.EntityID, cfg.SAML.EntityID)
		}
	})
}

// =============================================================================
// SAML LoadIDPMetadata Tests
// =============================================================================

func TestSAMLLoadIDPMetadata(t *testing.T) {
	mockServer, err := NewMockSAMLServer()
	if err != nil {
		t.Fatalf("Failed to create mock SAML server: %v", err)
	}
	defer mockServer.Close()

	cfg := &SSOConfig{
		Provider: ProviderSAML,
		Name:     "test-saml",
		SAML: &SAMLConfig{
			EntityID:    mockServer.Server.URL,
			ACSURL:      mockServer.Server.URL + "/acs",
			IDPEntityID: mockServer.EntityID,
		},
	}

	provider, err := NewSAMLProvider(cfg, nil)
	if err != nil {
		t.Fatalf("Failed to create SAML provider: %v", err)
	}

	t.Run("load from URL", func(t *testing.T) {
		err := provider.LoadIDPMetadata(mockServer.MetadataURL, nil)
		if err != nil {
			t.Fatalf("LoadIDPMetadata() error: %v", err)
		}
	})

	t.Run("load from bytes", func(t *testing.T) {
		metadataBytes, err := mockServer.GetMetadataBytes()
		if err != nil {
			t.Fatalf("Failed to get metadata: %v", err)
		}

		provider2, err := NewSAMLProvider(&SSOConfig{
			Provider: ProviderSAML,
			Name:     "test-saml-2",
			SAML: &SAMLConfig{
				EntityID:    mockServer.Server.URL,
				ACSURL:      mockServer.Server.URL + "/acs",
				IDPEntityID: mockServer.EntityID,
			},
		}, nil)
		if err != nil {
			t.Fatalf("Failed to create provider: %v", err)
		}

		err = provider2.LoadIDPMetadata("", metadataBytes)
		if err != nil {
			t.Fatalf("LoadIDPMetadata() error: %v", err)
		}
	})

	t.Run("no metadata provided", func(t *testing.T) {
		err := provider.LoadIDPMetadata("", nil)
		if err == nil {
			t.Error("LoadIDPMetadata() should fail with no metadata")
		}
	})
}

// =============================================================================
// SAML Name and Type Tests
// =============================================================================

func TestSAMLNameAndType(t *testing.T) {
	mockServer, err := NewMockSAMLServer()
	if err != nil {
		t.Fatalf("Failed to create mock SAML server: %v", err)
	}
	defer mockServer.Close()

	cfg := mockServer.NewSAMLConfig()
	provider, err := NewSAMLProvider(cfg, nil)
	if err != nil {
		t.Fatalf("Failed to create SAML provider: %v", err)
	}

	if provider.Name() == "" {
		t.Error("Name() should return non-empty string")
	}

	if provider.Type() != ProviderSAML {
		t.Error("Type() should return ProviderSAML")
	}
}

// =============================================================================
// Mock server tests
// =============================================================================

func TestMockSAMLServerMetadata(t *testing.T) {
	mockServer, err := NewMockSAMLServer()
	if err != nil {
		t.Fatalf("Failed to create mock SAML server: %v", err)
	}
	defer mockServer.Close()

	resp, err := http.Get(mockServer.MetadataURL)
	if err != nil {
		t.Fatalf("Metadata endpoint error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Metadata returned status %d", resp.StatusCode)
	}

	var metadata string
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read body: %v", err)
	}
	metadata = string(body)

	if !strings.Contains(metadata, mockServer.EntityID) {
		t.Error("Metadata should contain entityID")
	}
}

func TestMockSAMLServerSSO(t *testing.T) {
	mockServer, err := NewMockSAMLServer()
	if err != nil {
		t.Fatalf("Failed to create mock SAML server: %v", err)
	}
	defer mockServer.Close()

	// Create a test AuthnRequest
	authnReq := fmt.Sprintf(`<?xml version="1.0"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="test" Version="2.0">
</samlp:AuthnRequest>`)

	encoded := base64.StdEncoding.EncodeToString([]byte(authnReq))

	resp, err := http.Get(mockServer.SSOURL + "?SAMLRequest=" + encoded + "&RelayState=test")
	if err != nil {
		t.Fatalf("SSO endpoint error: %v", err)
	}
	defer resp.Body.Close()

	// Should return OK after processing (ACS endpoint)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("SSO returned status %d, want %d", resp.StatusCode, http.StatusOK)
	}

	// The SSO handler should have processed the request successfully
	// (either redirecting to ACS or processing inline)
}

// =============================================================================
// Helper function tests
// =============================================================================

func TestSAMLGenerateRequestID(t *testing.T) {
	id1 := generateRequestID()
	id2 := generateRequestID()

	if id1 == "" || id2 == "" {
		t.Error("generateRequestID() should return non-empty string")
	}

	if id1 == id2 {
		t.Error("generateRequestID() should generate unique IDs")
	}

	if !strings.HasPrefix(id1, "_") {
		t.Error("Request ID should start with underscore")
	}
}

func TestSAMLGenerateSessionID(t *testing.T) {
	id1 := generateSessionID()
	id2 := generateSessionID()

	if id1 == "" || id2 == "" {
		t.Error("generateSessionID() should return non-empty string")
	}

	if id1 == id2 {
		t.Error("generateSessionID() should generate unique IDs")
	}
}

// Test SAML load IDP metadata from URL
func TestSAMLLoadIDPMetadataFromURL(t *testing.T) {
	// Start mock SAML server
	mockServer, err := NewMockSAMLServer()
	if err != nil {
		t.Fatalf("NewMockSAMLServer() error: %v", err)
	}
	defer mockServer.Close()

	// Create provider with metadata URL
	provider, err := NewSAMLProvider(&SSOConfig{
		Name:     "test-saml",
		Provider: ProviderSAML,
		SAML: &SAMLConfig{
			EntityID:       mockServer.EntityID,
			ACSURL:         mockServer.Server.URL + "/acs",
			IDPEntityID:    mockServer.EntityID,
			IDPMetadataURL: mockServer.Server.URL + "/saml/metadata",
		},
	}, nil)
	if err != nil {
		t.Fatalf("NewSAMLProvider() error: %v", err)
	}

	// Test that provider was created
	if provider == nil {
		t.Error("NewSAMLProvider() returned nil")
	}
}

// Test SAML validateSignature - no certificates error path
func TestSAMLValidateSignatureNoCertificates(t *testing.T) {
	// Create provider WITHOUT certificates
	provider := &SAMLProvider{
		samlConfig: &SAMLConfig{
			EntityID: "test",
			ACSURL:   "http://localhost/acs",
			IDPSSODescriptor: &IDPSSODescriptor{
				SigningCertificates: nil, // No certificates
			},
		},
	}

	// Create a minimal response
	resp := &Response{}

	err := provider.validateSignature(resp)
	if err == nil {
		t.Error("validateSignature() should fail with no certificates")
	}
}
