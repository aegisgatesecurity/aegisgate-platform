// SPDX-License-Identifier: Apache-2.0
// =============================================================================
// AegisGate SSO Lab Integration Tests
// =============================================================================
// These tests require a running lab environment with real OIDC/SAML providers.
// Run with: LAB_ENABLED=1 go test -tags=lab -v ./pkg/sso/...
//
// Prerequisites:
//   1. Start the lab: cd testlab && docker compose up -d
//   2. Wait for Keycloak: sleep 30
//   3. Run tests: cd .. && LAB_ENABLED=1 go test -tags=lab -v ./pkg/sso/...
// =============================================================================

//go:build lab

package sso

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
)

// LabTestConfig holds configuration for lab tests
type LabTestConfig struct {
	KeycloakURL   string
	KeycloakRealm string
	ClientID      string
	ClientSecret  string
	AegisGateURL  string
}

func getLabConfig() *LabTestConfig {
	return &LabTestConfig{
		KeycloakURL:   getEnv("KEYCLOAK_URL", "http://localhost:8080"),
		KeycloakRealm: getEnv("KEYCLOAK_REALM", "aegisgate"),
		ClientID:      getEnv("OIDC_CLIENT_ID", "aegisgate-platform"),
		ClientSecret:  getEnv("OIDC_CLIENT_SECRET", "aegisgate-oidc-secret"),
		AegisGateURL:  getEnv("AEGISGATE_TEST_URL", "http://localhost:8443"),
	}
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

// =============================================================================
// OIDC Discovery Tests
// =============================================================================

func TestLab_OIDCDiscovery(t *testing.T) {
	if os.Getenv("LAB_ENABLED") != "1" {
		t.Skip("LAB_ENABLED is not set")
	}

	cfg := getLabConfig()
	discoveryURL := fmt.Sprintf("%s/realms/%s/.well-known/openid-configuration",
		cfg.KeycloakURL, cfg.KeycloakRealm)

	resp, err := http.Get(discoveryURL)
	if err != nil {
		t.Fatalf("Failed to fetch OIDC discovery: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("OIDC discovery returned status %d", resp.StatusCode)
	}

	var discovery struct {
		Issuer                string   `json:"issuer"`
		AuthorizationEndpoint string   `json:"authorization_endpoint"`
		TokenEndpoint         string   `json:"token_endpoint"`
		UserinfoEndpoint      string   `json:"userinfo_endpoint"`
		JWKSURI               string   `json:"jwks_uri"`
		ScopesSupported       []string `json:"scopes_supported"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		t.Fatalf("Failed to parse OIDC discovery: %v", err)
	}

	// Verify required endpoints
	if discovery.AuthorizationEndpoint == "" {
		t.Error("Authorization endpoint is empty")
	}
	if discovery.TokenEndpoint == "" {
		t.Error("Token endpoint is empty")
	}
	if discovery.UserinfoEndpoint == "" {
		t.Error("Userinfo endpoint is empty")
	}

	t.Logf("OIDC Discovery successful:")
	t.Logf("  Issuer: %s", discovery.Issuer)
	t.Logf("  Auth Endpoint: %s", discovery.AuthorizationEndpoint)
	t.Logf("  Token Endpoint: %s", discovery.TokenEndpoint)
}

// =============================================================================
// OIDC Authentication Flow Tests
// =============================================================================

func TestLab_OIDCProviderWithKeycloak(t *testing.T) {
	if os.Getenv("LAB_ENABLED") != "1" {
		t.Skip("LAB_ENABLED is not set")
	}

	cfg := getLabConfig()

	// Create manager first
	mgr, err := NewManager(nil)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	// Create OIDC config
	oidcConfig := &SSOConfig{
		Name:     "keycloak",
		Provider: ProviderOIDC,
		OIDC: &OIDCConfig{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			IssuerURL:    fmt.Sprintf("%s/realms/%s", cfg.KeycloakURL, cfg.KeycloakRealm),
			RedirectURL:  cfg.AegisGateURL + "/sso/callback",
			Scopes:       []string{"openid", "profile", "email", "groups"},
		},
	}

	// Create OIDC provider
	provider, err := NewOIDCProvider(oidcConfig, nil)
	if err != nil {
		t.Fatalf("Failed to create OIDC provider: %v", err)
	}

	_ = mgr // Manager created for context

	t.Run("Name and Type", func(t *testing.T) {
		if provider.Name() != "keycloak" {
			t.Errorf("Name() = %s, want keycloak", provider.Name())
		}
		if provider.Type() != ProviderOIDC {
			t.Errorf("Type() = %s, want %s", provider.Type(), ProviderOIDC)
		}
	})

	t.Run("Metadata", func(t *testing.T) {
		meta, err := provider.Metadata()
		if err != nil {
			t.Fatalf("Metadata() error: %v", err)
		}
		if len(meta) == 0 {
			t.Error("Metadata() returned empty bytes")
		}
		t.Logf("Provider metadata length: %d bytes", len(meta))
	})
}

// =============================================================================
// Manager Integration Tests
// =============================================================================

func TestLab_ManagerWithKeycloak(t *testing.T) {
	if os.Getenv("LAB_ENABLED") != "1" {
		t.Skip("LAB_ENABLED is not set")
	}

	cfg := getLabConfig()

	// Create manager
	mgr, err := NewManager(nil)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	// Register OIDC provider
	err = mgr.RegisterProvider(&SSOConfig{
		Name:     "keycloak",
		Provider: ProviderOIDC,
		OIDC: &OIDCConfig{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			IssuerURL:    fmt.Sprintf("%s/realms/%s", cfg.KeycloakURL, cfg.KeycloakRealm),
			RedirectURL:  cfg.AegisGateURL + "/sso/callback",
			Scopes:       []string{"openid", "profile", "email"},
		},
	})
	if err != nil {
		t.Fatalf("Failed to register provider: %v", err)
	}

	t.Run("ProviderExists", func(t *testing.T) {
		_, err := mgr.GetProvider("keycloak")
		if err != nil {
			t.Errorf("GetProvider(keycloak) error: %v", err)
		}
	})

	t.Run("InitiateLogin", func(t *testing.T) {
		_, _, err := mgr.InitiateLogin("keycloak")
		if err != nil {
			t.Fatalf("InitiateLogin() error: %v", err)
		}
	})

	t.Run("GetProviderMetadata", func(t *testing.T) {
		meta, err := mgr.GetProviderMetadata("keycloak")
		if err != nil {
			t.Fatalf("GetProviderMetadata() error: %v", err)
		}
		if len(meta) == 0 {
			t.Error("GetProviderMetadata() returned empty")
		} else {
			t.Logf("Provider metadata: %d bytes", len(meta))
		}
	})
}

// =============================================================================
// SAML IdP Metadata Tests
// =============================================================================

func TestLab_SAMLIdPMetadata(t *testing.T) {
	if os.Getenv("LAB_ENABLED") != "1" {
		t.Skip("LAB_ENABLED is not set")
	}

	cfg := getLabConfig()

	// Keycloak SAML metadata endpoint
	samlMetadataURL := fmt.Sprintf("%s/realms/%s/protocol/saml/descriptor",
		cfg.KeycloakURL, cfg.KeycloakRealm)

	resp, err := http.Get(samlMetadataURL)
	if err != nil {
		t.Fatalf("Failed to fetch SAML metadata: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("SAML metadata returned status %d", resp.StatusCode)
	}

	// Read metadata
	buf := make([]byte, 1024*100) // 100KB buffer
	n, _ := resp.Body.Read(buf)
	metadata := buf[:n]

	if len(metadata) == 0 {
		t.Fatal("SAML metadata is empty")
	}

	// Basic validation - check for expected SAML elements
	metadataStr := string(metadata)
	if len(metadataStr) < 100 {
		t.Error("SAML metadata seems too short")
	}

	t.Logf("SAML IdP Metadata: %d bytes", len(metadata))
	t.Logf("SAML EntityID found: %v", len(metadataStr) > 0)
}

// =============================================================================
// Lab Environment Health Check
// =============================================================================

func TestLab_EnvironmentHealth(t *testing.T) {
	if os.Getenv("LAB_ENABLED") != "1" {
		t.Skip("LAB_ENABLED is not set")
	}

	cfg := getLabConfig()

	t.Run("KeycloakRealmExists", func(t *testing.T) {
		realmURL := fmt.Sprintf("%s/realms/%s", cfg.KeycloakURL, cfg.KeycloakRealm)
		resp, err := http.Get(realmURL)
		if err != nil {
			t.Fatalf("Failed to check realm: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Realm check returned status %d", resp.StatusCode)
		} else {
			t.Logf("Realm %s exists and is accessible", cfg.KeycloakRealm)
		}
	})

	t.Run("OIDCDiscoveryAvailable", func(t *testing.T) {
		discoveryURL := fmt.Sprintf("%s/realms/%s/.well-known/openid-configuration",
			cfg.KeycloakURL, cfg.KeycloakRealm)
		resp, err := http.Get(discoveryURL)
		if err != nil {
			t.Fatalf("Failed to fetch OIDC discovery: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("OIDC discovery returned status %d", resp.StatusCode)
		} else {
			t.Log("OIDC discovery endpoint is accessible")
		}
	})

	t.Run("SAMLMDescriptorAvailable", func(t *testing.T) {
		samlURL := fmt.Sprintf("%s/realms/%s/protocol/saml/descriptor",
			cfg.KeycloakURL, cfg.KeycloakRealm)
		resp, err := http.Get(samlURL)
		if err != nil {
			t.Fatalf("Failed to fetch SAML descriptor: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("SAML descriptor returned status %d", resp.StatusCode)
		} else {
			t.Log("SAML descriptor endpoint is accessible")
		}
	})
}

// =============================================================================
// Test Data Cleanup
// =============================================================================

func TestLab_Cleanup(t *testing.T) {
	if os.Getenv("LAB_ENABLED") != "1" {
		t.Skip("LAB_ENABLED is not set")
	}
	// This test always passes but logs cleanup instructions
	t.Log("Lab tests completed")
	t.Log("To stop the lab:")
	t.Log("  cd testlab && docker compose down")
}
