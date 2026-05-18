// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// SAML Lab Integration Tests - Keycloak Signature Validation
// Requires: LAB_ENABLED=1 and running Keycloak Docker container
// =========================================================================

package sso

import (
	"encoding/base64"
	"encoding/xml"
	"testing"
)

// TestKeycloakSAMLSignatureValidation tests the real signature validation flow against a running Keycloak
func TestKeycloakSAMLSignatureValidation(t *testing.T) {
	SkipIfLabDisabled(t)

	// 1. Setup Provider with Keycloak settings
	config := &SSOConfig{
		Name:     "keycloak-saml-lab",
		Provider: ProviderSAML,
		SAML: &SAMLConfig{
			EntityID:          "aegisgate-platform",
			ACSURL:            "http://localhost/acs",
			IDPEntityID:       "http://localhost:8080/realms/aegisgate",
			ValidateSignature: true,
		},
	}

	provider, err := NewSAMLProvider(config, nil)
	if err != nil {
		t.Fatalf("Failed to create SAML provider: %v", err)
	}

	// 2. Automatically load Keycloak metadata to get the signing certificates
	metadataURL := "http://localhost:8080/realms/aegisgate/protocol/saml/descriptor"
	err = provider.LoadIDPMetadata(metadataURL, nil)
	if err != nil {
		t.Logf("Metadata load failed: %v", err)
		t.Skip("Skipping: Keycloak metadata could not be loaded, ensure Keycloak is running and realm is correct")
	}

	if len(provider.samlConfig.IDPSSODescriptor.SigningCertificates) == 0 {
		t.Fatal("No signing certificates found in Keycloak metadata")
	}

	// 3. Test with a real signed response from Keycloak
	signedResponseB64 := getTestSignedSAMLResponse()
	if signedResponseB64 == "" {
		t.Log("No signed SAML response provided via TEST_SIGNED_SAML_RESPONSE")
		t.Skip("Skipping: Provide TEST_SIGNED_SAML_RESPONSE to test actual signature verification")
	}

	decoded, err := base64.StdEncoding.DecodeString(signedResponseB64)
	if err != nil {
		t.Fatalf("Failed to decode signed response: %v", err)
	}

	response := &Response{}
	if err := xml.Unmarshal(decoded, response); err != nil {
		t.Fatalf("Failed to unmarshal SAML response: %v", err)
	}

	// Execution of the target function: validateSignature
	err = provider.validateSignature(response)
	if err != nil {
		t.Errorf("SAML signature validation failed: %v", err)
	}
}

// TestKeycloakSAMLInvalidSignature tests that validation fails with an altered response
func TestKeycloakSAMLInvalidSignature(t *testing.T) {
	SkipIfLabDisabled(t)

	config := &SSOConfig{
		Name:     "keycloak-saml-lab",
		Provider: ProviderSAML,
		SAML: &SAMLConfig{
			EntityID:          "aegisgate-platform",
			ACSURL:            "http://localhost/acs",
			IDPEntityID:       "http://localhost:8080/realms/aegisgate",
			ValidateSignature: true,
		},
	}

	provider, err := NewSAMLProvider(config, nil)
	if err != nil {
		t.Fatalf("Failed to create SAML provider: %v", err)
	}

	// Load metadata
	metadataURL := "http://localhost:8080/realms/aegisgate/protocol/saml/descriptor"
	_ = provider.LoadIDPMetadata(metadataURL, nil)

	signedResponseB64 := getTestSignedSAMLResponse()
	if signedResponseB64 == "" {
		t.Skip("Skipping: No signed response to corrupt")
	}

	decoded, _ := base64.StdEncoding.DecodeString(signedResponseB64)

	// Corrupt the payload to invalidate the signature
	if len(decoded) > 100 {
		decoded[50] = decoded[50] ^ 0xFF
	}

	response := &Response{}
	_ = xml.Unmarshal(decoded, response)

	err = provider.validateSignature(response)
	if err == nil {
		t.Error("Expected signature validation to fail for corrupted response, but it succeeded")
	}
}
