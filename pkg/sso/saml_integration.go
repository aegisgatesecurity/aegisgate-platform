// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// SAML Integration Tests
// These functions require real SAML IdP credentials and are excluded from
// standard coverage by the integration build tag.
// =========================================================================
//go:build integration
// +build integration

package sso

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestSAMLIntegration_InitiateLogin tests SAML InitiateLogin with real IdP
func TestSAMLIntegration_InitiateLogin(t *testing.T) {
	// Skip if no real IdP URL available
	idpSSOURL := getTestIDPSSOURL()
	if idpSSOURL == "" {
		t.Skip("Skipping: no SAML IdP SSO URL provided")
	}

	provider := &SAMLProvider{
		samlConfig: &SAMLConfig{
			EntityID: "test-sp",
			IDPSSODescriptor: &IDPSSODescriptor{
				SSOURLs: []string{idpSSOURL},
			},
		},
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

// TestSAMLIntegration_HandleCallback tests SAML HandleCallback with real IdP
func TestSAMLIntegration_HandleCallback(t *testing.T) {
	// Skip if no real SAML response available
	samlResponse := getTestSAMLResponse()
	if samlResponse == "" {
		t.Skip("Skipping: no SAML response provided")
	}

	provider := &SAMLProvider{
		samlConfig: &SAMLConfig{
			EntityID:          "test-sp",
			ACSURL:            "http://localhost/acs",
			ValidateSignature: false, // Disable for testing
		},
	}

	ssoReq := &SSORequest{
		ID:       "test-request",
		Provider: "test-idp",
	}

	params := map[string]string{
		"SAMLResponse": samlResponse,
	}

	resp, err := provider.HandleCallback(ssoReq, params)
	if err != nil {
		t.Fatalf("HandleCallback() error: %v", err)
	}

	if !resp.Success {
		t.Error("HandleCallback() should succeed with valid response")
	}

	if resp.User == nil {
		t.Error("HandleCallback() should return user")
	}
}

// TestSAMLIntegration_LoadIDPMetadata tests loading IdP metadata from URL
func TestSAMLIntegration_LoadIDPMetadata(t *testing.T) {
	// Skip if no real metadata URL available
	metadataURL := getTestIDPMetadataURL()
	if metadataURL == "" {
		t.Skip("Skipping: no IdP metadata URL provided")
	}

	provider := &SAMLProvider{
		samlConfig: &SAMLConfig{
			EntityID: "test-sp",
		},
		httpClient: &http.Client{Timeout: 30},
	}

	err := provider.LoadIDPMetadata(metadataURL, nil)
	if err != nil {
		t.Fatalf("LoadIDPMetadata() error: %v", err)
	}
}

// TestSAMLIntegration_validateSignature tests SAML signature validation
func TestSAMLIntegration_validateSignature(t *testing.T) {
	// Skip if no real signed response available
	signedResponse := getTestSignedSAMLResponse()
	if signedResponse == "" {
		t.Skip("Skipping: no signed SAML response provided")
	}

	// This test requires a real IdP certificate
	t.Skip("Signature validation requires real IdP certificates")
}

// Helper functions for test credentials
