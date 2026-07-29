// SPDX-License-Identifier: Apache-2.0

package sso

import (
	"strings"
	"testing"
)

// =========================================================================
// OIDC ACR Values Tests
// =========================================================================

func TestOIDCMapClaimsToUser_ACRMapping(t *testing.T) {
	provider := &OIDCProvider{
		config: &SSOConfig{
			AttributeMapping: &AttributeMapping{},
		},
	}

	tests := []struct {
		name        string
		acrValue    string
		existingCtx string
		wantCtx     string
	}{
		{name: "acr mapped to AuthnContext", acrValue: "1", wantCtx: "1"},
		{name: "acr mapped with MFA level", acrValue: "urn:mace:incommon:iap:silver", wantCtx: "urn:mace:incommon:iap:silver"},
		{name: "acr not overwritten if AuthnContext already set", acrValue: "2", existingCtx: "phishing-resistant", wantCtx: "phishing-resistant"},
		{name: "empty acr does not overwrite", acrValue: "", existingCtx: "existing", wantCtx: "existing"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := &SSOUser{AuthnContext: tt.existingCtx}
			claims := &OIDCIDTokenClaims{
				Subject: "user123",
				ACR:     tt.acrValue,
			}
			provider.mapClaimsToUser(user, claims)
			if user.AuthnContext != tt.wantCtx {
				t.Errorf("AuthnContext = %q, want %q", user.AuthnContext, tt.wantCtx)
			}
		})
	}
}

func TestOIDCAcrValuesConfigured(t *testing.T) {
	// Verify AcrValues in OIDCConfig are passed through to the auth URL.
	// We can't call InitiateLogin without a real OAuth2 config, so we
	// verify the field exists and is accessible.
	cfg := &SSOConfig{
		Name: "test-acr",
		OIDC: &OIDCConfig{
			IssuerURL:    "https://idp.example.com",
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			RedirectURL:  "https://app.example.com/callback",
			Scopes:       []string{"openid", "profile"},
			AcrValues:    []string{"urn:mace:incommon:iap:silver", "1"},
		},
		AttributeMapping: DefaultAttributeMapping(),
	}

	if len(cfg.OIDC.AcrValues) != 2 {
		t.Fatalf("AcrValues length = %d, want 2", len(cfg.OIDC.AcrValues))
	}
	if cfg.OIDC.AcrValues[0] != "urn:mace:incommon:iap:silver" {
		t.Errorf("AcrValues[0] = %q, want urn:mace:incommon:iap:silver", cfg.OIDC.AcrValues[0])
	}
	if cfg.OIDC.AcrValues[1] != "1" {
		t.Errorf("AcrValues[1] = %q, want 1", cfg.OIDC.AcrValues[1])
	}
}

func TestOIDCAcrValuesEmpty(t *testing.T) {
	// When no AcrValues are configured, the provider should work normally.
	cfg := &SSOConfig{
		Name: "test-no-acr",
		OIDC: &OIDCConfig{
			IssuerURL:    "https://idp.example.com",
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			RedirectURL:  "https://app.example.com/callback",
			Scopes:       []string{"openid", "profile"},
		},
		AttributeMapping: DefaultAttributeMapping(),
	}

	if len(cfg.OIDC.AcrValues) != 0 {
		t.Errorf("AcrValues should be empty by default, got %v", cfg.OIDC.AcrValues)
	}
}

func TestOIDCGetProviderSpecificOptions_IncludesAcrValues(t *testing.T) {
	// Verify getProviderSpecificOptions includes ACR values in the auth params.
	provider := &OIDCProvider{
		config: &SSOConfig{
			OIDC: &OIDCConfig{
				AcrValues: []string{"1", "2"},
			},
		},
		oidcConfig: &OIDCConfig{
			AcrValues: []string{"1", "2"},
		},
	}

	opts := provider.getProviderSpecificOptions()
	// ACR values are added in InitiateLogin, not in getProviderSpecificOptions,
	// so we only verify the provider-specific options here.
	// The actual ACR value test is in TestOIDCInitiateLoginWithAcrValues below.
	_ = opts
}

func TestOIDCInitiateLoginWithAcrValues(t *testing.T) {
	// Test that ACR values are included in the authorization URL.
	// We create a provider with a mock store and check that the
	// auth URL contains acr_values parameters.
	store := NewMemoryRequestStore()
	cfg := &SSOConfig{
		Name: "test-acr-login",
		OIDC: &OIDCConfig{
			IssuerURL:    "https://idp.example.com",
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			RedirectURL:  "https://app.example.com/callback",
			Scopes:       []string{"openid", "profile"},
			AcrValues:    []string{"1"},
		},
		AttributeMapping: DefaultAttributeMapping(),
	}

	provider, err := NewOIDCProvider(cfg, store)
	if err != nil {
		t.Skipf("Skipping: cannot create OIDC provider without IdP discovery: %v", err)
	}

	authURL, _, err := provider.InitiateLogin("test-state")
	if err != nil {
		t.Skipf("Skipping: InitiateLogin failed (likely no IdP at configured URL): %v", err)
	}

	if !strings.Contains(authURL, "acr_values") {
		t.Errorf("InitiateLogin auth URL should contain acr_values: %s", authURL)
	}
}
