package sso

import (
	"testing"
	"time"
)

func TestSSOProviderConstants(t *testing.T) {
	providers := []SSOProvider{ProviderSAML, ProviderOIDC, ProviderOAuth}
	for _, p := range providers {
		if p == "" {
			t.Error("Provider should not be empty")
		}
	}
}

func TestSSOConfigAllFields(t *testing.T) {
	cfg := &SSOConfig{
		Provider:           ProviderOIDC,
		Name:               "test-sso",
		DisplayName:        "Test SSO",
		Enabled:            true,
		Priority:           1,
		SessionDuration:    24 * time.Hour,
		MaxSessionAge:      7 * 24 * time.Hour,
		ClockSkewTolerance: 5 * time.Minute,
		CookieName:         "sso_session",
		CookieSecure:       true,
		CookieHTTPOnly:     true,
		CookieSameSite:     "strict",
		RequireHTTPS:       true,
		AllowIDPInitiated:  true,
		StrictAudience:     true,
	}

	if cfg.Provider != ProviderOIDC {
		t.Error("Provider should be OIDC")
	}
}

func TestOIDCConfigAllFields(t *testing.T) {
	cfg := &OIDCConfig{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		IssuerURL:    "https://issuer.example.com",
		RedirectURL:  "https://app.example.com/callback",
		Scopes:       []string{"openid", "profile", "email"},
	}

	if cfg.ClientID != "client-id" {
		t.Error("ClientID mismatch")
	}
}

func TestSAMLConfigAllFields(t *testing.T) {
	cfg := &SAMLConfig{
		EntityID:     "entity-id",
		MetadataURL:  "https://idp.example.com/metadata",
		ACSURL:       "https://app.example.com/saml/acs",
		SLSURL:       "https://app.example.com/saml/sls",
		NameIDFormat: "emailAddress",
		AllowCreate:  true,
	}

	if cfg.EntityID != "entity-id" {
		t.Error("EntityID mismatch")
	}
}
