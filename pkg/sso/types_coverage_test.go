// SPDX-License-Identifier: Apache-2.0

package sso

import (
	"errors"
	"testing"
	"time"
)

// -------------------------------------------------------------------------
// IsTokenExpired – cover the past-expiry and future-expiry branches
// -------------------------------------------------------------------------

func TestIsTokenExpired_PastExpiry(t *testing.T) {
	session := &SSOSession{
		AccessToken:    "access-token-abc",
		TokenExpiresAt: time.Now().Add(-1 * time.Hour), // in the past
	}
	if !session.IsTokenExpired() {
		t.Error("expected IsTokenExpired() = true when token expired in the past")
	}
}

func TestIsTokenExpired_FutureExpiry(t *testing.T) {
	session := &SSOSession{
		AccessToken:    "access-token-abc",
		TokenExpiresAt: time.Now().Add(1 * time.Hour), // in the future
	}
	if session.IsTokenExpired() {
		t.Error("expected IsTokenExpired() = false when token expires in the future")
	}
}

func TestIsTokenExpired_EmptyAccessToken(t *testing.T) {
	session := &SSOSession{
		AccessToken:    "",
		TokenExpiresAt: time.Now().Add(-1 * time.Hour), // past, but irrelevant
	}
	if session.IsTokenExpired() {
		t.Error("expected IsTokenExpired() = false when AccessToken is empty")
	}
}

func TestIsTokenExpired_ZeroTokenExpiresAt(t *testing.T) {
	session := &SSOSession{
		AccessToken:    "access-token-abc",
		TokenExpiresAt: time.Time{}, // zero value
	}
	if session.IsTokenExpired() {
		t.Error("expected IsTokenExpired() = false when TokenExpiresAt is zero")
	}
}

// -------------------------------------------------------------------------
// SSOError.Unwrap – cover both nil and non-nil Cause
// -------------------------------------------------------------------------

func TestSSOError_Unwrap_WithCause(t *testing.T) {
	inner := errors.New("inner cause")
	err := &SSOError{
		Code:    ErrInvalidToken,
		Message: "token failure",
		Cause:   inner,
	}
	if unwrapped := err.Unwrap(); unwrapped != inner {
		t.Errorf("expected Unwrap() = inner cause, got %v", unwrapped)
	}
}

func TestSSOError_Unwrap_NilCause(t *testing.T) {
	err := &SSOError{
		Code:    ErrInvalidRequest,
		Message: "no cause",
		Cause:   nil,
	}
	if unwrapped := err.Unwrap(); unwrapped != nil {
		t.Errorf("expected Unwrap() = nil, got %v", unwrapped)
	}
}

// -------------------------------------------------------------------------
// SSOConfig.Validate – SessionDuration / ClockSkewTolerance defaults
// -------------------------------------------------------------------------

func TestTypes_SSOConfigValidate_SessionDurationDefault(t *testing.T) {
	cfg := &SSOConfig{
		Provider: ProviderOIDC,
		Name:     "test-oidc",
		// SessionDuration is zero -> should default to 24h
		OIDC: &OIDCConfig{
			ClientID:    "cid",
			RedirectURL: "https://example.com/callback",
			IssuerURL:   "https://issuer.example.com",
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error: %v", err)
	}
	if cfg.SessionDuration != 24*time.Hour {
		t.Errorf("SessionDuration = %v, want %v", cfg.SessionDuration, 24*time.Hour)
	}
}

func TestTypes_SSOConfigValidate_NegativeSessionDuration(t *testing.T) {
	cfg := &SSOConfig{
		Provider:        ProviderOIDC,
		Name:            "test-oidc",
		SessionDuration: -1 * time.Hour, // negative -> should default to 24h
		OIDC: &OIDCConfig{
			ClientID:    "cid",
			RedirectURL: "https://example.com/callback",
			IssuerURL:   "https://issuer.example.com",
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error: %v", err)
	}
	if cfg.SessionDuration != 24*time.Hour {
		t.Errorf("SessionDuration = %v, want %v", cfg.SessionDuration, 24*time.Hour)
	}
}

func TestTypes_SSOConfigValidate_ClockSkewToleranceDefault(t *testing.T) {
	cfg := &SSOConfig{
		Provider: ProviderOIDC,
		Name:     "test-oidc",
		// ClockSkewTolerance is zero -> should default to 5m
		OIDC: &OIDCConfig{
			ClientID:    "cid",
			RedirectURL: "https://example.com/callback",
			IssuerURL:   "https://issuer.example.com",
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error: %v", err)
	}
	if cfg.ClockSkewTolerance != 5*time.Minute {
		t.Errorf("ClockSkewTolerance = %v, want %v", cfg.ClockSkewTolerance, 5*time.Minute)
	}
}

func TestTypes_SSOConfigValidate_NegativeClockSkewTolerance(t *testing.T) {
	cfg := &SSOConfig{
		Provider:           ProviderOIDC,
		Name:               "test-oidc",
		ClockSkewTolerance: -10 * time.Minute, // negative -> should default to 5m
		OIDC: &OIDCConfig{
			ClientID:    "cid",
			RedirectURL: "https://example.com/callback",
			IssuerURL:   "https://issuer.example.com",
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error: %v", err)
	}
	if cfg.ClockSkewTolerance != 5*time.Minute {
		t.Errorf("ClockSkewTolerance = %v, want %v", cfg.ClockSkewTolerance, 5*time.Minute)
	}
}

// -------------------------------------------------------------------------
// SAMLConfig.Validate – IDPEntityID empty with non-empty IDPMetadata should pass
// -------------------------------------------------------------------------

func TestTypes_SAMLConfigValidate_IDPEntityIDEmpty_WithMetadata(t *testing.T) {
	cfg := &SAMLConfig{
		EntityID:       "https://sp.example.com",
		ACSURL:         "https://sp.example.com/acs",
		IDPEntityID:    "",                                 // empty
		IDPMetadata:    []byte("<EntityDescriptor>...</>"), // non-empty
		IDPMetadataURL: "",                                 // empty
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("expected Validate() to pass when IDPMetadata is set, got: %v", err)
	}
}

func TestTypes_SAMLConfigValidate_IDPEntityIDEmpty_WithMetadataURL(t *testing.T) {
	cfg := &SAMLConfig{
		EntityID:       "https://sp.example.com",
		ACSURL:         "https://sp.example.com/acs",
		IDPEntityID:    "",
		IDPMetadataURL: "https://idp.example.com/metadata",
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("expected Validate() to pass when IDPMetadataURL is set, got: %v", err)
	}
}

func TestTypes_SAMLConfigValidate_IDPAllSourcesEmpty(t *testing.T) {
	cfg := &SAMLConfig{
		EntityID:       "https://sp.example.com",
		ACSURL:         "https://sp.example.com/acs",
		IDPEntityID:    "",
		IDPMetadata:    nil,
		IDPMetadataURL: "",
	}
	if err := cfg.Validate(); err == nil {
		t.Error("expected Validate() to fail when all IdP sources are empty")
	}
}

// -------------------------------------------------------------------------
// OIDCConfig.Validate – ClientSecret empty should still pass
// -------------------------------------------------------------------------

func TestTypes_OIDCConfigValidate_EmptyClientSecret(t *testing.T) {
	cfg := &OIDCConfig{
		IssuerURL:    "https://issuer.example.com",
		ClientID:     "my-client-id",
		RedirectURL:  "https://app.example.com/callback",
		ClientSecret: "", // empty, but Validate doesn't check it
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("expected Validate() to pass without ClientSecret, got: %v", err)
	}
}

func TestTypes_OIDCConfigValidate_MissingClientID(t *testing.T) {
	cfg := &OIDCConfig{
		IssuerURL:   "https://issuer.example.com",
		ClientID:    "",
		RedirectURL: "https://app.example.com/callback",
	}
	if err := cfg.Validate(); err == nil {
		t.Error("expected Validate() to fail with empty ClientID")
	}
}

func TestTypes_OIDCConfigValidate_MissingRedirectURL(t *testing.T) {
	cfg := &OIDCConfig{
		IssuerURL:   "https://issuer.example.com",
		ClientID:    "my-client-id",
		RedirectURL: "",
	}
	if err := cfg.Validate(); err == nil {
		t.Error("expected Validate() to fail with empty RedirectURL")
	}
}

func TestTypes_OIDCConfigValidate_MissingIssuerURL(t *testing.T) {
	cfg := &OIDCConfig{
		IssuerURL:   "",
		ClientID:    "my-client-id",
		RedirectURL: "https://app.example.com/callback",
	}
	if err := cfg.Validate(); err == nil {
		t.Error("expected Validate() to fail with empty IssuerURL")
	}
}
