// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

package sso

import (
	"crypto/x509"
	"encoding/xml"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/auth"
)

// SSOProvider represents the type of SSO provider
type SSOProvider string

const (
	ProviderSAML  SSOProvider = "saml"
	ProviderOIDC  SSOProvider = "oidc"
	ProviderOAuth SSOProvider = "oauth2"
)

// SSOConfig holds configuration for SSO providers
type SSOConfig struct {
	Provider           SSOProvider
	Name               string
	DisplayName        string
	Enabled            bool
	Priority           int
	SAML               *SAMLConfig
	OIDC               *OIDCConfig
	SessionDuration    time.Duration
	MaxSessionAge      time.Duration
	ClockSkewTolerance time.Duration
	CookieName         string
	CookieSecure       bool
	CookieHTTPOnly     bool
	CookieSameSite     string
	CookieDomain       string
	RequireHTTPS       bool
	AllowIDPInitiated  bool
	StrictAudience     bool
	AttributeMapping   *AttributeMapping
	RoleMappings       []RoleMapping
	AllowedDomains     []string
	BlockedDomains     []string
}

// SAMLConfig holds SAML 2.0 specific configuration
type SAMLConfig struct {
	EntityID                       string
	MetadataURL                    string
	ACSURL                         string
	SLSURL                         string
	CertFile                       string
	KeyFile                        string
	Certificate                    *x509.Certificate
	PrivateKey                     interface{}
	IDPEntityID                    string
	IDPMetadataURL                 string
	IDPMetadata                    []byte
	IDPSSODescriptor               *IDPSSODescriptor
	NameIDFormat                   string
	AuthnContextClass              string
	AllowCreate                    bool
	ForceAuthn                     bool
	IsPassive                      bool
	ValidateSignature              bool
	SignatureAlgorithm             string
	DigestAlgorithm                string
	AttributeConsumingServiceIndex int
	WantAssertionsSigned           bool
	WantResponseSigned             bool
}

// IDPSSODescriptor represents IdP SSO Descriptor from metadata
type IDPSSODescriptor struct {
	EntityID               string
	SSOURLs                []string
	SLOURLs                []string
	SigningCertificates    []*x509.Certificate
	EncryptionCertificates []*x509.Certificate
	NameIDFormats          []string
	Attributes             []string
}

// OIDCConfig holds OpenID Connect specific configuration
type OIDCConfig struct {
	IssuerURL           string
	AuthURL             string
	TokenURL            string
	UserInfoURL         string
	JWKSURL             string
	EndSessionURL       string
	ClientID            string
	ClientSecret        string
	RedirectURL         string
	Scopes              []string
	UsePKCE             bool
	PKCEChallenge       string
	ValidateAccessToken bool
	ValidateIDToken     bool
	SkipIssuerCheck     bool
	SkipExpiryCheck     bool
	AzureADTenant       string
	GSuiteDomain        string
	OktaDomain          string
	ProviderType        string
}

// SSOUser extends auth.User with SSO-specific attributes
type SSOUser struct {
	*auth.User
	SSOProvider   SSOProvider
	SSOProviderID string
	RawAttributes map[string]interface{}
	UpstreamID    string
	UpstreamName  string
	SessionIndex  string
	NameID        string
	AuthnContext  string
	AuthnInstant  time.Time
	AcrValues     []string
	AccessToken   string
	TokenType     string
	RefreshToken  string
	TokenExpiry   time.Time
	IDToken       string
	Groups        []string
}

// SSOSession represents an SSO authentication session
type SSOSession struct {
	ID             string
	User           *SSOUser
	UserID         string
	SessionID      string
	Provider       SSOProvider
	ProviderName   string
	CreatedAt      time.Time
	ExpiresAt      time.Time
	LastActivity   time.Time
	LastRefreshed  time.Time
	IPAddress      string
	UserAgent      string
	InitialIDP     string
	NameID         string
	SessionIndex   string
	AccessToken    string
	RefreshToken   string
	IDToken        string
	TokenExpiresAt time.Time
	Active         bool
	Flags          map[string]bool
	Metadata       map[string]interface{}
}

// IsExpired checks if the session has expired
func (s *SSOSession) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// IsTokenExpired checks if the OIDC token has expired
// Returns false if no token is set (for SAML sessions or sessions without tokens)
func (s *SSOSession) IsTokenExpired() bool {
	// If no access token is set, there's no token to expire
	if s.AccessToken == "" {
		return false
	}
	// If TokenExpiresAt is zero, we don't know the expiry, so consider it valid
	if s.TokenExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(s.TokenExpiresAt)
}

// IsValid checks if the session is active and not expired
func (s *SSOSession) IsValid() bool {
	return s.Active && !s.IsExpired()
}

// Refresh extends the session expiration
func (s *SSOSession) Refresh(duration time.Duration) {
	s.LastActivity = time.Now()
	s.ExpiresAt = time.Now().Add(duration)
}

// NeedsTokenRefresh checks if the access token needs refresh
func (s *SSOSession) NeedsTokenRefresh(buffer time.Duration) bool {
	if s.RefreshToken == "" {
		return false
	}
	return s.TokenExpiresAt.IsZero() || time.Now().Add(buffer).After(s.TokenExpiresAt)
}

// SSOError represents SSO-specific errors
type SSOError struct {
	Code        string
	Message     string
	Description string
	Provider    SSOProvider
	StatusCode  int
	Cause       error
}

func (e *SSOError) Error() string {
	if e.Cause != nil {
		return e.Code + ": " + e.Message + " - " + e.Cause.Error()
	}
	return e.Code + ": " + e.Message
}

func (e *SSOError) Unwrap() error {
	return e.Cause
}

// WithCause adds a cause to the error
func (e *SSOError) WithCause(cause error) *SSOError {
	e.Cause = cause
	return e
}

// Common SSO error codes
const (
	ErrInvalidRequest           = "invalid_request"
	ErrInvalidToken             = "invalid_token"
	ErrInvalidSignature         = "invalid_signature"
	ErrExpiredToken             = "expired_token"
	ErrInvalidAssertion         = "invalid_assertion"
	ErrMissingRequiredAttribute = "missing_required_attribute"
	ErrUserNotAllowed           = "user_not_allowed"
	ErrDomainNotAllowed         = "domain_not_allowed"
	ErrSessionExpired           = "session_expired"
	ErrProviderNotConfigured    = "provider_not_configured"
	ErrInvalidAuthnRequest      = "invalid_authn_request"
	ErrInvalidCallback          = "invalid_callback"
	ErrStateMismatch            = "state_mismatch"
	ErrMissingDiscovery         = "missing_discovery"
	ErrCertificateError         = "certificate_error"
	ErrMetadataError            = "metadata_error"
)

// NewSSOError creates a new SSO error
func NewSSOError(code, message string) *SSOError {
	return &SSOError{Code: code, Message: message}
}

// AttributeMapping defines how IdP attributes map to user fields
type AttributeMapping struct {
	IDAttribute           string
	UsernameAttribute     string
	EmailAttribute        string
	NameAttribute         string
	FirstNameAttribute    string
	LastNameAttribute     string
	DisplayNameAttribute  string
	GroupAttribute        string
	RoleAttribute         string
	DepartmentAttribute   string
	OrganizationAttribute string
	TitleAttribute        string
	CustomMappings        map[string]string
}

// DefaultAttributeMapping returns default attribute mappings
func DefaultAttributeMapping() *AttributeMapping {
	return &AttributeMapping{
		IDAttribute:           "sub",
		UsernameAttribute:     "preferred_username",
		EmailAttribute:        "email",
		NameAttribute:         "name",
		FirstNameAttribute:    "given_name",
		LastNameAttribute:     "family_name",
		DisplayNameAttribute:  "name",
		GroupAttribute:        "groups",
		RoleAttribute:         "roles",
		DepartmentAttribute:   "department",
		OrganizationAttribute: "organization",
		TitleAttribute:        "job_title",
		CustomMappings:        make(map[string]string),
	}
}

// SAMLAttributeMapping returns SAML-specific attribute mappings
func SAMLAttributeMapping() *AttributeMapping {
	return &AttributeMapping{
		IDAttribute:           "nameID",
		UsernameAttribute:     "urn:oid:0.9.2342.19200300.100.1.1",
		EmailAttribute:        "urn:oid:0.9.2342.19200300.100.1.3",
		NameAttribute:         "urn:oid:2.5.4.3",
		FirstNameAttribute:    "urn:oid:2.5.4.42",
		LastNameAttribute:     "urn:oid:2.5.4.4",
		DisplayNameAttribute:  "urn:oid:2.16.840.1.113730.3.1.241",
		GroupAttribute:        "urn:oid:1.3.6.1.4.1.5923.1.5.1.1",
		RoleAttribute:         "roles",
		DepartmentAttribute:   "urn:oid:2.5.4.11",
		OrganizationAttribute: "urn:oid:2.5.4.10",
		TitleAttribute:        "urn:oid:2.5.4.12",
		CustomMappings:        make(map[string]string),
	}
}

// RoleMapping maps IdP groups/roles to application roles
type RoleMapping struct {
	IdPRole    string
	IdPType    string
	AppRole    auth.Role
	Priority   int
	Conditions map[string]string
}

// SSORequest represents an SSO authentication request
type SSORequest struct {
	ID              string
	Provider        string
	SAMLRequest     string
	RelayState      string
	Destination     string
	ProtocolBinding string
	State           string
	CodeVerifier    string
	Nonce           string
	RedirectURL     string
	CreatedAt       time.Time
	ExpiresAt       time.Time
	IPAddress       string
	UserAgent       string
}

// SSOResponse represents an SSO authentication response
type SSOResponse struct {
	Success     bool
	User        *SSOUser
	Session     *SSOSession
	Error       *SSOError
	RedirectURL string
	Attributes  map[string]interface{}
}

// SSOProviderInterface defines the interface for SSO providers
type SSOProviderInterface interface {
	Name() string
	Type() SSOProvider
	InitiateLogin(state string) (loginURL string, request *SSORequest, err error)
	HandleCallback(request *SSORequest, params map[string]string) (*SSOResponse, error)
	ValidateSession(session *SSOSession) error
	Logout(session *SSOSession) (logoutURL string, err error)
	Metadata() ([]byte, error)
}

// SAMLMetadataType represents SAML metadata
type SAMLMetadataType struct {
	XMLName  xml.Name
	Xmlns    string
	EntityID string
}

// OIDCDiscoveryDocument represents OIDC discovery document
type OIDCDiscoveryDocument struct {
	Issuer                           string
	AuthorizationEndpoint            string
	TokenEndpoint                    string
	UserInfoEndpoint                 string
	JWKSEndpoint                     string
	RegistrationEndpoint             string
	ScopesSupported                  []string
	ResponseTypesSupported           []string
	ResponseModesSupported           []string
	GrantTypesSupported              []string
	SubjectTypesSupported            []string
	IDTokenSigningAlgValuesSupported []string
	ClaimsSupported                  []string
	EndSessionEndpoint               string
}

// OIDCToken represents an OIDC token response
type OIDCToken struct {
	AccessToken  string
	TokenType    string
	ExpiresIn    int64
	RefreshToken string
	IDToken      string
	Scope        string
}

// OIDCIDTokenClaims represents claims in an ID token
type OIDCIDTokenClaims struct {
	Issuer            string
	Subject           string
	Audience          []string
	Expiration        int64
	IssuedAt          int64
	AuthTime          int64
	Nonce             string
	ACR               string
	Email             string
	EmailVerified     bool
	Name              string
	GivenName         string
	FamilyName        string
	PreferredUsername string
	Picture           string
	Groups            []string
	Roles             []string
}

// SessionStore interface for session persistence
type SessionStore interface {
	Create(session *SSOSession) error
	Get(id string) (*SSOSession, error)
	Update(session *SSOSession) error
	Delete(id string) error
	GetByUserID(userID string) ([]*SSOSession, error)
	DeleteByUserID(userID string) error
	Cleanup() error
}

// RequestStore interface for SSO request state persistence
type RequestStore interface {
	Create(request *SSORequest) error
	Get(id string) (*SSORequest, error)
	GetByState(state string) (*SSORequest, error)
	Delete(id string) error
}

// DefaultSSOConfig returns default SSO configuration
func DefaultSSOConfig() *SSOConfig {
	return &SSOConfig{
		Enabled:            true,
		SessionDuration:    24 * time.Hour,
		MaxSessionAge:      7 * 24 * time.Hour,
		ClockSkewTolerance: 5 * time.Minute,
		CookieName:         "sso_session",
		CookieSecure:       true,
		CookieHTTPOnly:     true,
		CookieSameSite:     "Strict",
		RequireHTTPS:       true,
		AllowIDPInitiated:  false,
		StrictAudience:     true,
		AttributeMapping:   DefaultAttributeMapping(),
		RoleMappings:       []RoleMapping{},
	}
}

// Validate validates the SSO configuration
func (c *SSOConfig) Validate() error {
	if c.Provider == "" {
		return &SSOError{Code: ErrInvalidRequest, Message: "SSO provider type is required"}
	}
	if c.Name == "" {
		return &SSOError{Code: ErrInvalidRequest, Message: "SSO provider name is required"}
	}
	switch c.Provider {
	case ProviderSAML:
		if c.SAML == nil {
			return &SSOError{Code: ErrInvalidRequest, Message: "SAML configuration is required for SAML provider"}
		}
		if err := c.SAML.Validate(); err != nil {
			return err
		}
	case ProviderOIDC, ProviderOAuth:
		if c.OIDC == nil {
			return &SSOError{Code: ErrInvalidRequest, Message: "OIDC configuration is required for OIDC/OAuth provider"}
		}
		if err := c.OIDC.Validate(); err != nil {
			return err
		}
	}
	if c.SessionDuration <= 0 {
		c.SessionDuration = 24 * time.Hour
	}
	if c.ClockSkewTolerance <= 0 {
		c.ClockSkewTolerance = 5 * time.Minute
	}
	return nil
}

// Validate validates SAML configuration
func (c *SAMLConfig) Validate() error {
	if c.EntityID == "" {
		return &SSOError{Code: ErrInvalidRequest, Message: "SAML EntityID is required"}
	}
	if c.ACSURL == "" {
		return &SSOError{Code: ErrInvalidRequest, Message: "SAML ACS URL is required"}
	}
	if c.IDPEntityID == "" && len(c.IDPMetadata) == 0 && c.IDPMetadataURL == "" {
		return &SSOError{Code: ErrInvalidRequest, Message: "SAML IdP configuration is required"}
	}
	return nil
}

// Validate validates OIDC configuration
func (c *OIDCConfig) Validate() error {
	if c.ClientID == "" {
		return &SSOError{Code: ErrInvalidRequest, Message: "OIDC ClientID is required"}
	}
	if c.RedirectURL == "" {
		return &SSOError{Code: ErrInvalidRequest, Message: "OIDC Redirect URL is required"}
	}
	if c.IssuerURL == "" {
		return &SSOError{Code: ErrInvalidRequest, Message: "OIDC Issuer URL is required"}
	}
	return nil
}
