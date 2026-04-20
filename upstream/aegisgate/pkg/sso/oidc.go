// SPDX-License-Identifier: MIT
// =========================================================================
// =========================================================================
//
// =========================================================================

package sso

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/aegisgatesecurity/aegisgate/pkg/auth"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// OIDCProvider implements OpenID Connect SSO
type OIDCProvider struct {
	config     *SSOConfig
	oidcConfig *OIDCConfig
	oauth2     *oauth2.Config
	httpClient *http.Client
	store      RequestStore
	discovery  *OIDCDiscoveryDocument
}

// NewOIDCProvider creates a new OIDC provider
func NewOIDCProvider(config *SSOConfig, store RequestStore) (*OIDCProvider, error) {
	if config.OIDC == nil {
		return nil, NewSSOError(ErrProviderNotConfigured, "OIDC configuration is required")
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}

	provider := &OIDCProvider{
		config:     config,
		oidcConfig: config.OIDC,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		store:      store,
	}

	// Discover OIDC endpoints if not provided
	if err := provider.discover(); err != nil {
		return nil, err
	}

	// Configure OAuth2
	provider.oauth2 = &oauth2.Config{
		ClientID:     config.OIDC.ClientID,
		ClientSecret: config.OIDC.ClientSecret,
		RedirectURL:  config.OIDC.RedirectURL,
		Scopes:       config.OIDC.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  config.OIDC.AuthURL,
			TokenURL: config.OIDC.TokenURL,
		},
	}

	return provider, nil
}

// Name returns the provider name
func (p *OIDCProvider) Name() string {
	return p.config.Name
}

// Type returns the provider type
func (p *OIDCProvider) Type() SSOProvider {
	return ProviderOIDC
}

// discover fetches the OIDC discovery document
func (p *OIDCProvider) discover() error {
	// If all endpoints are configured, skip discovery
	if p.oidcConfig.AuthURL != "" && p.oidcConfig.TokenURL != "" &&
		p.oidcConfig.UserInfoURL != "" && p.oidcConfig.JWKSURL != "" {
		return nil
	}

	// Discover from issuer URL
	if p.oidcConfig.IssuerURL == "" {
		return NewSSOError(ErrMissingDiscovery, "issuer URL required for discovery")
	}

	discoveryURL := strings.TrimSuffix(p.oidcConfig.IssuerURL, "/") + "/.well-known/openid-configuration"

	resp, err := p.httpClient.Get(discoveryURL)
	if err != nil {
		return NewSSOError(ErrMissingDiscovery, "failed to fetch discovery document").WithCause(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return NewSSOError(ErrMissingDiscovery, fmt.Sprintf("discovery returned status %d", resp.StatusCode))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return NewSSOError(ErrMissingDiscovery, "failed to read discovery document").WithCause(err)
	}

	var discovery OIDCDiscoveryDocument
	if err := json.Unmarshal(body, &discovery); err != nil {
		return NewSSOError(ErrMissingDiscovery, "failed to parse discovery document").WithCause(err)
	}

	p.discovery = &discovery

	// Set discovered endpoints if not already configured
	if p.oidcConfig.AuthURL == "" {
		p.oidcConfig.AuthURL = discovery.AuthorizationEndpoint
	}
	if p.oidcConfig.TokenURL == "" {
		p.oidcConfig.TokenURL = discovery.TokenEndpoint
	}
	if p.oidcConfig.UserInfoURL == "" {
		p.oidcConfig.UserInfoURL = discovery.UserInfoEndpoint
	}
	if p.oidcConfig.JWKSURL == "" {
		p.oidcConfig.JWKSURL = discovery.JWKSEndpoint
	}
	if p.oidcConfig.EndSessionURL == "" {
		p.oidcConfig.EndSessionURL = discovery.EndSessionEndpoint
	}

	// Set default scopes if not configured
	if len(p.oidcConfig.Scopes) == 0 {
		p.oidcConfig.Scopes = []string{"openid", "profile", "email"}
	}

	return nil
}

// InitiateLogin creates an OIDC authorization request
func (p *OIDCProvider) InitiateLogin(state string) (string, *SSORequest, error) {
	// Generate code verifier for PKCE
	codeVerifier, codeChallenge := "", ""
	if p.oidcConfig.UsePKCE {
		codeVerifier = generateCodeVerifier()
		codeChallenge = generateCodeChallenge(codeVerifier, p.oidcConfig.PKCEChallenge)
	}

	// Build authorization URL
	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("response_type", "code"),
		oauth2.SetAuthURLParam("state", state),
	}

	if codeChallenge != "" {
		opts = append(opts,
			oauth2.SetAuthURLParam("code_challenge", codeChallenge),
			oauth2.SetAuthURLParam("code_challenge_method", p.oidcConfig.PKCEChallenge),
		)
	}

	// Add any extra parameters based on provider type
	opts = append(opts, p.getProviderSpecificOptions()...)

	authURL := p.oauth2.AuthCodeURL(state, opts...)

	// Create request record
	ssoRequest := &SSORequest{
		ID:           generateRequestID(),
		Provider:     p.config.Name,
		State:        state,
		CodeVerifier: codeVerifier,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(10 * time.Minute),
	}

	if p.store != nil {
		if err := p.store.Create(ssoRequest); err != nil {
			return "", nil, NewSSOError(ErrInvalidRequest, "failed to store request").WithCause(err)
		}
	}

	return authURL, ssoRequest, nil
}

// HandleCallback processes the OIDC callback
func (p *OIDCProvider) HandleCallback(request *SSORequest, params map[string]string) (*SSOResponse, error) {
	// Check for error response
	if errParam, ok := params["error"]; ok {
		errDesc := params["error_description"]
		return nil, NewSSOError(ErrInvalidCallback, fmt.Sprintf("%s: %s", errParam, errDesc))
	}

	// Verify state
	if params["state"] != request.State {
		return nil, NewSSOError(ErrStateMismatch, "state parameter mismatch")
	}

	code := params["code"]
	if code == "" {
		return nil, NewSSOError(ErrInvalidCallback, "missing authorization code")
	}

	// Exchange code for tokens
	opts := []oauth2.AuthCodeOption{}
	if p.oidcConfig.UsePKCE && request.CodeVerifier != "" {
		opts = append(opts, oauth2.SetAuthURLParam("code_verifier", request.CodeVerifier))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	token, err := p.oauth2.Exchange(ctx, code, opts...)
	if err != nil {
		return nil, NewSSOError(ErrInvalidToken, "failed to exchange authorization code").WithCause(err)
	}

	accessToken := token.AccessToken
	refreshToken := token.RefreshToken
	idToken, _ := token.Extra("id_token").(string)
	tokenType := token.TokenType
	if tokenType == "" {
		tokenType = "Bearer"
	}

	// Get user info
	userInfo, err := p.getUserInfo(accessToken)
	if err != nil {
		return nil, err
	}

	// Parse ID token if available
	var claims *OIDCIDTokenClaims
	if idToken != "" && p.oidcConfig.ValidateIDToken {
		claims, err = p.parseIDToken(idToken)
		if err != nil {
			return nil, NewSSOError(ErrInvalidToken, "failed to parse ID token").WithCause(err)
		}
	}

	// Create SSO user
	user := &SSOUser{
		SSOProvider:   ProviderOIDC,
		SSOProviderID: p.config.Name,
		RawAttributes: userInfo,
		AccessToken:   accessToken,
		TokenType:     tokenType,
		RefreshToken:  refreshToken,
		TokenExpiry:   token.Expiry,
		IDToken:       idToken,
	}

	// Map user info to user fields
	p.mapUserInfoToUser(user, userInfo)

	// Override with ID token claims if available
	if claims != nil {
		p.mapClaimsToUser(user, claims)
	}

	// Create session
	session := &SSOSession{
		ID:             generateSessionID(),
		User:           user,
		UserID:         user.ID,
		Provider:       ProviderOIDC,
		ProviderName:   p.config.Name,
		CreatedAt:      time.Now(),
		ExpiresAt:      time.Now().Add(p.config.SessionDuration),
		LastActivity:   time.Now(),
		AccessToken:    accessToken,
		RefreshToken:   refreshToken,
		IDToken:        idToken,
		TokenExpiresAt: token.Expiry,
		Active:         true,
		Metadata:       make(map[string]interface{}),
	}

	return &SSOResponse{
		Success:    true,
		User:       user,
		Session:    session,
		Attributes: userInfo,
	}, nil
}

// ValidateSession validates an existing OIDC session
func (p *OIDCProvider) ValidateSession(session *SSOSession) error {
	if session == nil {
		return NewSSOError(ErrInvalidToken, "nil session")
	}
	if session.IsExpired() {
		return NewSSOError(ErrSessionExpired, "session has expired")
	}
	if !session.Active {
		return NewSSOError(ErrInvalidToken, "session is not active")
	}

	// Optionally validate access token with provider
	if p.oidcConfig.ValidateAccessToken && session.AccessToken != "" {
		if err := p.validateAccessToken(session.AccessToken); err != nil {
			return err
		}
	}

	return nil
}

// Logout initiates OIDC logout
func (p *OIDCProvider) Logout(session *SSOSession) (string, error) {
	if session == nil {
		return "", NewSSOError(ErrInvalidToken, "nil session")
	}

	// Build logout URL
	if p.oidcConfig.EndSessionURL == "" {
		return "", nil
	}

	logoutURL, err := url.Parse(p.oidcConfig.EndSessionURL)
	if err != nil {
		return "", NewSSOError(ErrInvalidRequest, "invalid end session URL").WithCause(err)
	}

	query := logoutURL.Query()
	if session.IDToken != "" {
		query.Set("id_token_hint", session.IDToken)
	}
	logoutURL.RawQuery = query.Encode()

	return logoutURL.String(), nil
}

// Metadata returns provider metadata
func (p *OIDCProvider) Metadata() ([]byte, error) {
	metadata := map[string]interface{}{
		"issuer":                                p.oidcConfig.IssuerURL,
		"authorization_endpoint":                p.oidcConfig.AuthURL,
		"token_endpoint":                        p.oidcConfig.TokenURL,
		"userinfo_endpoint":                     p.oidcConfig.UserInfoURL,
		"jwks_uri":                              p.oidcConfig.JWKSURL,
		"end_session_endpoint":                  p.oidcConfig.EndSessionURL,
		"response_types_supported":              []string{"code", "id_token", "token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      p.oidcConfig.Scopes,
	}
	return json.MarshalIndent(metadata, "", "  ")
}

// RefreshToken refreshes an OIDC access token
func (p *OIDCProvider) RefreshToken(refreshToken string) (*OIDCToken, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tokenSource := p.oauth2.TokenSource(ctx, &oauth2.Token{
		RefreshToken: refreshToken,
	})

	token, err := tokenSource.Token()
	if err != nil {
		return nil, NewSSOError(ErrInvalidToken, "failed to refresh token").WithCause(err)
	}

	return &OIDCToken{
		AccessToken:  token.AccessToken,
		TokenType:    token.TokenType,
		ExpiresIn:    int64(time.Until(token.Expiry).Seconds()),
		RefreshToken: token.RefreshToken,
		IDToken:      getStringExtra(token, "id_token"),
		Scope:        getStringExtra(token, "scope"),
	}, nil
}

// getUserInfo fetches user info from the provider
func (p *OIDCProvider) getUserInfo(accessToken string) (map[string]interface{}, error) {
	if p.oidcConfig.UserInfoURL == "" {
		return nil, NewSSOError(ErrMissingDiscovery, "userinfo endpoint not configured")
	}

	req, err := http.NewRequest("GET", p.oidcConfig.UserInfoURL, nil)
	if err != nil {
		return nil, NewSSOError(ErrInvalidRequest, "failed to create userinfo request").WithCause(err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, NewSSOError(ErrInvalidRequest, "failed to fetch userinfo").WithCause(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, NewSSOError(ErrInvalidToken, fmt.Sprintf("userinfo returned status %d", resp.StatusCode))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, NewSSOError(ErrInvalidRequest, "failed to read userinfo response").WithCause(err)
	}

	var userInfo map[string]interface{}
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, NewSSOError(ErrInvalidRequest, "failed to parse userinfo").WithCause(err)
	}

	return userInfo, nil
}

// validateAccessToken validates an access token with the provider
func (p *OIDCProvider) validateAccessToken(accessToken string) error {
	// For now, we rely on token expiry checks
	// In production, you would call the introspection endpoint
	return nil
}

// parseIDToken parses and validates an ID token
func (p *OIDCProvider) parseIDToken(idToken string) (*OIDCIDTokenClaims, error) {
	// Split token into parts
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, NewSSOError(ErrInvalidToken, "invalid ID token format")
	}

	// Decode claims
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, NewSSOError(ErrInvalidToken, "failed to decode ID token claims").WithCause(err)
	}

	var claims OIDCIDTokenClaims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, NewSSOError(ErrInvalidToken, "failed to parse ID token claims").WithCause(err)
	}

	// Validate expiry
	if claims.Expiration > 0 && time.Unix(claims.Expiration, 0).Before(time.Now()) {
		return nil, NewSSOError(ErrExpiredToken, "ID token has expired")
	}

	// Validate issuer (if configured)
	if !p.oidcConfig.SkipIssuerCheck && p.oidcConfig.IssuerURL != "" && claims.Issuer != p.oidcConfig.IssuerURL {
		return nil, NewSSOError(ErrInvalidToken, "ID token issuer mismatch")
	}

	return &claims, nil
}

// mapUserInfoToUser maps user info to SSOUser fields
func (p *OIDCProvider) mapUserInfoToUser(user *SSOUser, userInfo map[string]interface{}) {
	mapping := p.config.AttributeMapping
	if mapping == nil {
		mapping = DefaultAttributeMapping()
	}

	user.UpstreamID = getString(userInfo, mapping.IDAttribute)
	user.UpstreamName = getString(userInfo, mapping.UsernameAttribute)

	// Map basic profile
	email := getString(userInfo, mapping.EmailAttribute)
	name := getString(userInfo, mapping.NameAttribute)

	// Create base auth.User
	user.User = &auth.User{
		ID: user.UpstreamID,
		// Username field removed - using ID instead
		// Username: user.UpstreamName,
		Email: email,
		Name:  name,
	}

	user.Groups = getStringSlice(userInfo, mapping.GroupAttribute)
}

// mapClaimsToUser maps ID token claims to SSOUser fields
func (p *OIDCProvider) mapClaimsToUser(user *SSOUser, claims *OIDCIDTokenClaims) {
	if claims.Subject != "" && user.ID == "" {
		user.UpstreamID = claims.Subject
	}
	if claims.PreferredUsername != "" && user.UpstreamName == "" {
		user.UpstreamName = claims.PreferredUsername
	}
	if claims.Email != "" && user.Email == "" {
		user.Email = claims.Email
	}
	if claims.Name != "" && user.Name == "" {
		user.Name = claims.Name
	}

	// Map groups from claims if not already set
	if len(user.Groups) == 0 && len(claims.Groups) > 0 {
		user.Groups = claims.Groups
	}
	// AcrValues mapping not implemented
}

// getProviderSpecificOptions returns provider-specific OAuth2 options
func (p *OIDCProvider) getProviderSpecificOptions() []oauth2.AuthCodeOption {
	opts := []oauth2.AuthCodeOption{}

	// Azure AD specific options
	if p.oidcConfig.AzureADTenant != "" {
		opts = append(opts, oauth2.SetAuthURLParam("resource", "https://graph.microsoft.com"))
	}

	// Google/GSuite domain restriction
	if p.oidcConfig.GSuiteDomain != "" {
		opts = append(opts, oauth2.SetAuthURLParam("hd", p.oidcConfig.GSuiteDomain))
	}

	return opts
}

// Helper functions

func generateCodeVerifier() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func generateCodeChallenge(verifier, method string) string {
	switch method {
	case "S256":
		h := sha256.Sum256([]byte(verifier))
		return base64.RawURLEncoding.EncodeToString(h[:])
	case "plain":
		return verifier
	default:
		h := sha256.Sum256([]byte(verifier))
		return base64.RawURLEncoding.EncodeToString(h[:])
	}
}

func getString(m map[string]interface{}, key string) string {
	if key == "" {
		return ""
	}
	if v, ok := m[key]; ok {
		switch val := v.(type) {
		case string:
			return val
		case float64:
			return fmt.Sprintf("%.0f", val)
		}
	}
	return ""
}

func getStringSlice(m map[string]interface{}, key string) []string {
	if key == "" {
		return nil
	}
	if v, ok := m[key]; ok {
		switch val := v.(type) {
		case []interface{}:
			result := make([]string, len(val))
			for i, item := range val {
				result[i], _ = item.(string)
			}
			return result
		case []string:
			return val
		case string:
			return []string{val}
		}
	}
	return nil
}

func getStringExtra(token *oauth2.Token, key string) string {
	if extra := token.Extra(key); extra != nil {
		if s, ok := extra.(string); ok {
			return s
		}
	}
	return ""
}
