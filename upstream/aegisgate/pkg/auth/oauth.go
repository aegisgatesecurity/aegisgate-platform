// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// =========================================================================
//
// =========================================================================

package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// OAuthEndpoints holds OAuth provider endpoint URLs.
// OAuthEndpoints defines OAuth provider endpoint URLs.
type OAuthEndpoints struct {
	AuthURL     string
	TokenURL    string
	UserInfoURL string
	Scopes      []string
}

// OAuthProviderEndpoints maps provider names to their OAuth endpoints.
var OAuthProviderEndpoints = map[Provider]OAuthEndpoints{
	ProviderGoogle: {
		AuthURL:     "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:    "https://oauth2.googleapis.com/token",
		UserInfoURL: "https://openidconnect.googleapis.com/v1/userinfo",
		Scopes:      []string{"openid", "profile", "email"},
	},
	ProviderMicrosoft: {
		AuthURL:     "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
		TokenURL:    "https://login.microsoftonline.com/common/oauth2/v2.0/token",
		UserInfoURL: "https://graph.microsoft.com/v1.0/me",
		Scopes:      []string{"openid", "profile", "email", "User.Read"},
	},
	ProviderGitHub: {
		AuthURL:     "https://github.com/login/oauth/authorize",
		TokenURL:    "https://github.com/login/oauth/access_token",
		UserInfoURL: "https://api.github.com/user",
		Scopes:      []string{"read:user", "user:email"},
	},
	ProviderOkta: {
		Scopes: []string{"openid", "profile", "email"},
	},
	ProviderAuth0: {
		Scopes: []string{"openid", "profile", "email"},
	},
}

// OAuthTokenResponse contains OAuth token response data.
// OAuthTokenResponse contains the OAuth token response from the provider.
type OAuthTokenResponse struct {
	AccessToken  string
	TokenType    string
	ExpiresIn    int
	RefreshToken string
	IDToken      string
	Scope        string
}

// OAuthUserInfo contains user information from OAuth provider.
// OAuthUserInfo represents user information returned by OAuth provider.
type OAuthUserInfo struct {
	ID            string
	Email         string
	Name          string
	GivenName     string
	FamilyName    string
	Picture       string
	VerifiedEmail bool
	Provider      string
}

// InitOAuthFlow initiates the OAuth authentication flow.
// InitOAuthFlow initiates OAuth authentication flow for the given provider.
func (m *Manager) InitOAuthFlow(w http.ResponseWriter, r *http.Request) {
	state := generateRandomString(32)
	if state == "" {
		slog.Error("Failed to generate OAuth state")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	verifier, err := generatePKCEVerifier()
	if err != nil {
		slog.Error("Failed to generate PKCE verifier", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	challenge := generatePKCEChallenge(verifier)

	m.oauthMu.Lock()
	m.oauthStates[state] = oauthState{
		State:       state,
		Verifier:    verifier,
		CreatedAt:   time.Now(),
		RedirectURL: r.URL.Query().Get("redirect"),
	}
	m.oauthMu.Unlock()

	endpoints := m.getOAuthEndpoints()

	authParams := url.Values{
		"client_id":             {m.config.ClientID},
		"redirect_uri":          {m.config.RedirectURL},
		"response_type":         {"code"},
		"scope":                 {strings.Join(m.config.Scopes, " ")},
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}

	authURL := endpoints.AuthURL + "?" + authParams.Encode()

	slog.Info("Initiating OAuth flow", "provider", m.config.Provider)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// HandleOAuthCallback processes the OAuth callback response.
func (m *Manager) HandleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	errorParam := r.URL.Query().Get("error")

	if errorParam != "" {
		errorDesc := r.URL.Query().Get("error_description")
		slog.Error("OAuth error from provider", "error", errorParam, "description", errorDesc)
		http.Error(w, fmt.Sprintf("Authentication error: %s", errorParam), http.StatusBadRequest)
		return
	}

	if code == "" || state == "" {
		slog.Error("Missing OAuth callback parameters")
		http.Error(w, "Invalid callback parameters", http.StatusBadRequest)
		return
	}

	m.oauthMu.Lock()
	storedState, exists := m.oauthStates[state]
	if exists {
		delete(m.oauthStates, state)
	}
	m.oauthMu.Unlock()

	if !exists {
		slog.Error("Invalid or expired OAuth state")
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	tokenResp, err := m.exchangeCodeForToken(code, storedState.Verifier)
	if err != nil {
		slog.Error("Failed to exchange OAuth code", "error", err)
		http.Error(w, "Token exchange failed", http.StatusInternalServerError)
		return
	}

	userInfo, err := m.getUserInfo(tokenResp.AccessToken)
	if err != nil {
		slog.Error("Failed to get user info", "error", err)
		http.Error(w, "Failed to get user information", http.StatusInternalServerError)
		return
	}

	if !m.isAllowedDomain(userInfo.Email) {
		slog.Warn("User domain not allowed", "email", userInfo.Email)
		http.Error(w, "Authentication not permitted for this domain", http.StatusForbidden)
		return
	}

	user := m.createUserFromOAuth(userInfo)

	session, err := m.CreateSession(user, r)
	if err != nil {
		slog.Error("Failed to create session", "error", err)
		http.Error(w, "Session creation failed", http.StatusInternalServerError)
		return
	}

	m.setSessionCookie(w, session)

	slog.Info("OAuth authentication successful", "email", userInfo.Email, "provider", m.config.Provider)

	redirectURL := storedState.RedirectURL
	if redirectURL == "" {
		redirectURL = "/"
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (m *Manager) exchangeCodeForToken(code, verifier string) (*OAuthTokenResponse, error) {
	endpoints := m.getOAuthEndpoints()

	tokenData := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {m.config.ClientID},
		"client_secret": {m.config.ClientSecret},
		"code":          {code},
		"redirect_uri":  {m.config.RedirectURL},
		"code_verifier": {verifier},
	}

	resp, err := m.httpClient.PostForm(endpoints.TokenURL, tokenData)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp OAuthTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	return &tokenResp, nil
}

func (m *Manager) getUserInfo(accessToken string) (*OAuthUserInfo, error) {
	endpoints := m.getOAuthEndpoints()

	req, err := http.NewRequest("GET", endpoints.UserInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create user info request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("user info request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("user info endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read user info response: %w", err)
	}

	return m.parseUserInfo(body)
}

func (m *Manager) parseUserInfo(body []byte) (*OAuthUserInfo, error) {
	var rawData map[string]interface{}
	if err := json.Unmarshal(body, &rawData); err != nil {
		return nil, fmt.Errorf("failed to parse user info: %w", err)
	}

	info := &OAuthUserInfo{}

	switch m.config.Provider {
	case ProviderGoogle:
		info.ID = getString(rawData, "sub")
		info.Email = getString(rawData, "email")
		info.Name = getString(rawData, "name")
		info.GivenName = getString(rawData, "given_name")
		info.FamilyName = getString(rawData, "family_name")
		info.Picture = getString(rawData, "picture")
		info.VerifiedEmail = getBool(rawData, "email_verified")

	case ProviderMicrosoft:
		info.ID = getString(rawData, "id")
		info.Email = getString(rawData, "mail")
		if info.Email == "" {
			info.Email = getString(rawData, "userPrincipalName")
		}
		info.Name = getString(rawData, "displayName")
		info.GivenName = getString(rawData, "givenName")
		info.FamilyName = getString(rawData, "surname")

	case ProviderGitHub:
		info.ID = fmt.Sprintf("%v", rawData["id"])
		info.Name = getString(rawData, "name")
		info.Email = getString(rawData, "email")
		if info.Email == "" {
			info.Email = getString(rawData, "login") + "@github.com"
		}
		info.Picture = getString(rawData, "avatar_url")

	default:
		info.ID = getString(rawData, "sub")
		if info.ID == "" {
			info.ID = getString(rawData, "id")
		}
		info.Email = getString(rawData, "email")
		info.Name = getString(rawData, "name")
		info.GivenName = getString(rawData, "given_name")
		info.FamilyName = getString(rawData, "family_name")
		info.VerifiedEmail = getBool(rawData, "email_verified")
	}

	info.Provider = string(m.config.Provider)
	return info, nil
}

func (m *Manager) createUserFromOAuth(info *OAuthUserInfo) *User {
	role := RoleViewer

	return &User{
		ID:          generateUserID(info.ID, m.config.Provider),
		Email:       info.Email,
		Name:        info.Name,
		Provider:    m.config.Provider,
		ProviderID:  info.ID,
		Role:        role,
		Permissions: RolePermissions[role],
		Attributes: map[string]interface{}{
			"picture":        info.Picture,
			"given_name":     info.GivenName,
			"family_name":    info.FamilyName,
			"email_verified": info.VerifiedEmail,
		},
		Authenticated: true,
		LastLogin:     time.Now(),
		CreatedAt:     time.Now(),
	}
}

func (m *Manager) getOAuthEndpoints() OAuthEndpoints {
	if m.config.AuthURL != "" && m.config.TokenURL != "" {
		return OAuthEndpoints{
			AuthURL:     m.config.AuthURL,
			TokenURL:    m.config.TokenURL,
			UserInfoURL: m.config.UserInfoURL,
			Scopes:      m.config.Scopes,
		}
	}

	if endpoints, ok := OAuthProviderEndpoints[m.config.Provider]; ok {
		if len(m.config.Scopes) > 0 {
			endpoints.Scopes = m.config.Scopes
		}
		return endpoints
	}

	return OAuthEndpoints{
		Scopes: m.config.Scopes,
	}
}

func (m *Manager) isAllowedDomain(email string) bool {
	domain := extractDomain(email)

	for _, blocked := range m.config.BlockedDomains {
		if strings.EqualFold(domain, blocked) {
			return false
		}
	}

	if len(m.config.AllowedDomains) == 0 {
		return true
	}

	for _, allowed := range m.config.AllowedDomains {
		if strings.EqualFold(domain, allowed) || strings.HasSuffix(domain, allowed) {
			return true
		}
	}

	return false
}

func getString(m map[string]interface{}, key string) string {
	if val, ok := m[key]; ok {
		if s, ok := val.(string); ok {
			return s
		}
	}
	return ""
}

func getBool(m map[string]interface{}, key string) bool {
	if val, ok := m[key]; ok {
		if b, ok := val.(bool); ok {
			return b
		}
	}
	return false
}
