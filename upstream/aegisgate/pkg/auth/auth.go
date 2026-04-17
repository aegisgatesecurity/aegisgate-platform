// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

package auth

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// Provider represents an authentication provider type
type Provider string

const (

	// ProviderGoogle identifies the Google OAuth provider.
	ProviderGoogle Provider = "google"
	// ProviderMicrosoft identifies the Microsoft OAuth provider.
	ProviderMicrosoft   Provider = "microsoft"
	ProviderGitHub      Provider = "github"
	ProviderOkta        Provider = "okta"
	ProviderAuth0       Provider = "auth0"
	ProviderGeneric     Provider = "generic_oauth"
	ProviderSAMLGeneric Provider = "saml"
	ProviderSAMLAzure   Provider = "saml_azure"
	ProviderSALMOkta    Provider = "saml_okta"
	ProviderLocal       Provider = "local"
)

// Role represents user authorization level
type Role string

const (

	// RoleAdmin defines the administrator role level.
	RoleAdmin Role = "admin"
	// RoleOperator defines the operator role level.
	RoleOperator Role = "operator"
	RoleViewer   Role = "viewer"
	RoleService  Role = "service"
)

// AtLeast returns true if this role has at least the required level
func (r Role) AtLeast(required Role) bool {
	roleLevel := map[Role]int{
		RoleViewer:   1,
		RoleOperator: 2,
		RoleService:  3,
		RoleAdmin:    4,
	}
	return roleLevel[r] >= roleLevel[required]
}

// Permission represents a specific authorization permission
type Permission string

const (

	// PermViewDashboard is the permission to view the dashboard.
	PermViewDashboard  Permission = "view:dashboard"
	PermManagePolicies Permission = "manage:policies"
	PermManageCerts    Permission = "manage:certificates"
	PermViewLogs       Permission = "view:logs"
	PermManageUsers    Permission = "manage:users"
	PermViewReports    Permission = "view:reports"
	PermSystemConfig   Permission = "system:config"
	PermViewAlerts     Permission = "view:alerts"
)

// RolePermissions maps roles to permissions.
var RolePermissions = map[Role][]Permission{
	RoleAdmin: {
		PermViewDashboard, PermManagePolicies, PermManageCerts,
		PermViewLogs, PermManageUsers, PermViewReports,
		PermSystemConfig, PermViewAlerts,
	},
	RoleOperator: {
		PermViewDashboard, PermManagePolicies, PermViewLogs,
		PermViewReports, PermViewAlerts,
	},
	RoleViewer: {
		PermViewDashboard, PermViewReports, PermViewAlerts,
	},
	RoleService: {
		PermViewDashboard, PermViewReports,
	},
}

// User represents an authenticated user
type User struct {
	ID            string
	Email         string
	Name          string
	Provider      Provider
	ProviderID    string
	Role          Role
	Permissions   []Permission
	Attributes    map[string]interface{}
	SessionID     string
	Authenticated bool
	LastLogin     time.Time
	CreatedAt     time.Time
}

// HasPermission checks if the user has a specific permission.
// HasPermission checks if the user has a specific permission.
func (u *User) HasPermission(perm Permission) bool {
	for _, p := range u.Permissions {
		if p == perm {
			return true
		}
	}
	return false
}

// IsAdmin returns true if user has admin role.
// IsAdmin returns true if user has admin role.
func (u *User) IsAdmin() bool {
	return u.Role == RoleAdmin
}

// Session represents an authenticated session
type Session struct {
	ID           string
	UserID       string
	User         *User
	CreatedAt    time.Time
	ExpiresAt    time.Time
	LastActivity time.Time
	IPAddress    string
	UserAgent    string
	Active       bool
}

// IsExpired checks if the session has expired.
// IsExpired checks if the session has expired.
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// IsValid checks if the session is valid and not expired.
// IsValid checks if the session is valid and not expired.
func (s *Session) IsValid() bool {
	return s.Active && !s.IsExpired()
}

// Refresh updates the session expiration time.
// Refresh updates the session expiration time.
func (s *Session) Refresh(duration time.Duration) {
	s.LastActivity = time.Now()
	s.ExpiresAt = time.Now().Add(duration)
}

// Config holds authentication configuration
type Config struct {
	Provider        Provider
	ClientID        string
	ClientSecret    string
	RedirectURL     string
	AuthURL         string
	TokenURL        string
	UserInfoURL     string
	Scopes          []string
	SAMLMetadataURL string
	SAMLIssuer      string
	SAMLCertPath    string
	SessionDuration time.Duration
	CookieName      string
	CookieSecure    bool
	CookieHTTPOnly  bool
	CookieSameSite  http.SameSite
	RequireHTTPS    bool
	MaxSessions     int
	EnableMFA       bool
	AllowedDomains  []string
	BlockedDomains  []string
	LocalUsers      map[string]LocalUserConfig
}

// LocalUserConfig holds local user credentials
type LocalUserConfig struct {
	PasswordHash string
	Salt         string
	Role         Role
	Enabled      bool
}

// DefaultConfig returns default authentication configuration
func DefaultConfig() *Config {
	return &Config{
		SessionDuration: 24 * time.Hour,
		CookieName:      "aegisgate_session",
		CookieSecure:    true,
		CookieHTTPOnly:  true,
		CookieSameSite:  http.SameSiteStrictMode,
		RequireHTTPS:    true,
		MaxSessions:     1000,
		Scopes:          []string{"openid", "profile", "email"},
		LocalUsers:      make(map[string]LocalUserConfig),
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Provider == "" {
		return errors.New("auth provider is required")
	}

	switch c.Provider {
	case ProviderLocal:
		if len(c.LocalUsers) == 0 {
			return errors.New("at least one local user must be configured")
		}
	case ProviderGoogle, ProviderMicrosoft, ProviderGitHub, ProviderOkta, ProviderAuth0, ProviderGeneric:
		if c.ClientID == "" {
			return errors.New("OAuth client ID is required")
		}
		if c.ClientSecret == "" {
			return errors.New("OAuth client secret is required")
		}
		if c.RedirectURL == "" {
			return errors.New("OAuth redirect URL is required")
		}
		if c.AuthURL == "" && c.Provider == ProviderGeneric {
			return errors.New("OAuth auth URL is required")
		}
		if c.TokenURL == "" && c.Provider == ProviderGeneric {
			return errors.New("OAuth token URL is required")
		}
	case ProviderSAMLGeneric, ProviderSAMLAzure, ProviderSALMOkta:
		if c.SAMLMetadataURL == "" && c.SAMLIssuer == "" {
			return errors.New("SAML metadata URL or issuer is required")
		}
	}

	if c.SessionDuration <= 0 {
		c.SessionDuration = 24 * time.Hour
	}

	return nil
}

// Manager handles authentication and session management
type Manager struct {
	config      *Config
	sessions    map[string]*Session
	sessionsMu  sync.RWMutex
	httpClient  *http.Client
	oauthStates map[string]oauthState
	oauthMu     sync.Mutex
}

// oauthState tracks OAuth authorization state
type oauthState struct {
	State       string
	Verifier    string
	CreatedAt   time.Time
	RedirectURL string
}

// NewManager creates a new authentication manager
func NewManager(config *Config) (*Manager, error) {
	if config == nil {
		config = DefaultConfig()
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid auth config: %w", err)
	}

	m := &Manager{
		config:      config,
		sessions:    make(map[string]*Session),
		oauthStates: make(map[string]oauthState),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}

	go m.cleanupLoop()

	slog.Info("Authentication manager initialized",
		"provider", config.Provider,
		"session_duration", config.SessionDuration.String(),
	)

	return m, nil
}

// cleanupLoop periodically cleans up expired sessions and states
func (m *Manager) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		m.cleanup()
	}
}

// cleanup removes expired sessions and old OAuth states
func (m *Manager) cleanup() {
	now := time.Now()

	m.sessionsMu.Lock()
	expiredCount := 0
	for id, session := range m.sessions {
		if session.IsExpired() || !session.Active {
			delete(m.sessions, id)
			expiredCount++
		}
	}
	m.sessionsMu.Unlock()

	m.oauthMu.Lock()
	stateCount := 0
	for state, data := range m.oauthStates {
		if now.Sub(data.CreatedAt) > 10*time.Minute {
			delete(m.oauthStates, state)
			stateCount++
		}
	}
	m.oauthMu.Unlock()

	if expiredCount > 0 || stateCount > 0 {
		slog.Debug("Auth cleanup completed",
			"expired_sessions", expiredCount,
			"expired_states", stateCount,
		)
	}
}

// GetConfig returns the authentication configuration
func (m *Manager) GetConfig() *Config {
	return m.config
}

// Close shuts down the authentication manager
func (m *Manager) Close() {
	m.sessionsMu.Lock()
	m.sessions = make(map[string]*Session)
	m.sessionsMu.Unlock()

	slog.Info("Authentication manager shut down")
}
