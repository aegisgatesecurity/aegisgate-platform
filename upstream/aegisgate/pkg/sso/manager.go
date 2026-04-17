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
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/auth"
)

// Manager manages SSO providers and sessions
type Manager struct {
	mu          sync.RWMutex
	providers   map[string]SSOProviderInterface
	configs     map[string]*SSOConfig
	sessions    SessionStore
	requests    RequestStore
	defaultConf *SSOConfig
	httpClient  *http.Client
}

// ManagerConfig holds manager configuration
type ManagerConfig struct {
	SessionStore   SessionStore
	RequestStore   RequestStore
	DefaultConfig  *SSOConfig
	HTTPClient     *http.Client
	SessionTimeout time.Duration
}

// NewManager creates a new SSO manager
func NewManager(config *ManagerConfig) (*Manager, error) {
	if config == nil {
		config = &ManagerConfig{}
	}

	if config.SessionStore == nil {
		config.SessionStore = NewMemorySessionStore()
	}
	if config.RequestStore == nil {
		config.RequestStore = NewMemoryRequestStore()
	}
	if config.DefaultConfig == nil {
		config.DefaultConfig = DefaultSSOConfig()
	}

	m := &Manager{
		providers:   make(map[string]SSOProviderInterface),
		configs:     make(map[string]*SSOConfig),
		sessions:    config.SessionStore,
		requests:    config.RequestStore,
		defaultConf: config.DefaultConfig,
		httpClient:  config.HTTPClient,
	}

	if m.httpClient == nil {
		m.httpClient = &http.Client{Timeout: 30 * time.Second}
	}

	return m, nil
}

// RegisterProvider registers an SSO provider
func (m *Manager) RegisterProvider(config *SSOConfig) error {
	if config == nil {
		return NewSSOError(ErrInvalidRequest, "provider config is required")
	}

	if err := config.Validate(); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	var provider SSOProviderInterface
	var err error

	switch config.Provider {
	case ProviderSAML:
		provider, err = NewSAMLProvider(config, m.requests)
	case ProviderOIDC, ProviderOAuth:
		provider, err = NewOIDCProvider(config, m.requests)
	default:
		return NewSSOError(ErrProviderNotConfigured, fmt.Sprintf("unknown provider type: %s", config.Provider))
	}

	if err != nil {
		return err
	}

	m.providers[config.Name] = provider
	m.configs[config.Name] = config

	return nil
}

// UnregisterProvider unregisters an SSO provider
func (m *Manager) UnregisterProvider(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.providers, name)
	delete(m.configs, name)

	return nil
}

// GetProvider returns an SSO provider by name
func (m *Manager) GetProvider(name string) (SSOProviderInterface, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	provider, ok := m.providers[name]
	if !ok {
		return nil, NewSSOError(ErrProviderNotConfigured, fmt.Sprintf("provider not found: %s", name))
	}

	return provider, nil
}

// ListProviders returns all registered provider names
func (m *Manager) ListProviders() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	names := make([]string, 0, len(m.providers))
	for name := range m.providers {
		names = append(names, name)
	}
	return names
}

// InitiateLogin initiates SSO login for a provider
func (m *Manager) InitiateLogin(providerName string) (string, *SSORequest, error) {
	provider, err := m.GetProvider(providerName)
	if err != nil {
		return "", nil, err
	}

	state := generateState()
	loginURL, request, err := provider.InitiateLogin(state)
	if err != nil {
		return "", nil, err
	}

	// Store the request
	if err := m.requests.Create(request); err != nil {
		return "", nil, NewSSOError(ErrInvalidRequest, "failed to store SSO request").WithCause(err)
	}

	return loginURL, request, nil
}

// HandleCallback handles the SSO callback from the provider
func (m *Manager) HandleCallback(providerName string, params map[string]string) (*SSOResponse, error) {
	provider, err := m.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	// Get state from params
	state := params["state"]
	if state == "" {
		return nil, NewSSOError(ErrInvalidCallback, "missing state parameter")
	}

	// Retrieve the original request
	request, err := m.requests.GetByState(state)
	if err != nil {
		return nil, NewSSOError(ErrStateMismatch, "invalid or expired state").WithCause(err)
	}

	// Check if request belongs to this provider
	if request.Provider != providerName {
		return nil, NewSSOError(ErrInvalidCallback, "provider mismatch in callback")
	}

	// Handle callback with provider
	response, err := provider.HandleCallback(request, params)
	if err != nil {
		return nil, err
	}

	// Clean up request - ignore error as request is already handled
	_ = m.requests.Delete(request.ID)

	// Store session
	if response.Session != nil {
		if err := m.sessions.Create(response.Session); err != nil {
			return nil, NewSSOError(ErrInvalidRequest, "failed to store session").WithCause(err)
		}
	}

	// Apply role mappings
	if response.User != nil {
		m.applyRoleMappings(response.User, m.configs[providerName])
	}

	return response, nil
}

// ValidateSession validates an SSO session
func (m *Manager) ValidateSession(sessionID string) (*SSOSession, error) {
	session, err := m.sessions.Get(sessionID)
	if err != nil {
		return nil, NewSSOError(ErrSessionExpired, "session not found").WithCause(err)
	}

	if session.IsExpired() {
		_ = m.sessions.Delete(sessionID)
		return nil, NewSSOError(ErrSessionExpired, "session has expired")
	}

	if !session.Active {
		return nil, NewSSOError(ErrInvalidToken, "session is inactive")
	}

	// Validate with provider
	provider, err := m.GetProvider(session.ProviderName)
	if err != nil {
		return nil, err
	}

	if err := provider.ValidateSession(session); err != nil {
		return nil, err
	}

	// Update activity
	session.LastActivity = time.Now()
	if err := m.sessions.Update(session); err != nil {
		return nil, NewSSOError(ErrInvalidRequest, "failed to update session").WithCause(err)
	}

	return session, nil
}

// Logout logs out an SSO session
func (m *Manager) Logout(sessionID string) (string, error) {
	session, err := m.sessions.Get(sessionID)
	if err != nil {
		return "", NewSSOError(ErrSessionExpired, "session not found").WithCause(err)
	}

	// Mark session as inactive
	session.Active = false
	_ = m.sessions.Update(session)

	// Get logout URL from provider
	provider, err := m.GetProvider(session.ProviderName)
	if err != nil {
		// Provider not found, just invalidate local session
		_ = m.sessions.Delete(sessionID)
		return "", nil
	}

	logoutURL, err := provider.Logout(session)
	if err != nil {
		// Still delete local session even if logout URL fails
		_ = m.sessions.Delete(sessionID)
		return "", err
	}

	// Delete local session
	_ = m.sessions.Delete(sessionID)

	return logoutURL, nil
}

// GetSession returns a session by ID
func (m *Manager) GetSession(sessionID string) (*SSOSession, error) {
	return m.sessions.Get(sessionID)
}

// GetUserSessions returns all sessions for a user
func (m *Manager) GetUserSessions(userID string) ([]*SSOSession, error) {
	return m.sessions.GetByUserID(userID)
}

// TerminateUserSessions terminates all sessions for a user
func (m *Manager) TerminateUserSessions(userID string) error {
	sessions, err := m.sessions.GetByUserID(userID)
	if err != nil {
		return err
	}

	for _, session := range sessions {
		session.Active = false
		_ = m.sessions.Update(session)
	}

	return nil
}

// RefreshSession refreshes an OIDC session's tokens
func (m *Manager) RefreshSession(sessionID string) (*SSOSession, error) {
	session, err := m.sessions.Get(sessionID)
	if err != nil {
		return nil, NewSSOError(ErrSessionExpired, "session not found").WithCause(err)
	}

	if session.Provider != ProviderOIDC && session.Provider != ProviderOAuth {
		return nil, NewSSOError(ErrInvalidRequest, "session refresh only supported for OIDC providers")
	}

	if session.RefreshToken == "" {
		return nil, NewSSOError(ErrInvalidToken, "no refresh token available")
	}

	// Get provider
	provider, err := m.GetProvider(session.ProviderName)
	if err != nil {
		return nil, err
	}

	oidcProvider, ok := provider.(*OIDCProvider)
	if !ok {
		return nil, NewSSOError(ErrProviderNotConfigured, "provider does not support token refresh")
	}

	// Refresh tokens
	token, err := oidcProvider.RefreshToken(session.RefreshToken)
	if err != nil {
		return nil, err
	}

	// Update session
	session.AccessToken = token.AccessToken
	if token.RefreshToken != "" {
		session.RefreshToken = token.RefreshToken
	}
	if token.IDToken != "" {
		session.IDToken = token.IDToken
	}
	session.TokenExpiresAt = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
	session.LastRefreshed = time.Now()

	if err := m.sessions.Update(session); err != nil {
		return nil, NewSSOError(ErrInvalidRequest, "failed to update session").WithCause(err)
	}

	return session, nil
}

// CleanupSessions removes expired sessions
func (m *Manager) CleanupSessions() error {
	return m.sessions.Cleanup()
}

// GetProviderMetadata returns the metadata for a provider
func (m *Manager) GetProviderMetadata(providerName string) ([]byte, error) {
	provider, err := m.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	return provider.Metadata()
}

// CheckDomainAccess checks if a domain is allowed for a provider
func (m *Manager) CheckDomainAccess(providerName, email string) error {
	m.mu.RLock()
	config, ok := m.configs[providerName]
	m.mu.RUnlock()

	if !ok {
		return NewSSOError(ErrProviderNotConfigured, "provider not found")
	}

	// Check blocked domains first
	for _, blocked := range config.BlockedDomains {
		if domainMatches(email, blocked) {
			return NewSSOError(ErrDomainNotAllowed, fmt.Sprintf("domain %s is blocked", blocked))
		}
	}

	// Check allowed domains (if any are specified)
	if len(config.AllowedDomains) > 0 {
		allowed := false
		for _, domain := range config.AllowedDomains {
			if domainMatches(email, domain) {
				allowed = true
				break
			}
		}
		if !allowed {
			return NewSSOError(ErrDomainNotAllowed, "domain is not in allowed list")
		}
	}

	return nil
}

// applyRoleMappings applies role mappings to a user
func (m *Manager) applyRoleMappings(user *SSOUser, config *SSOConfig) {
	if config == nil || len(config.RoleMappings) == 0 {
		return
	}

	roles := make([]auth.Role, 0)
	for _, mapping := range config.RoleMappings {
		// Check groups
		for _, group := range user.Groups {
			if group == mapping.IdPRole {
				roles = append(roles, mapping.AppRole)
			}
		}
	}

	// Apply roles to user if any matched
	if len(roles) > 0 && user.User != nil {
		user.Role = roles[0] // Use highest priority role
	}
}

// Stats returns manager statistics
type ManagerStats struct {
	Providers      int
	ActiveSessions int
}

// Stats returns manager statistics
func (m *Manager) Stats() (*ManagerStats, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := &ManagerStats{
		Providers: len(m.providers),
	}

	// Count sessions if possible
	if sessions, ok := m.sessions.(*MemorySessionStore); ok {
		sessions.mu.RLock()
		stats.ActiveSessions = len(sessions.sessions)
		sessions.mu.RUnlock()
	}

	return stats, nil
}

// MemorySessionStore implements SessionStore in memory
type MemorySessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*SSOSession
}

// NewMemorySessionStore creates a new memory session store
func NewMemorySessionStore() *MemorySessionStore {
	return &MemorySessionStore{
		sessions: make(map[string]*SSOSession),
	}
}

// Create stores a new session
func (s *MemorySessionStore) Create(session *SSOSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.ID] = session
	return nil
}

// Get retrieves a session by ID
func (s *MemorySessionStore) Get(id string) (*SSOSession, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	session, ok := s.sessions[id]
	if !ok {
		return nil, errors.New("session not found")
	}
	return session, nil
}

// Update updates an existing session
func (s *MemorySessionStore) Update(session *SSOSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.ID] = session
	return nil
}

// Delete removes a session
func (s *MemorySessionStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
	return nil
}

// GetByUserID returns all sessions for a user
func (s *MemorySessionStore) GetByUserID(userID string) ([]*SSOSession, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var sessions []*SSOSession
	for _, session := range s.sessions {
		if session.UserID == userID {
			sessions = append(sessions, session)
		}
	}
	return sessions, nil
}

// DeleteByUserID removes all sessions for a user
func (s *MemorySessionStore) DeleteByUserID(userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, session := range s.sessions {
		if session.UserID == userID {
			delete(s.sessions, id)
		}
	}
	return nil
}

// Cleanup removes expired sessions
func (s *MemorySessionStore) Cleanup() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, session := range s.sessions {
		if session.IsExpired() {
			delete(s.sessions, id)
		}
	}
	return nil
}

// MemoryRequestStore implements RequestStore in memory
type MemoryRequestStore struct {
	mu       sync.RWMutex
	requests map[string]*SSORequest
	byState  map[string]string
}

// NewMemoryRequestStore creates a new memory request store
func NewMemoryRequestStore() *MemoryRequestStore {
	return &MemoryRequestStore{
		requests: make(map[string]*SSORequest),
		byState:  make(map[string]string),
	}
}

// Create stores a new request
func (s *MemoryRequestStore) Create(request *SSORequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests[request.ID] = request
	s.byState[request.State] = request.ID
	return nil
}

// Get retrieves a request by ID
func (s *MemoryRequestStore) Get(id string) (*SSORequest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	request, ok := s.requests[id]
	if !ok {
		return nil, errors.New("request not found")
	}
	return request, nil
}

// GetByState retrieves a request by state
func (s *MemoryRequestStore) GetByState(state string) (*SSORequest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byState[state]
	if !ok {
		return nil, errors.New("request not found for state")
	}
	return s.requests[id], nil
}

// Delete removes a request
func (s *MemoryRequestStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if request, ok := s.requests[id]; ok {
		delete(s.byState, request.State)
	}
	delete(s.requests, id)
	return nil
}

// Helper functions

func generateState() string {
	b := make([]byte, 24)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func domainMatches(email, domain string) bool {
	// Extract domain from email
	atIdx := -1
	for i, c := range email {
		if c == '@' {
			atIdx = i
			break
		}
	}
	if atIdx == -1 {
		return false
	}
	emailDomain := email[atIdx+1:]
	return emailDomain == domain
}

// Context keys
type contextKey string

const (
	SessionContextKey contextKey = "sso_session"
	UserContextKey    contextKey = "sso_user"
)

// SessionFromContext retrieves the session from context
func SessionFromContext(ctx context.Context) *SSOSession {
	session, _ := ctx.Value(SessionContextKey).(*SSOSession)
	return session
}

// UserFromContext retrieves the user from context
func UserFromContext(ctx context.Context) *SSOUser {
	user, _ := ctx.Value(UserContextKey).(*SSOUser)
	return user
}

// ContextWithSession adds a session to context
func ContextWithSession(ctx context.Context, session *SSOSession) context.Context {
	return context.WithValue(ctx, SessionContextKey, session)
}

// ContextWithUser adds a user to context
func ContextWithUser(ctx context.Context, user *SSOUser) context.Context {
	return context.WithValue(ctx, UserContextKey, user)
}
