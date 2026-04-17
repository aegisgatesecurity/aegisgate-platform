// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGuard Security (adapted from AegisGate Security)
// Copyright (c) 2025-2026 AegisGuard Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

// Package auth provides authentication and session management for agents
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
	ProviderLocal  Provider = "local"
	ProviderAPIKey Provider = "api_key"
	ProviderJWT    Provider = "jwt"
	ProviderOAuth  Provider = "oauth"
)

// Role represents agent authorization level
type Role string

const (
	RoleRestricted Role = "restricted"
	RoleStandard   Role = "standard"
	RolePrivileged Role = "privileged"
	RoleAdmin      Role = "admin"
)

// AtLeast returns true if this role has at least the required level
func (r Role) AtLeast(required Role) bool {
	roleLevel := map[Role]int{
		RoleRestricted: 1,
		RoleStandard:   2,
		RolePrivileged: 3,
		RoleAdmin:      4,
	}
	return roleLevel[r] >= roleLevel[required]
}

// Permission represents a specific authorization permission
type Permission string

const (
	PermToolFileRead    Permission = "tool:file:read"
	PermToolFileWrite   Permission = "tool:file:write"
	PermToolFileDelete  Permission = "tool:file:delete"
	PermToolWebSearch   Permission = "tool:web:search"
	PermToolHTTPRequest Permission = "tool:http:request"
	PermToolShellExec   Permission = "tool:shell:execute"
	PermToolCodeExec    Permission = "tool:code:execute"
	PermToolDatabase    Permission = "tool:database:query"
)

// RolePermissions maps roles to permissions
var RolePermissions = map[Role][]Permission{
	RoleRestricted: {
		PermToolFileRead, PermToolWebSearch,
	},
	RoleStandard: {
		PermToolFileRead, PermToolFileWrite, PermToolWebSearch,
		PermToolHTTPRequest, PermToolCodeExec,
	},
	RolePrivileged: {
		PermToolFileRead, PermToolFileWrite, PermToolFileDelete,
		PermToolWebSearch, PermToolHTTPRequest,
		PermToolShellExec, PermToolCodeExec, PermToolDatabase,
	},
	RoleAdmin: {
		PermToolFileRead, PermToolFileWrite, PermToolFileDelete,
		PermToolWebSearch, PermToolHTTPRequest,
		PermToolShellExec, PermToolCodeExec, PermToolDatabase,
	},
}

// Agent represents an authenticated AI agent
type Agent struct {
	ID            string
	Name          string
	Type          string // cursor, claude, openclaw, etc.
	Role          Role
	Permissions   []Permission
	Attributes    map[string]interface{}
	SessionID     string
	Authenticated bool
	LastActivity  time.Time
	CreatedAt     time.Time
	Enabled       bool
}

// HasPermission checks if the agent has a specific permission
func (a *Agent) HasPermission(perm Permission) bool {
	for _, p := range a.Permissions {
		if p == perm {
			return true
		}
	}
	return false
}

// IsAdmin returns true if agent has admin role
func (a *Agent) IsAdmin() bool {
	return a.Role == RoleAdmin
}

// Session represents an authenticated agent session
type Session struct {
	ID           string
	AgentID      string
	Agent        *Agent
	CreatedAt    time.Time
	ExpiresAt    time.Time
	LastActivity time.Time
	IPAddress    string
	UserAgent    string
	Active       bool
	Tags         map[string]string
}

// IsExpired checks if the session has expired
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// IsValid checks if the session is valid and not expired
func (s *Session) IsValid() bool {
	return s.Active && !s.IsExpired()
}

// Refresh updates the session expiration time
func (s *Session) Refresh(duration time.Duration) {
	s.LastActivity = time.Now()
	s.ExpiresAt = time.Now().Add(duration)
}

// Config holds authentication configuration
type Config struct {
	Provider        Provider
	SessionDuration time.Duration
	CookieName      string
	CookieSecure    bool
	CookieHTTPOnly  bool
	CookieSameSite  http.SameSite
	MaxSessions     int
	AllowedAgents   map[string]AgentConfig
	APIKeys         map[string]string // key -> agent ID
	JWTSecret       string
}

// AgentConfig holds agent configuration
type AgentConfig struct {
	Role     Role
	Enabled  bool
	Metadata map[string]string
}

// DefaultConfig returns default authentication configuration
func DefaultConfig() *Config {
	return &Config{
		Provider:        ProviderAPIKey,
		SessionDuration: 24 * time.Hour,
		CookieName:      "aegisguard_session",
		CookieSecure:    true,
		CookieHTTPOnly:  true,
		CookieSameSite:  http.SameSiteStrictMode,
		MaxSessions:     10000,
		AllowedAgents:   make(map[string]AgentConfig),
		APIKeys:         make(map[string]string),
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Provider == "" {
		return errors.New("auth provider is required")
	}

	if c.SessionDuration <= 0 {
		c.SessionDuration = 24 * time.Hour
	}

	return nil
}

// Manager handles authentication and session management
type Manager struct {
	config     *Config
	sessions   map[string]*Session
	agents     map[string]*Agent
	sessionsMu sync.RWMutex
	agentsMu   sync.RWMutex
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
		config:   config,
		sessions: make(map[string]*Session),
		agents:   make(map[string]*Agent),
	}

	go m.cleanupLoop()

	slog.Info("Auth manager initialized",
		"provider", config.Provider,
		"session_duration", config.SessionDuration.String(),
	)

	return m, nil
}

// cleanupLoop periodically cleans up expired sessions
func (m *Manager) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		m.cleanup()
	}
}

// cleanup removes expired sessions
func (m *Manager) cleanup() {
	m.sessionsMu.Lock()
	expiredCount := 0
	for id, session := range m.sessions {
		if session.IsExpired() || !session.Active {
			delete(m.sessions, id)
			expiredCount++
		}
	}
	m.sessionsMu.Unlock()

	if expiredCount > 0 {
		slog.Debug("Auth cleanup completed", "expired_sessions", expiredCount)
	}
}

// RegisterAgent registers a new agent
func (m *Manager) RegisterAgent(agent *Agent) error {
	m.agentsMu.Lock()
	defer m.agentsMu.Unlock()

	if _, exists := m.agents[agent.ID]; exists {
		return fmt.Errorf("agent already registered: %s", agent.ID)
	}

	agent.CreatedAt = time.Now()
	agent.LastActivity = time.Now()
	agent.Authenticated = true

	m.agents[agent.ID] = agent

	slog.Info("Agent registered", "agent_id", agent.ID, "role", agent.Role)

	return nil
}

// GetAgent retrieves an agent by ID
func (m *Manager) GetAgent(agentID string) (*Agent, error) {
	m.agentsMu.RLock()
	defer m.agentsMu.RUnlock()

	agent, exists := m.agents[agentID]
	if !exists {
		return nil, fmt.Errorf("agent not found: %s", agentID)
	}

	return agent, nil
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

	slog.Info("Auth manager shut down")
}
