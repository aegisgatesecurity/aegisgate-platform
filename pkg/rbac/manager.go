// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform — RBAC Manager
// =========================================================================
//
// Role-Based Access Control Manager for agents and users.
// Provides session-aware authorization, agent management, and permission checking.
// =========================================================================

package rbac

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// ============================================================================
// MANAGER
// ============================================================================

// Manager handles RBAC operations for agents and users
type Manager struct {
	config         *Config
	agents         map[string]*Agent
	agentMu        sync.RWMutex
	users          map[string]*User
	userMu         sync.RWMutex
	agentSessions  map[string]*AgentSession
	agentSessionMu sync.RWMutex
	userSessions   map[string]*UserSession
	userSessionMu  sync.RWMutex
	cleanupMu      sync.Mutex
	logger         *slog.Logger
	stopCleanup    chan struct{}
}

// NewManager creates a new RBAC manager
func NewManager(config *Config) (*Manager, error) {
	if config == nil {
		config = DefaultConfig()
	}

	m := &Manager{
		config:        config,
		agents:        make(map[string]*Agent),
		users:         make(map[string]*User),
		agentSessions: make(map[string]*AgentSession),
		userSessions:  make(map[string]*UserSession),
		logger:        slog.Default(),
		stopCleanup:   make(chan struct{}),
	}

	// Start cleanup goroutine
	go m.cleanupLoop()

	m.logger.Info("RBAC manager initialized",
		"session_duration", config.SessionDuration.String(),
		"max_agents", config.MaxAgents,
		"max_users", config.MaxUsers,
		"default_role", config.DefaultRole,
		"default_user_role", config.DefaultUserRole,
	)

	return m, nil
}

// Close shuts down the RBAC manager
func (m *Manager) Close() {
	close(m.stopCleanup)
	m.agentMu.Lock()
	m.agents = make(map[string]*Agent)
	m.agentMu.Unlock()
	m.userMu.Lock()
	m.users = make(map[string]*User)
	m.userMu.Unlock()
	m.agentSessionMu.Lock()
	m.agentSessions = make(map[string]*AgentSession)
	m.agentSessionMu.Unlock()
	m.userSessionMu.Lock()
	m.userSessions = make(map[string]*UserSession)
	m.userSessionMu.Unlock()
	m.logger.Info("RBAC manager shut down")
}

// ============================================================================
// AGENT MANAGEMENT
// ============================================================================

// RegisterAgent registers a new agent with the specified role
func (m *Manager) RegisterAgent(agent *Agent) error {
	m.agentMu.Lock()
	defer m.agentMu.Unlock()

	if agent.ID == "" {
		return errors.New("agent ID is required")
	}

	if _, exists := m.agents[agent.ID]; exists {
		return fmt.Errorf("agent already registered: %s", agent.ID)
	}

	if len(m.agents) >= m.config.MaxAgents {
		return errors.New("maximum number of agents reached")
	}

	// Set defaults
	agent.CreatedAt = time.Now()
	agent.UpdatedAt = time.Now()
	agent.Enabled = true

	// If no role specified, use default
	if agent.Role == "" {
		agent.Role = m.config.DefaultRole
	}

	// If no permissions specified, use role defaults
	if len(agent.Tools) == 0 {
		agent.Tools = GetPermissionsForRole(agent.Role)
	}

	// Initialize tags if nil
	if agent.Tags == nil {
		agent.Tags = make(map[string]string)
	}

	m.agents[agent.ID] = agent

	m.logger.Info("agent registered",
		"agent_id", truncateID(agent.ID),
		"name", agent.Name,
		"role", agent.Role,
	)

	return nil
}

// GetAgent retrieves an agent by ID
func (m *Manager) GetAgent(agentID string) (*Agent, error) {
	m.agentMu.RLock()
	defer m.agentMu.RUnlock()

	agent, exists := m.agents[agentID]
	if !exists {
		return nil, fmt.Errorf("agent not found: %s", agentID)
	}

	return agent, nil
}

// UpdateAgent updates an existing agent
func (m *Manager) UpdateAgent(agentID string, updates *AgentUpdates) error {
	m.agentMu.Lock()
	defer m.agentMu.Unlock()

	agent, exists := m.agents[agentID]
	if !exists {
		return fmt.Errorf("agent not found: %s", agentID)
	}

	// Apply updates
	if updates.Name != "" {
		agent.Name = updates.Name
	}
	if updates.Description != "" {
		agent.Description = updates.Description
	}
	if updates.Role != "" {
		// Validate role
		switch updates.Role {
		case AgentRoleRestricted, AgentRoleStandard, AgentRolePrivileged, AgentRoleAdmin:
			agent.Role = updates.Role
			// Update permissions if role changes and no explicit permissions set
			if len(updates.Tools) == 0 {
				agent.Tools = GetPermissionsForRole(updates.Role)
			}
		default:
			return fmt.Errorf("invalid role: %s", updates.Role)
		}
	}
	if len(updates.Tools) > 0 {
		agent.Tools = updates.Tools
	}
	if updates.Tags != nil {
		for k, v := range updates.Tags {
			agent.Tags[k] = v
		}
	}
	// Note: We don't update Enabled here as it's a critical field that should be set explicitly

	agent.UpdatedAt = time.Now()

	m.logger.Info("agent updated",
		"agent_id", truncateID(agentID),
		"updates", fmt.Sprintf("%+v", updates),
	)

	return nil
}

// UnregisterAgent removes an agent
func (m *Manager) UnregisterAgent(agentID string) error {
	m.agentMu.Lock()
	defer m.agentMu.Unlock()

	if _, exists := m.agents[agentID]; !exists {
		return errors.New("agent not found")
	}

	// Invalidate all sessions for this agent
	m.agentSessionMu.Lock()
	for sessionID, session := range m.agentSessions {
		if session.AgentID == agentID {
			session.Active = false
			delete(m.agentSessions, sessionID)
		}
	}
	m.agentSessionMu.Unlock()

	delete(m.agents, agentID)

	m.logger.Info("agent unregistered",
		"agent_id", truncateID(agentID),
	)

	return nil
}

// ListAgents returns all registered agents
func (m *Manager) ListAgents() []*Agent {
	m.agentMu.RLock()
	defer m.agentMu.RUnlock()

	agents := make([]*Agent, 0, len(m.agents))
	for _, agent := range m.agents {
		agents = append(agents, agent)
	}
	return agents
}

// ============================================================================
// SESSION MANAGEMENT
// ============================================================================

// CreateSession creates a new session for an agent
func (m *Manager) CreateSession(ctx context.Context, agentID string, opts ...SessionOption) (*AgentSession, error) {
	m.agentSessionMu.Lock()
	defer m.agentSessionMu.Unlock()

	// Get agent
	m.agentMu.RLock()
	agent, exists := m.agents[agentID]
	m.agentMu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("agent not found: %s", agentID)
	}

	if !agent.Enabled {
		return nil, errors.New("agent is disabled")
	}

	// Count existing sessions for this agent
	sessionCount := 0
	for _, s := range m.agentSessions {
		if s.AgentID == agentID && s.Active {
			sessionCount++
		}
	}

	if sessionCount >= m.config.MaxSessionsPerAgent {
		return nil, errors.New("maximum sessions reached for agent")
	}

	// Generate session ID
	sessionID, err := generateID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}

	// Apply options
	session := &AgentSession{
		ID:        sessionID,
		AgentID:   agentID,
		Agent:     agent,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(m.config.SessionDuration),
		Tags:      make(map[string]string),
		Active:    true,
	}
	session.SetLastActivity(time.Now())

	// Apply session options
	for _, opt := range opts {
		opt(session)
	}

	m.agentSessions[sessionID] = session

	m.logger.Info("session created",
		"session_id", truncateID(sessionID),
		"agent_id", truncateID(agentID),
		"role", agent.Role,
	)

	return session, nil
}

// GetSession retrieves a session by ID
func (m *Manager) GetSession(sessionID string) (*AgentSession, error) {
	m.agentSessionMu.RLock()
	defer m.agentSessionMu.RUnlock()

	session, exists := m.agentSessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("session not found: %s", sessionID)
	}

	if !session.IsValid() {
		return nil, errors.New("session expired or invalid")
	}

	return session, nil
}

// GetAgentSessions returns all active sessions for an agent
func (m *Manager) GetAgentSessions(agentID string) []*AgentSession {
	m.agentSessionMu.RLock()
	defer m.agentSessionMu.RUnlock()

	sessions := make([]*AgentSession, 0)
	for _, session := range m.agentSessions {
		if session.AgentID == agentID && session.Active {
			sessions = append(sessions, session)
		}
	}
	return sessions
}

// RefreshSession extends a session's expiration time
func (m *Manager) RefreshSession(sessionID string) error {
	m.agentSessionMu.Lock()
	defer m.agentSessionMu.Unlock()

	session, exists := m.agentSessions[sessionID]
	if !exists {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	if !session.Active {
		return errors.New("session is not active")
	}

	session.Refresh(m.config.SessionDuration)

	m.logger.Debug("session refreshed",
		"session_id", truncateID(sessionID),
		"new_expiry", session.ExpiresAt,
	)

	return nil
}

// InvalidateSession marks a session as inactive
func (m *Manager) InvalidateSession(sessionID string) error {
	m.agentSessionMu.Lock()
	defer m.agentSessionMu.Unlock()

	session, exists := m.agentSessions[sessionID]
	if !exists {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	session.Active = false

	m.logger.Info("session invalidated",
		"session_id", truncateID(sessionID),
	)

	return nil
}

// InvalidateAgentSessions invalidates all sessions for an agent
func (m *Manager) InvalidateAgentSessions(agentID string) error {
	m.agentSessionMu.Lock()
	defer m.agentSessionMu.Unlock()

	count := 0
	for sessionID, session := range m.agentSessions {
		if session.AgentID == agentID && session.Active {
			session.Active = false
			delete(m.agentSessions, sessionID)
			count++
		}
	}

	m.logger.Info("agent sessions invalidated",
		"agent_id", truncateID(agentID),
		"count", count,
	)

	return nil
}

// ============================================================================
// AUTHORIZATION CHECKS
// ============================================================================

// AuthorizeToolCall checks if an agent can execute a tool in a session context
func (m *Manager) AuthorizeToolCall(ctx context.Context, sessionID, toolName string) (*AuthorizationResult, error) {
	// Get session
	session, err := m.GetSession(sessionID)
	if err != nil {
		return &AuthorizationResult{
			Allowed: false,
			Reason:  "Invalid or expired session",
			Error:   err.Error(),
		}, nil
	}

	// Get agent
	agent := session.Agent
	if agent == nil {
		m.agentMu.RLock()
		agent, err = m.GetAgent(session.AgentID)
		m.agentMu.RUnlock()
		if err != nil {
			return &AuthorizationResult{
				Allowed: false,
				Reason:  "Agent not found",
				Error:   err.Error(),
			}, nil
		}
	}

	// Check if agent is enabled
	if !agent.Enabled {
		return &AuthorizationResult{
			Allowed: false,
			Reason:  "Agent is disabled",
		}, nil
	}

	// Check tool permission
	canExecute := agent.CanExecuteTool(toolName)
	if !canExecute {
		return &AuthorizationResult{
			Allowed:      false,
			Reason:       fmt.Sprintf("Agent role '%s' does not have permission for tool '%s'", agent.Role, toolName),
			AgentRole:    agent.Role,
			ToolName:     toolName,
			RequiredRole: getMinimumRoleForTool(toolName),
		}, nil
	}

	// Check if tool requires approval (high-risk tools)
	requiresApproval := toolRequiresApproval(toolName)
	if requiresApproval && m.config.RequireApproval {
		// Check if agent has privileged+ role
		if !agent.Role.AtLeast(AgentRolePrivileged) {
			return &AuthorizationResult{
				Allowed:          false,
				Reason:           "Tool requires privileged role or approval",
				RequiresApproval: true,
				AgentRole:        agent.Role,
				ToolName:         toolName,
			}, nil
		}
	}

	// Update session activity
	session.SetLastActivity(time.Now())

	return &AuthorizationResult{
		Allowed:   true,
		Reason:    "Authorized by RBAC",
		AgentRole: agent.Role,
		ToolName:  toolName,
	}, nil
}

// AuthorizeAgent checks if an agent has a specific permission
func (m *Manager) AuthorizeAgent(ctx context.Context, agentID string, permission ToolPermission) (*AuthorizationResult, error) {
	agent, err := m.GetAgent(agentID)
	if err != nil {
		return &AuthorizationResult{
			Allowed: false,
			Reason:  "Agent not found",
			Error:   err.Error(),
		}, nil
	}

	if !agent.Enabled {
		return &AuthorizationResult{
			Allowed: false,
			Reason:  "Agent is disabled",
		}, nil
	}

	hasPerm := agent.HasToolPermission(permission)

	return &AuthorizationResult{
		Allowed:   hasPerm,
		Reason:    map[bool]string{true: "Permission granted", false: "Permission denied"}[hasPerm],
		AgentRole: agent.Role,
	}, nil
}

// ============================================================================
// CLEANUP
// ============================================================================

// cleanupLoop periodically cleans up expired sessions
func (m *Manager) cleanupLoop() {
	ticker := time.NewTicker(m.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCleanup:
			return
		case <-ticker.C:
			m.cleanup()
		}
	}
}

// cleanup removes expired sessions
func (m *Manager) cleanup() {
	m.cleanupMu.Lock()
	defer m.cleanupMu.Unlock()

	m.agentSessionMu.Lock()
	now := time.Now()
	expiredCount := 0
	for sessionID, session := range m.agentSessions {
		if now.After(session.ExpiresAt) || !session.Active {
			delete(m.agentSessions, sessionID)
			expiredCount++
		}
	}
	m.agentSessionMu.Unlock()

	if expiredCount > 0 {
		m.logger.Debug("cleanup completed", "expired_sessions", expiredCount)
	}
}

// ============================================================================
// HELPERS
// ============================================================================

// AuthorizationResult represents an authorization decision
type AuthorizationResult struct {
	Allowed          bool
	Reason           string
	Error            string
	AgentRole        AgentRole
	ToolName         string
	RequiredRole     AgentRole
	RequiresApproval bool
}

// AgentUpdates represents updates to an agent
type AgentUpdates struct {
	Name        string
	Description string
	Role        AgentRole
	Tools       []ToolPermission
	Tags        map[string]string
	Enabled     bool
}

// SessionOption configures a session
type SessionOption func(*AgentSession)

// WithSessionTags sets tags on a session
func WithSessionTags(tags map[string]string) SessionOption {
	return func(s *AgentSession) {
		for k, v := range tags {
			s.Tags[k] = v
		}
	}
}

// WithSessionIP sets the IP address on a session
func WithSessionIP(ip string) SessionOption {
	return func(s *AgentSession) {
		s.IPAddress = ip
	}
}

// WithSessionContextHash sets a context hash on a session
func WithSessionContextHash(hash string) SessionOption {
	return func(s *AgentSession) {
		s.ContextHash = hash
	}
}

// generateID generates a unique ID
func generateID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// truncateID truncates an ID for logging
func truncateID(id string) string {
	if len(id) > 8 {
		return id[:8] + "..."
	}
	return id
}

// toolRequiresApproval checks if a tool requires privileged role
func toolRequiresApproval(toolName string) bool {
	highRiskTools := map[string]bool{
		"shell_command":  true,
		"bash":           true,
		"code_execute":   true,
		"database_query": true,
	}
	return highRiskTools[toolName]
}

// getMinimumRoleForTool returns the minimum role required for a tool
func getMinimumRoleForTool(toolName string) AgentRole {
	switch toolName {
	case "shell_command", "bash":
		return AgentRolePrivileged
	case "code_execute_go", "code_execute_python", "code_execute_javascript":
		return AgentRolePrivileged
	case "database_query":
		return AgentRolePrivileged
	case "file_write", "file_delete":
		return AgentRoleStandard
	default:
		return AgentRoleRestricted
	}
}
