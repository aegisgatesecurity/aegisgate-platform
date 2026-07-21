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

// Manager handles RBAC operations for agents and users.
// When a PostgresRBACStore is provided via NewWithPostgres, agent registrations
// and sessions are persisted to PostgreSQL for multi-instance deployment.
// Otherwise, the Manager falls back to in-memory maps (Community/Developer tiers).
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

	// PostgreSQL backend (nil for in-memory mode)
	pgStore     *PostgresRBACStore
	usePostgres bool
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

// NewWithPostgres creates a Manager that persists agent registrations and
// sessions to PostgreSQL. If pgStore is nil, falls back to in-memory mode
// (same as NewManager). This is for Professional/Enterprise tiers with
// FeaturePostgreSQL enabled.
func NewWithPostgres(config *Config, pgStore *PostgresRBACStore) (*Manager, error) {
	if pgStore == nil {
		// No PostgreSQL available; fall back to in-memory
		return NewManager(config)
	}

	if config == nil {
		config = DefaultConfig()
	}

	m, err := NewManager(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create base manager: %w", err)
	}

	m.pgStore = pgStore
	m.usePostgres = true

	m.logger.Info("RBAC manager initialized with PostgreSQL backend")

	return m, nil
}

// UsesPostgres returns whether PostgreSQL storage is active.
func (m *Manager) UsesPostgres() bool {
	m.agentMu.RLock()
	defer m.agentMu.RUnlock()
	return m.usePostgres
}

// PostgresStore returns the underlying PostgresRBACStore.
// Returns nil if using in-memory storage.
func (m *Manager) PostgresStore() *PostgresRBACStore {
	m.agentMu.RLock()
	defer m.agentMu.RUnlock()
	return m.pgStore
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

	// Close PostgreSQL backend if present. G104 suppressed:
	// Close() at manager teardown is best-effort.
	if m.pgStore != nil {
		_ = m.pgStore.Close()
	}

	m.logger.Info("RBAC manager shut down")
}

// ============================================================================
// AGENT MANAGEMENT
// ============================================================================

// RegisterAgent registers a new agent with the specified role.
// If PostgreSQL is active, the agent is persisted to the database.
func (m *Manager) RegisterAgent(agent *Agent, tenantCtx ...RBACTenantContext) error {
	// Extract tenant context
	tenantID := ""
	if len(tenantCtx) > 0 {
		tenantID = tenantCtx[0].TenantID
	}

	// Set tenant ID on agent if not already set
	if tenantID != "" && agent.TenantID == "" {
		agent.TenantID = tenantID
	}

	// PostgreSQL path: persist to database, then cache in-memory
	if m.usePostgres {
		ctx := context.Background()
		if err := m.pgStore.RegisterAgent(ctx, agent, tenantCtx...); err != nil {
			return fmt.Errorf("postgres register agent: %w", err)
		}
		// Also cache in-memory for fast reads
		m.agentMu.Lock()
		m.agents[agent.ID] = agent
		m.agentMu.Unlock()
		return nil
	}

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
		"tenant_id", tenantID,
	)

	return nil
}

// GetAgent retrieves an agent by ID.
// If PostgreSQL is active, reads from the database (with in-memory cache fallback).
func (m *Manager) GetAgent(agentID string, tenantCtx ...RBACTenantContext) (*Agent, error) {
	// Extract tenant context
	var tenantID string
	isAdmin := false
	if len(tenantCtx) > 0 {
		tenantID = tenantCtx[0].TenantID
		isAdmin = tenantCtx[0].IsAdmin
	}

	// PostgreSQL path: read from database
	if m.usePostgres {
		ctx := context.Background()
		agent, err := m.pgStore.GetAgent(ctx, agentID, tenantCtx...)
		if err != nil {
			return nil, fmt.Errorf("postgres get agent: %w", err)
		}
		if agent == nil {
			return nil, fmt.Errorf("agent not found: %s", agentID)
		}
		return agent, nil
	}

	m.agentMu.RLock()
	defer m.agentMu.RUnlock()

	agent, exists := m.agents[agentID]
	if !exists {
		return nil, fmt.Errorf("agent not found: %s", agentID)
	}

	// In-memory tenant filter
	if !isAdmin && tenantID != "" && agent.TenantID != "" && agent.TenantID != tenantID {
		return nil, fmt.Errorf("agent not found or access denied: %s", agentID)
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
// UnregisterAgent removes an agent.
// If PostgreSQL is active, deletes from database and invalidates its sessions.
func (m *Manager) UnregisterAgent(agentID string) error {
	// PostgreSQL path: delete from database (cascades to sessions)
	if m.usePostgres {
		ctx := context.Background()
		if err := m.pgStore.UnregisterAgent(ctx, agentID); err != nil {
			return fmt.Errorf("postgres unregister agent: %w", err)
		}
		// Also remove from in-memory cache
		m.agentMu.Lock()
		delete(m.agents, agentID)
		m.agentMu.Unlock()
		// Invalidate in-memory sessions
		m.agentSessionMu.Lock()
		for sessionID, session := range m.agentSessions {
			if session.AgentID == agentID {
				session.Active = false
				delete(m.agentSessions, sessionID)
			}
		}
		m.agentSessionMu.Unlock()
		m.logger.Info("agent unregistered (postgres)", "agent_id", truncateID(agentID))
		return nil
	}

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
// CreateSession creates a new session for an agent.
// If PostgreSQL is active, the session is persisted to the database.
func (m *Manager) CreateSession(ctx context.Context, agentID string, opts ...SessionOption) (*AgentSession, error) {
	// Get agent (from PostgreSQL or in-memory)
	var agent *Agent
	var err error
	if m.usePostgres {
		agent, err = m.pgStore.GetAgent(ctx, agentID)
		if err != nil {
			return nil, fmt.Errorf("postgres get agent for session: %w", err)
		}
		if agent == nil {
			return nil, fmt.Errorf("agent not found: %s", agentID)
		}
	} else {
		m.agentMu.RLock()
		var exists bool
		agent, exists = m.agents[agentID]
		m.agentMu.RUnlock()
		if !exists {
			return nil, fmt.Errorf("agent not found: %s", agentID)
		}
	}

	if !agent.Enabled {
		return nil, errors.New("agent is disabled")
	}

	// Count existing sessions for this agent
	var sessionCount int
	if m.usePostgres {
		count, err := m.pgStore.CountActiveSessions(ctx, agentID)
		if err != nil {
			return nil, fmt.Errorf("postgres count sessions: %w", err)
		}
		sessionCount = count
	} else {
		m.agentSessionMu.RLock()
		for _, s := range m.agentSessions {
			if s.AgentID == agentID && s.Active {
				sessionCount++
			}
		}
		m.agentSessionMu.RUnlock()
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

	// PostgreSQL path: persist session
	if m.usePostgres {
		if err := m.pgStore.CreateAgentSession(ctx, session); err != nil {
			return nil, fmt.Errorf("postgres create session: %w", err)
		}
	} else {
		m.agentSessionMu.Lock()
		m.agentSessions[sessionID] = session
		m.agentSessionMu.Unlock()
	}

	m.logger.Info("session created",
		"session_id", truncateID(sessionID),
		"agent_id", truncateID(agentID),
		"role", agent.Role,
		"postgres", m.usePostgres,
	)

	return session, nil
}

// GetSession retrieves a session by ID
// GetSession retrieves a session by ID.
// If PostgreSQL is active, reads from the database.
func (m *Manager) GetSession(sessionID string) (*AgentSession, error) {
	// PostgreSQL path: read from database
	if m.usePostgres {
		ctx := context.Background()
		session, err := m.pgStore.GetAgentSession(ctx, sessionID)
		if err != nil {
			return nil, fmt.Errorf("postgres get session: %w", err)
		}
		if session == nil {
			return nil, fmt.Errorf("session not found: %s", sessionID)
		}
		// Populate the Agent reference from PostgreSQL
		agent, err := m.pgStore.GetAgent(ctx, session.AgentID)
		if err != nil {
			return nil, fmt.Errorf("postgres get agent for session: %w", err)
		}
		if agent != nil {
			session.Agent = agent
		}
		if !session.IsValid() {
			return nil, errors.New("session expired or invalid")
		}
		return session, nil
	}

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
// InvalidateSession marks a session as inactive.
// If PostgreSQL is active, invalidates in the database.
func (m *Manager) InvalidateSession(sessionID string) error {
	// PostgreSQL path
	if m.usePostgres {
		ctx := context.Background()
		if err := m.pgStore.InvalidateAgentSession(ctx, sessionID); err != nil {
			return fmt.Errorf("postgres invalidate session: %w", err)
		}
		// Also remove from in-memory cache
		m.agentSessionMu.Lock()
		delete(m.agentSessions, sessionID)
		m.agentSessionMu.Unlock()
		m.logger.Info("session invalidated (postgres)", "session_id", truncateID(sessionID))
		return nil
	}

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

// InvalidateAgentSessions invalidates all sessions for an agent.
// If PostgreSQL is active, invalidates in the database.
func (m *Manager) InvalidateAgentSessions(agentID string) error {
	// PostgreSQL path
	if m.usePostgres {
		ctx := context.Background()
		count, err := m.pgStore.InvalidateAgentSessions(ctx, agentID)
		if err != nil {
			return fmt.Errorf("postgres invalidate agent sessions: %w", err)
		}
		// Also remove from in-memory cache
		m.agentSessionMu.Lock()
		for sessionID, session := range m.agentSessions {
			if session.AgentID == agentID && session.Active {
				session.Active = false
				delete(m.agentSessions, sessionID)
			}
		}
		m.agentSessionMu.Unlock()
		m.logger.Info("agent sessions invalidated (postgres)", "agent_id", truncateID(agentID), "count", count)
		return nil
	}

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

	// PostgreSQL path: prune expired sessions in the database
	if m.usePostgres && m.pgStore != nil {
		ctx := context.Background()
		count, err := m.pgStore.PruneExpiredSessions(ctx)
		if err != nil {
			m.logger.Error("postgres session prune error", "error", err)
		} else if count > 0 {
			m.logger.Debug("postgres session cleanup completed", "expired_sessions", count)
		}
		// Also prune license cache if available
		// (license cache pruning is handled by the persistence Manager)
		return
	}

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

// PruneExpiredSessions prunes expired sessions from PostgreSQL.
// Called by the persistence Manager's background goroutine.
// Returns 0 and nil if not using PostgreSQL.
func (m *Manager) PruneExpiredSessions(ctx context.Context) (int, error) {
	if !m.usePostgres || m.pgStore == nil {
		return 0, nil
	}
	return m.pgStore.PruneExpiredSessions(ctx)
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
