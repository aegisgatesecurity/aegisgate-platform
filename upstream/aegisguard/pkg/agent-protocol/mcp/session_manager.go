// SPDX-License-Identifier: MIT
// =========================================================================
// AegisGuard Security
// Copyright (c) 2025-2026 AegisGuard Security. All rights reserved.
// =========================================================================
//
// MCP Session Manager - Integrates MCP connections with RBAC sessions
// =========================================================================

package mcp

import (
	"context"
	"sync"
	"time"

	"github.com/aegisguardsecurity/aegisguard/pkg/rbac"
)

// ConnectionSessionManager handles MCP connection-to-session binding
type ConnectionSessionManager struct {
	manager *rbac.Manager
	conns   map[string]*MCPSession
	mu      sync.RWMutex
}

// MCPSession represents a session bound to an MCP connection
type MCPSession struct {
	ConnectionID string
	RBACSession  *rbac.AgentSession
	Agent        *rbac.Agent
	CreatedAt    time.Time
	LastActivity time.Time
}

// NewConnectionSessionManager creates a new MCP session manager
func NewConnectionSessionManager(rbacManager *rbac.Manager) *ConnectionSessionManager {
	return &ConnectionSessionManager{
		manager: rbacManager,
		conns:   make(map[string]*MCPSession),
	}
}

// CreateSession creates a new RBAC session bound to an MCP connection
func (sm *ConnectionSessionManager) CreateSession(ctx context.Context, connID, agentID string) (*MCPSession, error) {
	// Create RBAC session
	session, err := sm.manager.CreateSession(ctx, agentID)
	if err != nil {
		return nil, err
	}

	// Get agent info
	agent, err := sm.manager.GetAgent(agentID)
	if err != nil {
		// Cleanup the RBAC session
		sm.manager.InvalidateSession(session.ID)
		return nil, err
	}

	mcpSession := &MCPSession{
		ConnectionID: connID,
		RBACSession:  session,
		Agent:        agent,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
	}

	sm.mu.Lock()
	sm.conns[connID] = mcpSession
	sm.mu.Unlock()

	return mcpSession, nil
}

// GetSession retrieves a session by connection ID
func (sm *ConnectionSessionManager) GetSession(connID string) (*MCPSession, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	session, ok := sm.conns[connID]
	if !ok {
		return nil, ErrSessionNotFound
	}

	// Check if RBAC session is still valid
	if !session.RBACSession.IsValid() {
		return nil, ErrSessionExpired
	}

	return session, nil
}

// GetOrCreateSession gets existing session or creates new one
func (sm *ConnectionSessionManager) GetOrCreateSession(ctx context.Context, connID, agentID string) (*MCPSession, error) {
	// Try to get existing
	if session, err := sm.GetSession(connID); err == nil {
		return session, nil
	}

	// Create new
	return sm.CreateSession(ctx, connID, agentID)
}

// BindAgent binds an MCP connection to an agent (creates session)
func (sm *ConnectionSessionManager) BindAgent(ctx context.Context, connID, agentID string) (*MCPSession, error) {
	// Check if already bound
	sm.mu.RLock()
	if existing, ok := sm.conns[connID]; ok {
		if existing.Agent.ID == agentID {
			sm.mu.RUnlock()
			return existing, nil
		}
		// Different agent, invalidate old
		sm.mu.RUnlock()
		sm.CloseConnection(connID)
	} else {
		sm.mu.RUnlock()
	}

	return sm.CreateSession(ctx, connID, agentID)
}

// UpdateActivity updates last activity timestamp
func (sm *ConnectionSessionManager) UpdateActivity(connID string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if session, ok := sm.conns[connID]; ok {
		session.LastActivity = time.Now()
	}
}

// RefreshSession extends the RBAC session TTL
func (sm *ConnectionSessionManager) RefreshSession(connID string) error {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	session, ok := sm.conns[connID]
	if !ok {
		return ErrSessionNotFound
	}

	return sm.manager.RefreshSession(session.RBACSession.ID)
}

// CloseConnection closes and cleans up a connection
func (sm *ConnectionSessionManager) CloseConnection(connID string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if session, ok := sm.conns[connID]; ok {
		// Invalidate RBAC session
		sm.manager.InvalidateSession(session.RBACSession.ID)
		delete(sm.conns, connID)
	}
}

// CloseAll closes all connections
func (sm *ConnectionSessionManager) CloseAll() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	for connID := range sm.conns {
		sm.CloseConnection(connID)
	}
}

// ListConnections returns all active connections
func (sm *ConnectionSessionManager) ListConnections() []*MCPSession {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	sessions := make([]*MCPSession, 0, len(sm.conns))
	for _, s := range sm.conns {
		sessions = append(sessions, s)
	}
	return sessions
}

// Count returns the number of active connections
func (sm *ConnectionSessionManager) Count() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.conns)
}

// GetAgentForConnection returns the agent for a connection
func (sm *ConnectionSessionManager) GetAgentForConnection(connID string) (*rbac.Agent, error) {
	session, err := sm.GetSession(connID)
	if err != nil {
		return nil, err
	}
	return session.Agent, nil
}

// GetSessionIDForConnection returns the RBAC session ID for a connection
func (sm *ConnectionSessionManager) GetSessionIDForConnection(connID string) (string, error) {
	session, err := sm.GetSession(connID)
	if err != nil {
		return "", err
	}
	return session.RBACSession.ID, nil
}

// Errors
var (
	ErrSessionNotFound = &MCPSessionError{"session not found for connection"}
	ErrSessionExpired  = &MCPSessionError{"session expired"}
)

// MCPSessionError represents a session-related error
type MCPSessionError struct {
	message string
}

func (e *MCPSessionError) Error() string {
	return e.message
}

// =============================================================================
// RBACSessionManager - Implements SessionManager interface for RequestHandler
// =============================================================================

// RBACSessionManager wraps RBAC Manager to implement MCP SessionManager interface
type RBACSessionManager struct {
	manager *rbac.Manager
}

// NewRBACSessionManager creates a new RBAC session manager
func NewRBACSessionManager(manager *rbac.Manager) *RBACSessionManager {
	return &RBACSessionManager{manager: manager}
}

// CreateSession creates a new RBAC session
func (sm *RBACSessionManager) CreateSession(ctx context.Context, agentID string) (*Session, error) {
	session, err := sm.manager.CreateSession(ctx, agentID)
	if err != nil {
		return nil, err
	}
	return &Session{ID: session.ID, AgentID: agentID}, nil
}

// GetSession retrieves a session by ID
func (sm *RBACSessionManager) GetSession(ctx context.Context, sessionID string) (*Session, error) {
	session, err := sm.manager.GetSession(sessionID)
	if err != nil {
		return nil, err
	}
	return &Session{ID: session.ID, AgentID: session.AgentID}, nil
}

// DeleteSession removes a session
func (sm *RBACSessionManager) DeleteSession(ctx context.Context, sessionID string) error {
	return sm.manager.InvalidateSession(sessionID)
}
