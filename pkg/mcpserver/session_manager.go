// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform

// =========================================================================
//
// MCP Session Manager - Integrates MCP connections with RBAC sessions
// =========================================================================

package mcpserver

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/rbac"
)

// Session manager errors
var (
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionExpired  = errors.New("session expired")
	ErrAgentNotFound   = errors.New("agent not found")
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
		return nil, ErrAgentNotFound
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
		// Update last activity
		sm.mu.Lock()
		session.LastActivity = time.Now()
		sm.mu.Unlock()
		return session, nil
	}

	// Create new
	return sm.CreateSession(ctx, connID, agentID)
}

// UpdateActivity updates the last activity timestamp for a session
func (sm *ConnectionSessionManager) UpdateActivity(connID string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	session, ok := sm.conns[connID]
	if !ok {
		return ErrSessionNotFound
	}

	session.LastActivity = time.Now()
	return nil
}

// CloseSession closes and cleans up a session
func (sm *ConnectionSessionManager) CloseSession(connID string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	session, ok := sm.conns[connID]
	if !ok {
		return ErrSessionNotFound
	}

	// Invalidate RBAC session
	sm.manager.InvalidateSession(session.RBACSession.ID)

	// Remove from map
	delete(sm.conns, connID)

	return nil
}

// ListSessions returns all active sessions
func (sm *ConnectionSessionManager) ListSessions() []*MCPSession {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	sessions := make([]*MCPSession, 0, len(sm.conns))
	for _, session := range sm.conns {
		if session.RBACSession.IsValid() {
			sessions = append(sessions, session)
		}
	}

	return sessions
}

// CountSessions returns the number of active sessions
func (sm *ConnectionSessionManager) CountSessions() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	count := 0
	for _, session := range sm.conns {
		if session.RBACSession.IsValid() {
			count++
		}
	}

	return count
}

// CleanupExpired removes expired sessions
func (sm *ConnectionSessionManager) CleanupExpired() int {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	count := 0
	for connID, session := range sm.conns {
		if !session.RBACSession.IsValid() {
			delete(sm.conns, connID)
			count++
		}
	}

	return count
}

// GetSessionStats returns session statistics
func (sm *ConnectionSessionManager) GetSessionStats() SessionStats {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	stats := SessionStats{
		TotalSessions:   len(sm.conns),
		ActiveSessions:  0,
		ExpiredSessions: 0,
	}

	for _, session := range sm.conns {
		if session.RBACSession.IsValid() {
			stats.ActiveSessions++
		} else {
			stats.ExpiredSessions++
		}
	}

	return stats
}

// SessionStats holds session statistics
type SessionStats struct {
	TotalSessions   int
	ActiveSessions  int
	ExpiredSessions int
}

// StartCleanupRoutine starts a background goroutine to clean up expired sessions
func (sm *ConnectionSessionManager) StartCleanupRoutine(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				sm.CleanupExpired()
			}
		}
	}()
}
