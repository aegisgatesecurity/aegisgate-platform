// Package contextisolator - Session isolation for AI agents
// Prevents context bleed between agent sessions and tasks
package contextisolator

import (
	"context"
	"sync"
	"time"
)

// SessionManager manages isolated agent sessions
type SessionManager struct {
	sessions    map[string]*Session
	mu          sync.RWMutex
	maxSessions int
	ttl         time.Duration
}

// Session represents an isolated agent session
type Session struct {
	ID          string
	AgentID     string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	MemoryLimit int64
	Isolated    bool
	Tags        map[string]string
	Metadata    map[string]interface{}
}

// NewSessionManager creates a new session manager
func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions:    make(map[string]*Session),
		maxSessions: 1000,
		ttl:         24 * time.Hour,
	}
}

// CreateSession creates a new isolated session
func (sm *SessionManager) CreateSession(ctx context.Context, agentID string) (*Session, error) {
	session := &Session{
		ID:          generateSessionID(),
		AgentID:     agentID,
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(sm.ttl),
		MemoryLimit: 100 * 1024 * 1024, // 100MB default
		Isolated:    true,
		Tags:        make(map[string]string),
		Metadata:    make(map[string]interface{}),
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Check max sessions
	if len(sm.sessions) >= sm.maxSessions {
		// Clean expired sessions
		sm.cleanExpired()
		if len(sm.sessions) >= sm.maxSessions {
			return nil, ErrMaxSessionsReached
		}
	}

	sm.sessions[session.ID] = session
	return session, nil
}

// GetSession retrieves a session by ID
func (sm *SessionManager) GetSession(ctx context.Context, sessionID string) (*Session, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	session, ok := sm.sessions[sessionID]
	if !ok {
		return nil, ErrSessionNotFound
	}

	if time.Now().After(session.ExpiresAt) {
		return nil, ErrSessionExpired
	}

	return session, nil
}

// DeleteSession removes a session
func (sm *SessionManager) DeleteSession(ctx context.Context, sessionID string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if _, ok := sm.sessions[sessionID]; !ok {
		return ErrSessionNotFound
	}

	delete(sm.sessions, sessionID)
	return nil
}

// cleanExpired removes expired sessions
func (sm *SessionManager) cleanExpired() {
	now := time.Now()
	for id, session := range sm.sessions {
		if now.After(session.ExpiresAt) {
			delete(sm.sessions, id)
		}
	}
}

// SetMemoryLimit sets the memory limit for a session
func (sm *SessionManager) SetMemoryLimit(sessionID string, limit int64) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	session, ok := sm.sessions[sessionID]
	if !ok {
		return ErrSessionNotFound
	}

	session.MemoryLimit = limit
	return nil
}

// GetActiveSessions returns all active sessions
func (sm *SessionManager) GetActiveSessions() []*Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	sessions := make([]*Session, 0, len(sm.sessions))
	now := time.Now()

	for _, session := range sm.sessions {
		if now.Before(session.ExpiresAt) {
			sessions = append(sessions, session)
		}
	}

	return sessions
}

// generateSessionID creates a unique session ID
func generateSessionID() string {
	return time.Now().Format("20060102150405.000000000")
}

// Errors
var (
	ErrMaxSessionsReached = &SessionError{"maximum sessions reached"}
	ErrSessionNotFound    = &SessionError{"session not found"}
	ErrSessionExpired     = &SessionError{"session expired"}
)

// SessionError represents a session-related error
type SessionError struct {
	message string
}

func (e *SessionError) Error() string {
	return e.message
}
