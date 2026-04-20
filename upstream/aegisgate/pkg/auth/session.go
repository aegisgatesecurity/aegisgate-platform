// SPDX-License-Identifier: MIT
// =========================================================================
// =========================================================================
//
// =========================================================================

package auth

import (
	"errors"
	"log/slog"
	"net/http"
	"time"
)

// CreateSession creates a new authenticated session
func (m *Manager) CreateSession(user *User, r *http.Request) (*Session, error) {
	sessionID := generateSessionID()

	session := &Session{
		ID:           sessionID,
		UserID:       user.ID,
		User:         user,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(m.config.SessionDuration),
		LastActivity: time.Now(),
		IPAddress:    r.RemoteAddr,
		UserAgent:    r.UserAgent(),
		Active:       true,
	}

	user.SessionID = sessionID

	m.sessionsMu.Lock()
	defer m.sessionsMu.Unlock()

	if len(m.sessions) >= m.config.MaxSessions {
		return nil, errors.New("maximum sessions reached")
	}

	m.sessions[sessionID] = session

	slog.Info("Session created",
		"session_id", sessionID[:8]+"...",
		"user_id", user.ID[:8]+"...",
		"email", user.Email,
	)

	return session, nil
}

// GetSession retrieves a session by ID
func (m *Manager) GetSession(sessionID string) (*Session, error) {
	m.sessionsMu.RLock()
	defer m.sessionsMu.RUnlock()

	session, exists := m.sessions[sessionID]
	if !exists {
		return nil, errors.New("session not found")
	}

	if !session.IsValid() {
		return nil, errors.New("session expired")
	}

	return session, nil
}

// GetSessionFromRequest extracts session from HTTP request cookie
func (m *Manager) GetSessionFromRequest(r *http.Request) (*Session, error) {
	cookie, err := r.Cookie(m.config.CookieName)
	if err != nil {
		return nil, errors.New("no session cookie")
	}

	return m.GetSession(cookie.Value)
}

// RefreshSession extends session expiration
func (m *Manager) RefreshSession(sessionID string) error {
	m.sessionsMu.Lock()
	defer m.sessionsMu.Unlock()

	session, exists := m.sessions[sessionID]
	if !exists {
		return errors.New("session not found")
	}

	if !session.IsValid() {
		return errors.New("session expired")
	}

	session.Refresh(m.config.SessionDuration)

	slog.Debug("Session refreshed",
		"session_id", sessionID[:8]+"...",
		"new_expiry", session.ExpiresAt,
	)

	return nil
}

// InvalidateSession marks a session as inactive
func (m *Manager) InvalidateSession(sessionID string) error {
	m.sessionsMu.Lock()
	defer m.sessionsMu.Unlock()

	session, exists := m.sessions[sessionID]
	if !exists {
		return errors.New("session not found")
	}

	session.Active = false

	slog.Info("Session invalidated",
		"session_id", sessionID[:8]+"...",
		"user_id", session.UserID[:8]+"...",
	)

	return nil
}

// Logout handles user logout
func (m *Manager) Logout(w http.ResponseWriter, r *http.Request) error {
	session, err := m.GetSessionFromRequest(r)
	if err != nil {
		return err
	}

	if err := m.InvalidateSession(session.ID); err != nil {
		return err
	}

	m.clearSessionCookie(w)

	slog.Info("User logged out",
		"session_id", session.ID[:8]+"...",
		"user_id", session.UserID[:8]+"...",
	)

	return nil
}

// GetActiveSessions returns all active sessions
func (m *Manager) GetActiveSessions() []*Session {
	m.sessionsMu.RLock()
	defer m.sessionsMu.RUnlock()

	active := make([]*Session, 0)
	for _, session := range m.sessions {
		if session.IsValid() {
			active = append(active, session)
		}
	}

	return active
}

// GetUserSessions returns all sessions for a user
func (m *Manager) GetUserSessions(userID string) []*Session {
	m.sessionsMu.RLock()
	defer m.sessionsMu.RUnlock()

	sessions := make([]*Session, 0)
	for _, session := range m.sessions {
		if session.UserID == userID && session.IsValid() {
			sessions = append(sessions, session)
		}
	}

	return sessions
}

// InvalidateUserSessions invalidates all sessions for a user
func (m *Manager) InvalidateUserSessions(userID string) {
	m.sessionsMu.Lock()
	defer m.sessionsMu.Unlock()

	count := 0
	for _, session := range m.sessions {
		if session.UserID == userID {
			session.Active = false
			count++
		}
	}

	if count > 0 {
		slog.Info("Invalidated user sessions",
			"user_id", userID[:8]+"...",
			"count", count,
		)
	}
}
