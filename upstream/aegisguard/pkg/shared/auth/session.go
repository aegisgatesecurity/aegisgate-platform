// SPDX-License-Identifier: Apache-2.0
// =========================================================================

// =========================================================================

package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"time"
)

// generateSessionID generates a unique session ID
func generateSessionID() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return ""
	}
	return hex.EncodeToString(bytes)
}

// CreateSession creates a new authenticated session
func (m *Manager) CreateSession(agent *Agent, r *http.Request) (*Session, error) {
	sessionID := generateSessionID()

	session := &Session{
		ID:           sessionID,
		AgentID:      agent.ID,
		Agent:        agent,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(m.config.SessionDuration),
		LastActivity: time.Now(),
		IPAddress:    r.RemoteAddr,
		UserAgent:    r.UserAgent(),
		Active:       true,
		Tags:         make(map[string]string),
	}

	agent.SessionID = sessionID

	m.sessionsMu.Lock()
	defer m.sessionsMu.Unlock()

	if len(m.sessions) >= m.config.MaxSessions {
		return nil, errors.New("maximum sessions reached")
	}

	m.sessions[sessionID] = session

	slog.Info("Session created",
		"session_id", sessionID[:8]+"...",
		"agent_id", agent.ID,
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

// GetSessionFromRequest extracts session from HTTP request
func (m *Manager) GetSessionFromRequest(r *http.Request) (*Session, error) {
	// Try header first (API key auth)
	if agentID := r.Header.Get("X-Agent-ID"); agentID != "" {
		if sessionID := r.Header.Get("X-Session-ID"); sessionID != "" {
			return m.GetSession(sessionID)
		}
	}

	// Try cookie
	cookie, err := r.Cookie(m.config.CookieName)
	if err != nil {
		return nil, errors.New("no session")
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

	slog.Info("Session invalidated", "session_id", sessionID[:8]+"...")

	return nil
}

// Logout handles agent logout
func (m *Manager) Logout(w http.ResponseWriter, r *http.Request) error {
	session, err := m.GetSessionFromRequest(r)
	if err != nil {
		return err
	}

	if err := m.InvalidateSession(session.ID); err != nil {
		return err
	}

	m.clearSessionCookie(w)

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

// GetAgentSessions returns all sessions for an agent
func (m *Manager) GetAgentSessions(agentID string) []*Session {
	m.sessionsMu.RLock()
	defer m.sessionsMu.RUnlock()

	sessions := make([]*Session, 0)
	for _, session := range m.sessions {
		if session.AgentID == agentID && session.IsValid() {
			sessions = append(sessions, session)
		}
	}

	return sessions
}

// InvalidateAgentSessions invalidates all sessions for an agent
func (m *Manager) InvalidateAgentSessions(agentID string) {
	m.sessionsMu.Lock()
	defer m.sessionsMu.Unlock()

	count := 0
	for _, session := range m.sessions {
		if session.AgentID == agentID {
			session.Active = false
			count++
		}
	}

	if count > 0 {
		slog.Info("Invalidated agent sessions", "agent_id", agentID, "count", count)
	}
}

// ValidateAPIKey validates an API key and returns the associated agent ID
func (m *Manager) ValidateAPIKey(apiKey string) (string, error) {
	m.agentsMu.RLock()
	defer m.agentsMu.RUnlock()

	agentID, exists := m.config.APIKeys[apiKey]
	if !exists {
		return "", errors.New("invalid API key")
	}

	return agentID, nil
}

// RegisterAPIKey registers an API key for an agent
func (m *Manager) RegisterAPIKey(agentID, apiKey string) error {
	m.agentsMu.Lock()
	defer m.agentsMu.Unlock()

	if _, exists := m.agents[agentID]; !exists {
		return errors.New("agent not found")
	}

	m.config.APIKeys[apiKey] = agentID
	return nil
}

// clearSessionCookie clears the session cookie
func (m *Manager) clearSessionCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     m.config.CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: m.config.CookieHTTPOnly,
		Secure:   m.config.CookieSecure,
		SameSite: m.config.CookieSameSite,
	}
	http.SetCookie(w, cookie)
}

// SetSessionCookie sets the session cookie
func (m *Manager) SetSessionCookie(w http.ResponseWriter, session *Session) {
	cookie := &http.Cookie{
		Name:     m.config.CookieName,
		Value:    session.ID,
		Path:     "/",
		MaxAge:   int(m.config.SessionDuration.Seconds()),
		HttpOnly: m.config.CookieHTTPOnly,
		Secure:   m.config.CookieSecure,
		SameSite: m.config.CookieSameSite,
	}
	http.SetCookie(w, cookie)
}
