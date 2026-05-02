// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// SSO Stores Package (Stub)
// =========================================================================
// This package provides stub implementations for SSO session/token storage.
// Full implementation pending dependency injection architecture decisions.

package stores

import (
	"context"
	"time"
)

// ============================================================================
// Session Store Interface
// ============================================================================

// Session represents an authenticated user session
type Session struct {
	ID        string
	UserID    string
	CreatedAt time.Time
	ExpiresAt time.Time
	Metadata  map[string]interface{}
}

// SessionStore defines the interface for session storage operations
type SessionStore interface {
	// Create creates a new session and returns it
	Create(ctx context.Context, session *Session) error

	// Get retrieves a session by ID
	Get(ctx context.Context, sessionID string) (*Session, error)

	// Delete removes a session by ID
	Delete(ctx context.Context, sessionID string) error

	// DeleteUserSessions removes all sessions for a user
	DeleteUserSessions(ctx context.Context, userID string) error

	// List returns all active sessions (with optional pagination)
	List(ctx context.Context, userID string, limit, offset int) ([]*Session, error)

	// Cleanup removes expired sessions
	Cleanup(ctx context.Context) (int, error)
}

// ============================================================================
// Token Store Interface
// ============================================================================

// Token represents an OAuth/OIDC token
type Token struct {
	ID           string
	UserID       string
	Scope        string
	AccessToken  string
	RefreshToken string
	IssuedAt     time.Time
	ExpiresAt    time.Time
	Metadata     map[string]interface{}
}

// TokenStore defines the interface for token storage operations
type TokenStore interface {
	// Store saves a new token
	Store(ctx context.Context, token *Token) error

	// Get retrieves a token by ID
	Get(ctx context.Context, tokenID string) (*Token, error)

	// GetByRefreshToken retrieves a token by refresh token
	GetByRefreshToken(ctx context.Context, refreshToken string) (*Token, error)

	// Delete removes a token by ID
	Delete(ctx context.Context, tokenID string) error

	// DeleteUserTokens removes all tokens for a user
	DeleteUserTokens(ctx context.Context, userID string) error

	// Cleanup removes expired tokens
	Cleanup(ctx context.Context) (int, error)
}

// ============================================================================
// In-Memory Stub Implementations (for testing/development)
// ============================================================================

// InMemorySessionStore provides a simple in-memory session store
type InMemorySessionStore struct {
	sessions map[string]*Session
}

// NewInMemorySessionStore creates a new in-memory session store
func NewInMemorySessionStore() *InMemorySessionStore {
	return &InMemorySessionStore{
		sessions: make(map[string]*Session),
	}
}

func (s *InMemorySessionStore) Create(ctx context.Context, session *Session) error {
	s.sessions[session.ID] = session
	return nil
}

func (s *InMemorySessionStore) Get(ctx context.Context, sessionID string) (*Session, error) {
	session, ok := s.sessions[sessionID]
	if !ok {
		return nil, nil
	}
	if time.Now().After(session.ExpiresAt) {
		delete(s.sessions, sessionID)
		return nil, nil
	}
	return session, nil
}

func (s *InMemorySessionStore) Delete(ctx context.Context, sessionID string) error {
	delete(s.sessions, sessionID)
	return nil
}

func (s *InMemorySessionStore) DeleteUserSessions(ctx context.Context, userID string) error {
	for id, session := range s.sessions {
		if session.UserID == userID {
			delete(s.sessions, id)
		}
	}
	return nil
}

func (s *InMemorySessionStore) List(ctx context.Context, userID string, limit, offset int) ([]*Session, error) {
	var result []*Session
	for _, session := range s.sessions {
		if session.UserID == userID && time.Now().Before(session.ExpiresAt) {
			result = append(result, session)
		}
	}
	if offset >= len(result) {
		return []*Session{}, nil
	}
	end := offset + limit
	if end > len(result) {
		end = len(result)
	}
	return result[offset:end], nil
}

func (s *InMemorySessionStore) Cleanup(ctx context.Context) (int, error) {
	count := 0
	now := time.Now()
	for id, session := range s.sessions {
		if now.After(session.ExpiresAt) {
			delete(s.sessions, id)
			count++
		}
	}
	return count, nil
}

// InMemoryTokenStore provides a simple in-memory token store
type InMemoryTokenStore struct {
	tokens       map[string]*Token
	refreshIndex map[string]string // refreshToken -> tokenID
}

// NewInMemoryTokenStore creates a new in-memory token store
func NewInMemoryTokenStore() *InMemoryTokenStore {
	return &InMemoryTokenStore{
		tokens:       make(map[string]*Token),
		refreshIndex: make(map[string]string),
	}
}

func (s *InMemoryTokenStore) Store(ctx context.Context, token *Token) error {
	s.tokens[token.ID] = token
	if token.RefreshToken != "" {
		s.refreshIndex[token.RefreshToken] = token.ID
	}
	return nil
}

func (s *InMemoryTokenStore) Get(ctx context.Context, tokenID string) (*Token, error) {
	token, ok := s.tokens[tokenID]
	if !ok {
		return nil, nil
	}
	if time.Now().After(token.ExpiresAt) {
		delete(s.tokens, tokenID)
		return nil, nil
	}
	return token, nil
}

func (s *InMemoryTokenStore) GetByRefreshToken(ctx context.Context, refreshToken string) (*Token, error) {
	tokenID, ok := s.refreshIndex[refreshToken]
	if !ok {
		return nil, nil
	}
	return s.Get(ctx, tokenID)
}

func (s *InMemoryTokenStore) Delete(ctx context.Context, tokenID string) error {
	token, ok := s.tokens[tokenID]
	if ok && token.RefreshToken != "" {
		delete(s.refreshIndex, token.RefreshToken)
	}
	delete(s.tokens, tokenID)
	return nil
}

func (s *InMemoryTokenStore) DeleteUserTokens(ctx context.Context, userID string) error {
	for id, token := range s.tokens {
		if token.UserID == userID {
			if token.RefreshToken != "" {
				delete(s.refreshIndex, token.RefreshToken)
			}
			delete(s.tokens, id)
		}
	}
	return nil
}

func (s *InMemoryTokenStore) Cleanup(ctx context.Context) (int, error) {
	count := 0
	now := time.Now()
	for id, token := range s.tokens {
		if now.After(token.ExpiresAt) {
			if token.RefreshToken != "" {
				delete(s.refreshIndex, token.RefreshToken)
			}
			delete(s.tokens, id)
			count++
		}
	}
	return count, nil
}
