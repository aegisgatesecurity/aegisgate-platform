// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — PostgreSQL-Backed SSO Session Store (v3.5.0+ D1 Phase 1E)
// =========================================================================
//
// postgres_session_store.go implements SessionStore backed by PostgreSQL,
// persisting SSO sessions across restarts and enabling multi-instance
// deployment where any instance can validate a session.
//
// Architecture:
//
//   - Shares the pgxpool.Pool from ioc.PostgresStore (single pool per process)
//   - Satisfies the SessionStore interface from types.go (no context param)
//   - Uses context.Background() internally for all database operations
//   - JSONB columns store flexible fields (user, flags, metadata)
//   - INSERT ON CONFLICT for Create/Update upsert semantics
//   - Automatic schema migration on first connection (migrate method)
//   - Falls back gracefully when PostgreSQL is not available (nil store)
//
// Tier gating: FeaturePostgreSQL is required. Community and Developer tiers
// continue using the in-memory MemorySessionStore.
//
// v3.5.0+ D1 Phase 1E.
// =========================================================================

package sso

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
)

// PostgresSessionStore persists SSO sessions to PostgreSQL.
// It shares the connection pool from an existing ioc.PostgresStore instance.
type PostgresSessionStore struct {
	pool   *pgxpool.Pool
	mgr    *ioc.PostgresStore // owns the pool lifecycle
	closed bool
	mu     sync.RWMutex // protects closed flag
}

// NewPostgresSessionStore creates a PostgreSQL-backed session store.
// If pgStore is nil, returns nil (caller should fall back to in-memory).
func NewPostgresSessionStore(pgStore *ioc.PostgresStore) (*PostgresSessionStore, error) {
	if pgStore == nil {
		return nil, fmt.Errorf("postgres store is nil, cannot create SSO session store")
	}

	store := &PostgresSessionStore{
		pool: pgStore.Pool(),
		mgr:  pgStore,
	}

	ctx := context.Background()
	if err := store.migrate(ctx); err != nil {
		return nil, fmt.Errorf("sso session store migration: %w", err)
	}

	return store, nil
}

// ============================================================================
// SCHEMA MIGRATION
// ============================================================================

// migrate creates the SSO sessions table if it does not exist.
// Uses CREATE IF NOT EXISTS for idempotency.
func (s *PostgresSessionStore) migrate(ctx context.Context) error {
	const schema = `
-- SSO sessions table: persists SSO authentication sessions.
-- One row per active session. Expired sessions are pruned by Cleanup().
CREATE TABLE IF NOT EXISTS sso_sessions (
    id              TEXT        NOT NULL PRIMARY KEY,
    user_id         TEXT        NOT NULL DEFAULT '',
    session_id      TEXT        NOT NULL DEFAULT '',
    provider        TEXT        NOT NULL DEFAULT '',
    provider_name   TEXT        NOT NULL DEFAULT '',
    initial_idp     TEXT        NOT NULL DEFAULT '',
    name_id         TEXT        NOT NULL DEFAULT '',
    session_index   TEXT        NOT NULL DEFAULT '',
    ip_address      TEXT        NOT NULL DEFAULT '',
    user_agent      TEXT        NOT NULL DEFAULT '',
    access_token    TEXT        NOT NULL DEFAULT '',
    refresh_token   TEXT        NOT NULL DEFAULT '',
    id_token        TEXT        NOT NULL DEFAULT '',
    active          BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL,
    last_activity   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_refreshed  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    token_expires_at TIMESTAMPTZ NOT NULL DEFAULT '1970-01-01 00:00:00Z',
    user_data      JSONB       NOT NULL DEFAULT '{}',
    flags          JSONB       NOT NULL DEFAULT '{}',
    metadata       JSONB       NOT NULL DEFAULT '{}'
);

-- Index: sessions for a specific user, sorted by expiry
CREATE INDEX IF NOT EXISTS idx_sso_sessions_user
    ON sso_sessions (user_id, expires_at DESC);

-- Index: active sessions for quick lookup
CREATE INDEX IF NOT EXISTS idx_sso_sessions_active
    ON sso_sessions (active, expires_at) WHERE active = TRUE;

-- Index: expired sessions for cleanup
CREATE INDEX IF NOT EXISTS idx_sso_sessions_expiry
    ON sso_sessions (expires_at) WHERE active = TRUE;

-- SSO requests table: persists SSO authentication request state.
-- Used for CSRF/state validation during the OIDC/SAML callback flow.
CREATE TABLE IF NOT EXISTS sso_requests (
    id              TEXT        NOT NULL PRIMARY KEY,
    provider        TEXT        NOT NULL DEFAULT '',
    saml_request    TEXT        NOT NULL DEFAULT '',
    relay_state     TEXT        NOT NULL DEFAULT '',
    destination     TEXT        NOT NULL DEFAULT '',
    protocol_binding TEXT       NOT NULL DEFAULT '',
    state           TEXT        NOT NULL DEFAULT '',
    code_verifier   TEXT        NOT NULL DEFAULT '',
    nonce           TEXT        NOT NULL DEFAULT '',
    redirect_url    TEXT        NOT NULL DEFAULT '',
    ip_address     TEXT        NOT NULL DEFAULT '',
    user_agent     TEXT        NOT NULL DEFAULT '',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at     TIMESTAMPTZ NOT NULL
);

-- Index: request lookup by state (CSRF validation)
CREATE INDEX IF NOT EXISTS idx_sso_requests_state
    ON sso_requests (state);

-- Index: expired requests for cleanup
CREATE INDEX IF NOT EXISTS idx_sso_requests_expiry
    ON sso_requests (expires_at);

-- Record in the shared schema migrations table.
INSERT INTO ioc_schema_migrations (version, description, applied_at)
VALUES (
    8,
    'sso_sessions and sso_requests tables for SSO session persistence',
    NOW()
) ON CONFLICT (version) DO NOTHING;
`

	if _, err := s.pool.Exec(ctx, schema); err != nil {
		return fmt.Errorf("create sso schema: %w", err)
	}

	log.Println("PostgreSQL SSO session store: schema migration complete")
	return nil
}

// ============================================================================
// SessionStore INTERFACE IMPLEMENTATION
// ============================================================================

// Create persists a new SSO session to PostgreSQL.
// If a session with the same ID exists, it is replaced (upsert).
func (s *PostgresSessionStore) Create(session *SSOSession) error {
	if s.isClosed() {
		return fmt.Errorf("postgres sso session store is closed")
	}
	if session == nil {
		return fmt.Errorf("session is nil")
	}

	ctx := context.Background()

	userJSON, err := json.Marshal(session.User) //nosec G117 -- AccessToken is a SSO token field name, not a leaked secret
	if err != nil {
		userJSON = []byte("null")
	}
	flagsJSON, err := json.Marshal(session.Flags)
	if err != nil {
		flagsJSON = []byte("{}")
	}
	metadataJSON, err := json.Marshal(session.Metadata)
	if err != nil {
		metadataJSON = []byte("{}")
	}

	const sql = `
		INSERT INTO sso_sessions (
			id, user_id, session_id, provider, provider_name,
			initial_idp, name_id, session_index,
			ip_address, user_agent,
			access_token, refresh_token, id_token,
			active, created_at, expires_at,
			last_activity, last_refreshed, token_expires_at,
			user_data, flags, metadata
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8,
			$9, $10,
			$11, $12, $13,
			$14, $15, $16,
			$17, $18, $19,
			$20, $21, $22
		) ON CONFLICT (id) DO UPDATE SET
			user_id = EXCLUDED.user_id,
			session_id = EXCLUDED.session_id,
			provider = EXCLUDED.provider,
			provider_name = EXCLUDED.provider_name,
			initial_idp = EXCLUDED.initial_idp,
			name_id = EXCLUDED.name_id,
			session_index = EXCLUDED.session_index,
			ip_address = EXCLUDED.ip_address,
			user_agent = EXCLUDED.user_agent,
			access_token = EXCLUDED.access_token,
			refresh_token = EXCLUDED.refresh_token,
			id_token = EXCLUDED.id_token,
			active = EXCLUDED.active,
			created_at = EXCLUDED.created_at,
			expires_at = EXCLUDED.expires_at,
			last_activity = EXCLUDED.last_activity,
			last_refreshed = EXCLUDED.last_refreshed,
			token_expires_at = EXCLUDED.token_expires_at,
			user_data = EXCLUDED.user_data,
			flags = EXCLUDED.flags,
			metadata = EXCLUDED.metadata
	`

	_, err = s.pool.Exec(ctx, sql,
		session.ID, session.UserID, session.SessionID,
		string(session.Provider), session.ProviderName,
		session.InitialIDP, session.NameID, session.SessionIndex,
		session.IPAddress, session.UserAgent,
		session.AccessToken, session.RefreshToken, session.IDToken,
		session.Active, session.CreatedAt, session.ExpiresAt,
		session.LastActivity, session.LastRefreshed, session.TokenExpiresAt,
		userJSON, flagsJSON, metadataJSON,
	)
	if err != nil {
		return fmt.Errorf("postgres create sso session: %w", err)
	}

	return nil
}

// Get retrieves an SSO session by ID from PostgreSQL.
// Returns nil (not an error) if the session is not found.
func (s *PostgresSessionStore) Get(id string) (*SSOSession, error) {
	if s.isClosed() {
		return nil, fmt.Errorf("postgres sso session store is closed")
	}

	ctx := context.Background()

	session, err := scanSession(s.pool.QueryRow(ctx, `
		SELECT id, user_id, session_id, provider, provider_name,
		       initial_idp, name_id, session_index,
		       ip_address, user_agent,
		       access_token, refresh_token, id_token,
		       active, created_at, expires_at,
		       last_activity, last_refreshed, token_expires_at,
		       user_data, flags, metadata
		FROM sso_sessions WHERE id = $1
	`, id))
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("postgres get sso session: %w", err)
	}

	return session, nil
}

// Update modifies an existing SSO session in PostgreSQL.
func (s *PostgresSessionStore) Update(session *SSOSession) error {
	if s.isClosed() {
		return fmt.Errorf("postgres sso session store is closed")
	}
	if session == nil {
		return fmt.Errorf("session is nil")
	}

	ctx := context.Background()

	userJSON, err := json.Marshal(session.User) //nosec G117 -- AccessToken is a SSO token field name, not a leaked secret
	if err != nil {
		userJSON = []byte("null")
	}
	flagsJSON, err := json.Marshal(session.Flags)
	if err != nil {
		flagsJSON = []byte("{}")
	}
	metadataJSON, err := json.Marshal(session.Metadata)
	if err != nil {
		metadataJSON = []byte("{}")
	}

	tag, err := s.pool.Exec(ctx, `
		UPDATE sso_sessions SET
			user_id = $2, session_id = $3, provider = $4, provider_name = $5,
			initial_idp = $6, name_id = $7, session_index = $8,
			ip_address = $9, user_agent = $10,
			access_token = $11, refresh_token = $12, id_token = $13,
			active = $14, expires_at = $15,
			last_activity = $16, last_refreshed = $17, token_expires_at = $18,
			user_data = $19, flags = $20, metadata = $21
		WHERE id = $1
	`,
		session.ID, session.UserID, session.SessionID,
		string(session.Provider), session.ProviderName,
		session.InitialIDP, session.NameID, session.SessionIndex,
		session.IPAddress, session.UserAgent,
		session.AccessToken, session.RefreshToken, session.IDToken,
		session.Active, session.ExpiresAt,
		session.LastActivity, session.LastRefreshed, session.TokenExpiresAt,
		userJSON, flagsJSON, metadataJSON,
	)
	if err != nil {
		return fmt.Errorf("postgres update sso session: %w", err)
	}

	if tag.RowsAffected() == 0 {
		return fmt.Errorf("session not found: %s", session.ID)
	}

	return nil
}

// Delete removes an SSO session by ID from PostgreSQL.
func (s *PostgresSessionStore) Delete(id string) error {
	if s.isClosed() {
		return fmt.Errorf("postgres sso session store is closed")
	}

	ctx := context.Background()

	_, err := s.pool.Exec(ctx, `DELETE FROM sso_sessions WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("postgres delete sso session: %w", err)
	}

	return nil
}

// GetByUserID returns all active sessions for a given user from PostgreSQL.
func (s *PostgresSessionStore) GetByUserID(userID string) ([]*SSOSession, error) {
	if s.isClosed() {
		return nil, fmt.Errorf("postgres sso session store is closed")
	}

	ctx := context.Background()

	rows, err := s.pool.Query(ctx, `
		SELECT id, user_id, session_id, provider, provider_name,
		       initial_idp, name_id, session_index,
		       ip_address, user_agent,
		       access_token, refresh_token, id_token,
		       active, created_at, expires_at,
		       last_activity, last_refreshed, token_expires_at,
		       user_data, flags, metadata
		FROM sso_sessions
		WHERE user_id = $1 AND active = TRUE AND expires_at > NOW()
		ORDER BY last_activity DESC
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("postgres get sso sessions by user: %w", err)
	}
	defer rows.Close()

	var sessions []*SSOSession
	for rows.Next() {
		session, err := scanSessionRow(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres scan sso session: %w", err)
		}
		sessions = append(sessions, session)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres iterate sso sessions: %w", err)
	}

	return sessions, nil
}

// DeleteByUserID removes all sessions for a given user from PostgreSQL.
func (s *PostgresSessionStore) DeleteByUserID(userID string) error {
	if s.isClosed() {
		return fmt.Errorf("postgres sso session store is closed")
	}

	ctx := context.Background()

	tag, err := s.pool.Exec(ctx, `DELETE FROM sso_sessions WHERE user_id = $1`, userID)
	if err != nil {
		return fmt.Errorf("postgres delete sso sessions by user: %w", err)
	}

	count := tag.RowsAffected()
	if count > 0 {
		log.Printf("PostgreSQL SSO: deleted %d sessions for user %s", count, userID)
	}

	return nil
}

// Cleanup removes expired sessions from PostgreSQL.
// Returns the number of sessions removed.
func (s *PostgresSessionStore) Cleanup() error {
	if s.isClosed() {
		return fmt.Errorf("postgres sso session store is closed")
	}

	ctx := context.Background()

	tag, err := s.pool.Exec(ctx, `DELETE FROM sso_sessions WHERE expires_at < NOW() OR active = FALSE`)
	if err != nil {
		return fmt.Errorf("postgres cleanup sso sessions: %w", err)
	}

	count := tag.RowsAffected()
	if count > 0 {
		log.Printf("PostgreSQL SSO: cleaned up %d expired sessions", count)
	}

	// Also clean up expired SSO requests
	reqTag, err := s.pool.Exec(ctx, `DELETE FROM sso_requests WHERE expires_at < NOW()`)
	if err != nil {
		log.Printf("PostgreSQL SSO: failed to clean up expired requests: %v", err)
	} else if reqTag.RowsAffected() > 0 {
		log.Printf("PostgreSQL SSO: cleaned up %d expired requests", reqTag.RowsAffected())
	}

	return nil
}

// Close marks the store as closed. Does NOT close the pool (PostgresStore owns it).
func (s *PostgresSessionStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	log.Println("PostgreSQL SSO session store closed (pool remains open for IOC store)")
	return nil
}

// isClosed returns whether the store has been closed.
func (s *PostgresSessionStore) isClosed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.closed
}

// ============================================================================
// RequestStore INTERFACE IMPLEMENTATION (PostgreSQL-backed)
// ============================================================================

// PostgresRequestStore persists SSO authentication requests to PostgreSQL.
// It shares the connection pool from an existing ioc.PostgresStore instance.
type PostgresRequestStore struct {
	pool   *pgxpool.Pool
	mgr    *ioc.PostgresStore
	closed bool
	mu     sync.RWMutex
}

// NewPostgresRequestStore creates a PostgreSQL-backed request store.
// If pgStore is nil, returns nil (caller should fall back to in-memory).
func NewPostgresRequestStore(pgStore *ioc.PostgresStore) (*PostgresRequestStore, error) {
	if pgStore == nil {
		return nil, fmt.Errorf("postgres store is nil, cannot create SSO request store")
	}

	return &PostgresRequestStore{
		pool: pgStore.Pool(),
		mgr:  pgStore,
	}, nil
}

// Create persists a new SSO request to PostgreSQL.
func (s *PostgresRequestStore) Create(request *SSORequest) error {
	if s.isClosed() {
		return fmt.Errorf("postgres sso request store is closed")
	}
	if request == nil {
		return fmt.Errorf("request is nil")
	}

	ctx := context.Background()

	_, err := s.pool.Exec(ctx, `
		INSERT INTO sso_requests (
			id, provider, saml_request, relay_state, destination,
			protocol_binding, state, code_verifier, nonce,
			redirect_url, ip_address, user_agent,
			created_at, expires_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9,
			$10, $11, $12,
			$13, $14
		) ON CONFLICT (id) DO UPDATE SET
			provider = EXCLUDED.provider,
			saml_request = EXCLUDED.saml_request,
			relay_state = EXCLUDED.relay_state,
			destination = EXCLUDED.destination,
			protocol_binding = EXCLUDED.protocol_binding,
			state = EXCLUDED.state,
			code_verifier = EXCLUDED.code_verifier,
			nonce = EXCLUDED.nonce,
			redirect_url = EXCLUDED.redirect_url,
			ip_address = EXCLUDED.ip_address,
			user_agent = EXCLUDED.user_agent,
			expires_at = EXCLUDED.expires_at
	`, request.ID, request.Provider, request.SAMLRequest, request.RelayState,
		request.Destination, request.ProtocolBinding, request.State,
		request.CodeVerifier, request.Nonce, request.RedirectURL,
		request.IPAddress, request.UserAgent,
		request.CreatedAt, request.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("postgres create sso request: %w", err)
	}

	return nil
}

// Get retrieves an SSO request by ID from PostgreSQL.
func (s *PostgresRequestStore) Get(id string) (*SSORequest, error) {
	if s.isClosed() {
		return nil, fmt.Errorf("postgres sso request store is closed")
	}

	ctx := context.Background()

	var req SSORequest
	err := s.pool.QueryRow(ctx, `
		SELECT id, provider, saml_request, relay_state, destination,
		       protocol_binding, state, code_verifier, nonce,
		       redirect_url, ip_address, user_agent,
		       created_at, expires_at
		FROM sso_requests WHERE id = $1
	`, id).Scan(
		&req.ID, &req.Provider, &req.SAMLRequest, &req.RelayState,
		&req.Destination, &req.ProtocolBinding, &req.State,
		&req.CodeVerifier, &req.Nonce, &req.RedirectURL,
		&req.IPAddress, &req.UserAgent,
		&req.CreatedAt, &req.ExpiresAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("postgres get sso request: %w", err)
	}

	return &req, nil
}

// GetByState retrieves an SSO request by state parameter from PostgreSQL.
func (s *PostgresRequestStore) GetByState(state string) (*SSORequest, error) {
	if s.isClosed() {
		return nil, fmt.Errorf("postgres sso request store is closed")
	}

	ctx := context.Background()

	var req SSORequest
	err := s.pool.QueryRow(ctx, `
		SELECT id, provider, saml_request, relay_state, destination,
		       protocol_binding, state, code_verifier, nonce,
		       redirect_url, ip_address, user_agent,
		       created_at, expires_at
		FROM sso_requests WHERE state = $1
	`, state).Scan(
		&req.ID, &req.Provider, &req.SAMLRequest, &req.RelayState,
		&req.Destination, &req.ProtocolBinding, &req.State,
		&req.CodeVerifier, &req.Nonce, &req.RedirectURL,
		&req.IPAddress, &req.UserAgent,
		&req.CreatedAt, &req.ExpiresAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("postgres get sso request by state: %w", err)
	}

	return &req, nil
}

// Delete removes an SSO request by ID from PostgreSQL.
func (s *PostgresRequestStore) Delete(id string) error {
	if s.isClosed() {
		return fmt.Errorf("postgres sso request store is closed")
	}

	ctx := context.Background()

	_, err := s.pool.Exec(ctx, `DELETE FROM sso_requests WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("postgres delete sso request: %w", err)
	}

	return nil
}

// CloseRequestStore marks the request store as closed.
func (s *PostgresRequestStore) CloseRequestStore() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	log.Println("PostgreSQL SSO request store closed (pool remains open for IOC store)")
	return nil
}

func (s *PostgresRequestStore) isClosed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.closed
}

// ============================================================================
// SCAN HELPERS
// ============================================================================

// scanSession scans a single SSO session from a query row.
func scanSession(row pgx.Row) (*SSOSession, error) {
	var s SSOSession
	var provider string
	var userJSON, flagsJSON, metadataJSON []byte

	err := row.Scan(
		&s.ID, &s.UserID, &s.SessionID, &provider, &s.ProviderName,
		&s.InitialIDP, &s.NameID, &s.SessionIndex,
		&s.IPAddress, &s.UserAgent,
		&s.AccessToken, &s.RefreshToken, &s.IDToken,
		&s.Active, &s.CreatedAt, &s.ExpiresAt,
		&s.LastActivity, &s.LastRefreshed, &s.TokenExpiresAt,
		&userJSON, &flagsJSON, &metadataJSON,
	)
	if err != nil {
		return nil, err
	}

	s.Provider = SSOProvider(provider)

	// Deserialize JSONB columns
	if err := json.Unmarshal(userJSON, &s.User); err != nil {
		// User may be null for orphaned sessions
		s.User = nil
	}
	if s.Flags == nil {
		s.Flags = make(map[string]bool)
	}
	if err := json.Unmarshal(flagsJSON, &s.Flags); err != nil {
		s.Flags = make(map[string]bool)
	}
	if s.Metadata == nil {
		s.Metadata = make(map[string]interface{})
	}
	if err := json.Unmarshal(metadataJSON, &s.Metadata); err != nil {
		s.Metadata = make(map[string]interface{})
	}

	return &s, nil
}

// scanSessionRow scans a single SSO session from query rows.
func scanSessionRow(rows pgx.Rows) (*SSOSession, error) {
	var s SSOSession
	var provider string
	var userJSON, flagsJSON, metadataJSON []byte

	err := rows.Scan(
		&s.ID, &s.UserID, &s.SessionID, &provider, &s.ProviderName,
		&s.InitialIDP, &s.NameID, &s.SessionIndex,
		&s.IPAddress, &s.UserAgent,
		&s.AccessToken, &s.RefreshToken, &s.IDToken,
		&s.Active, &s.CreatedAt, &s.ExpiresAt,
		&s.LastActivity, &s.LastRefreshed, &s.TokenExpiresAt,
		&userJSON, &flagsJSON, &metadataJSON,
	)
	if err != nil {
		return nil, err
	}

	s.Provider = SSOProvider(provider)

	if err := json.Unmarshal(userJSON, &s.User); err != nil {
		s.User = nil
	}
	if s.Flags == nil {
		s.Flags = make(map[string]bool)
	}
	if err := json.Unmarshal(flagsJSON, &s.Flags); err != nil {
		s.Flags = make(map[string]bool)
	}
	if s.Metadata == nil {
		s.Metadata = make(map[string]interface{})
	}
	if err := json.Unmarshal(metadataJSON, &s.Metadata); err != nil {
		s.Metadata = make(map[string]interface{})
	}

	return &s, nil
}

// StatsPostgres returns session statistics from the PostgreSQL store.
// This is an alternative to the in-memory Stats() method that counts
// sessions via SQL instead of the in-memory map.
func (s *PostgresSessionStore) StatsPostgres() (activeCount int, totalCount int, err error) {
	if s.isClosed() {
		return 0, 0, fmt.Errorf("postgres sso session store is closed")
	}

	ctx := context.Background()

	err = s.pool.QueryRow(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE active = TRUE AND expires_at > NOW()),
			COUNT(*)
		FROM sso_sessions
	`).Scan(&activeCount, &totalCount)
	if err != nil {
		return 0, 0, fmt.Errorf("postgres sso session stats: %w", err)
	}

	return activeCount, totalCount, nil
}
