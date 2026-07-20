// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — PostgreSQL-Backed RBAC Store (v3.5.0+ D1 Phase 1C)
// =========================================================================
//
// postgres_store.go implements a PostgreSQL-backed RBAC store that persists
// agent registrations and sessions across restarts. It enables multi-instance
// deployment where any instance can validate an agent or session.
//
// Architecture:
//
//   - Shares the pgxpool.Pool from ioc.PostgresStore (single pool per process)
//   - Falls back to the in-memory Manager when PostgreSQL is not available
//   - Agent CRUD operations use INSERT ON CONFLICT for upsert semantics
//   - Sessions use PostgreSQL's expires_at for automatic cleanup
//   - JSONB columns store flexible fields (tools, tags, metadata, permissions)
//
// Tier gating: FeaturePostgreSQL is required. Community and Developer tiers
// continue using the in-memory Manager.
//
// v3.5.0+ D1 Phase 1C.
// =========================================================================

package rbac

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
)

// PostgresRBACStore persists agent registrations and sessions to PostgreSQL.
// It shares the connection pool from an existing ioc.PostgresStore instance.
type PostgresRBACStore struct {
	pool   *pgxpool.Pool
	mgr    *ioc.PostgresStore // owns the pool lifecycle
	cfg    *Config
	closed bool
}

// RBACTenantContext holds the tenant context for RBAC operations.
// When TenantID is empty, operations are tenant-agnostic (admin mode).
type RBACTenantContext struct {
	TenantID string
	IsAdmin  bool // If true, can access all tenants' data
}

// NewPostgresRBACStore creates a PostgreSQL-backed RBAC store.
// If pgStore is nil, returns nil (caller should fall back to in-memory).
func NewPostgresRBACStore(pgStore *ioc.PostgresStore, cfg *Config) (*PostgresRBACStore, error) {
	if pgStore == nil {
		return nil, fmt.Errorf("postgres store is nil, cannot create RBAC store")
	}
	if cfg == nil {
		cfg = DefaultConfig()
	}

	return &PostgresRBACStore{
		pool: pgStore.Pool(),
		mgr:  pgStore,
		cfg:  cfg,
	}, nil
}

// ============================================================================
// AGENT MANAGEMENT
// ============================================================================

// RegisterAgent inserts or updates an agent in PostgreSQL.
func (s *PostgresRBACStore) RegisterAgent(ctx context.Context, agent *Agent, tenantCtx ...RBACTenantContext) error {
	if s.closed {
		return fmt.Errorf("postgres RBAC store is closed")
	}
	if agent == nil {
		return fmt.Errorf("agent is nil")
	}

	// Extract tenant context (optional)
	tenantID := ""
	if len(tenantCtx) > 0 {
		tenantID = tenantCtx[0].TenantID
	}

	toolsJSON, err := json.Marshal(agent.Tools)
	if err != nil {
		toolsJSON = []byte("[]")
	}
	tagsJSON, err := json.Marshal(agent.Tags)
	if err != nil {
		tagsJSON = []byte("{}")
	}
	metadataJSON, err := json.Marshal(agent.Metadata)
	if err != nil {
		metadataJSON = []byte("{}")
	}

	now := time.Now().UTC()
	createdAt := agent.CreatedAt
	if createdAt.IsZero() {
		createdAt = now
	}
	updatedAt := agent.UpdatedAt
	if updatedAt.IsZero() {
		updatedAt = now
	}

	const sql = `
		INSERT INTO rbac_agents (id, name, description, role, tools, tags, metadata, enabled, tenant_id, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (id) DO UPDATE SET
			name = EXCLUDED.name,
			description = EXCLUDED.description,
			role = EXCLUDED.role,
			tools = EXCLUDED.tools,
			tags = EXCLUDED.tags,
			metadata = EXCLUDED.metadata,
			enabled = EXCLUDED.enabled,
			tenant_id = EXCLUDED.tenant_id,
			updated_at = EXCLUDED.updated_at`

	_, err = s.pool.Exec(ctx, sql,
		agent.ID, agent.Name, agent.Description, string(agent.Role),
		toolsJSON, tagsJSON, metadataJSON, agent.Enabled, tenantID,
		createdAt, updatedAt,
	)
	if err != nil {
		return fmt.Errorf("postgres register agent: %w", err)
	}

	return nil
}

// GetAgent retrieves an agent by ID from PostgreSQL.
// If tenantCtx is provided and IsAdmin is false, verifies tenant ownership.
func (s *PostgresRBACStore) GetAgent(ctx context.Context, agentID string, tenantCtx ...RBACTenantContext) (*Agent, error) {
	if s.closed {
		return nil, fmt.Errorf("postgres RBAC store is closed")
	}

	// Extract tenant context
	var tenantID string
	isAdmin := false
	if len(tenantCtx) > 0 {
		tenantID = tenantCtx[0].TenantID
		isAdmin = tenantCtx[0].IsAdmin
	}

	query := `
		SELECT id, name, description, role, tools, tags, metadata, enabled, tenant_id, created_at, updated_at
		FROM rbac_agents WHERE id = $1`
	args := []interface{}{agentID}
	argIdx := 2

	// Add tenant filter unless admin mode
	if !isAdmin && tenantID != "" {
		query += fmt.Sprintf(" AND tenant_id = $%d", argIdx)
		args = append(args, tenantID)
	}

	agent, err := scanAgent(s.pool.QueryRow(ctx, query, args...))
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("postgres get agent: %w", err)
	}
	return agent, nil
}

// UpdateAgent updates an existing agent's mutable fields.
func (s *PostgresRBACStore) UpdateAgent(ctx context.Context, agentID string, updates *AgentUpdates) error {
	if s.closed {
		return fmt.Errorf("postgres RBAC store is closed")
	}
	if updates == nil {
		return nil
	}

	// Build dynamic SET clause
	setClauses := []string{}
	args := []interface{}{}
	argIdx := 1

	if updates.Name != "" {
		setClauses = append(setClauses, fmt.Sprintf("name = $%d", argIdx))
		args = append(args, updates.Name)
		argIdx++
	}
	if updates.Description != "" {
		setClauses = append(setClauses, fmt.Sprintf("description = $%d", argIdx))
		args = append(args, updates.Description)
		argIdx++
	}
	if updates.Role != "" {
		setClauses = append(setClauses, fmt.Sprintf("role = $%d", argIdx))
		args = append(args, string(updates.Role))
		argIdx++
	}
	if len(updates.Tools) > 0 {
		toolsJSON, _ := json.Marshal(updates.Tools)
		setClauses = append(setClauses, fmt.Sprintf("tools = $%d", argIdx))
		args = append(args, toolsJSON)
		argIdx++
	}
	if updates.Tags != nil {
		tagsJSON, _ := json.Marshal(updates.Tags)
		setClauses = append(setClauses, fmt.Sprintf("tags = $%d", argIdx))
		args = append(args, tagsJSON)
		argIdx++
	}

	setClauses = append(setClauses, fmt.Sprintf("updated_at = $%d", argIdx))
	args = append(args, time.Now().UTC())
	argIdx++

	args = append(args, agentID) // WHERE id = $N

	sql := fmt.Sprintf(
		`UPDATE rbac_agents SET %s WHERE id = $%d`,
		joinRBACStrings(setClauses, ", "),
		argIdx,
	)

	tag, err := s.pool.Exec(ctx, sql, args...)
	if err != nil {
		return fmt.Errorf("postgres update agent: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("agent not found: %s", agentID)
	}
	return nil
}

// UnregisterAgent deletes an agent and cascades to its sessions.
func (s *PostgresRBACStore) UnregisterAgent(ctx context.Context, agentID string) error {
	if s.closed {
		return fmt.Errorf("postgres RBAC store is closed")
	}

	const sql = `DELETE FROM rbac_agents WHERE id = $1`
	tag, err := s.pool.Exec(ctx, sql, agentID)
	if err != nil {
		return fmt.Errorf("postgres unregister agent: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("agent not found: %s", agentID)
	}
	return nil
}

// ListAgents returns all registered agents.
// If tenantCtx is provided and IsAdmin is false, returns only tenant's agents.
func (s *PostgresRBACStore) ListAgents(ctx context.Context, tenantCtx ...RBACTenantContext) ([]*Agent, error) {
	if s.closed {
		return nil, fmt.Errorf("postgres RBAC store is closed")
	}

	// Extract tenant context
	var tenantID string
	isAdmin := false
	if len(tenantCtx) > 0 {
		tenantID = tenantCtx[0].TenantID
		isAdmin = tenantCtx[0].IsAdmin
	}

	query := `
		SELECT id, name, description, role, tools, tags, metadata, enabled, tenant_id, created_at, updated_at
		FROM rbac_agents`
	args := []interface{}{}

	// Add tenant filter unless admin mode
	if !isAdmin && tenantID != "" {
		query += " WHERE tenant_id = $1"
		args = append(args, tenantID)
	}

	query += " ORDER BY created_at ASC"

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres list agents: %w", err)
	}
	defer rows.Close()

	var agents []*Agent
	for rows.Next() {
		agent, err := scanAgentFromRows(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres scan agent: %w", err)
		}
		agents = append(agents, agent)
	}
	return agents, rows.Err()
}

// ============================================================================
// AGENT SESSION MANAGEMENT
// ============================================================================

// CreateAgentSession inserts a new agent session.
func (s *PostgresRBACStore) CreateAgentSession(ctx context.Context, session *AgentSession, tenantCtx ...RBACTenantContext) error {
	if s.closed {
		return fmt.Errorf("postgres RBAC store is closed")
	}
	if session == nil {
		return fmt.Errorf("session is nil")
	}

	// Extract tenant context
	tenantID := ""
	if len(tenantCtx) > 0 {
		tenantID = tenantCtx[0].TenantID
	}

	tagsJSON, _ := json.Marshal(session.Tags)

	const sql = `
		INSERT INTO rbac_agent_sessions (id, agent_id, ip_address, context_hash, tags, active, tenant_id, created_at, expires_at, last_activity)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	_, err := s.pool.Exec(ctx, sql,
		session.ID, session.AgentID, session.IPAddress, session.ContextHash,
		tagsJSON, session.Active, tenantID, session.CreatedAt, session.ExpiresAt,
		time.Unix(0, session.lastActivity.Load()),
	)
	if err != nil {
		return fmt.Errorf("postgres create agent session: %w", err)
	}
	return nil
}

// GetAgentSession retrieves an agent session by ID.
// If tenantCtx is provided and IsAdmin is false, verifies tenant ownership.
// Returns nil, nil if the session is not found or expired.
func (s *PostgresRBACStore) GetAgentSession(ctx context.Context, sessionID string, tenantCtx ...RBACTenantContext) (*AgentSession, error) {
	if s.closed {
		return nil, fmt.Errorf("postgres RBAC store is closed")
	}

	// Extract tenant context
	var tenantID string
	isAdmin := false
	if len(tenantCtx) > 0 {
		tenantID = tenantCtx[0].TenantID
		isAdmin = tenantCtx[0].IsAdmin
	}

	query := `
		SELECT id, agent_id, ip_address, context_hash, tags, active, tenant_id, created_at, expires_at, last_activity
		FROM rbac_agent_sessions
		WHERE id = $1 AND active = TRUE AND expires_at > NOW()`
	args := []interface{}{sessionID}
	argIdx := 2

	// Add tenant filter unless admin mode
	if !isAdmin && tenantID != "" {
		query += fmt.Sprintf(" AND tenant_id = $%d", argIdx)
		args = append(args, tenantID)
	}

	session, err := scanAgentSession(s.pool.QueryRow(ctx, query, args...))
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("postgres get agent session: %w", err)
	}
	return session, nil
}

// RefreshAgentSession extends a session's expiration time.
func (s *PostgresRBACStore) RefreshAgentSession(ctx context.Context, sessionID string, duration time.Duration) error {
	if s.closed {
		return fmt.Errorf("postgres RBAC store is closed")
	}

	const sql = `
		UPDATE rbac_agent_sessions
		SET expires_at = NOW() + $1, last_activity = NOW()
		WHERE id = $2 AND active = TRUE`

	tag, err := s.pool.Exec(ctx, sql, duration, sessionID)
	if err != nil {
		return fmt.Errorf("postgres refresh agent session: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("session not found or inactive: %s", sessionID)
	}
	return nil
}

// InvalidateAgentSession marks a session as inactive.
func (s *PostgresRBACStore) InvalidateAgentSession(ctx context.Context, sessionID string) error {
	if s.closed {
		return fmt.Errorf("postgres RBAC store is closed")
	}

	const sql = `UPDATE rbac_agent_sessions SET active = FALSE WHERE id = $1`
	_, err := s.pool.Exec(ctx, sql, sessionID)
	if err != nil {
		return fmt.Errorf("postgres invalidate agent session: %w", err)
	}
	return nil
}

// InvalidateAgentSessions marks all sessions for an agent as inactive.
func (s *PostgresRBACStore) InvalidateAgentSessions(ctx context.Context, agentID string) (int, error) {
	if s.closed {
		return 0, fmt.Errorf("postgres RBAC store is closed")
	}

	const sql = `UPDATE rbac_agent_sessions SET active = FALSE WHERE agent_id = $1 AND active = TRUE`
	tag, err := s.pool.Exec(ctx, sql, agentID)
	if err != nil {
		return 0, fmt.Errorf("postgres invalidate agent sessions: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// GetAgentSessions returns all active sessions for an agent.
func (s *PostgresRBACStore) GetAgentSessions(ctx context.Context, agentID string) ([]*AgentSession, error) {
	if s.closed {
		return nil, fmt.Errorf("postgres RBAC store is closed")
	}

	const sql = `
		SELECT id, agent_id, ip_address, context_hash, tags, active, created_at, expires_at, last_activity
		FROM rbac_agent_sessions
		WHERE agent_id = $1 AND active = TRUE AND expires_at > NOW()
		ORDER BY created_at DESC`

	rows, err := s.pool.Query(ctx, sql, agentID)
	if err != nil {
		return nil, fmt.Errorf("postgres get agent sessions: %w", err)
	}
	defer rows.Close()

	var sessions []*AgentSession
	for rows.Next() {
		session, err := scanAgentSessionFromRows(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres scan agent session: %w", err)
		}
		sessions = append(sessions, session)
	}
	return sessions, rows.Err()
}

// ============================================================================
// USER SESSION MANAGEMENT
// ============================================================================

// CreateUserSession inserts a new user session.
func (s *PostgresRBACStore) CreateUserSession(ctx context.Context, session *UserSession) error {
	if s.closed {
		return fmt.Errorf("postgres RBAC store is closed")
	}
	if session == nil {
		return fmt.Errorf("session is nil")
	}

	permsJSON, _ := json.Marshal(session.User.Permissions)
	tagsJSON, _ := json.Marshal(session.Tags)

	const sql = `
		INSERT INTO rbac_user_sessions (id, user_id, role, permissions, ip_address, tags, active, created_at, expires_at, last_activity)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	_, err := s.pool.Exec(ctx, sql,
		session.ID, session.UserID, string(session.User.Role),
		permsJSON, session.IPAddress, tagsJSON, session.Active,
		session.CreatedAt, session.ExpiresAt,
		time.Unix(0, session.lastActivity.Load()),
	)
	if err != nil {
		return fmt.Errorf("postgres create user session: %w", err)
	}
	return nil
}

// GetUserSession retrieves a user session by ID.
// If tenantCtx is provided and IsAdmin is false, verifies tenant ownership.
// Returns nil, nil if the session is not found or expired.
func (s *PostgresRBACStore) GetUserSession(ctx context.Context, sessionID string, tenantCtx ...RBACTenantContext) (*UserSession, error) {
	if s.closed {
		return nil, fmt.Errorf("postgres RBAC store is closed")
	}

	// Extract tenant context
	var tenantID string
	isAdmin := false
	if len(tenantCtx) > 0 {
		tenantID = tenantCtx[0].TenantID
		isAdmin = tenantCtx[0].IsAdmin
	}

	query := `
		SELECT id, user_id, role, permissions, ip_address, tags, active, tenant_id, created_at, expires_at, last_activity
		FROM rbac_user_sessions
		WHERE id = $1 AND active = TRUE AND expires_at > NOW()`
	args := []interface{}{sessionID}
	argIdx := 2

	// Add tenant filter unless admin mode
	if !isAdmin && tenantID != "" {
		query += fmt.Sprintf(" AND tenant_id = $%d", argIdx)
		args = append(args, tenantID)
	}

	row := s.pool.QueryRow(ctx, query, args...)
	var id, userID, role, ipAddress, tenantIDResult string
	var permsJSON, tagsJSON []byte
	var active bool
	var createdAt, expiresAt time.Time
	var lastActivity time.Time

	err := row.Scan(&id, &userID, &role, &permsJSON, &ipAddress, &tagsJSON, &active, &tenantIDResult, &createdAt, &expiresAt, &lastActivity)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("postgres get user session: %w", err)
	}

	var permissions []Permission
	if err := json.Unmarshal(permsJSON, &permissions); err != nil {
		permissions = nil
	}
	var tags map[string]string
	if err := json.Unmarshal(tagsJSON, &tags); err != nil {
		tags = nil
	}

	session := &UserSession{
		ID:        id,
		UserID:    userID,
		Active:    active,
		CreatedAt: createdAt,
		ExpiresAt: expiresAt,
		IPAddress: ipAddress,
		TenantID:  tenantIDResult,
		Tags:      tags,
		User: &User{
			ID:          userID,
			Role:        ParseUserRole(role),
			Permissions: permissions,
		},
	}
	session.SetLastActivity(lastActivity)

	return session, nil
}

// InvalidateUserSession marks a user session as inactive.
func (s *PostgresRBACStore) InvalidateUserSession(ctx context.Context, sessionID string) error {
	if s.closed {
		return fmt.Errorf("postgres RBAC store is closed")
	}

	const sql = `UPDATE rbac_user_sessions SET active = FALSE WHERE id = $1`
	_, err := s.pool.Exec(ctx, sql, sessionID)
	if err != nil {
		return fmt.Errorf("postgres invalidate user session: %w", err)
	}
	return nil
}

// ============================================================================
// CLEANUP
// ============================================================================

// PruneExpiredSessions deletes all expired sessions (agent and user).
// Called by the persistence Manager's background goroutine.
func (s *PostgresRBACStore) PruneExpiredSessions(ctx context.Context) (int, error) {
	if s.closed {
		return 0, fmt.Errorf("postgres RBAC store is closed")
	}

	agentTag, err := s.pool.Exec(ctx, `DELETE FROM rbac_agent_sessions WHERE expires_at < NOW() OR active = FALSE`)
	if err != nil {
		return 0, fmt.Errorf("postgres prune agent sessions: %w", err)
	}
	agentPruned := int(agentTag.RowsAffected())

	userTag, err := s.pool.Exec(ctx, `DELETE FROM rbac_user_sessions WHERE expires_at < NOW() OR active = FALSE`)
	if err != nil {
		return 0, fmt.Errorf("postgres prune user sessions: %w", err)
	}
	userPruned := int(userTag.RowsAffected())

	total := agentPruned + userPruned
	if total > 0 {
		log.Printf("PostgreSQL RBAC prune: removed %d agent + %d user = %d expired sessions",
			agentPruned, userPruned, total)
	}
	return total, nil
}

// CountAgents returns the number of registered agents.
func (s *PostgresRBACStore) CountAgents(ctx context.Context) (int, error) {
	if s.closed {
		return 0, fmt.Errorf("postgres RBAC store is closed")
	}

	var count int
	err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM rbac_agents WHERE enabled = TRUE`).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("postgres count agents: %w", err)
	}
	return count, nil
}

// CountActiveSessions returns the number of active agent sessions.
func (s *PostgresRBACStore) CountActiveSessions(ctx context.Context, agentID string) (int, error) {
	if s.closed {
		return 0, fmt.Errorf("postgres RBAC store is closed")
	}

	var count int
	err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM rbac_agent_sessions WHERE agent_id = $1 AND active = TRUE AND expires_at > NOW()`,
		agentID,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("postgres count agent sessions: %w", err)
	}
	return count, nil
}

// Close marks the store as closed. Does NOT close the pool (PostgresStore owns it).
func (s *PostgresRBACStore) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	log.Println("PostgreSQL RBAC store closed (pool remains open for IOC store)")
	return nil
}

// ============================================================================
// SCAN HELPERS
// ============================================================================

// scanAgent scans a single agent from a query row.
func scanAgent(row pgx.Row) (*Agent, error) {
	var a Agent
	var role string
	var toolsJSON, tagsJSON, metadataJSON []byte

	err := row.Scan(
		&a.ID, &a.Name, &a.Description, &role,
		&toolsJSON, &tagsJSON, &metadataJSON,
		&a.Enabled, &a.TenantID, &a.CreatedAt, &a.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	a.Role = AgentRole(role)

	if err := json.Unmarshal(toolsJSON, &a.Tools); err != nil {
		a.Tools = nil
	}
	if err := json.Unmarshal(tagsJSON, &a.Tags); err != nil {
		a.Tags = nil
	}
	if a.Tags == nil {
		a.Tags = make(map[string]string)
	}
	if err := json.Unmarshal(metadataJSON, &a.Metadata); err != nil {
		a.Metadata = nil
	}

	return &a, nil
}

// scanAgentFromRows scans a single agent from an active rows iterator.
func scanAgentFromRows(rows pgx.Rows) (*Agent, error) {
	var a Agent
	var role string
	var toolsJSON, tagsJSON, metadataJSON []byte

	err := rows.Scan(
		&a.ID, &a.Name, &a.Description, &role,
		&toolsJSON, &tagsJSON, &metadataJSON,
		&a.Enabled, &a.TenantID, &a.CreatedAt, &a.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	a.Role = AgentRole(role)

	if err := json.Unmarshal(toolsJSON, &a.Tools); err != nil {
		a.Tools = nil
	}
	if err := json.Unmarshal(tagsJSON, &a.Tags); err != nil {
		a.Tags = nil
	}
	if a.Tags == nil {
		a.Tags = make(map[string]string)
	}
	if err := json.Unmarshal(metadataJSON, &a.Metadata); err != nil {
		a.Metadata = nil
	}

	return &a, nil
}

// scanAgentSession scans a single agent session from a query row.
func scanAgentSession(row pgx.Row) (*AgentSession, error) {
	var s AgentSession
	var tagsJSON []byte
	var lastActivity time.Time

	err := row.Scan(
		&s.ID, &s.AgentID, &s.IPAddress, &s.ContextHash,
		&tagsJSON, &s.Active, &s.TenantID, &s.CreatedAt, &s.ExpiresAt, &lastActivity,
	)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(tagsJSON, &s.Tags); err != nil {
		s.Tags = nil
	}
	if s.Tags == nil {
		s.Tags = make(map[string]string)
	}
	s.SetLastActivity(lastActivity)

	return &s, nil
}

// scanAgentSessionFromRows scans a single agent session from an active rows iterator.
func scanAgentSessionFromRows(rows pgx.Rows) (*AgentSession, error) {
	var s AgentSession
	var tagsJSON []byte
	var lastActivity time.Time

	err := rows.Scan(
		&s.ID, &s.AgentID, &s.IPAddress, &s.ContextHash,
		&tagsJSON, &s.Active, &s.TenantID, &s.CreatedAt, &s.ExpiresAt, &lastActivity,
	)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(tagsJSON, &s.Tags); err != nil {
		s.Tags = nil
	}
	if s.Tags == nil {
		s.Tags = make(map[string]string)
	}
	s.SetLastActivity(lastActivity)

	return &s, nil
}

// joinRBACStrings joins string slices with a separator (helper for SQL SET clauses).
func joinRBACStrings(ss []string, sep string) string {
	if len(ss) == 0 {
		return ""
	}
	result := ss[0]
	for _, s := range ss[1:] {
		result += sep + s
	}
	return result
}
