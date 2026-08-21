// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform — PostgreSQL-Backed Tenant Manager
// =========================================================================
//
// postgres_manager.go implements a PostgreSQL-backed tenant manager that
// persists tenant metadata across restarts. It follows the same pattern as
// pkg/rbac/postgres_store.go: shares the *pgxpool.Pool from ioc.PostgresStore
// via pgStore.Pool().
//
// The PostgresManager implements the Store interface so it can be used
// interchangeably with the in-memory Manager via NewHandler(s Store).
//
// =========================================================================

package tenant

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
)

// Store defines the tenant CRUD interface with context-aware methods.
// Both the in-memory Manager (via wrapper methods) and PostgresManager
// implement this interface.
type Store interface {
	Create(ctx context.Context, name, displayName, email, licenseTier string, maxUsers, maxAgents int) (*Tenant, error)
	Get(ctx context.Context, id string) (*Tenant, error)
	List(ctx context.Context) ([]*Tenant, error)
	Update(ctx context.Context, id string, updates map[string]interface{}) (*Tenant, error)
	Delete(ctx context.Context, id string) error
	Count(ctx context.Context) (int, error)
}

// PostgresManager persists tenant metadata to PostgreSQL.
// It shares the connection pool from an existing ioc.PostgresStore instance.
type PostgresManager struct {
	pool   *pgxpool.Pool
	mgr    *ioc.PostgresStore // owns the pool lifecycle
	closed bool
}

// NewPostgresManager creates a PostgreSQL-backed tenant manager.
// If pgStore is nil, returns nil (caller should fall back to in-memory).
func NewPostgresManager(pgStore *ioc.PostgresStore) (*PostgresManager, error) {
	if pgStore == nil {
		return nil, fmt.Errorf("postgres store is nil, cannot create tenant manager")
	}

	pm := &PostgresManager{
		pool: pgStore.Pool(),
		mgr:  pgStore,
	}

	// Auto-create the tenants table if it doesn't exist.
	// The migration 009_tenant_management.sql handles this during normal
	// startup, but we also create it here as a safety net for when the
	// manager is initialized before migrations run.
	if err := pm.createTable(context.Background()); err != nil {
		return nil, fmt.Errorf("create tenants table: %w", err)
	}

	return pm, nil
}

// createTable creates the tenants table if it doesn't already exist.
func (pm *PostgresManager) createTable(ctx context.Context) error {
	const sql = `CREATE TABLE IF NOT EXISTS tenants (
		id           VARCHAR(64) PRIMARY KEY,
		name         VARCHAR(255) NOT NULL,
		display_name VARCHAR(255) DEFAULT '',
		email        VARCHAR(255) DEFAULT '',
		license_tier VARCHAR(32) DEFAULT '',
		max_users    INTEGER DEFAULT 0,
		max_agents   INTEGER DEFAULT 0,
		active       BOOLEAN DEFAULT TRUE,
		created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`
	if _, err := pm.pool.Exec(ctx, sql); err != nil {
		return fmt.Errorf("create tenants table: %w", err)
	}

	// Create indexes
	if _, err := pm.pool.Exec(ctx, `CREATE INDEX IF NOT EXISTS idx_tenants_name ON tenants(name)`); err != nil {
		return fmt.Errorf("create idx_tenants_name: %w", err)
	}
	if _, err := pm.pool.Exec(ctx, `CREATE INDEX IF NOT EXISTS idx_tenants_active ON tenants(active)`); err != nil {
		return fmt.Errorf("create idx_tenants_active: %w", err)
	}

	return nil
}

// Create inserts a new tenant into PostgreSQL and returns the created record.
func (pm *PostgresManager) Create(ctx context.Context, name, displayName, email, licenseTier string, maxUsers, maxAgents int) (*Tenant, error) {
	if pm.closed {
		return nil, fmt.Errorf("postgres tenant manager is closed")
	}
	if name == "" {
		return nil, fmt.Errorf("tenant name is required")
	}

	id := generateTenantID()
	now := time.Now().UTC()

	const sql = `
		INSERT INTO tenants (id, name, display_name, email, license_tier, max_users, max_agents, active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id, name, display_name, email, license_tier, max_users, max_agents, active, created_at, updated_at`

	var t Tenant
	err := pm.pool.QueryRow(ctx, sql,
		id, name, displayName, email, licenseTier, maxUsers, maxAgents, true, now, now,
	).Scan(
		&t.ID, &t.Name, &t.DisplayName, &t.Email, &t.LicenseTier,
		&t.MaxUsers, &t.MaxAgents, &t.Active, &t.CreatedAt, &t.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("postgres create tenant: %w", err)
	}
	return &t, nil
}

// Get retrieves a tenant by ID from PostgreSQL.
func (pm *PostgresManager) Get(ctx context.Context, id string) (*Tenant, error) {
	if pm.closed {
		return nil, fmt.Errorf("postgres tenant manager is closed")
	}

	const sql = `SELECT id, name, display_name, email, license_tier, max_users, max_agents, active, created_at, updated_at FROM tenants WHERE id = $1`

	var t Tenant
	err := pm.pool.QueryRow(ctx, sql, id).Scan(
		&t.ID, &t.Name, &t.DisplayName, &t.Email, &t.LicenseTier,
		&t.MaxUsers, &t.MaxAgents, &t.Active, &t.CreatedAt, &t.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("tenant %q not found", id)
		}
		return nil, fmt.Errorf("postgres get tenant: %w", err)
	}
	return &t, nil
}

// List returns all tenants from PostgreSQL, ordered by created_at.
func (pm *PostgresManager) List(ctx context.Context) ([]*Tenant, error) {
	if pm.closed {
		return nil, fmt.Errorf("postgres tenant manager is closed")
	}

	const sql = `SELECT id, name, display_name, email, license_tier, max_users, max_agents, active, created_at, updated_at FROM tenants ORDER BY created_at`

	rows, err := pm.pool.Query(ctx, sql)
	if err != nil {
		return nil, fmt.Errorf("postgres list tenants: %w", err)
	}
	defer rows.Close()

	var tenants []*Tenant
	for rows.Next() {
		var t Tenant
		if err := rows.Scan(
			&t.ID, &t.Name, &t.DisplayName, &t.Email, &t.LicenseTier,
			&t.MaxUsers, &t.MaxAgents, &t.Active, &t.CreatedAt, &t.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("postgres scan tenant: %w", err)
		}
		tenants = append(tenants, &t)
	}
	return tenants, rows.Err()
}

// Update updates tenant fields in PostgreSQL using a dynamic UPDATE.
// Only the fields present in the updates map are modified.
func (pm *PostgresManager) Update(ctx context.Context, id string, updates map[string]interface{}) (*Tenant, error) {
	if pm.closed {
		return nil, fmt.Errorf("postgres tenant manager is closed")
	}
	if len(updates) == 0 {
		// Nothing to update — just return the current tenant.
		return pm.Get(ctx, id)
	}

	// Map JSON field names to DB column names.
	columnMap := map[string]string{
		"name":        "name",
		"displayName": "display_name",
		"email":       "email",
		"licenseTier": "license_tier",
		"maxUsers":    "max_users",
		"maxAgents":   "max_agents",
		"active":      "active",
	}

	setClauses := []string{}
	args := []interface{}{}
	argIdx := 1

	for jsonField, colName := range columnMap {
		val, ok := updates[jsonField]
		if !ok {
			continue
		}
		// Skip empty string for name (required field).
		if jsonField == "name" {
			if s, ok := val.(string); ok && s == "" {
				continue
			}
		}
		// Convert float64 to int for integer fields (JSON numbers).
		if jsonField == "maxUsers" || jsonField == "maxAgents" {
			if f, ok := val.(float64); ok {
				val = int(f)
			}
		}
		setClauses = append(setClauses, fmt.Sprintf("%s = $%d", colName, argIdx))
		args = append(args, val)
		argIdx++
	}

	// Always update updated_at.
	setClauses = append(setClauses, fmt.Sprintf("updated_at = $%d", argIdx))
	args = append(args, time.Now().UTC())
	argIdx++

	// WHERE id = $N
	args = append(args, id)

	sql := fmt.Sprintf(
		`UPDATE tenants SET %s WHERE id = $%d
		RETURNING id, name, display_name, email, license_tier, max_users, max_agents, active, created_at, updated_at`,
		joinStrings(setClauses, ", "),
		argIdx,
	)

	var t Tenant
	err := pm.pool.QueryRow(ctx, sql, args...).Scan(
		&t.ID, &t.Name, &t.DisplayName, &t.Email, &t.LicenseTier,
		&t.MaxUsers, &t.MaxAgents, &t.Active, &t.CreatedAt, &t.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("tenant %q not found", id)
		}
		return nil, fmt.Errorf("postgres update tenant: %w", err)
	}
	return &t, nil
}

// Delete removes a tenant from PostgreSQL.
func (pm *PostgresManager) Delete(ctx context.Context, id string) error {
	if pm.closed {
		return fmt.Errorf("postgres tenant manager is closed")
	}

	const sql = `DELETE FROM tenants WHERE id = $1`
	tag, err := pm.pool.Exec(ctx, sql, id)
	if err != nil {
		return fmt.Errorf("postgres delete tenant: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("tenant %q not found", id)
	}
	return nil
}

// Count returns the total number of tenants in PostgreSQL.
func (pm *PostgresManager) Count(ctx context.Context) (int, error) {
	if pm.closed {
		return 0, fmt.Errorf("postgres tenant manager is closed")
	}

	var count int
	err := pm.pool.QueryRow(ctx, `SELECT COUNT(*) FROM tenants`).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("postgres count tenants: %w", err)
	}
	return count, nil
}

// Close marks the manager as closed. Does NOT close the pool (PostgresStore owns it).
func (pm *PostgresManager) Close() error {
	if pm.closed {
		return nil
	}
	pm.closed = true
	log.Println("PostgreSQL tenant manager closed (pool remains open for IOC store)")
	return nil
}

// Handler returns an http.Handler for the tenant management API backed by PostgreSQL.
// It uses the same routing logic as the in-memory Manager's Handler, but calls
// the context-aware PostgresManager methods.
func (pm *PostgresManager) Handler() http.Handler {
	return NewHandler(pm)
}

// joinStrings joins string slices with a separator (helper for SQL SET clauses).
func joinStrings(ss []string, sep string) string {
	if len(ss) == 0 {
		return ""
	}
	result := ss[0]
	for _, s := range ss[1:] {
		result += sep + s
	}
	return result
}
