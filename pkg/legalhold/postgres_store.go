// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — Legal Hold Postgres Store (v4.3.1)
//
// postgres_store.go provides PostgreSQL-backed persistence for legal holds.
// This ensures holds survive platform restarts and are consistent across
// multi-instance deployments. All queries are wrapped with RLS context
// via WithTenantContextOrPool for defense-in-depth tenant isolation.

package legalhold

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
)

// PostgresStore implements legal hold persistence using PostgreSQL.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore creates a new PostgreSQL-backed legal hold store.
// It creates the legal_holds table if it doesn't exist.
func NewPostgresStore(pool *pgxpool.Pool) (*PostgresStore, error) {
	s := &PostgresStore{pool: pool}
	if err := s.ensureSchema(context.Background()); err != nil {
		return nil, fmt.Errorf("legal hold schema: %w", err)
	}
	return s, nil
}

func (s *PostgresStore) ensureSchema(ctx context.Context) error {
	// Schema creation runs as admin (no tenant context).
	err := ioc.WithTenantContextOrPool(ctx, s.pool, "", true, func(q ioc.DBQuerier) error {
		_, err := q.Exec(ctx, `
			CREATE TABLE IF NOT EXISTS legal_holds (
				id          TEXT PRIMARY KEY,
				entity_id   TEXT NOT NULL,
				entity_type TEXT NOT NULL DEFAULT 'user',
				reason      TEXT NOT NULL,
				issued_by   TEXT NOT NULL DEFAULT '',
				created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
				released_at TIMESTAMPTZ,
				tenant_id   TEXT DEFAULT ''
			);
			CREATE INDEX IF NOT EXISTS idx_legal_holds_entity_id ON legal_holds (entity_id);
			CREATE INDEX IF NOT EXISTS idx_legal_holds_active ON legal_holds (entity_id) WHERE released_at IS NULL;
		`)
		return err
	})
	return err
}

// Create persists a new legal hold.
func (s *PostgresStore) Create(ctx context.Context, h *Hold) error {
	tenantID := h.TenantID
	isAdmin := tenantID == ""
	return ioc.WithTenantContextOrPool(ctx, s.pool, tenantID, isAdmin, func(q ioc.DBQuerier) error {
		_, err := q.Exec(ctx,
			`INSERT INTO legal_holds (id, entity_id, entity_type, reason, issued_by, created_at, released_at, tenant_id)
			 VALUES ($1, $2, $3, $4, $5, $6, NULL, $7)`,
			h.ID, h.EntityID, h.EntityType, h.Reason, h.IssuedBy, h.CreatedAt, tenantID,
		)
		return err
	})
}

// Release marks a hold as released by setting released_at.
func (s *PostgresStore) Release(ctx context.Context, holdID string) error {
	// Admin-scoped: release can be called by admins across tenants.
	return ioc.WithTenantContextOrPool(ctx, s.pool, "", true, func(q ioc.DBQuerier) error {
		_, err := q.Exec(ctx,
			`UPDATE legal_holds SET released_at = $1 WHERE id = $2 AND released_at IS NULL`,
			time.Now().UTC(), holdID,
		)
		return err
	})
}

// IsUnderHold returns true if the entity has any active (unreleased) hold.
func (s *PostgresStore) IsUnderHold(ctx context.Context, entityID string) bool {
	// Admin-scoped: the DSAR service checks this across all tenants.
	var count int
	err := ioc.WithTenantContextOrPool(ctx, s.pool, "", true, func(q ioc.DBQuerier) error {
		return q.QueryRow(ctx,
			`SELECT COUNT(*) FROM legal_holds WHERE entity_id = $1 AND released_at IS NULL`,
			entityID,
		).Scan(&count)
	})
	if err != nil {
		return false
	}
	return count > 0
}

// GetActiveHolds returns all active holds for an entity.
func (s *PostgresStore) GetActiveHolds(ctx context.Context, entityID string) []*Hold {
	// Admin-scoped: system query for hold management.
	var rows pgx.Rows
	err := ioc.WithTenantContextOrPool(ctx, s.pool, "", true, func(q ioc.DBQuerier) error {
		var queryErr error
		rows, queryErr = q.Query(ctx,
			`SELECT id, entity_id, entity_type, reason, issued_by, created_at FROM legal_holds
			 WHERE entity_id = $1 AND released_at IS NULL ORDER BY created_at DESC`,
			entityID,
		)
		return queryErr
	})
	if err != nil {
		return nil
	}
	defer rows.Close()

	var holds []*Hold
	for rows.Next() {
		h := &Hold{}
		if err := rows.Scan(&h.ID, &h.EntityID, &h.EntityType, &h.Reason, &h.IssuedBy, &h.CreatedAt); err == nil {
			holds = append(holds, h)
		}
	}
	return holds
}

// List returns all holds (active and released).
func (s *PostgresStore) List(ctx context.Context) []*Hold {
	// Admin-scoped: listing all holds is a system operation.
	var rows pgx.Rows
	err := ioc.WithTenantContextOrPool(ctx, s.pool, "", true, func(q ioc.DBQuerier) error {
		var queryErr error
		rows, queryErr = q.Query(ctx,
			`SELECT id, entity_id, entity_type, reason, issued_by, created_at, released_at FROM legal_holds
			 ORDER BY created_at DESC`,
		)
		return queryErr
	})
	if err != nil {
		return nil
	}
	defer rows.Close()

	var holds []*Hold
	for rows.Next() {
		h := &Hold{}
		var releasedAt sql.NullTime
		if err := rows.Scan(&h.ID, &h.EntityID, &h.EntityType, &h.Reason, &h.IssuedBy, &h.CreatedAt, &releasedAt); err == nil {
			if releasedAt.Valid {
				h.ReleasedAt = releasedAt.Time
			}
			holds = append(holds, h)
		}
	}
	return holds
}

// Get retrieves a single hold by ID.
func (s *PostgresStore) Get(ctx context.Context, holdID string) (*Hold, error) {
	// Admin-scoped: system query for hold retrieval.
	h := &Hold{}
	var releasedAt sql.NullTime
	err := ioc.WithTenantContextOrPool(ctx, s.pool, "", true, func(q ioc.DBQuerier) error {
		return q.QueryRow(ctx,
			`SELECT id, entity_id, entity_type, reason, issued_by, created_at, released_at
			 FROM legal_holds WHERE id = $1`,
			holdID,
		).Scan(&h.ID, &h.EntityID, &h.EntityType, &h.Reason, &h.IssuedBy, &h.CreatedAt, &releasedAt)
	})
	if err != nil {
		return nil, fmt.Errorf("hold %s not found: %w", holdID, err)
	}
	if releasedAt.Valid {
		h.ReleasedAt = releasedAt.Time
	}
	return h, nil
}
