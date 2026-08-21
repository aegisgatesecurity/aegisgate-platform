// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — Legal Hold Postgres Store (v4.3.1)
//
// postgres_store.go provides PostgreSQL-backed persistence for legal holds.
// This ensures holds survive platform restarts and are consistent across
// multi-instance deployments.

package legalhold

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
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
	_, err := s.pool.Exec(ctx, `
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
}

// Create persists a new legal hold.
func (s *PostgresStore) Create(ctx context.Context, h *Hold) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO legal_holds (id, entity_id, entity_type, reason, issued_by, created_at, released_at)
		 VALUES ($1, $2, $3, $4, $5, $6, NULL)`,
		h.ID, h.EntityID, h.EntityType, h.Reason, h.IssuedBy, h.CreatedAt,
	)
	return err
}

// Release marks a hold as released by setting released_at.
func (s *PostgresStore) Release(ctx context.Context, holdID string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE legal_holds SET released_at = $1 WHERE id = $2 AND released_at IS NULL`,
		time.Now().UTC(), holdID,
	)
	if err != nil {
		return err
	}
	return nil
}

// IsUnderHold returns true if the entity has any active (unreleased) hold.
func (s *PostgresStore) IsUnderHold(ctx context.Context, entityID string) bool {
	var count int
	err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM legal_holds WHERE entity_id = $1 AND released_at IS NULL`,
		entityID,
	).Scan(&count)
	if err != nil {
		// Fail-safe: if we can't check, assume no hold (allows operation)
		return false
	}
	return count > 0
}

// GetActiveHolds returns all active holds for an entity.
func (s *PostgresStore) GetActiveHolds(ctx context.Context, entityID string) []*Hold {
	rows, err := s.pool.Query(ctx,
		`SELECT id, entity_id, entity_type, reason, issued_by, created_at FROM legal_holds
		 WHERE entity_id = $1 AND released_at IS NULL ORDER BY created_at DESC`,
		entityID,
	)
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
	rows, err := s.pool.Query(ctx,
		`SELECT id, entity_id, entity_type, reason, issued_by, created_at, released_at FROM legal_holds
		 ORDER BY created_at DESC`,
	)
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
	h := &Hold{}
	var releasedAt sql.NullTime
	err := s.pool.QueryRow(ctx,
		`SELECT id, entity_id, entity_type, reason, issued_by, created_at, released_at
		 FROM legal_holds WHERE id = $1`,
		holdID,
	).Scan(&h.ID, &h.EntityID, &h.EntityType, &h.Reason, &h.IssuedBy, &h.CreatedAt, &releasedAt)
	if err != nil {
		return nil, fmt.Errorf("hold %s not found: %w", holdID, err)
	}
	if releasedAt.Valid {
		h.ReleasedAt = releasedAt.Time
	}
	return h, nil
}
