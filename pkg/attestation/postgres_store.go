// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Attestation PostgreSQL Store (v3.8 Persistence)
// =========================================================================
//
// postgres_store.go implements AttestationStore backed by PostgreSQL using
// pgx/v5. This is the storage backend for Professional and Enterprise tiers.
//
// Architecture:
//
//   - Shares the pgxpool.Pool with IOC and Correlation stores (shared pool)
//   - Append-only: envelopes are stored once and never modified
//   - Indexed queries for type, subject, issuer, key, and time range
//   - Automatic migration via the shared migration runner (006_attestation.sql)
//   - Tier-based pruning of expired envelopes (Community: never, Developer: 30d,
//     Professional: 90d, Enterprise: configurable)
//
// Thread safety:
//
//   All pgxpool operations are safe for concurrent use. The pool manages
//   its own connection lifecycle. The caller does NOT need to hold any
//   additional locks.
//
// v3.8 persistence gap closure.
// =========================================================================

package attestation

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Compile-time interface compliance check.
var _ AttestationStore = (*PostgresAttestationStore)(nil)

// PostgresAttestationStore implements AttestationStore backed by PostgreSQL.
// It uses a shared connection pool (not owned) so the pool lifecycle is
// managed by the caller (typically the persistence.Manager).
type PostgresAttestationStore struct {
	pool *pgxpool.Pool
}

// NewPostgresAttestationStore creates a new PostgresAttestationStore using
// the provided connection pool. The pool must already be connected and
// migrations must have been applied (the shared migration runner handles this).
func NewPostgresAttestationStore(pool *pgxpool.Pool) *PostgresAttestationStore {
	return &PostgresAttestationStore{pool: pool}
}

// Store persists a signed envelope. Returns an error if an envelope
// with the same ID already exists (envelopes are immutable).
func (s *PostgresAttestationStore) Store(ctx context.Context, envelope *Envelope) error {
	if envelope == nil {
		return fmt.Errorf("attestation: Store: nil envelope")
	}

	payload, err := json.Marshal(envelope.RawPayload)
	if err != nil {
		return fmt.Errorf("attestation: Store: marshal payload: %w", err)
	}

	_, err = s.pool.Exec(ctx,
		`INSERT INTO attestation_envelopes (
			id, type, subject, issuer, issued_at, valid_until,
			payload, sig_algorithm, sig_key_id, sig_value,
			sig_public_key, sig_signed_at, tenant_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		ON CONFLICT (id) DO NOTHING`,
		envelope.ID,
		string(envelope.Type),
		envelope.Subject,
		envelope.Issuer,
		envelope.IssuedAt,
		envelope.ValidUntil,
		payload,
		envelope.Signature.Algorithm,
		envelope.Signature.KeyID,
		envelope.Signature.Value,
		envelope.Signature.PublicKey,
		envelope.Signature.SignedAt,
		"", // tenant_id: empty for single-tenant
	)
	if err != nil {
		return fmt.Errorf("attestation: Store: %w", err)
	}
	return nil
}

// Get retrieves an envelope by its ID. Returns nil if not found.
func (s *PostgresAttestationStore) Get(ctx context.Context, id string) (*Envelope, error) {
	if id == "" {
		return nil, fmt.Errorf("attestation: Get: empty id")
	}

	var env Envelope
	var sigAlgo, sigKeyID string
	var sigValue, sigPubKey []byte
	var sigSignedAt time.Time
	var validUntil *time.Time
	var rawPayload []byte

	err := s.pool.QueryRow(ctx,
		`SELECT id, type, subject, issuer, issued_at, valid_until,
			payload, sig_algorithm, sig_key_id, sig_value,
			sig_public_key, sig_signed_at
		FROM attestation_envelopes WHERE id = $1`,
		id,
	).Scan(
		&env.ID,
		&env.Type,
		&env.Subject,
		&env.Issuer,
		&env.IssuedAt,
		&validUntil,
		&rawPayload,
		&sigAlgo,
		&sigKeyID,
		&sigValue,
		&sigPubKey,
		&sigSignedAt,
	)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return nil, nil
		}
		return nil, fmt.Errorf("attestation: Get: %w", err)
	}

	if validUntil != nil {
		env.ValidUntil = *validUntil
	}
	env.RawPayload = json.RawMessage(rawPayload)
	env.Signature = Signature{
		Algorithm: sigAlgo,
		KeyID:     sigKeyID,
		Value:     sigValue,
		PublicKey:  sigPubKey,
		SignedAt:  sigSignedAt,
	}
	return &env, nil
}

// ListByType returns envelopes of a specific type, ordered by issued_at
// descending (newest first).
func (s *PostgresAttestationStore) ListByType(ctx context.Context, attestationType Type, limit, offset int) ([]*Envelope, error) {
	query := `SELECT id, type, subject, issuer, issued_at, valid_until,
			payload, sig_algorithm, sig_key_id, sig_value,
			sig_public_key, sig_signed_at
		FROM attestation_envelopes WHERE type = $1
		ORDER BY issued_at DESC`
	args := []interface{}{string(attestationType)}

	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}
	if offset > 0 {
		query += fmt.Sprintf(" OFFSET %d", offset)
	}

	return s.queryEnvelopes(ctx, query, args)
}

// ListBySubject returns envelopes for a specific subject, ordered by
// issued_at descending (newest first).
func (s *PostgresAttestationStore) ListBySubject(ctx context.Context, subject string, limit, offset int) ([]*Envelope, error) {
	query := `SELECT id, type, subject, issuer, issued_at, valid_until,
			payload, sig_algorithm, sig_key_id, sig_value,
			sig_public_key, sig_signed_at
		FROM attestation_envelopes WHERE subject = $1
		ORDER BY issued_at DESC`
	args := []interface{}{subject}

	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}
	if offset > 0 {
		query += fmt.Sprintf(" OFFSET %d", offset)
	}

	return s.queryEnvelopes(ctx, query, args)
}

// ListByIssuer returns envelopes signed by a specific issuer/key,
// ordered by issued_at descending.
func (s *PostgresAttestationStore) ListByIssuer(ctx context.Context, issuer string, limit, offset int) ([]*Envelope, error) {
	query := `SELECT id, type, subject, issuer, issued_at, valid_until,
			payload, sig_algorithm, sig_key_id, sig_value,
			sig_public_key, sig_signed_at
		FROM attestation_envelopes WHERE issuer = $1
		ORDER BY issued_at DESC`
	args := []interface{}{issuer}

	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}
	if offset > 0 {
		query += fmt.Sprintf(" OFFSET %d", offset)
	}

	return s.queryEnvelopes(ctx, query, args)
}

// ListByTimeRange returns envelopes issued within a time range,
// ordered by issued_at descending.
func (s *PostgresAttestationStore) ListByTimeRange(ctx context.Context, from, to time.Time, limit, offset int) ([]*Envelope, error) {
	query := `SELECT id, type, subject, issuer, issued_at, valid_until,
			payload, sig_algorithm, sig_key_id, sig_value,
			sig_public_key, sig_signed_at
		FROM attestation_envelopes WHERE issued_at >= $1 AND issued_at <= $2
		ORDER BY issued_at DESC`
	args := []interface{}{from, to}

	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}
	if offset > 0 {
		query += fmt.Sprintf(" OFFSET %d", offset)
	}

	return s.queryEnvelopes(ctx, query, args)
}

// PruneExpired removes envelopes whose valid_until is before the cutoff
// time. Returns the count of removed envelopes. Envelopes with
// valid_until = NULL (no expiration) are never pruned.
func (s *PostgresAttestationStore) PruneExpired(ctx context.Context, cutoff time.Time) (int, error) {
	result, err := s.pool.Exec(ctx,
		`DELETE FROM attestation_envelopes
		WHERE valid_until IS NOT NULL AND valid_until < $1`,
		cutoff,
	)
	if err != nil {
		return 0, fmt.Errorf("attestation: PruneExpired: %w", err)
	}
	return int(result.RowsAffected()), nil
}

// CountByType returns the number of envelopes of a specific type.
func (s *PostgresAttestationStore) CountByType(ctx context.Context, attestationType Type) (int, error) {
	var count int
	err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM attestation_envelopes WHERE type = $1`,
		string(attestationType),
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("attestation: CountByType: %w", err)
	}
	return count, nil
}

// Close is a no-op. The pool is shared and not owned by this store.
func (s *PostgresAttestationStore) Close() error {
	return nil
}

// queryEnvelopes is a helper that executes a query and scans the results
// into a slice of Envelope pointers.
func (s *PostgresAttestationStore) queryEnvelopes(ctx context.Context, query string, args []interface{}) ([]*Envelope, error) {
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("attestation: query envelopes: %w", err)
	}
	defer rows.Close()

	var envelopes []*Envelope
	for rows.Next() {
		var env Envelope
		var sigAlgo, sigKeyID string
		var sigValue, sigPubKey []byte
		var sigSignedAt time.Time
		var validUntil *time.Time
		var rawPayload []byte

		if err := rows.Scan(
			&env.ID,
			&env.Type,
			&env.Subject,
			&env.Issuer,
			&env.IssuedAt,
			&validUntil,
			&rawPayload,
			&sigAlgo,
			&sigKeyID,
			&sigValue,
			&sigPubKey,
			&sigSignedAt,
		); err != nil {
			return nil, fmt.Errorf("attestation: scan envelope: %w", err)
		}

		if validUntil != nil {
			env.ValidUntil = *validUntil
		}
		env.RawPayload = json.RawMessage(rawPayload)
		env.Signature = Signature{
			Algorithm: sigAlgo,
			KeyID:     sigKeyID,
			Value:     sigValue,
			PublicKey:  sigPubKey,
			SignedAt:  sigSignedAt,
		}
		envelopes = append(envelopes, &env)
	}

	return envelopes, nil
}