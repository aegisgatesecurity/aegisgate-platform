// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Attestation Store Interface (v3.8 Persistence)
// =========================================================================
//
// store_interface.go defines the AttestationStore interface that both the
// in-memory and PostgreSQL backends implement. This allows the platform
// to switch storage backends based on tier and configuration:
//
//   - Community/Developer tiers → InMemoryAttestationStore (no persistence)
//   - Professional/Enterprise tiers → PostgresAttestationStore (durable)
//
// Tier gating: FeaturePostgreSQL is required for PostgresAttestationStore.
// The platform startup code checks this feature flag and falls back to
// InMemoryAttestationStore if PostgreSQL is not available or not entitled.
//
// v3.8 persistence gap closure.
// =========================================================================

package attestation

import (
	"context"
	"time"
)

// AttestationStore is the interface for persisting signed attestation
// envelopes. Both in-memory and PostgreSQL backends implement this interface.
//
// The store is append-only: envelopes are stored once and never modified.
// This matches the cryptographic nature of attestation — once signed, an
// envelope is immutable. The only mutable operation is pruning expired
// envelopes.
//
// All methods accept a context for PostgreSQL cancellation and timeout
// support. The in-memory store ignores the context parameter.
type AttestationStore interface {
	// Store persists a signed envelope. Returns an error if an envelope
	// with the same ID already exists (envelopes are immutable).
	Store(ctx context.Context, envelope *Envelope) error

	// Get retrieves an envelope by its ID. Returns nil if not found.
	Get(ctx context.Context, id string) (*Envelope, error)

	// ListByType returns envelopes of a specific type, ordered by
	// issued_at descending (newest first). Type must be a registered
	// attestation type (e.g., "benchmark.sxc.v1", "audit.soc2.v1").
	ListByType(ctx context.Context, attestationType Type, limit, offset int) ([]*Envelope, error)

	// ListBySubject returns envelopes for a specific subject, ordered
	// by issued_at descending (newest first).
	ListBySubject(ctx context.Context, subject string, limit, offset int) ([]*Envelope, error)

	// ListByIssuer returns envelopes signed by a specific issuer/key,
	// ordered by issued_at descending.
	ListByIssuer(ctx context.Context, issuer string, limit, offset int) ([]*Envelope, error)

	// ListByTimeRange returns envelopes issued within a time range,
	// ordered by issued_at descending.
	ListByTimeRange(ctx context.Context, from, to time.Time, limit, offset int) ([]*Envelope, error)

	// PruneExpired removes envelopes whose valid_until is before the
	// cutoff time. Returns the count of removed envelopes.
	// Envelopes with valid_until = NULL (no expiration) are never pruned.
	PruneExpired(ctx context.Context, cutoff time.Time) (int, error)

	// CountByType returns the number of envelopes of a specific type.
	CountByType(ctx context.Context, attestationType Type) (int, error)

	// Close releases resources. For the in-memory store this is a no-op.
	// For PostgresAttestationStore this does NOT close the pool (shared).
	Close() error
}

// AttestationQuery defines filter criteria for querying envelopes.
// All fields are optional; zero values mean "match all".
type AttestationQuery struct {
	// Type filters by attestation type (e.g., "benchmark.sxc.v1").
	Type Type

	// Subject filters by subject (e.g., "aegisgate://evaluation/bench-2026").
	Subject string

	// Issuer filters by issuer (e.g., "instance-1:key-2026-07-23").
	Issuer string

	// KeyID filters by the signing key ID.
	KeyID string

	// Since filters envelopes issued after this time.
	Since time.Time

	// Until filters envelopes issued before this time.
	Until time.Time

	// Limit caps the number of results. 0 means no limit.
	Limit int

	// Offset is the number of results to skip (for pagination).
	Offset int
}