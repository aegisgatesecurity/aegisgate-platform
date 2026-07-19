// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Federated IOC Library (v3.5.0+ D1 PostgreSQL)
// =========================================================================
//
// store_interface.go defines the StoreInterface that both the in-memory
// Store and the PostgresStore implement. This allows the platform to
// switch storage backends based on tier and configuration:
//
//   - Community/Developer tiers → in-memory Store with JSON flush (existing)
//   - Professional/Enterprise tiers → PostgresStore with pgx/v5 (new)
//
// The interface preserves the existing Store's semantics while adding
// batch operations and query capabilities that PostgreSQL enables.
//
// Tier gating: FeaturePostgreSQL is required for PostgresStore. The
// platform startup code checks this feature flag and falls back to
// in-memory Store if PostgreSQL is not available or not entitled.
//
// v3.5.0+ D1 Phase 1A.
// =========================================================================

package ioc

import (
	"context"
	"time"
)

// StoreInterface is the contract that both in-memory Store and PostgresStore
// implement. All methods accept a context for PostgreSQL cancellation and
// timeout support. The in-memory Store ignores the context parameter.
type StoreInterface interface {
	// Observe records a new observation of an IOC. If the fingerprint
	// already exists, Count is incremented, LastSeen and Severity
	// are updated. Returns the (possibly updated) IOC.
	Observe(ctx context.Context, ioc IOC) (*IOC, error)

	// ObserveBatch records multiple IOCs in a single transaction.
	// This is significantly faster than calling Observe in a loop
	// when using PostgreSQL. The in-memory Store calls Observe
	// sequentially.
	ObserveBatch(ctx context.Context, iocs []IOC) error

	// Get returns the IOC with the given fingerprint, or nil if
	// not found.
	Get(ctx context.Context, fingerprint string) (*IOC, error)

	// Size returns the current number of IOCs in the store.
	Size(ctx context.Context) (int, error)

	// Snapshot returns all IOCs, sorted by LastSeen descending.
	// The returned slice is safe to iterate without holding any lock.
	Snapshot(ctx context.Context) ([]IOC, error)

	// SnapshotSince returns IOCs with LastSeen >= since, sorted
	// by LastSeen descending. This is the delta query used by
	// the gossip sync protocol.
	SnapshotSince(ctx context.Context, since time.Time) ([]IOC, error)

	// Query returns IOCs matching the given filter criteria.
	// This is the indexed query path that PostgreSQL enables
	// (the in-memory Store falls back to a linear scan).
	// Nil/zero filter fields mean "match all".
	Query(ctx context.Context, filter IOCQuery) ([]IOC, error)

	// Prune removes IOCs older than maxAge and returns the
	// count of removed IOCs.
	Prune(ctx context.Context, maxAge time.Duration) (int, error)

	// Flush persists the in-memory state to disk (Store) or
	// is a no-op for PostgreSQL (WAL handles persistence).
	Flush(ctx context.Context) error

	// Close releases resources. For Store this stops the flusher.
	// For PostgresStore this closes the connection pool.
	Close() error
}

// IOCQuery defines filter criteria for querying IOCs. All fields are
// optional; zero values mean "match all". This enables the /check
// endpoint to serve indexed queries instead of scanning the entire
// in-memory store.
type IOCQuery struct {
	// Type filters by IOC type (e.g., "proxy_response", "prompt_injection").
	// Empty string means "match all types".
	Type IOCType

	// Severity filters by severity. If SeverityMin is set, only
	// IOCs with severity >= SeverityMin are returned.
	SeverityMin Severity

	// Category filters by Lens category (e.g., "pii_email", "secret_api_key").
	// Empty string means "match all categories".
	Category string

	// SourceProvider filters by AI provider (e.g., "chatgpt", "claude").
	// Empty string means "match all providers".
	SourceProvider string

	// AffectsLens filters IOCs that should be propagated to Lens.
	// nil means "match all" (both true and false).
	AffectsLens *bool

	// AffectsGateway filters IOCs that should be propagated to Gateway.
	// nil means "match all" (both true and false).
	AffectsGateway *bool

	// Since filters IOCs with LastSeen >= Since. Zero time means
	// "match all time ranges".
	Since time.Time

	// Limit caps the number of results. 0 means no limit.
	Limit int

	// Offset is the number of results to skip (for pagination).
	Offset int
}