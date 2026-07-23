// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Correlation Store Interface (v3.5.0+ D1 PostgreSQL)
// =========================================================================
//
// store_interface.go defines the CorrelationStore interface that both the
// in-memory Engine and a future PostgresStore will implement. This allows
// the platform to switch storage backends based on tier and configuration:
//
//   - Community/Developer tiers → in-memory Engine with map-based storage
//   - Professional/Enterprise tiers → PostgresStore with pgx/v5 (new)
//
// The interface preserves the existing Engine's semantics while adding
// query capabilities that PostgreSQL enables. The in-memory Engine
// delegates to its existing map[string][]*Event when serving StoreInterface
// methods.
//
// Tier gating: FeaturePostgreSQL is required for PostgresStore. The
// platform startup code checks this feature flag and falls back to
// in-memory Engine if PostgreSQL is not available or not entitled.
//
// v3.5.0+ D1 Phase 1A.
// =========================================================================

package correlation

import (
	"context"
	"time"
)

// CorrelationStore is the contract that both the in-memory Engine and
// PostgresStore implement. All methods accept a context for PostgreSQL
// cancellation and timeout support. The in-memory Engine ignores the
// context parameter where it delegates to its existing map-based storage.
type CorrelationStore interface {
	// RecordEvent persists a security event. If the event already
	// exists (same ID), it is updated in place. Returns nil on
	// success.
	RecordEvent(ctx context.Context, event *Event) error

	// ListEventsBySession returns all events for a session across
	// all agents. The events are returned in insertion order; the
	// caller should sort by timestamp if needed. Returns nil (not
	// an error) if no events match.
	ListEventsBySession(ctx context.Context, sessionID string) ([]*Event, error)

	// ListEventsByAgent returns all events for a specific agent,
	// across all sessions. Returns nil (not an error) if no events
	// match.
	ListEventsByAgent(ctx context.Context, agentID string) ([]*Event, error)

	// ListEventsByAgentAndSession returns events for a specific
	// agent+session pair. This is the primary query path used by
	// the correlation analysis engine. Returns nil (not an error)
	// if no events match.
	ListEventsByAgentAndSession(ctx context.Context, agentID, sessionID string) ([]*Event, error)

	// Analyze retrieves events within a time window for correlation
	// analysis. The window is measured backwards from the current
	// time. This is the indexed query path that PostgreSQL enables;
	// the in-memory Engine falls back to a linear scan with
	// timestamp filtering.
	Analyze(ctx context.Context, agentID, sessionID string, window time.Duration) ([]*Event, error)

	// Prune removes events older than maxAge and returns the count
	// of removed events.
	Prune(ctx context.Context, maxAge time.Duration) (int, error)

	// Close releases resources. For the in-memory Engine this is a
	// no-op. For PostgresStore this closes the connection pool.
	Close() error
}

// CorrelationQuery defines filter criteria for querying events. All
// fields are optional; zero values mean "match all". This enables the
// correlation analysis endpoint to serve indexed queries instead of
// scanning the entire in-memory store.
type CorrelationQuery struct {
	// Protocol filters by protocol (e.g., "mcp", "a2a", "anp").
	// Empty string means "match all protocols".
	Protocol string

	// AgentID filters by agent ID. Empty string means "match all".
	AgentID string

	// SessionID filters by session ID. Empty string means "match all".
	SessionID string

	// EventType filters by event type (e.g., "error", "request").
	// Empty string means "match all types".
	EventType string

	// SeverityMin filters by minimum severity. Only events with
	// severity >= SeverityMin are returned. Empty string means
	// "match all severities".
	SeverityMin string

	// Since filters events with Timestamp >= Since. Zero time
	// means "match all time ranges".
	Since time.Time

	// Until filters events with Timestamp < Until. Zero time
	// means "no upper bound".
	Until time.Time

	// Limit caps the number of results. 0 means no limit.
	Limit int

	// Offset is the number of results to skip (for pagination).
	Offset int
}
