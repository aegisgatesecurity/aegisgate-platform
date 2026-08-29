// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Cross-Protocol Threat Correlation (PostgreSQL Store)
// =========================================================================
//
// postgres_store.go implements CorrelationStore backed by PostgreSQL using
// pgx/v5. This is the persistent storage backend for correlation events,
// enabling SOC incident timelines and long-term threat analysis.
//
// Architecture:
//
//   - Connection pooling via shared pgxpool.Pool (NOT owned by this store)
//   - Batch inserts via pgx.Batch for RecordEventBatch
//   - Indexed queries for session, agent, and time-window lookups
//   - JSONB storage for Data and Metadata fields
//   - Retention pruning via Prune method
//   - Close is a no-op (pool lifecycle is managed externally)
//   - All pool access is wrapped with ioc.WithTenantContextOrPool so that
//     PostgreSQL Row-Level Security (RLS) policies enforce tenant isolation
//     at the database level (defense-in-depth).
//
// Lifecycle:
//
//   The pool is shared with the IOC PostgresStore or the persistence manager.
//   Migrations are run by the shared migration runner (pkg/ioc/migrations/),
//   NOT by this constructor. Callers must ensure migrations have been applied
//   before using this store.
//
// Thread safety:
//
//   All pgxpool operations are safe for concurrent use. The pool manages
//   its own connection lifecycle. The caller does NOT need to hold any
//   additional locks.
//
// v3.5.0+ D1 Phase 1A.
// =========================================================================

package correlation

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresCorrelationStore implements CorrelationStore backed by PostgreSQL.
type PostgresCorrelationStore struct {
	pool *pgxpool.Pool
}

// NewPostgresCorrelationStore creates a new PostgresCorrelationStore using
// the provided pool. The pool is NOT owned by this store; the caller is
// responsible for pool lifecycle (including Close).
//
// Migrations are NOT run here — they are handled by the shared migration
// runner in pkg/ioc/migrations/.
func NewPostgresCorrelationStore(pool *pgxpool.Pool) *PostgresCorrelationStore {
	return &PostgresCorrelationStore{pool: pool}
}

// RecordEvent persists a single correlation event.
func (s *PostgresCorrelationStore) RecordEvent(ctx context.Context, event *Event) error {
	if event == nil {
		return fmt.Errorf("correlation: RecordEvent: event is nil")
	}

	dataJSON, err := json.Marshal(event.Data)
	if err != nil {
		return fmt.Errorf("correlation: marshal data: %w", err)
	}

	metadataJSON, err := json.Marshal(event.Metadata)
	if err != nil {
		return fmt.Errorf("correlation: marshal metadata: %w", err)
	}

	tenantID, isAdmin := ioc.TenantFromContext(ctx)
	return ioc.WithTenantContextOrPool(ctx, s.pool, tenantID, isAdmin, func(q ioc.DBQuerier) error {
		_, err := q.Exec(ctx,
			`INSERT INTO correlation_events (
				id, protocol, agent_id, session_id, event_type, severity,
				decision, data, metadata, event_time, tenant_id
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
			event.ID, event.Protocol, event.AgentID, event.SessionID,
			event.EventType, event.Severity, event.Decision,
			dataJSON, metadataJSON, event.Timestamp, tenantID,
		)
		if err != nil {
			return fmt.Errorf("correlation: record event: %w", err)
		}
		return nil
	})
}

// ListEventsBySession returns events for the given session ID, ordered by
// event_time ascending. Uses idx_correlation_events_session.
func (s *PostgresCorrelationStore) ListEventsBySession(ctx context.Context, sessionID string) ([]*Event, error) {
	if sessionID == "" {
		return nil, fmt.Errorf("correlation: ListEventsBySession: sessionID is required")
	}

	tenantID, isAdmin := ioc.TenantFromContext(ctx)
	var events []*Event
	err := ioc.WithTenantContextOrPool(ctx, s.pool, tenantID, isAdmin, func(q ioc.DBQuerier) error {
		rows, err := q.Query(ctx,
			`SELECT id, protocol, agent_id, session_id, event_type, severity,
				decision, data, metadata, event_time
			FROM correlation_events
			WHERE session_id = $1
			ORDER BY event_time ASC`,
			sessionID,
		)
		if err != nil {
			return fmt.Errorf("correlation: list events by session: %w", err)
		}
		defer rows.Close()
		events, err = scanEvents(rows)
		return err
	})
	if err != nil {
		return nil, err
	}
	return events, nil
}

// ListEventsByAgent returns events for the given agent ID, ordered by
// event_time ascending. Uses idx_correlation_events_agent.
func (s *PostgresCorrelationStore) ListEventsByAgent(ctx context.Context, agentID string) ([]*Event, error) {
	if agentID == "" {
		return nil, fmt.Errorf("correlation: ListEventsByAgent: agentID is required")
	}

	tenantID, isAdmin := ioc.TenantFromContext(ctx)
	var events []*Event
	err := ioc.WithTenantContextOrPool(ctx, s.pool, tenantID, isAdmin, func(q ioc.DBQuerier) error {
		rows, err := q.Query(ctx,
			`SELECT id, protocol, agent_id, session_id, event_type, severity,
				decision, data, metadata, event_time
			FROM correlation_events
			WHERE agent_id = $1
			ORDER BY event_time ASC`,
			agentID,
		)
		if err != nil {
			return fmt.Errorf("correlation: list events by agent: %w", err)
		}
		defer rows.Close()
		events, err = scanEvents(rows)
		return err
	})
	if err != nil {
		return nil, err
	}
	return events, nil
}

// ListEventsByAgentAndSession returns events for the given agent and session,
// ordered by event_time ascending. Uses idx_correlation_events_agent_session.
func (s *PostgresCorrelationStore) ListEventsByAgentAndSession(ctx context.Context, agentID, sessionID string) ([]*Event, error) {
	if agentID == "" {
		return nil, fmt.Errorf("correlation: ListEventsByAgentAndSession: agentID is required")
	}
	if sessionID == "" {
		return nil, fmt.Errorf("correlation: ListEventsByAgentAndSession: sessionID is required")
	}

	tenantID, isAdmin := ioc.TenantFromContext(ctx)
	var events []*Event
	err := ioc.WithTenantContextOrPool(ctx, s.pool, tenantID, isAdmin, func(q ioc.DBQuerier) error {
		rows, err := q.Query(ctx,
			`SELECT id, protocol, agent_id, session_id, event_type, severity,
				decision, data, metadata, event_time
			FROM correlation_events
			WHERE agent_id = $1 AND session_id = $2
			ORDER BY event_time ASC`,
			agentID, sessionID,
		)
		if err != nil {
			return fmt.Errorf("correlation: list events by agent and session: %w", err)
		}
		defer rows.Close()
		events, err = scanEvents(rows)
		return err
	})
	if err != nil {
		return nil, err
	}
	return events, nil
}

// Analyze returns recent events for the given agent and session within
// the specified time window, ordered by event_time ascending.
// Uses idx_correlation_events_agent_session.
func (s *PostgresCorrelationStore) Analyze(ctx context.Context, agentID, sessionID string, window time.Duration) ([]*Event, error) {
	if agentID == "" {
		return nil, fmt.Errorf("correlation: Analyze: agentID is required")
	}
	if sessionID == "" {
		return nil, fmt.Errorf("correlation: Analyze: sessionID is required")
	}

	cutoff := time.Now().UTC().Add(-window)

	tenantID, isAdmin := ioc.TenantFromContext(ctx)
	var events []*Event
	err := ioc.WithTenantContextOrPool(ctx, s.pool, tenantID, isAdmin, func(q ioc.DBQuerier) error {
		rows, err := q.Query(ctx,
			`SELECT id, protocol, agent_id, session_id, event_type, severity,
				decision, data, metadata, event_time
			FROM correlation_events
			WHERE agent_id = $1 AND session_id = $2 AND event_time > $3
			ORDER BY event_time ASC`,
			agentID, sessionID, cutoff,
		)
		if err != nil {
			return fmt.Errorf("correlation: analyze: %w", err)
		}
		defer rows.Close()
		events, err = scanEvents(rows)
		return err
	})
	if err != nil {
		return nil, err
	}
	return events, nil
}

// Prune removes correlation events older than maxAge and returns the count removed.
// Uses idx_correlation_events_created_at for efficient pruning.
func (s *PostgresCorrelationStore) Prune(ctx context.Context, maxAge time.Duration) (int, error) {
	cutoff := time.Now().UTC().Add(-maxAge)

	tenantID, isAdmin := ioc.TenantFromContext(ctx)
	var count int
	err := ioc.WithTenantContextOrPool(ctx, s.pool, tenantID, isAdmin, func(q ioc.DBQuerier) error {
		result, err := q.Exec(ctx,
			`DELETE FROM correlation_events WHERE event_time < $1`,
			cutoff,
		)
		if err != nil {
			return fmt.Errorf("correlation: prune events: %w", err)
		}
		count = int(result.RowsAffected())
		return nil
	})
	if err != nil {
		return 0, err
	}
	return count, nil
}

// Close is a no-op. The pool is shared and its lifecycle is managed
// externally (by the IOC PostgresStore or persistence manager).
func (s *PostgresCorrelationStore) Close() error {
	return nil
}

// scanEvents is a helper that scans pgx rows into a slice of Event pointers.
func scanEvents(rows pgx.Rows) ([]*Event, error) {
	var events []*Event
	for rows.Next() {
		var e Event
		var dataJSON []byte
		var metadataJSON []byte

		if err := rows.Scan(
			&e.ID, &e.Protocol, &e.AgentID, &e.SessionID,
			&e.EventType, &e.Severity, &e.Decision,
			&dataJSON, &metadataJSON, &e.Timestamp,
		); err != nil {
			return nil, fmt.Errorf("correlation: scan event: %w", err)
		}

		if err := json.Unmarshal(dataJSON, &e.Data); err != nil {
			e.Data = make(map[string]interface{})
		}
		if e.Data == nil {
			e.Data = make(map[string]interface{})
		}

		if err := json.Unmarshal(metadataJSON, &e.Metadata); err != nil {
			e.Metadata = make(map[string]string)
		}
		if e.Metadata == nil {
			e.Metadata = make(map[string]string)
		}

		events = append(events, &e)
	}
	return events, nil
}
