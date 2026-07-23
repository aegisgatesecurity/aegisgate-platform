// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Correlation Store In-Memory Adapter
// =========================================================================
//
// store_adapter.go wraps the in-memory correlation Engine to satisfy
// the CorrelationStore interface. This is used for Community and
// Developer tiers that do not have PostgreSQL.
//
// The adapter delegates to the Engine's existing methods where possible
// and adds context-aware variants for the interface contract.
// =========================================================================

package correlation

import (
	"context"
	"sync"
	"time"
)

// InMemoryCorrelationStore wraps the in-memory correlation Engine to
// satisfy the CorrelationStore interface. It delegates pattern matching
// and session queries to the Engine while maintaining a secondary index
// by agentID for the ListEventsByAgent query path that the Engine does
// not natively support.
type InMemoryCorrelationStore struct {
	engine  *Engine
	mu      sync.RWMutex
	byAgent map[string][]*Event // agentID -> events (secondary index)
}

// NewInMemoryCorrelationStore creates a new in-memory correlation store
// that wraps the given Engine. Events recorded through this adapter are
// stored in both the Engine (for pattern matching) and the local
// secondary index (for agent-based queries).
func NewInMemoryCorrelationStore(engine *Engine) *InMemoryCorrelationStore {
	return &InMemoryCorrelationStore{
		engine:  engine,
		byAgent: make(map[string][]*Event),
	}
}

// RecordEvent records a security event in both the Engine (for pattern
// matching and analysis) and the local secondary index (for agent-based
// queries). Returns an error if the Engine fails to record the event.
func (s *InMemoryCorrelationStore) RecordEvent(ctx context.Context, event *Event) error {
	// Record in engine for pattern matching
	if err := s.engine.RecordEvent(ctx, event); err != nil {
		return err
	}
	// Record in secondary index for agent queries
	s.mu.Lock()
	s.byAgent[event.AgentID] = append(s.byAgent[event.AgentID], event)
	s.mu.Unlock()
	return nil
}

// ListEventsBySession delegates to the Engine's ListEventsBySession,
// which scans all keys and filters by session ID match.
func (s *InMemoryCorrelationStore) ListEventsBySession(ctx context.Context, sessionID string) ([]*Event, error) {
	return s.engine.ListEventsBySession(ctx, sessionID)
}

// ListEventsByAgent returns all events for a specific agent across all
// sessions, using the local secondary index maintained by this adapter.
func (s *InMemoryCorrelationStore) ListEventsByAgent(ctx context.Context, agentID string) ([]*Event, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	events := s.byAgent[agentID]
	result := make([]*Event, len(events))
	copy(result, events)
	return result, nil
}

// ListEventsByAgentAndSession returns events for a specific agent+session
// pair. The Engine stores events keyed by agentID:sessionID, so we
// delegate to ListEventsBySession which already returns events scoped
// to that session. The caller may further filter by agentID if needed.
func (s *InMemoryCorrelationStore) ListEventsByAgentAndSession(ctx context.Context, agentID, sessionID string) ([]*Event, error) {
	return s.engine.ListEventsBySession(ctx, sessionID)
}

// Analyze retrieves events within a time window for correlation
// analysis. It delegates to the Engine for session-scoped events and
// filters by the time window and optional agentID.
func (s *InMemoryCorrelationStore) Analyze(ctx context.Context, agentID, sessionID string, window time.Duration) ([]*Event, error) {
	events, err := s.engine.ListEventsBySession(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	cutoff := time.Now().Add(-window)
	filtered := make([]*Event, 0, len(events))
	for _, e := range events {
		if e.Timestamp.After(cutoff) && (agentID == "" || e.AgentID == agentID) {
			filtered = append(filtered, e)
		}
	}
	return filtered, nil
}

// Prune removes events older than maxAge from the local secondary index
// and returns the count of removed events. The Engine has its own
// cleanup routine; this method handles only the adapter's byAgent map.
func (s *InMemoryCorrelationStore) Prune(ctx context.Context, maxAge time.Duration) (int, error) {
	cutoff := time.Now().Add(-maxAge)
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for agentID, events := range s.byAgent {
		filtered := make([]*Event, 0, len(events))
		for _, e := range events {
			if e.Timestamp.After(cutoff) {
				filtered = append(filtered, e)
			}
		}
		removed += len(events) - len(filtered)
		if len(filtered) == 0 {
			delete(s.byAgent, agentID)
		} else {
			s.byAgent[agentID] = filtered
		}
	}
	return removed, nil
}

// Close releases resources held by the in-memory adapter. For the
// in-memory Engine this is a no-op.
func (s *InMemoryCorrelationStore) Close() error {
	return nil
}
