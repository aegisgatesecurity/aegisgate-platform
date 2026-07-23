// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Attestation In-Memory Store (v3.8 Persistence)
// =========================================================================
//
// memory_store.go implements AttestationStore with an in-memory map.
// This is the storage backend for Community and Developer tiers that
// do not have PostgreSQL configured.
//
// The in-memory store is sufficient for single-instance deployments
// where attestation envelopes are generated and verified in-process.
// Envelopes are lost on process restart; for durability, use
// PostgresAttestationStore (Professional/Enterprise tiers).
//
// Thread safety: all methods are protected by sync.RWMutex.
//
// v3.8 persistence gap closure.
// =========================================================================

package attestation

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Compile-time interface compliance check.
var _ AttestationStore = (*InMemoryAttestationStore)(nil)

// InMemoryAttestationStore implements AttestationStore with an in-memory map.
// Safe for concurrent use. Envelopes are lost on process restart.
type InMemoryAttestationStore struct {
	mu        sync.RWMutex
	byID      map[string]*Envelope
	byType    map[string][]string // type -> envelope IDs (insertion order)
	bySubject map[string][]string // subject -> envelope IDs
	byIssuer  map[string][]string // issuer -> envelope IDs
}

// NewInMemoryAttestationStore creates a new empty in-memory store.
func NewInMemoryAttestationStore() *InMemoryAttestationStore {
	return &InMemoryAttestationStore{
		byID:      make(map[string]*Envelope),
		byType:    make(map[string][]string),
		bySubject: make(map[string][]string),
		byIssuer:  make(map[string][]string),
	}
}

// Store persists a signed envelope. Returns an error if an envelope
// with the same ID already exists (envelopes are immutable).
func (s *InMemoryAttestationStore) Store(_ context.Context, envelope *Envelope) error {
	if envelope == nil {
		return fmt.Errorf("attestation: Store: nil envelope")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.byID[envelope.ID]; exists {
		return fmt.Errorf("attestation: Store: envelope %s already exists", envelope.ID)
	}

	s.byID[envelope.ID] = envelope
	s.byType[string(envelope.Type)] = append(s.byType[string(envelope.Type)], envelope.ID)
	s.bySubject[envelope.Subject] = append(s.bySubject[envelope.Subject], envelope.ID)
	s.byIssuer[envelope.Issuer] = append(s.byIssuer[envelope.Issuer], envelope.ID)

	return nil
}

// Get retrieves an envelope by its ID. Returns nil if not found.
func (s *InMemoryAttestationStore) Get(_ context.Context, id string) (*Envelope, error) {
	if id == "" {
		return nil, fmt.Errorf("attestation: Get: empty id")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.byID[id], nil
}

// ListByType returns envelopes of a specific type, ordered by issued_at
// descending (newest first).
func (s *InMemoryAttestationStore) ListByType(_ context.Context, attestationType Type, limit, offset int) ([]*Envelope, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ids := s.byType[string(attestationType)]
	return s.getEnvelopesSorted(ids, limit, offset)
}

// ListBySubject returns envelopes for a specific subject, ordered by
// issued_at descending (newest first).
func (s *InMemoryAttestationStore) ListBySubject(_ context.Context, subject string, limit, offset int) ([]*Envelope, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ids := s.bySubject[subject]
	return s.getEnvelopesSorted(ids, limit, offset)
}

// ListByIssuer returns envelopes signed by a specific issuer/key,
// ordered by issued_at descending.
func (s *InMemoryAttestationStore) ListByIssuer(_ context.Context, issuer string, limit, offset int) ([]*Envelope, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ids := s.byIssuer[issuer]
	return s.getEnvelopesSorted(ids, limit, offset)
}

// ListByTimeRange returns envelopes issued within a time range,
// ordered by issued_at descending.
func (s *InMemoryAttestationStore) ListByTimeRange(_ context.Context, from, to time.Time, limit, offset int) ([]*Envelope, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var filtered []*Envelope
	for _, env := range s.byID {
		if (env.IssuedAt.Equal(from) || env.IssuedAt.After(from)) &&
			(env.IssuedAt.Equal(to) || env.IssuedAt.Before(to)) {
			filtered = append(filtered, env)
		}
	}

	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].IssuedAt.After(filtered[j].IssuedAt)
	})

	if offset > 0 {
		if offset >= len(filtered) {
			return nil, nil
		}
		filtered = filtered[offset:]
	}
	if limit > 0 && len(filtered) > limit {
		filtered = filtered[:limit]
	}

	return filtered, nil
}

// PruneExpired removes envelopes whose valid_until is before the cutoff
// time. Returns the count of removed envelopes.
func (s *InMemoryAttestationStore) PruneExpired(_ context.Context, cutoff time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	removed := 0
	for id, env := range s.byID {
		if env.ValidUntil.IsZero() {
			continue // no expiration
		}
		if env.ValidUntil.Before(cutoff) {
			delete(s.byID, id)
			s.removeFromIndex(s.byType, string(env.Type), id)
			s.removeFromIndex(s.bySubject, env.Subject, id)
			s.removeFromIndex(s.byIssuer, env.Issuer, id)
			removed++
		}
	}
	return removed, nil
}

// CountByType returns the number of envelopes of a specific type.
func (s *InMemoryAttestationStore) CountByType(_ context.Context, attestationType Type) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return len(s.byType[string(attestationType)]), nil
}

// Close is a no-op for the in-memory store.
func (s *InMemoryAttestationStore) Close() error {
	return nil
}

// getEnvelopesSorted resolves IDs to envelopes, sorts by issued_at descending,
// and applies limit/offset pagination.
func (s *InMemoryAttestationStore) getEnvelopesSorted(ids []string, limit, offset int) ([]*Envelope, error) {
	envelopes := make([]*Envelope, 0, len(ids))
	for _, id := range ids {
		if env, ok := s.byID[id]; ok {
			envelopes = append(envelopes, env)
		}
	}

	sort.Slice(envelopes, func(i, j int) bool {
		return envelopes[i].IssuedAt.After(envelopes[j].IssuedAt)
	})

	if offset > 0 {
		if offset >= len(envelopes) {
			return nil, nil
		}
		envelopes = envelopes[offset:]
	}
	if limit > 0 && len(envelopes) > limit {
		envelopes = envelopes[:limit]
	}

	return envelopes, nil
}

// removeFromIndex removes an ID from a string->[]string index map.
func (s *InMemoryAttestationStore) removeFromIndex(idx map[string][]string, key, id string) {
	ids := idx[key]
	for i, v := range ids {
		if v == id {
			idx[key] = append(ids[:i], ids[i+1:]...)
			return
		}
	}
}
