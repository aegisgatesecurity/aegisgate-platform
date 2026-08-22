// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — Legal Hold Service (v4.3.1)
//
// legalhold.go provides e-discovery compliance by freezing data
// deletion for users/agents under litigation hold. When a hold is
// active, DSAR erasure requests and retention pruning must skip
// the held entity's data.
//
// Design:
//   - In-memory store with optional Postgres backing (future)
//   - Holds scoped by UserID or AgentID
//   - Hold metadata: reason, issuedBy, createdAt, releasedAt
//   - IsUnderHold(ctx, entityID) is the check function called by
//     DSAR erasure and retention pruning

package legalhold

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Hold represents a legal hold on a specific entity.
type Hold struct {
	ID         string    `json:"id"`
	EntityID   string    `json:"entity_id"`   // user ID or agent ID
	EntityType string    `json:"entity_type"` // "user" or "agent"
	Reason     string    `json:"reason"`      // legal case reference
	IssuedBy   string    `json:"issued_by"`   // admin who placed the hold
	CreatedAt  time.Time `json:"created_at"`
	ReleasedAt time.Time `json:"released_at,omitempty"` // zero = active
	TenantID   string    `json:"tenant_id,omitempty"`   // tenant scope
}

// IsActive returns true if the hold has not been released.
func (h *Hold) IsActive() bool {
	return h.ReleasedAt.IsZero()
}

// Store is the persistence interface for legal holds.
// Implementations: in-memory (default), PostgresStore (optional).
type Store interface {
	Create(ctx context.Context, h *Hold) error
	Release(ctx context.Context, holdID string) error
	IsUnderHold(ctx context.Context, entityID string) bool
	GetActiveHolds(ctx context.Context, entityID string) []*Hold
	List(ctx context.Context) []*Hold
	Get(ctx context.Context, holdID string) (*Hold, error)
}

// Service manages legal holds.
type Service struct {
	mu    sync.RWMutex
	holds map[string]*Hold // hold ID → Hold
	store Store            // optional persistent backing
}

// NewService creates a new legal hold service.
func NewService() *Service {
	return &Service{
		holds: make(map[string]*Hold),
	}
}

// SetStore sets a persistent backing store (e.g., PostgresStore).
// When a store is set, all operations delegate to it instead of the
// in-memory map. The in-memory map is kept as a fallback.
func (s *Service) SetStore(store Store) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store = store
}

// CreateHold places a legal hold on an entity.
func (s *Service) CreateHold(ctx context.Context, entityID, entityType, reason, issuedBy string) (*Hold, error) {
	if entityID == "" {
		return nil, fmt.Errorf("entity_id is required")
	}
	if reason == "" {
		return nil, fmt.Errorf("reason is required")
	}

	hold := &Hold{
		ID:         fmt.Sprintf("hold_%d", time.Now().UnixNano()),
		EntityID:   entityID,
		EntityType: entityType,
		Reason:     reason,
		IssuedBy:   issuedBy,
		CreatedAt:  time.Now().UTC(),
	}

	if s.store != nil {
		if err := s.store.Create(ctx, hold); err != nil {
			return nil, fmt.Errorf("persist hold: %w", err)
		}
		return hold, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.holds[hold.ID] = hold
	return hold, nil
}

// ReleaseHold releases a legal hold by its ID.
func (s *Service) ReleaseHold(ctx context.Context, holdID string) error {
	if s.store != nil {
		return s.store.Release(ctx, holdID)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	hold, exists := s.holds[holdID]
	if !exists {
		return fmt.Errorf("hold %s not found", holdID)
	}

	hold.ReleasedAt = time.Now().UTC()
	return nil
}

// IsUnderHold checks if an entity has any active legal hold.
// This is the check function called by DSAR erasure and retention pruning.
func (s *Service) IsUnderHold(ctx context.Context, entityID string) bool {
	if s.store != nil {
		return s.store.IsUnderHold(ctx, entityID)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, h := range s.holds {
		if h.EntityID == entityID && h.IsActive() {
			return true
		}
	}
	return false
}

// GetActiveHolds returns all active holds for an entity.
func (s *Service) GetActiveHolds(ctx context.Context, entityID string) []*Hold {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*Hold
	for _, h := range s.holds {
		if h.EntityID == entityID && h.IsActive() {
			result = append(result, h)
		}
	}
	return result
}

// ListHolds returns all holds (active and released).
func (s *Service) ListHolds(ctx context.Context) []*Hold {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*Hold, 0, len(s.holds))
	for _, h := range s.holds {
		result = append(result, h)
	}
	return result
}

// GetHold retrieves a single hold by ID.
func (s *Service) GetHold(ctx context.Context, holdID string) (*Hold, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	hold, exists := s.holds[holdID]
	if !exists {
		return nil, fmt.Errorf("hold %s not found", holdID)
	}
	return hold, nil
}
