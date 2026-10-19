// SPDX-License-Identifier: Apache-2.0
// Phase 4 unit tests for legal hold service store delegation paths.
// Covers SetStore, CreateHold with store, ReleaseHold with store,
// IsUnderHold with store, ListHolds, GetHold, and error paths.

package legalhold

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// --- mockStore for Service delegation tests ---

type mockStore struct {
	holds      map[string]*Hold
	createErr  error
	releaseErr error
}

func newMockStore() *mockStore {
	return &mockStore{holds: make(map[string]*Hold)}
}

func (m *mockStore) Create(ctx context.Context, h *Hold) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.holds[h.ID] = h
	return nil
}

func (m *mockStore) Release(ctx context.Context, holdID string) error {
	if m.releaseErr != nil {
		return m.releaseErr
	}
	if h, ok := m.holds[holdID]; ok {
		h.ReleasedAt = time.Now().UTC()
	}
	return nil
}

func (m *mockStore) IsUnderHold(ctx context.Context, entityID string) bool {
	for _, h := range m.holds {
		if h.EntityID == entityID && h.IsActive() {
			return true
		}
	}
	return false
}

func (m *mockStore) GetActiveHolds(ctx context.Context, entityID string) []*Hold {
	var result []*Hold
	for _, h := range m.holds {
		if h.EntityID == entityID && h.IsActive() {
			result = append(result, h)
		}
	}
	return result
}

func (m *mockStore) List(ctx context.Context) []*Hold {
	result := make([]*Hold, 0, len(m.holds))
	for _, h := range m.holds {
		result = append(result, h)
	}
	return result
}

func (m *mockStore) Get(ctx context.Context, holdID string) (*Hold, error) {
	h, ok := m.holds[holdID]
	if !ok {
		return nil, fmt.Errorf("hold %s not found", holdID)
	}
	return h, nil
}

// --- SetStore tests ---

func TestPhase4_SetStore(t *testing.T) {
	s := NewService()
	store := newMockStore()
	s.SetStore(store)
	// Internal: store should be set. We verify by checking that
	// CreateHold delegates to the store.
	ctx := context.Background()
	hold, err := s.CreateHold(ctx, "user-store-test", "user", "Case #1", "admin")
	if err != nil {
		t.Fatalf("CreateHold with store: %v", err)
	}
	if _, ok := store.holds[hold.ID]; !ok {
		t.Fatal("hold was not persisted to store")
	}
}

// --- CreateHold with store ---

func TestPhase4_CreateHold_StoreError(t *testing.T) {
	s := NewService()
	store := newMockStore()
	store.createErr = fmt.Errorf("database error")
	s.SetStore(store)
	ctx := context.Background()
	_, err := s.CreateHold(ctx, "user-err", "user", "reason", "admin")
	if err == nil {
		t.Fatal("expected error from store.Create")
	}
}

// --- ReleaseHold with store ---

func TestPhase4_ReleaseHold_StoreSuccess(t *testing.T) {
	s := NewService()
	store := newMockStore()
	s.SetStore(store)
	ctx := context.Background()
	hold, _ := s.CreateHold(ctx, "user-rel", "user", "Case #1", "admin")
	if err := s.ReleaseHold(ctx, hold.ID); err != nil {
		t.Fatalf("ReleaseHold: %v", err)
	}
	// Verify the hold is released in the store
	if store.holds[hold.ID].IsActive() {
		t.Error("hold should be released in store")
	}
}

func TestPhase4_ReleaseHold_StoreError(t *testing.T) {
	s := NewService()
	store := newMockStore()
	store.releaseErr = fmt.Errorf("release error")
	s.SetStore(store)
	ctx := context.Background()
	if err := s.ReleaseHold(ctx, "any-hold-id"); err == nil {
		t.Fatal("expected error from store.Release")
	}
}

// --- IsUnderHold with store ---

func TestPhase4_IsUnderHold_StoreTrue(t *testing.T) {
	s := NewService()
	store := newMockStore()
	s.SetStore(store)
	ctx := context.Background()
	_, _ = s.CreateHold(ctx, "user-under-hold", "user", "Case #1", "admin")
	if !s.IsUnderHold(ctx, "user-under-hold") {
		t.Fatal("should be under hold via store")
	}
}

func TestPhase4_IsUnderHold_StoreFalse(t *testing.T) {
	s := NewService()
	store := newMockStore()
	s.SetStore(store)
	ctx := context.Background()
	if s.IsUnderHold(ctx, "user-not-held") {
		t.Fatal("should not be under hold")
	}
}

// --- ListHolds (in-memory only, no store delegation) ---

func TestPhase4_ListHolds_Empty(t *testing.T) {
	s := NewService()
	ctx := context.Background()
	holds := s.ListHolds(ctx)
	if len(holds) != 0 {
		t.Fatalf("expected 0 holds, got %d", len(holds))
	}
}

func TestPhase4_ListHolds_Multiple(t *testing.T) {
	s := NewService()
	ctx := context.Background()
	_, _ = s.CreateHold(ctx, "user-1", "user", "Case #1", "admin")
	_, _ = s.CreateHold(ctx, "user-2", "user", "Case #2", "admin")
	holds := s.ListHolds(ctx)
	if len(holds) != 2 {
		t.Fatalf("expected 2 holds, got %d", len(holds))
	}
}

// --- GetHold (in-memory only) ---

func TestPhase4_GetHold_Success(t *testing.T) {
	s := NewService()
	ctx := context.Background()
	hold, _ := s.CreateHold(ctx, "user-get", "user", "Case #1", "admin")
	got, err := s.GetHold(ctx, hold.ID)
	if err != nil {
		t.Fatalf("GetHold: %v", err)
	}
	if got.ID != hold.ID {
		t.Errorf("ID: got %q, want %q", got.ID, hold.ID)
	}
}

func TestPhase4_GetHold_NotFound(t *testing.T) {
	s := NewService()
	ctx := context.Background()
	_, err := s.GetHold(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent hold")
	}
}

// --- ReleaseHold in-memory (no store) ---

func TestPhase4_ReleaseHold_InMemoryNotFound(t *testing.T) {
	s := NewService()
	ctx := context.Background()
	if err := s.ReleaseHold(ctx, "nonexistent"); err == nil {
		t.Fatal("expected error for nonexistent hold")
	}
}

// --- CreateHold validation with store ---

func TestPhase4_CreateHold_ValidationWithStore(t *testing.T) {
	s := NewService()
	store := newMockStore()
	s.SetStore(store)
	ctx := context.Background()

	// Empty entityID
	_, err := s.CreateHold(ctx, "", "user", "reason", "admin")
	if err == nil {
		t.Fatal("should error on empty entityID even with store")
	}

	// Empty reason
	_, err = s.CreateHold(ctx, "user-1", "user", "", "admin")
	if err == nil {
		t.Fatal("should error on empty reason even with store")
	}
}

// --- GetActiveHolds (in-memory) ---

func TestPhase4_GetActiveHolds_WithReleased(t *testing.T) {
	s := NewService()
	ctx := context.Background()
	h1, _ := s.CreateHold(ctx, "user-multi", "user", "Case #1", "admin")
	_, _ = s.CreateHold(ctx, "user-multi", "user", "Case #2", "admin")

	// Release one
	_ = s.ReleaseHold(ctx, h1.ID)

	active := s.GetActiveHolds(ctx, "user-multi")
	if len(active) != 1 {
		t.Fatalf("expected 1 active hold, got %d", len(active))
	}
	if active[0].ID == h1.ID {
		t.Error("released hold should not be in active list")
	}
}

func TestPhase4_GetActiveHolds_NoMatch(t *testing.T) {
	s := NewService()
	ctx := context.Background()
	_, _ = s.CreateHold(ctx, "user-1", "user", "Case #1", "admin")
	active := s.GetActiveHolds(ctx, "user-nonexistent")
	if len(active) != 0 {
		t.Fatalf("expected 0 active holds for nonexistent user, got %d", len(active))
	}
}

// --- IsActive ---

func TestPhase4_HoldIsActive_Released(t *testing.T) {
	h := &Hold{
		ID:         "test-hold",
		EntityID:   "user-1",
		EntityType: "user",
		Reason:     "test",
		IssuedBy:   "admin",
		CreatedAt:  time.Now().UTC(),
		ReleasedAt: time.Now().UTC(),
	}
	if h.IsActive() {
		t.Error("released hold should not be active")
	}
}

func TestPhase4_HoldIsActive_Active(t *testing.T) {
	h := &Hold{
		ID:         "test-hold",
		EntityID:   "user-1",
		EntityType: "user",
		Reason:     "test",
		IssuedBy:   "admin",
		CreatedAt:  time.Now().UTC(),
	}
	if !h.IsActive() {
		t.Error("unreleased hold should be active")
	}
}
