// SPDX-License-Identifier: Apache-2.0
//go:build integration

// Phase 4 integration tests for legal hold PostgresStore.
// Uses testcontainers to spin up an ephemeral PostgreSQL container.
// Run with: go test -tags=integration -count=1 ./pkg/legalhold/...

package legalhold

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/testdb"
)

func setupLegalHoldStore(t *testing.T) (*PostgresStore, func()) {
	t.Helper()
	pgStore, dbCleanup := testdb.SetupTestDB(t)
	store, err := NewPostgresStore(pgStore.Pool())
	if err != nil {
		dbCleanup()
		t.Fatalf("NewPostgresStore: %v", err)
	}
	cleanup := func() {
		dbCleanup()
	}
	return store, cleanup
}

func makeTestHold(entityID, reason, issuedBy string) *Hold {
	return &Hold{
		ID:         fmt.Sprintf("hold_%d", time.Now().UnixNano()),
		EntityID:   entityID,
		EntityType: "user",
		Reason:     reason,
		IssuedBy:   issuedBy,
		CreatedAt:  time.Now().UTC(),
	}
}

func TestPhase4_PostgresStore_CreateAndGet(t *testing.T) {
	store, cleanup := setupLegalHoldStore(t)
	defer cleanup()
	ctx := context.Background()

	hold := makeTestHold("user-pg-1", "Case #CV-2026-001", "admin@corp.com")
	if err := store.Create(ctx, hold); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := store.Get(ctx, hold.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != hold.ID {
		t.Errorf("ID: got %q, want %q", got.ID, hold.ID)
	}
	if got.EntityID != hold.EntityID {
		t.Errorf("EntityID: got %q, want %q", got.EntityID, hold.EntityID)
	}
	if got.Reason != hold.Reason {
		t.Errorf("Reason: got %q, want %q", got.Reason, hold.Reason)
	}
	if got.IssuedBy != hold.IssuedBy {
		t.Errorf("IssuedBy: got %q, want %q", got.IssuedBy, hold.IssuedBy)
	}
	if !got.IsActive() {
		t.Error("new hold should be active")
	}
}

func TestPhase4_PostgresStore_Get_NotFound(t *testing.T) {
	store, cleanup := setupLegalHoldStore(t)
	defer cleanup()
	ctx := context.Background()

	_, err := store.Get(ctx, "nonexistent-hold-id")
	if err == nil {
		t.Fatal("expected error for nonexistent hold")
	}
}

func TestPhase4_PostgresStore_IsUnderHold(t *testing.T) {
	store, cleanup := setupLegalHoldStore(t)
	defer cleanup()
	ctx := context.Background()

	// Before creating hold — should be false
	if store.IsUnderHold(ctx, "user-pg-2") {
		t.Fatal("should not be under hold before creation")
	}

	hold := makeTestHold("user-pg-2", "Case #2", "admin")
	if err := store.Create(ctx, hold); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// After creating hold — should be true
	if !store.IsUnderHold(ctx, "user-pg-2") {
		t.Fatal("should be under hold after creation")
	}
}

func TestPhase4_PostgresStore_Release(t *testing.T) {
	store, cleanup := setupLegalHoldStore(t)
	defer cleanup()
	ctx := context.Background()

	hold := makeTestHold("user-pg-3", "Case #3", "admin")
	if err := store.Create(ctx, hold); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if !store.IsUnderHold(ctx, "user-pg-3") {
		t.Fatal("should be under hold before release")
	}

	if err := store.Release(ctx, hold.ID); err != nil {
		t.Fatalf("Release: %v", err)
	}

	if store.IsUnderHold(ctx, "user-pg-3") {
		t.Fatal("should not be under hold after release")
	}

	// Verify Get shows released
	got, _ := store.Get(ctx, hold.ID)
	if got.IsActive() {
		t.Error("hold should be released after Release")
	}
}

func TestPhase4_PostgresStore_GetActiveHolds(t *testing.T) {
	store, cleanup := setupLegalHoldStore(t)
	defer cleanup()
	ctx := context.Background()

	hold1 := makeTestHold("user-pg-4", "Case #4a", "admin")
	hold2 := makeTestHold("user-pg-4", "Case #4b", "admin")
	hold3 := makeTestHold("user-pg-4", "Case #4c", "admin")

	_ = store.Create(ctx, hold1)
	_ = store.Create(ctx, hold2)
	_ = store.Create(ctx, hold3)

	// Release one
	_ = store.Release(ctx, hold2.ID)

	active := store.GetActiveHolds(ctx, "user-pg-4")
	if len(active) != 2 {
		t.Fatalf("expected 2 active holds, got %d", len(active))
	}

	// Verify released hold is not in active list
	for _, h := range active {
		if h.ID == hold2.ID {
			t.Error("released hold should not be in active list")
		}
	}
}

func TestPhase4_PostgresStore_GetActiveHolds_Empty(t *testing.T) {
	store, cleanup := setupLegalHoldStore(t)
	defer cleanup()
	ctx := context.Background()

	active := store.GetActiveHolds(ctx, "user-nonexistent")
	if len(active) != 0 {
		t.Fatalf("expected 0 active holds, got %d", len(active))
	}
}

func TestPhase4_PostgresStore_List(t *testing.T) {
	store, cleanup := setupLegalHoldStore(t)
	defer cleanup()
	ctx := context.Background()

	hold1 := makeTestHold("user-pg-5a", "Case #5a", "admin")
	hold2 := makeTestHold("user-pg-5b", "Case #5b", "admin")

	_ = store.Create(ctx, hold1)
	_ = store.Create(ctx, hold2)
	_ = store.Release(ctx, hold2.ID)

	all := store.List(ctx)
	if len(all) != 2 {
		t.Fatalf("expected 2 total holds, got %d", len(all))
	}

	// Verify both active and released are in list
	foundReleased := false
	for _, h := range all {
		if h.ID == hold2.ID && !h.IsActive() {
			foundReleased = true
		}
	}
	if !foundReleased {
		t.Error("released hold should be in List result")
	}
}

func TestPhase4_PostgresStore_List_Empty(t *testing.T) {
	store, cleanup := setupLegalHoldStore(t)
	defer cleanup()
	ctx := context.Background()

	all := store.List(ctx)
	if len(all) != 0 {
		t.Fatalf("expected 0 holds, got %d", len(all))
	}
}

func TestPhase4_PostgresStore_Release_Nonexistent(t *testing.T) {
	store, cleanup := setupLegalHoldStore(t)
	defer cleanup()
	ctx := context.Background()

	// Release of nonexistent hold should not error (UPDATE with no match)
	if err := store.Release(ctx, "nonexistent-hold-id"); err != nil {
		t.Fatalf("Release nonexistent should not error: %v", err)
	}
}

func TestPhase4_PostgresStore_IsUnderHold_AfterRelease(t *testing.T) {
	store, cleanup := setupLegalHoldStore(t)
	defer cleanup()
	ctx := context.Background()

	hold := makeTestHold("user-pg-6", "Case #6", "admin")
	_ = store.Create(ctx, hold)
	_ = store.Release(ctx, hold.ID)

	if store.IsUnderHold(ctx, "user-pg-6") {
		t.Fatal("should not be under hold after release")
	}
}

func TestPhase4_PostgresStore_MultipleEntities(t *testing.T) {
	store, cleanup := setupLegalHoldStore(t)
	defer cleanup()
	ctx := context.Background()

	hold1 := makeTestHold("user-a", "Case A", "admin")
	hold1.EntityType = "user"
	hold2 := makeTestHold("agent-b", "Case B", "admin")
	hold2.EntityType = "agent"

	_ = store.Create(ctx, hold1)
	_ = store.Create(ctx, hold2)

	if !store.IsUnderHold(ctx, "user-a") {
		t.Error("user-a should be under hold")
	}
	if !store.IsUnderHold(ctx, "agent-b") {
		t.Error("agent-b should be under hold")
	}
	if store.IsUnderHold(ctx, "user-c") {
		t.Error("user-c should not be under hold")
	}

	all := store.List(ctx)
	if len(all) != 2 {
		t.Fatalf("expected 2 holds, got %d", len(all))
	}
}

func TestPhase4_Service_WithPostgresStore(t *testing.T) {
	pgStore, dbCleanup := testdb.SetupTestDB(t)
	defer dbCleanup()

	store, err := NewPostgresStore(pgStore.Pool())
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}

	svc := NewService()
	svc.SetStore(store)
	ctx := context.Background()

	// Create hold via service
	hold, err := svc.CreateHold(ctx, "user-svc-pg", "user", "Case #SVC", "admin@corp.com")
	if err != nil {
		t.Fatalf("CreateHold: %v", err)
	}

	// Verify via store directly
	got, err := store.Get(ctx, hold.ID)
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	if got.EntityID != "user-svc-pg" {
		t.Errorf("EntityID: got %q, want %q", got.EntityID, "user-svc-pg")
	}

	// Check IsUnderHold via service
	if !svc.IsUnderHold(ctx, "user-svc-pg") {
		t.Fatal("should be under hold via service")
	}

	// Release via service
	if err := svc.ReleaseHold(ctx, hold.ID); err != nil {
		t.Fatalf("ReleaseHold: %v", err)
	}

	// Verify released via store
	got, _ = store.Get(ctx, hold.ID)
	if got.IsActive() {
		t.Error("hold should be released")
	}
}
