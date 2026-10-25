// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — Agent Registry PostgreSQL Store Unit Tests (v5.0)
// =========================================================================
//
// Unit tests covering constructor behavior, nil-pool validation, and
// Close semantics without requiring a live PostgreSQL connection.
// Integration tests for SQL execution paths use //go:build integration
// with a real database via pkg/testdb.
// =========================================================================

package agentregistry

import (
	"context"
	"testing"
	"time"
)

// Test sentinel errors for mapPGError tests.
var errNoRows = errNotFound{}
var errTestOther = errTestOtherType{}

type errTestOtherType struct{}

func (errTestOtherType) Error() string { return "some other pgx error" }

// =====================================================================
// PostgresStore — Constructor
// =====================================================================

func TestNewPostgresStore_NilPool(t *testing.T) {
	// NewPostgresStore with nil pool should fail at ensureSchema
	// because WithTenantContextOrPool checks for nil pool.
	_, err := NewPostgresStore(nil)
	if err == nil {
		t.Error("NewPostgresStore(nil) should return an error (schema creation fails)")
	}
}

// =====================================================================
// PostgresStore — Input Validation (nil pool)
// =====================================================================

func TestPostgresStore_Get_NilPool(t *testing.T) {
	// Construct store by bypassing NewPostgresStore (skip schema).
	store := &PostgresStore{pool: nil}
	ctx := context.Background()

	_, err := store.Get(ctx, "agent-1")
	if err == nil {
		t.Error("Get with nil pool should return an error")
	}
}

func TestPostgresStore_List_NilPool(t *testing.T) {
	store := &PostgresStore{pool: nil}
	ctx := context.Background()

	_, err := store.List(ctx, nil)
	if err == nil {
		t.Error("List with nil pool should return an error")
	}
}

func TestPostgresStore_Upsert_NilPool(t *testing.T) {
	store := &PostgresStore{pool: nil}
	ctx := context.Background()

	err := store.Upsert(ctx, &AgentRecord{ID: "agent-1"})
	if err == nil {
		t.Error("Upsert with nil pool should return an error")
	}
}

func TestPostgresStore_Delete_NilPool(t *testing.T) {
	store := &PostgresStore{pool: nil}
	ctx := context.Background()

	err := store.Delete(ctx, "agent-1")
	if err == nil {
		t.Error("Delete with nil pool should return an error")
	}
}

func TestPostgresStore_Close(t *testing.T) {
	store := &PostgresStore{pool: nil}
	if err := store.Close(); err != nil {
		t.Errorf("Close should be a no-op returning nil, got: %v", err)
	}
}

// =====================================================================
// PostgresPolicyStore — Constructor
// =====================================================================

func TestNewPostgresPolicyStore_NilPool(t *testing.T) {
	_, err := NewPostgresPolicyStore(nil)
	if err == nil {
		t.Error("NewPostgresPolicyStore(nil) should return an error")
	}
}

// =====================================================================
// PostgresPolicyStore — Input Validation (nil pool)
// =====================================================================

func TestPostgresPolicyStore_GetPolicy_NilPool(t *testing.T) {
	store := &PostgresPolicyStore{pool: nil}
	ctx := context.Background()

	_, err := store.GetPolicy(ctx, "pol-1")
	if err == nil {
		t.Error("GetPolicy with nil pool should return an error")
	}
}

func TestPostgresPolicyStore_ListPolicies_NilPool(t *testing.T) {
	store := &PostgresPolicyStore{pool: nil}
	ctx := context.Background()

	_, err := store.ListPolicies(ctx)
	if err == nil {
		t.Error("ListPolicies with nil pool should return an error")
	}
}

func TestPostgresPolicyStore_UpsertPolicy_NilPool(t *testing.T) {
	store := &PostgresPolicyStore{pool: nil}
	ctx := context.Background()

	err := store.UpsertPolicy(ctx, &LifecyclePolicy{ID: "pol-1", Name: "Test"})
	if err == nil {
		t.Error("UpsertPolicy with nil pool should return an error")
	}
}

func TestPostgresPolicyStore_DeletePolicy_NilPool(t *testing.T) {
	store := &PostgresPolicyStore{pool: nil}
	ctx := context.Background()

	err := store.DeletePolicy(ctx, "pol-1")
	if err == nil {
		t.Error("DeletePolicy with nil pool should return an error")
	}
}

func TestPostgresPolicyStore_Close(t *testing.T) {
	store := &PostgresPolicyStore{pool: nil}
	if err := store.Close(); err != nil {
		t.Errorf("Close should be a no-op returning nil, got: %v", err)
	}
}

// =====================================================================
// Helper function tests
// =====================================================================

func TestNullTime(t *testing.T) {
	// Zero time should return nil.
	result := nullTime(time.Time{})
	if result != nil {
		t.Errorf("nullTime(zero) should return nil, got: %v", result)
	}

	// Non-zero time should return the time.
	now := time.Now()
	result = nullTime(now)
	if result == nil {
		t.Error("nullTime(non-zero) should return non-nil")
	}
	if ti, ok := result.(time.Time); ok {
		if !ti.Equal(now) {
			t.Errorf("nullTime should return the same time, got: %v, want: %v", ti, now)
		}
	} else {
		t.Errorf("nullTime should return time.Time, got: %T", result)
	}
}

func TestMapPGError_Nil(t *testing.T) {
	if err := mapPGError(nil); err != nil {
		t.Errorf("mapPGError(nil) should return nil, got: %v", err)
	}
}

func TestMapPGError_NoRows(t *testing.T) {
	// Simulate a pgx "no rows" error.
	err := mapPGError(errNoRows)
	if err != ErrNotFound {
		t.Errorf("mapPGError(no rows) should return ErrNotFound, got: %v", err)
	}
}

func TestMapPGError_Other(t *testing.T) {
	otherErr := errTestOther
	err := mapPGError(otherErr)
	if err != otherErr {
		t.Errorf("mapPGError(other) should return the same error, got: %v", err)
	}
}

// =====================================================================
// Compile-time interface checks
// =====================================================================

func TestPostgresStore_ImplementsStore(t *testing.T) {
	var _ Store = (*PostgresStore)(nil)
	var _ LifecyclePolicyStore = (*PostgresPolicyStore)(nil)
}
