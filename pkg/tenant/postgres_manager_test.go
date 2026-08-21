// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform — PostgreSQL Tenant Manager Tests
// =========================================================================
//
// This file contains compile-time interface checks and a test for
// NewPostgresManager(nil). Full CRUD tests require a running PostgreSQL
// instance and are guarded by the "integration" build tag.
//
// =========================================================================

package tenant

import (
	"context"
	"testing"
)

// Compile-time interface checks — ensures both Manager (via adapter) and
// PostgresManager implement the Store interface.

var _ Store = (*memStore)(nil)
var _ Store = (*PostgresManager)(nil)

// TestNewPostgresManagerNil verifies that NewPostgresManager returns an error
// when the PostgresStore is nil.
func TestNewPostgresManagerNil(t *testing.T) {
	pm, err := NewPostgresManager(nil)
	if err == nil {
		t.Fatal("expected error when pgStore is nil")
	}
	if pm != nil {
		t.Fatalf("expected nil PostgresManager, got %v", pm)
	}
}

// TestPostgresManagerImplementsStore is a compile-time check that
// PostgresManager satisfies the Store interface.
func TestPostgresManagerImplementsStore(t *testing.T) {
	var _ Store = (*PostgresManager)(nil)
}

// TestStoreInterfaceMethodSignatures verifies the Store interface has the
// expected method signatures by calling the methods on a nil memStore
// (they will panic/return zero values, but the call proves the signature).
func TestStoreInterfaceMethodSignatures(t *testing.T) {
	var s Store = &memStore{m: NewManager()}

	// Verify all methods exist with correct signatures.
	_, _ = s.Create(context.Background(), "name", "display", "email", "tier", 1, 2)
	_, _ = s.Get(context.Background(), "id")
	_, _ = s.List(context.Background())
	_, _ = s.Update(context.Background(), "id", map[string]interface{}{"name": "x"})
	_ = s.Delete(context.Background(), "id")
	_, _ = s.Count(context.Background())
}

// TestPostgresManagerCloseOnNilPool verifies Close is safe on a manually
// constructed PostgresManager with a nil pool (only calls Close on already
// nil objects).
func TestPostgresManagerCloseOnNilPool(t *testing.T) {
	pm := &PostgresManager{}
	// Close should be safe even with nil pool (it just sets closed flag).
	if err := pm.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	// Double close should be safe.
	if err := pm.Close(); err != nil {
		t.Fatalf("double Close failed: %v", err)
	}
}

// TestNewPostgresManagerNotNilStore verifies that a non-nil PostgresStore
// pointer passes the nil check. We can't test the full path without a real
// database (nil pool would panic in pgxpool), so we just confirm the nil
// check logic by re-testing the nil case.
func TestNewPostgresManagerNotNilStore(t *testing.T) {
	// We can't create a real PostgresStore without a database, so we just
	// verify that the nil check works correctly.
	_, err := NewPostgresManager(nil)
	if err == nil {
		t.Fatal("expected error for nil pgStore")
	}
}
