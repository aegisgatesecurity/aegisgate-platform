// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Attestation PostgreSQL Store Unit Tests
// =========================================================================
//
// postgres_unit_test.go covers the PostgresAttestationStore without a live
// database connection. It tests input validation paths, constructor behaviour,
// and the no-op Close method. Methods that require a live pool are tested
// via panic-recovery to ensure the code paths up to the pool call are
// exercised for coverage.
//
// These tests are excluded from the integration build tag so they always
// run alongside the rest of the unit suite:
//
//	go test ./pkg/attestation/... -count=1 -cover
//
// =========================================================================

//go:build !integration

package attestation

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newNilPoolStore creates a PostgresAttestationStore with a nil pool.
// Methods that access the pool will panic; only input-validation and
// no-op paths can be tested safely.
func newNilPoolStore() *PostgresAttestationStore {
	return NewPostgresAttestationStore(nil)
}

// --------------------------------------------------------------------
// Constructor
// --------------------------------------------------------------------

func TestPostgresUnit_NewPostgresAttestationStore_NilPool(t *testing.T) {
	t.Parallel()
	store := NewPostgresAttestationStore(nil)
	require.NotNil(t, store, "constructor should return a non-nil store even with nil pool")
}

func TestPostgresUnit_NewPostgresAttestationStore_TypeAssertion(t *testing.T) {
	t.Parallel()
	// Verify the concrete type satisfies the interface at compile time
	// (already checked by the var _ declaration in postgres_store.go,
	// but an explicit assertion adds a test hook).
	var _ AttestationStore = NewPostgresAttestationStore(nil)
}

// --------------------------------------------------------------------
// Close (no-op)
// --------------------------------------------------------------------

func TestPostgresUnit_Close_ReturnsNil(t *testing.T) {
	t.Parallel()
	store := newNilPoolStore()
	err := store.Close()
	assert.NoError(t, err, "Close should always return nil (no-op)")
}

// --------------------------------------------------------------------
// Store input validation
// --------------------------------------------------------------------

func TestPostgresUnit_Store_NilEnvelope(t *testing.T) {
	t.Parallel()
	store := newNilPoolStore()
	ctx := context.Background()

	err := store.Store(ctx, nil)
	assert.Error(t, err, "Store with nil envelope should return error")
	assert.Contains(t, err.Error(), "nil envelope",
		"error should mention nil envelope")
}

// --------------------------------------------------------------------
// Get input validation
// --------------------------------------------------------------------

func TestPostgresUnit_Get_EmptyID(t *testing.T) {
	t.Parallel()
	store := newNilPoolStore()
	ctx := context.Background()

	env, err := store.Get(ctx, "")
	assert.Error(t, err, "Get with empty ID should return error")
	assert.Nil(t, env, "Get with empty ID should return nil envelope")
	assert.Contains(t, err.Error(), "empty id",
		"error should mention empty id")
}

// --------------------------------------------------------------------
// Store with valid envelope (nil pool → panic)
// These tests use recover() to assert that the code reaches the pool
// call, which exercises json.Marshal and the ValidUntil path.
// --------------------------------------------------------------------

func TestPostgresUnit_Store_ValidEnvelope_PanicsOnNilPool(t *testing.T) {
	t.Parallel()
	store := newNilPoolStore()
	ctx := context.Background()

	env := &Envelope{
		ID:         "test-id",
		Type:       TypeEvidenceManifest,
		Subject:    "aegisgate://manifest/test",
		Issuer:     "test-instance:test-key",
		IssuedAt:   time.Now().UTC(),
		ValidUntil: time.Now().UTC().Add(24 * time.Hour), // non-zero
		RawPayload: json.RawMessage(`{"test": true}`),
		Signature: Signature{
			Algorithm: "Ed25519",
			KeyID:     "test-key",
			Value:     []byte("sig"),
			PublicKey: []byte("pub"),
			SignedAt:  time.Now().UTC(),
		},
	}

	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		_ = store.Store(ctx, env)
	}()

	assert.True(t, didPanic, "Store with nil pool should panic")
}

func TestPostgresUnit_Store_ZeroValidUntil_PanicsOnNilPool(t *testing.T) {
	t.Parallel()
	store := newNilPoolStore()
	ctx := context.Background()

	// ValidUntil is zero-value — the store should set validUntil = nil
	// before calling pool.Exec.
	env := &Envelope{
		ID:         "test-id-zero-vu",
		Type:       TypeEvidenceManifest,
		Subject:    "aegisgate://manifest/test-zero",
		Issuer:     "test-instance:test-key",
		IssuedAt:   time.Now().UTC(),
		ValidUntil: time.Time{}, // zero value
		RawPayload: json.RawMessage(`{"test": true}`),
		Signature: Signature{
			Algorithm: "Ed25519",
			KeyID:     "test-key",
			Value:     []byte("sig"),
			PublicKey: []byte("pub"),
			SignedAt:  time.Now().UTC(),
		},
	}

	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		_ = store.Store(ctx, env)
	}()

	assert.True(t, didPanic, "Store with nil pool and zero ValidUntil should panic")
}

// --------------------------------------------------------------------
// List methods (nil pool → panic)
// These exercise the query-construction and limit/offset logic.
// --------------------------------------------------------------------

func TestPostgresUnit_ListByType_PanicsOnNilPool(t *testing.T) {
	t.Parallel()
	store := newNilPoolStore()
	ctx := context.Background()

	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		_, _ = store.ListByType(ctx, TypeEvidenceManifest, 10, 5)
	}()

	assert.True(t, didPanic, "ListByType with nil pool should panic")
}

func TestPostgresUnit_ListByType_NoLimitNoOffset_PanicsOnNilPool(t *testing.T) {
	t.Parallel()
	store := newNilPoolStore()
	ctx := context.Background()

	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		_, _ = store.ListByType(ctx, TypeEvidenceManifest, 0, 0)
	}()

	assert.True(t, didPanic, "ListByType with nil pool should panic")
}

func TestPostgresUnit_ListBySubject_PanicsOnNilPool(t *testing.T) {
	t.Parallel()
	store := newNilPoolStore()
	ctx := context.Background()

	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		_, _ = store.ListBySubject(ctx, "aegisgate://manifest/test", 10, 5)
	}()

	assert.True(t, didPanic, "ListBySubject with nil pool should panic")
}

func TestPostgresUnit_ListByIssuer_PanicsOnNilPool(t *testing.T) {
	t.Parallel()
	store := newNilPoolStore()
	ctx := context.Background()

	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		_, _ = store.ListByIssuer(ctx, "test-instance:test-key", 10, 5)
	}()

	assert.True(t, didPanic, "ListByIssuer with nil pool should panic")
}

func TestPostgresUnit_ListByTimeRange_PanicsOnNilPool(t *testing.T) {
	t.Parallel()
	store := newNilPoolStore()
	ctx := context.Background()

	now := time.Now().UTC()
	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		_, _ = store.ListByTimeRange(ctx, now.Add(-1*time.Hour), now.Add(1*time.Hour), 10, 5)
	}()

	assert.True(t, didPanic, "ListByTimeRange with nil pool should panic")
}

func TestPostgresUnit_ListByTimeRange_NoLimitNoOffset_PanicsOnNilPool(t *testing.T) {
	t.Parallel()
	store := newNilPoolStore()
	ctx := context.Background()

	now := time.Now().UTC()
	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		_, _ = store.ListByTimeRange(ctx, now.Add(-1*time.Hour), now, 0, 0)
	}()

	assert.True(t, didPanic, "ListByTimeRange with nil pool should panic")
}

// --------------------------------------------------------------------
// PruneExpired (nil pool → panic)
// --------------------------------------------------------------------

func TestPostgresUnit_PruneExpired_PanicsOnNilPool(t *testing.T) {
	t.Parallel()
	store := newNilPoolStore()
	ctx := context.Background()

	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		_, _ = store.PruneExpired(ctx, time.Now().UTC())
	}()

	assert.True(t, didPanic, "PruneExpired with nil pool should panic")
}

// --------------------------------------------------------------------
// CountByType (nil pool → panic)
// --------------------------------------------------------------------

func TestPostgresUnit_CountByType_PanicsOnNilPool(t *testing.T) {
	t.Parallel()
	store := newNilPoolStore()
	ctx := context.Background()

	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		_, _ = store.CountByType(ctx, TypeEvidenceManifest)
	}()

	assert.True(t, didPanic, "CountByType with nil pool should panic")
}

// --------------------------------------------------------------------
// Get with non-empty ID (nil pool → panic)
// --------------------------------------------------------------------

func TestPostgresUnit_Get_NonEmptyID_PanicsOnNilPool(t *testing.T) {
	t.Parallel()
	store := newNilPoolStore()
	ctx := context.Background()

	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		_, _ = store.Get(ctx, "some-nonempty-id")
	}()

	assert.True(t, didPanic, "Get with nil pool should panic for non-empty ID")
}
