// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Attestation PostgreSQL Store Unit Tests
// =========================================================================
//
// postgres_unit_test.go covers the PostgresAttestationStore without a live
// database connection. It tests input validation paths, constructor behaviour,
// and the no-op Close method. Methods that require a live pool are tested
// via error-assertion to ensure the code paths up to the pool call are
// exercised for coverage.
//
// After L-4 remediation, nil pool returns an error instead of panicking.
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
// Methods that access the pool will return an error; only input-validation
// and no-op paths can be tested safely.
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
// Store with valid envelope (nil pool → error)
// These tests assert that the code reaches the pool call, which exercises
// json.Marshal and the ValidUntil path. After L-4, nil pool returns an error.
// --------------------------------------------------------------------

func TestPostgresUnit_Store_ValidEnvelope_ErrorsOnNilPool(t *testing.T) {
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

	err := store.Store(ctx, env)
	assert.Error(t, err, "Store with nil pool should return error")
}

func TestPostgresUnit_Store_ZeroValidUntil_ErrorsOnNilPool(t *testing.T) {
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

	err := store.Store(ctx, env)
	assert.Error(t, err, "Store with nil pool and zero ValidUntil should return error")
}

// --------------------------------------------------------------------
// List methods (nil pool → error)
// These exercise the query-construction and limit/offset logic.
// --------------------------------------------------------------------

func TestPostgresUnit_ListByType_ErrorsOnNilPool(t *testing.T) {
	t.Parallel()
	store := newNilPoolStore()
	ctx := context.Background()

	_, err := store.ListByType(ctx, TypeEvidenceManifest, 10, 5)
	assert.Error(t, err, "ListByType with nil pool should return error")
}

func TestPostgresUnit_ListByType_NoLimitNoOffset_ErrorsOnNilPool(t *testing.T) {
	t.Parallel()
	store := newNilPoolStore()
	ctx := context.Background()

	_, err := store.ListByType(ctx, TypeEvidenceManifest, 0, 0)
	assert.Error(t, err, "ListByType with nil pool should return error")
}

func TestPostgresUnit_ListBySubject_ErrorsOnNilPool(t *testing.T) {
	t.Parallel()
	store := newNilPoolStore()
	ctx := context.Background()

	_, err := store.ListBySubject(ctx, "aegisgate://manifest/test", 10, 5)
	assert.Error(t, err, "ListBySubject with nil pool should return error")
}

func TestPostgresUnit_ListByIssuer_ErrorsOnNilPool(t *testing.T) {
	t.Parallel()
	store := newNilPoolStore()
	ctx := context.Background()

	_, err := store.ListByIssuer(ctx, "test-instance:test-key", 10, 5)
	assert.Error(t, err, "ListByIssuer with nil pool should return error")
}

func TestPostgresUnit_ListByTimeRange_ErrorsOnNilPool(t *testing.T) {
	t.Parallel()
	store := newNilPoolStore()
	ctx := context.Background()

	now := time.Now().UTC()
	_, err := store.ListByTimeRange(ctx, now.Add(-1*time.Hour), now.Add(1*time.Hour), 10, 5)
	assert.Error(t, err, "ListByTimeRange with nil pool should return error")
}

func TestPostgresUnit_ListByTimeRange_NoLimitNoOffset_ErrorsOnNilPool(t *testing.T) {
	t.Parallel()
	store := newNilPoolStore()
	ctx := context.Background()

	now := time.Now().UTC()
	_, err := store.ListByTimeRange(ctx, now.Add(-1*time.Hour), now, 0, 0)
	assert.Error(t, err, "ListByTimeRange with nil pool should return error")
}

// --------------------------------------------------------------------
// PruneExpired (nil pool → error)
// --------------------------------------------------------------------

func TestPostgresUnit_PruneExpired_ErrorsOnNilPool(t *testing.T) {
	t.Parallel()
	store := newNilPoolStore()
	ctx := context.Background()

	_, err := store.PruneExpired(ctx, time.Now().UTC())
	assert.Error(t, err, "PruneExpired with nil pool should return error")
}

// --------------------------------------------------------------------
// CountByType (nil pool → error)
// --------------------------------------------------------------------

func TestPostgresUnit_CountByType_ErrorsOnNilPool(t *testing.T) {
	t.Parallel()
	store := newNilPoolStore()
	ctx := context.Background()

	_, err := store.CountByType(ctx, TypeEvidenceManifest)
	assert.Error(t, err, "CountByType with nil pool should return error")
}

// --------------------------------------------------------------------
// Get with non-empty ID (nil pool → error)
// --------------------------------------------------------------------

func TestPostgresUnit_Get_NonEmptyID_ErrorsOnNilPool(t *testing.T) {
	t.Parallel()
	store := newNilPoolStore()
	ctx := context.Background()

	_, err := store.Get(ctx, "some-nonempty-id")
	assert.Error(t, err, "Get with nil pool should return error for non-empty ID")
}