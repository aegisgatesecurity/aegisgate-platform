// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Attestation Store Tests (v3.8 Persistence)
// =========================================================================
//
// store_test.go covers InMemoryAttestationStore and
// PostgresAttestationStore with table-driven tests matching the
// style in attestation_test.go.
//
// PostgresAttestationStore tests use a real pgxpool if
// AEGISGATE_TEST_DATABASE_URL is set; otherwise they fall back
// to a lightweight mock.
//
// v3.8 persistence gap closure.
// =========================================================================

package attestation

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
)

// --------------------------------------------------------------------
// Shared test helpers
// --------------------------------------------------------------------

// createTestEnvelope creates a signed attestation envelope suitable for
// store tests. The KeyRing is created fresh each call so envelopes get
// unique IDs.
func createTestEnvelope(t *testing.T, kr *ioc.KeyRing, attType Type, subject string) *Envelope {
	t.Helper()
	payload := []byte(`{"test": true}`)
	env, err := Sign(payload, subject, attType, "test-instance:test-key", kr, 24*time.Hour)
	require.NoError(t, err, "Sign should succeed")
	return env
}

// createTestEnvelopeWithTTL is like createTestEnvelope but lets the
// caller control the TTL (0 = no expiration).
func createTestEnvelopeWithTTL(t *testing.T, kr *ioc.KeyRing, attType Type, subject string, ttl time.Duration) *Envelope {
	t.Helper()
	payload := []byte(`{"test": true}`)
	env, err := Sign(payload, subject, attType, "test-instance:test-key", kr, ttl)
	require.NoError(t, err, "Sign should succeed")
	return env
}

// newTestKeyRing creates an in-memory KeyRing with one rotated key.
func newTestKeyRing(t *testing.T) *ioc.KeyRing {
	t.Helper()
	kr, err := ioc.LoadKeyRing(t.TempDir() + "/kr.json")
	require.NoError(t, err, "LoadKeyRing should succeed")
	_, err = kr.Rotate()
	require.NoError(t, err, "Rotate should succeed")
	return kr
}

// ====================================================================
// InMemoryAttestationStore tests
// ====================================================================

func TestInMemoryStore_StoreAndGet(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := NewInMemoryAttestationStore()
	kr := newTestKeyRing(t)

	t.Run("happy_path", func(t *testing.T) {
		env := createTestEnvelope(t, kr, TypeEvidenceManifest, "aegisgate://manifest/test-1")
		err := store.Store(ctx, env)
		require.NoError(t, err, "Store should succeed")

		got, err := store.Get(ctx, env.ID)
		require.NoError(t, err, "Get should succeed")
		require.NotNil(t, got, "Get should return the envelope")
		assert.Equal(t, env.ID, got.ID, "ID should match")
		assert.Equal(t, env.Type, got.Type, "Type should match")
		assert.Equal(t, env.Subject, got.Subject, "Subject should match")
		assert.Equal(t, env.Issuer, got.Issuer, "Issuer should match")
	})

	t.Run("empty_id_returns_error", func(t *testing.T) {
		_, err := store.Get(ctx, "")
		assert.Error(t, err, "Get with empty ID should return error")
	})

	t.Run("nil_envelope_returns_error", func(t *testing.T) {
		err := store.Store(ctx, nil)
		assert.Error(t, err, "Store with nil envelope should return error")
	})

	t.Run("not_found_returns_nil", func(t *testing.T) {
		got, err := store.Get(ctx, "nonexistent-id")
		assert.NoError(t, err, "Get for nonexistent ID should not error")
		assert.Nil(t, got, "Get for nonexistent ID should return nil")
	})
}

func TestInMemoryStore_StoreDuplicateID(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := NewInMemoryAttestationStore()
	kr := newTestKeyRing(t)

	env := createTestEnvelope(t, kr, TypeEvidenceManifest, "aegisgate://manifest/dup-test")
	err := store.Store(ctx, env)
	require.NoError(t, err, "first Store should succeed")

	// Storing the same envelope again should fail.
	err = store.Store(ctx, env)
	assert.Error(t, err, "storing duplicate ID should return error")
}

func TestInMemoryStore_ListByType(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := NewInMemoryAttestationStore()
	kr := newTestKeyRing(t)

	// Store envelopes of different types.
	env1 := createTestEnvelope(t, kr, TypeEvidenceManifest, "aegisgate://manifest/1")
	env2 := createTestEnvelope(t, kr, TypeEvaluatorRun, "aegisgate://evaluation/2")
	env3 := createTestEnvelope(t, kr, TypeEvidenceManifest, "aegisgate://manifest/3")

	require.NoError(t, store.Store(ctx, env1))
	require.NoError(t, store.Store(ctx, env2))
	require.NoError(t, store.Store(ctx, env3))

	t.Run("returns_correct_type", func(t *testing.T) {
		results, err := store.ListByType(ctx, TypeEvidenceManifest, 0, 0)
		require.NoError(t, err)
		assert.Len(t, results, 2, "should return 2 evidence.manifest.v1 envelopes")
		for _, e := range results {
			assert.Equal(t, TypeEvidenceManifest, e.Type)
		}
	})

	t.Run("pagination_with_limit", func(t *testing.T) {
		results, err := store.ListByType(ctx, TypeEvidenceManifest, 1, 0)
		require.NoError(t, err)
		assert.Len(t, results, 1, "limit=1 should return 1 envelope")
	})

	t.Run("pagination_with_offset", func(t *testing.T) {
		results, err := store.ListByType(ctx, TypeEvidenceManifest, 0, 1)
		require.NoError(t, err)
		assert.Len(t, results, 1, "offset=1 should return 1 envelope (skip first)")
	})

	t.Run("pagination_with_limit_and_offset", func(t *testing.T) {
		// Store a few more to have more data for pagination.
		for i := 0; i < 5; i++ {
			env := createTestEnvelope(t, kr, TypeEvidenceManifest, fmt.Sprintf("aegisgate://manifest/pagination-%d", i))
			require.NoError(t, store.Store(ctx, env))
		}
		results, err := store.ListByType(ctx, TypeEvidenceManifest, 3, 2)
		require.NoError(t, err)
		assert.Len(t, results, 3, "limit=3, offset=2 should return 3 envelopes")
	})

	t.Run("offset_beyond_results", func(t *testing.T) {
		results, err := store.ListByType(ctx, TypeEvidenceManifest, 0, 1000)
		require.NoError(t, err)
		assert.Nil(t, results, "offset beyond available results should return nil")
	})

	t.Run("no_matching_type", func(t *testing.T) {
		results, err := store.ListByType(ctx, TypeCVEEntry, 0, 0)
		require.NoError(t, err)
		assert.Len(t, results, 0, "no envelopes of unmatched type")
	})
}

func TestInMemoryStore_ListBySubject(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := NewInMemoryAttestationStore()
	kr := newTestKeyRing(t)

	subject := "aegisgate://manifest/subject-1"
	env1 := createTestEnvelope(t, kr, TypeEvidenceManifest, subject)
	env2 := createTestEnvelope(t, kr, TypeEvidenceCrossProtocol, subject)
	env3 := createTestEnvelope(t, kr, TypeEvaluatorRun, "aegisgate://evaluation/other")

	require.NoError(t, store.Store(ctx, env1))
	require.NoError(t, store.Store(ctx, env2))
	require.NoError(t, store.Store(ctx, env3))

	results, err := store.ListBySubject(ctx, subject, 0, 0)
	require.NoError(t, err)
	assert.Len(t, results, 2, "should return 2 envelopes for subject-1")

	for _, e := range results {
		assert.Equal(t, subject, e.Subject)
	}
}

func TestInMemoryStore_ListByIssuer(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := NewInMemoryAttestationStore()
	kr := newTestKeyRing(t)

	issuer := "test-instance:test-key"
	env1 := createTestEnvelope(t, kr, TypeEvidenceManifest, "aegisgate://manifest/1")
	env2 := createTestEnvelope(t, kr, TypeEvaluatorRun, "aegisgate://evaluation/2")

	require.NoError(t, store.Store(ctx, env1))
	require.NoError(t, store.Store(ctx, env2))

	results, err := store.ListByIssuer(ctx, issuer, 0, 0)
	require.NoError(t, err)
	assert.Len(t, results, 2, "should return 2 envelopes for issuer")

	for _, e := range results {
		assert.Equal(t, issuer, e.Issuer)
	}
}

func TestInMemoryStore_ListByTimeRange(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := NewInMemoryAttestationStore()
	kr := newTestKeyRing(t)

	env := createTestEnvelope(t, kr, TypeEvidenceManifest, "aegisgate://manifest/time-range")
	require.NoError(t, store.Store(ctx, env))

	// Query a range that includes env.IssuedAt.
	from := env.IssuedAt.Add(-1 * time.Hour)
	to := env.IssuedAt.Add(1 * time.Hour)

	results, err := store.ListByTimeRange(ctx, from, to, 0, 0)
	require.NoError(t, err)
	assert.Len(t, results, 1, "should return 1 envelope within range")
	assert.Equal(t, env.ID, results[0].ID)

	// Query a range that excludes env.IssuedAt.
	fromExcluded := env.IssuedAt.Add(1 * time.Minute)
	toExcluded := env.IssuedAt.Add(2 * time.Hour)
	results, err = store.ListByTimeRange(ctx, fromExcluded, toExcluded, 0, 0)
	require.NoError(t, err)
	assert.Len(t, results, 0, "should return 0 envelopes outside range")
}

func TestInMemoryStore_PruneExpired(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := NewInMemoryAttestationStore()
	kr := newTestKeyRing(t)

	// Store an envelope with a short TTL (will expire quickly).
	expiredEnv := createTestEnvelopeWithTTL(t, kr, TypeEvidenceManifest, "aegisgate://manifest/expired", 1*time.Millisecond)
	require.NoError(t, store.Store(ctx, expiredEnv))

	// Wait for the envelope to expire.
	time.Sleep(50 * time.Millisecond)

	// Store a non-expiring envelope (TTL=0).
	nonExpiringEnv := createTestEnvelopeWithTTL(t, kr, TypeEvaluatorRun, "aegisgate://evaluation/no-expire", 0)
	require.NoError(t, store.Store(ctx, nonExpiringEnv))

	// Store a long-lived envelope.
	longLivedEnv := createTestEnvelopeWithTTL(t, kr, TypeAIBOM, "aegisgate://manifest/long-lived", 24*time.Hour)
	require.NoError(t, store.Store(ctx, longLivedEnv))

	// Prune with cutoff = now (should remove the expired envelope).
	pruned, err := store.PruneExpired(ctx, time.Now().UTC())
	require.NoError(t, err)
	assert.Equal(t, 1, pruned, "should prune 1 expired envelope")

	// Verify the expired envelope is gone.
	got, err := store.Get(ctx, expiredEnv.ID)
	require.NoError(t, err)
	assert.Nil(t, got, "expired envelope should be removed")

	// Verify the non-expiring envelope still exists.
	got, err = store.Get(ctx, nonExpiringEnv.ID)
	require.NoError(t, err)
	assert.NotNil(t, got, "non-expiring envelope should still exist")

	// Verify the long-lived envelope still exists.
	got, err = store.Get(ctx, longLivedEnv.ID)
	require.NoError(t, err)
	assert.NotNil(t, got, "long-lived envelope should still exist")

	// Prune again — nothing left to prune.
	pruned, err = store.PruneExpired(ctx, time.Now().UTC())
	require.NoError(t, err)
	assert.Equal(t, 0, pruned, "no more envelopes to prune")
}

func TestInMemoryStore_PruneExpired_ZeroValidUntil(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := NewInMemoryAttestationStore()
	kr := newTestKeyRing(t)

	// Store multiple envelopes with no expiration (TTL=0).
	for i := 0; i < 3; i++ {
		env := createTestEnvelopeWithTTL(t, kr, TypeEvidenceManifest,
			fmt.Sprintf("aegisgate://manifest/never-expire-%d", i), 0)
		require.NoError(t, store.Store(ctx, env))
	}

	// Prune with a very old cutoff — should not remove any.
	pruned, err := store.PruneExpired(ctx, time.Now().UTC())
	require.NoError(t, err)
	assert.Equal(t, 0, pruned, "zero-value ValidUntil envelopes should never be pruned")
}

func TestInMemoryStore_CountByType(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := NewInMemoryAttestationStore()
	kr := newTestKeyRing(t)

	// Initially 0.
	count, err := store.CountByType(ctx, TypeEvidenceManifest)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "initial count should be 0")

	// Store envelopes.
	for i := 0; i < 5; i++ {
		env := createTestEnvelope(t, kr, TypeEvidenceManifest,
			fmt.Sprintf("aegisgate://manifest/count-%d", i))
		require.NoError(t, store.Store(ctx, env))
	}

	count, err = store.CountByType(ctx, TypeEvidenceManifest)
	require.NoError(t, err)
	assert.Equal(t, 5, count, "should count 5 evidence.manifest.v1 envelopes")

	// Other type should still be 0.
	count, err = store.CountByType(ctx, TypeCVEEntry)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "unmatched type should have 0 count")
}

func TestInMemoryStore_Close(t *testing.T) {
	t.Parallel()
	store := NewInMemoryAttestationStore()
	assert.NoError(t, store.Close(), "Close should be a no-op and not error")
}

// --------------------------------------------------------------------
// InMemoryAttestationStore concurrency test
// --------------------------------------------------------------------

func TestInMemoryStore_ConcurrentStoreAndGet(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := NewInMemoryAttestationStore()
	kr := newTestKeyRing(t)

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)

	// Store envelopes concurrently.
	envelopes := make([]*Envelope, goroutines)
	for i := 0; i < goroutines; i++ {
		env := createTestEnvelope(t, kr, TypeEvidenceManifest,
			fmt.Sprintf("aegisgate://manifest/concurrent-%d", i))
		envelopes[i] = env
	}

	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			err := store.Store(ctx, envelopes[idx])
			assert.NoError(t, err, "concurrent Store should succeed")
		}(i)
	}
	wg.Wait()

	// Verify all envelopes are stored.
	for i := 0; i < goroutines; i++ {
		got, err := store.Get(ctx, envelopes[i].ID)
		require.NoError(t, err)
		require.NotNil(t, got, "envelope %d should be stored", i)
		assert.Equal(t, envelopes[i].ID, got.ID)
	}

	// Count should match.
	count, err := store.CountByType(ctx, TypeEvidenceManifest)
	require.NoError(t, err)
	assert.Equal(t, goroutines, count)
}

// ====================================================================
// PostgresAttestationStore tests
// ====================================================================

// pgTestHarness wraps a PostgresAttestationStore (real or mock) for
// testing. If AEGISGATE_TEST_DATABASE_URL is set, it uses a real pool;
// otherwise it falls back to a mock store.
type pgTestHarness struct {
	store   AttestationStore
	realDB  bool
	cleanup func()
}

// newPGTestHarness creates a test harness. Skips the test if
// AEGISGATE_TEST_DATABASE_URL is not set and no mock is available.
func newPGTestHarness(t *testing.T) *pgTestHarness {
	t.Helper()
	dsn := os.Getenv("AEGISGATE_TEST_DATABASE_URL")
	if dsn != "" {
		ctx := context.Background()
		cfg, err := pgxpool.ParseConfig(dsn)
		require.NoError(t, err, "failed to parse database URL")
		pool, err := pgxpool.NewWithConfig(ctx, cfg)
		require.NoError(t, err, "failed to connect to database")
		t.Cleanup(func() { pool.Close() })
		return &pgTestHarness{
			store:  NewPostgresAttestationStore(pool),
			realDB: true,
			cleanup: func() {
				// Clean up test data from the table.
				pool.Exec(ctx, "DELETE FROM attestation_envelopes")
			},
		}
	}

	// Fall back to a mock that delegates to InMemoryAttestationStore.
	// This lets the test logic run without a real database.
	t.Log("AEGISGATE_TEST_DATABASE_URL not set; using in-memory mock for PostgresAttestationStore tests")
	memStore := NewInMemoryAttestationStore()
	return &pgTestHarness{
		store:   memStore,
		realDB:  false,
		cleanup: func() {},
	}
}

func TestPostgresStore_StoreAndGet(t *testing.T) {
	t.Parallel()
	h := newPGTestHarness(t)
	defer h.cleanup()
	ctx := context.Background()
	kr := newTestKeyRing(t)

	t.Run("happy_path", func(t *testing.T) {
		env := createTestEnvelope(t, kr, TypeEvidenceManifest, "aegisgate://manifest/pg-1")
		err := h.store.Store(ctx, env)
		require.NoError(t, err, "Store should succeed")

		got, err := h.store.Get(ctx, env.ID)
		require.NoError(t, err, "Get should succeed")
		require.NotNil(t, got, "Get should return the envelope")
		assert.Equal(t, env.ID, got.ID)
		assert.Equal(t, env.Type, got.Type)
		assert.Equal(t, env.Subject, got.Subject)
		assert.Equal(t, env.Issuer, got.Issuer)
	})

	t.Run("nil_envelope_returns_error", func(t *testing.T) {
		err := h.store.Store(ctx, nil)
		assert.Error(t, err, "Store with nil envelope should return error")
	})

	t.Run("empty_id_returns_error", func(t *testing.T) {
		_, err := h.store.Get(ctx, "")
		assert.Error(t, err, "Get with empty ID should return error")
	})

	t.Run("not_found_returns_nil", func(t *testing.T) {
		got, err := h.store.Get(ctx, "nonexistent-pg-id")
		assert.NoError(t, err, "Get for nonexistent ID should not error")
		assert.Nil(t, got, "Get for nonexistent ID should return nil")
	})
}

func TestPostgresStore_ListByType(t *testing.T) {
	t.Parallel()
	h := newPGTestHarness(t)
	defer h.cleanup()
	ctx := context.Background()
	kr := newTestKeyRing(t)

	env1 := createTestEnvelope(t, kr, TypeEvidenceManifest, "aegisgate://manifest/pg-list-1")
	env2 := createTestEnvelope(t, kr, TypeEvaluatorRun, "aegisgate://evaluation/pg-list-2")
	env3 := createTestEnvelope(t, kr, TypeEvidenceManifest, "aegisgate://manifest/pg-list-3")

	require.NoError(t, h.store.Store(ctx, env1))
	require.NoError(t, h.store.Store(ctx, env2))
	require.NoError(t, h.store.Store(ctx, env3))

	results, err := h.store.ListByType(ctx, TypeEvidenceManifest, 0, 0)
	require.NoError(t, err)
	assert.Len(t, results, 2, "should return 2 evidence.manifest.v1 envelopes")

	results, err = h.store.ListByType(ctx, TypeEvidenceManifest, 1, 0)
	require.NoError(t, err)
	assert.Len(t, results, 1, "limit=1 should return 1 envelope")
}

func TestPostgresStore_ListBySubject(t *testing.T) {
	t.Parallel()
	h := newPGTestHarness(t)
	defer h.cleanup()
	ctx := context.Background()
	kr := newTestKeyRing(t)

	subject := "aegisgate://manifest/pg-subject-1"
	env1 := createTestEnvelope(t, kr, TypeEvidenceManifest, subject)
	env2 := createTestEnvelope(t, kr, TypeEvidenceCrossProtocol, subject)
	env3 := createTestEnvelope(t, kr, TypeEvaluatorRun, "aegisgate://evaluation/other")

	require.NoError(t, h.store.Store(ctx, env1))
	require.NoError(t, h.store.Store(ctx, env2))
	require.NoError(t, h.store.Store(ctx, env3))

	results, err := h.store.ListBySubject(ctx, subject, 0, 0)
	require.NoError(t, err)
	assert.Len(t, results, 2, "should return 2 envelopes for subject")

	for _, e := range results {
		assert.Equal(t, subject, e.Subject)
	}
}

func TestPostgresStore_ListByIssuer(t *testing.T) {
	t.Parallel()
	h := newPGTestHarness(t)
	defer h.cleanup()
	ctx := context.Background()
	kr := newTestKeyRing(t)

	issuer := "test-instance:test-key"
	env1 := createTestEnvelope(t, kr, TypeEvidenceManifest, "aegisgate://manifest/pg-issuer-1")
	env2 := createTestEnvelope(t, kr, TypeEvaluatorRun, "aegisgate://evaluation/pg-issuer-2")

	require.NoError(t, h.store.Store(ctx, env1))
	require.NoError(t, h.store.Store(ctx, env2))

	results, err := h.store.ListByIssuer(ctx, issuer, 0, 0)
	require.NoError(t, err)
	assert.Len(t, results, 2, "should return 2 envelopes for issuer")

	for _, e := range results {
		assert.Equal(t, issuer, e.Issuer)
	}
}

func TestPostgresStore_ListByTimeRange(t *testing.T) {
	t.Parallel()
	h := newPGTestHarness(t)
	defer h.cleanup()
	ctx := context.Background()
	kr := newTestKeyRing(t)

	env := createTestEnvelope(t, kr, TypeEvidenceManifest, "aegisgate://manifest/pg-time-range")
	require.NoError(t, h.store.Store(ctx, env))

	from := env.IssuedAt.Add(-1 * time.Hour)
	to := env.IssuedAt.Add(1 * time.Hour)

	results, err := h.store.ListByTimeRange(ctx, from, to, 0, 0)
	require.NoError(t, err)
	assert.Len(t, results, 1, "should return 1 envelope within range")
	assert.Equal(t, env.ID, results[0].ID)
}

func TestPostgresStore_PruneExpired(t *testing.T) {
	t.Parallel()
	h := newPGTestHarness(t)
	defer h.cleanup()
	ctx := context.Background()
	kr := newTestKeyRing(t)

	// Store a short-lived envelope.
	expiredEnv := createTestEnvelopeWithTTL(t, kr, TypeEvidenceManifest,
		"aegisgate://manifest/pg-expired", 1*time.Millisecond)
	require.NoError(t, h.store.Store(ctx, expiredEnv))

	// Wait for it to expire.
	time.Sleep(50 * time.Millisecond)

	// Store a non-expiring envelope.
	nonExpiringEnv := createTestEnvelopeWithTTL(t, kr, TypeEvaluatorRun,
		"aegisgate://evaluation/pg-no-expire", 0)
	require.NoError(t, h.store.Store(ctx, nonExpiringEnv))

	// Prune.
	pruned, err := h.store.PruneExpired(ctx, time.Now().UTC())
	require.NoError(t, err)
	assert.Equal(t, 1, pruned, "should prune 1 expired envelope")

	// Verify the expired envelope is gone.
	got, err := h.store.Get(ctx, expiredEnv.ID)
	require.NoError(t, err)
	assert.Nil(t, got, "expired envelope should be removed")

	// Verify the non-expiring envelope still exists.
	got, err = h.store.Get(ctx, nonExpiringEnv.ID)
	require.NoError(t, err)
	assert.NotNil(t, got, "non-expiring envelope should still exist")
}

func TestPostgresStore_CountByType(t *testing.T) {
	t.Parallel()
	h := newPGTestHarness(t)
	defer h.cleanup()
	ctx := context.Background()
	kr := newTestKeyRing(t)

	// Initially 0 (or whatever the DB has).
	for i := 0; i < 3; i++ {
		env := createTestEnvelope(t, kr, TypeEvidenceManifest,
			fmt.Sprintf("aegisgate://manifest/pg-count-%d", i))
		require.NoError(t, h.store.Store(ctx, env))
	}

	count, err := h.store.CountByType(ctx, TypeEvidenceManifest)
	require.NoError(t, err)
	assert.Equal(t, 3, count, "should count 3 evidence.manifest.v1 envelopes")
}

// ====================================================================
// Table-driven tests for store interface compliance
// ====================================================================

// storeFactory creates a fresh AttestationStore for table-driven tests.
type storeFactory struct {
	name  string
	new   func(t *testing.T) AttestationStore
	clean func(t *testing.T, s AttestationStore)
}

func TestStore_InterfaceCompliance_TableDriven(t *testing.T) {
	t.Parallel()

	factories := []storeFactory{
		{
			name: "InMemory",
			new: func(t *testing.T) AttestationStore {
				return NewInMemoryAttestationStore()
			},
			clean: func(t *testing.T, s AttestationStore) {
				// No-op for in-memory.
			},
		},
		{
			name: "Postgres",
			new: func(t *testing.T) AttestationStore {
				h := newPGTestHarness(t)
				return h.store
			},
			clean: func(t *testing.T, s AttestationStore) {
				// Cleanup handled by harness.
			},
		},
	}

	for _, factory := range factories {
		t.Run(factory.name, func(t *testing.T) {
			t.Parallel()
			store := factory.new(t)
			defer factory.clean(t, store)
			ctx := context.Background()
			kr := newTestKeyRing(t)

			env := createTestEnvelope(t, kr, TypeEvidenceManifest, "aegisgate://manifest/compliance")
			require.NoError(t, store.Store(ctx, env), "Store should succeed")

			got, err := store.Get(ctx, env.ID)
			require.NoError(t, err)
			require.NotNil(t, got)
			assert.Equal(t, env.ID, got.ID, "Get should return the stored envelope")
		})
	}
}
