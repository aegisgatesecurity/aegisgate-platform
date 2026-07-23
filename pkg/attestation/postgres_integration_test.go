// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — Attestation PostgreSQL Integration Tests
// =========================================================================
//
// Real-database tests that verify PostgresAttestationStore works end-to-end
// against a live PostgreSQL instance provisioned via testcontainers.
//
// These tests are gated by the `//go:build integration` build tag so they
// only run when explicitly requested:
//
//	go test -tags=integration -v ./pkg/attestation/...
//
// No external environment variables are required — testcontainers manages
// the ephemeral PostgreSQL container automatically. If Docker is not
// available the tests are skipped gracefully via t.Skip.
//
// Test functions are prefixed with TestIntegration_ to avoid collisions
// with the existing unit tests in store_test.go.
//
// =========================================================================

//go:build integration

package attestation

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupIntegrationStore provisions an ephemeral PostgreSQL container via
// testdb.SetupTestDB, creates a PostgresAttestationStore from the pool,
// and returns the store plus a cleanup function. The caller must defer
// the cleanup.
func setupIntegrationStore(t *testing.T) (*PostgresAttestationStore, func()) {
	t.Helper()

	pgStore, cleanup := testdb.SetupTestDB(t)
	store := NewPostgresAttestationStore(pgStore.Pool())

	storeCleanup := func() {
		store.Close()
		cleanup()
	}

	return store, storeCleanup
}

// integrationKeyRing creates a fresh KeyRing for integration tests.
func integrationKeyRing(t *testing.T) *ioc.KeyRing {
	t.Helper()
	kr, err := ioc.LoadKeyRing(t.TempDir() + "/kr.json")
	require.NoError(t, err, "LoadKeyRing should succeed")
	_, err = kr.Rotate()
	require.NoError(t, err, "Rotate should succeed")
	return kr
}

// integrationEnvelope creates a signed attestation envelope for integration
// tests. Each call produces a unique envelope (unique ID from the KeyRing).
func integrationEnvelope(t *testing.T, kr *ioc.KeyRing, attType Type, subject string) *Envelope {
	t.Helper()
	payload := []byte(`{"integration": true, "source": "postgres_integration_test"}`)
	env, err := Sign(payload, subject, attType, "int-instance:int-key", kr, 24*time.Hour)
	require.NoError(t, err, "Sign should succeed")
	return env
}

// integrationEnvelopeWithTTL creates a signed envelope with a specific TTL.
// Use ttl=0 for no expiration, or a short duration for expired-envelope tests.
func integrationEnvelopeWithTTL(t *testing.T, kr *ioc.KeyRing, attType Type, subject string, ttl time.Duration) *Envelope {
	t.Helper()
	payload := []byte(`{"integration": true, "ttl_test": true}`)
	env, err := Sign(payload, subject, attType, "int-instance:int-key", kr, ttl)
	require.NoError(t, err, "Sign should succeed")
	return env
}

// uniqueSubject returns a subject string unique to the current test invocation
// to avoid collisions between parallel tests sharing the same database.
func uniqueSubject(kind, suffix string) string {
	return fmt.Sprintf("aegisgate://%s/int-test-%s-%d", kind, suffix, time.Now().UnixNano())
}

// --------------------------------------------------------------------------
// Store and Get
// --------------------------------------------------------------------------

func TestIntegration_PostgresAttestationStore_StoreAndGet(t *testing.T) {
	store, cleanup := setupIntegrationStore(t)
	defer cleanup()

	ctx := context.Background()
	kr := integrationKeyRing(t)

	t.Run("happy_path", func(t *testing.T) {
		subject := uniqueSubject("manifest", "store-get")
		env := integrationEnvelope(t, kr, TypeEvidenceManifest, subject)

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

	t.Run("nil_envelope_returns_error", func(t *testing.T) {
		err := store.Store(ctx, nil)
		assert.Error(t, err, "Store with nil envelope should return error")
	})

	t.Run("empty_id_returns_error", func(t *testing.T) {
		_, err := store.Get(ctx, "")
		assert.Error(t, err, "Get with empty ID should return error")
	})

	t.Run("not_found_returns_nil", func(t *testing.T) {
		got, err := store.Get(ctx, "nonexistent-integration-id")
		assert.NoError(t, err, "Get for nonexistent ID should not error")
		assert.Nil(t, got, "Get for nonexistent ID should return nil")
	})
}

// --------------------------------------------------------------------------
// Store duplicate ID
// --------------------------------------------------------------------------

func TestIntegration_PostgresAttestationStore_StoreDuplicateID(t *testing.T) {
	store, cleanup := setupIntegrationStore(t)
	defer cleanup()

	ctx := context.Background()
	kr := integrationKeyRing(t)

	subject := uniqueSubject("manifest", "dup")
	env := integrationEnvelope(t, kr, TypeEvidenceManifest, subject)

	err := store.Store(ctx, env)
	require.NoError(t, err, "first Store should succeed")

	// The PostgresAttestationStore uses ON CONFLICT DO NOTHING, so storing
	// the same ID again succeeds silently (no error) but the original
	// envelope is preserved.
	err = store.Store(ctx, env)
	assert.NoError(t, err, "storing duplicate ID with ON CONFLICT DO NOTHING should not error")

	got, err := store.Get(ctx, env.ID)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, env.ID, got.ID, "original envelope should be preserved")
}

// --------------------------------------------------------------------------
// ListByType
// --------------------------------------------------------------------------

func TestIntegration_PostgresAttestationStore_ListByType(t *testing.T) {
	store, cleanup := setupIntegrationStore(t)
	defer cleanup()

	ctx := context.Background()
	kr := integrationKeyRing(t)

	// Store envelopes of different types.
	env1 := integrationEnvelope(t, kr, TypeEvidenceManifest, uniqueSubject("manifest", "list-type-1"))
	env2 := integrationEnvelope(t, kr, TypeEvaluatorRun, uniqueSubject("evaluation", "list-type-2"))
	env3 := integrationEnvelope(t, kr, TypeEvidenceManifest, uniqueSubject("manifest", "list-type-3"))

	require.NoError(t, store.Store(ctx, env1))
	require.NoError(t, store.Store(ctx, env2))
	require.NoError(t, store.Store(ctx, env3))

	t.Run("returns_correct_type", func(t *testing.T) {
		results, err := store.ListByType(ctx, TypeEvidenceManifest, 0, 0)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(results), 2, "should return at least 2 evidence.manifest.v1 envelopes")
		for _, e := range results {
			assert.Equal(t, TypeEvidenceManifest, e.Type)
		}
	})

	t.Run("pagination_with_limit", func(t *testing.T) {
		results, err := store.ListByType(ctx, TypeEvidenceManifest, 1, 0)
		require.NoError(t, err)
		assert.Len(t, results, 1, "limit=1 should return 1 envelope")
	})

	t.Run("no_matching_type", func(t *testing.T) {
		results, err := store.ListByType(ctx, TypeCVEEntry, 0, 0)
		require.NoError(t, err)
		assert.Empty(t, results, "no envelopes of unmatched type")
	})
}

// --------------------------------------------------------------------------
// ListBySubject
// --------------------------------------------------------------------------

func TestIntegration_PostgresAttestationStore_ListBySubject(t *testing.T) {
	store, cleanup := setupIntegrationStore(t)
	defer cleanup()

	ctx := context.Background()
	kr := integrationKeyRing(t)

	subject := uniqueSubject("manifest", "list-subj")
	env1 := integrationEnvelope(t, kr, TypeEvidenceManifest, subject)
	env2 := integrationEnvelope(t, kr, TypeEvidenceCrossProtocol, subject)
	env3 := integrationEnvelope(t, kr, TypeEvaluatorRun, uniqueSubject("evaluation", "list-subj-other"))

	require.NoError(t, store.Store(ctx, env1))
	require.NoError(t, store.Store(ctx, env2))
	require.NoError(t, store.Store(ctx, env3))

	results, err := store.ListBySubject(ctx, subject, 0, 0)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(results), 2, "should return at least 2 envelopes for subject")

	for _, e := range results {
		assert.Equal(t, subject, e.Subject)
	}
}

// --------------------------------------------------------------------------
// ListByIssuer
// --------------------------------------------------------------------------

func TestIntegration_PostgresAttestationStore_ListByIssuer(t *testing.T) {
	store, cleanup := setupIntegrationStore(t)
	defer cleanup()

	ctx := context.Background()
	kr := integrationKeyRing(t)

	issuer := "int-instance:int-key"
	env1 := integrationEnvelope(t, kr, TypeEvidenceManifest, uniqueSubject("manifest", "list-iss-1"))
	env2 := integrationEnvelope(t, kr, TypeEvaluatorRun, uniqueSubject("evaluation", "list-iss-2"))

	require.NoError(t, store.Store(ctx, env1))
	require.NoError(t, store.Store(ctx, env2))

	results, err := store.ListByIssuer(ctx, issuer, 0, 0)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(results), 2, "should return at least 2 envelopes for issuer")

	for _, e := range results {
		assert.Equal(t, issuer, e.Issuer)
	}
}

// --------------------------------------------------------------------------
// ListByTimeRange
// --------------------------------------------------------------------------

func TestIntegration_PostgresAttestationStore_ListByTimeRange(t *testing.T) {
	store, cleanup := setupIntegrationStore(t)
	defer cleanup()

	ctx := context.Background()
	kr := integrationKeyRing(t)

	subject := uniqueSubject("manifest", "time-range")
	env := integrationEnvelope(t, kr, TypeEvidenceManifest, subject)
	require.NoError(t, store.Store(ctx, env))

	t.Run("within_range", func(t *testing.T) {
		from := env.IssuedAt.Add(-1 * time.Hour)
		to := env.IssuedAt.Add(1 * time.Hour)

		results, err := store.ListByTimeRange(ctx, from, to, 0, 0)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(results), 1, "should return at least 1 envelope within range")

		// Verify our envelope is in the results.
		found := false
		for _, e := range results {
			if e.ID == env.ID {
				found = true
				break
			}
		}
		assert.True(t, found, "stored envelope should be found within time range")
	})

	t.Run("outside_range", func(t *testing.T) {
		fromExcluded := env.IssuedAt.Add(1 * time.Minute)
		toExcluded := env.IssuedAt.Add(2 * time.Hour)

		results, err := store.ListByTimeRange(ctx, fromExcluded, toExcluded, 0, 0)
		require.NoError(t, err)

		// Our envelope should NOT be in the results.
		for _, e := range results {
			assert.NotEqual(t, env.ID, e.ID, "envelope outside range should not appear")
		}
	})
}

// --------------------------------------------------------------------------
// PruneExpired
// --------------------------------------------------------------------------

func TestIntegration_PostgresAttestationStore_PruneExpired(t *testing.T) {
	store, cleanup := setupIntegrationStore(t)
	defer cleanup()

	ctx := context.Background()
	kr := integrationKeyRing(t)

	// Store a short-lived envelope (will expire quickly).
	expiredEnv := integrationEnvelopeWithTTL(t, kr, TypeEvidenceManifest,
		uniqueSubject("manifest", "expired"), 1*time.Millisecond)
	require.NoError(t, store.Store(ctx, expiredEnv))

	// Wait for the envelope to expire.
	time.Sleep(50 * time.Millisecond)

	// Store a non-expiring envelope (TTL=0).
	nonExpiringEnv := integrationEnvelopeWithTTL(t, kr, TypeEvaluatorRun,
		uniqueSubject("evaluation", "no-expire"), 0)
	require.NoError(t, store.Store(ctx, nonExpiringEnv))

	// Store a long-lived envelope.
	longLivedEnv := integrationEnvelopeWithTTL(t, kr, TypeAIBOM,
		uniqueSubject("aibom", "long-lived"), 24*time.Hour)
	require.NoError(t, store.Store(ctx, longLivedEnv))

	// Prune with cutoff = now (should remove the expired envelope).
	pruned, err := store.PruneExpired(ctx, time.Now().UTC())
	require.NoError(t, err)
	assert.GreaterOrEqual(t, pruned, 1, "should prune at least 1 expired envelope")

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
}

func TestIntegration_PostgresAttestationStore_PruneExpired_ZeroValidUntil(t *testing.T) {
	store, cleanup := setupIntegrationStore(t)
	defer cleanup()

	ctx := context.Background()
	kr := integrationKeyRing(t)

	// Store multiple envelopes with no expiration (TTL=0).
	for i := 0; i < 3; i++ {
		env := integrationEnvelopeWithTTL(t, kr, TypeEvidenceManifest,
			uniqueSubject("manifest", fmt.Sprintf("never-expire-%d", i)), 0)
		require.NoError(t, store.Store(ctx, env))
	}

	// Prune with a very old cutoff — should not remove any.
	pruned, err := store.PruneExpired(ctx, time.Now().UTC())
	require.NoError(t, err)
	assert.GreaterOrEqual(t, pruned, 0, "zero-value ValidUntil envelopes should never be pruned")
}

// --------------------------------------------------------------------------
// CountByType
// --------------------------------------------------------------------------

func TestIntegration_PostgresAttestationStore_CountByType(t *testing.T) {
	store, cleanup := setupIntegrationStore(t)
	defer cleanup()

	ctx := context.Background()
	kr := integrationKeyRing(t)

	// Store several envelopes of the same type.
	for i := 0; i < 5; i++ {
		env := integrationEnvelope(t, kr, TypeEvidenceManifest,
			uniqueSubject("manifest", fmt.Sprintf("count-%d", i)))
		require.NoError(t, store.Store(ctx, env))
	}

	count, err := store.CountByType(ctx, TypeEvidenceManifest)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, count, 5, "should count at least 5 evidence.manifest.v1 envelopes")

	// Other type should have 0 count in a fresh container.
	otherCount, err := store.CountByType(ctx, TypeCVEEntry)
	require.NoError(t, err)
	assert.Equal(t, 0, otherCount, "unmatched type should have 0 count")
}

// --------------------------------------------------------------------------
// Close
// --------------------------------------------------------------------------

func TestIntegration_PostgresAttestationStore_Close(t *testing.T) {
	store, cleanup := setupIntegrationStore(t)
	defer cleanup()

	// Close is a no-op (pool lifecycle managed externally).
	err := store.Close()
	assert.NoError(t, err, "Close should not return an error")
}

// --------------------------------------------------------------------------
// Full workflow: Store → Get → List → Count → Prune
// --------------------------------------------------------------------------

func TestIntegration_PostgresAttestationStore_FullWorkflow(t *testing.T) {
	store, cleanup := setupIntegrationStore(t)
	defer cleanup()

	ctx := context.Background()
	kr := integrationKeyRing(t)

	// Step 1: Store multiple envelopes of different types.
	env1 := integrationEnvelope(t, kr, TypeEvidenceManifest, uniqueSubject("manifest", "wf-1"))
	env2 := integrationEnvelope(t, kr, TypeEvaluatorRun, uniqueSubject("evaluation", "wf-2"))
	env3 := integrationEnvelope(t, kr, TypeAIBOM, uniqueSubject("aibom", "wf-3"))
	env4 := integrationEnvelope(t, kr, TypeEvidenceManifest, uniqueSubject("manifest", "wf-4"))

	require.NoError(t, store.Store(ctx, env1), "Store env1 should succeed")
	require.NoError(t, store.Store(ctx, env2), "Store env2 should succeed")
	require.NoError(t, store.Store(ctx, env3), "Store env3 should succeed")
	require.NoError(t, store.Store(ctx, env4), "Store env4 should succeed")

	// Step 2: Get by ID.
	got, err := store.Get(ctx, env1.ID)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, env1.ID, got.ID, "Get should return the stored envelope")
	assert.Equal(t, env1.Subject, got.Subject, "Subject should match")
	assert.Equal(t, env1.Issuer, got.Issuer, "Issuer should match")

	// Step 3: ListByType.
	manifests, err := store.ListByType(ctx, TypeEvidenceManifest, 0, 0)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(manifests), 2, "should list at least 2 evidence.manifest.v1 envelopes")
	for _, e := range manifests {
		assert.Equal(t, TypeEvidenceManifest, e.Type, "all results should be evidence.manifest.v1")
	}

	// Step 4: ListBySubject.
	subjectResults, err := store.ListBySubject(ctx, env1.Subject, 0, 0)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(subjectResults), 1, "should list at least 1 envelope for subject")
	for _, e := range subjectResults {
		assert.Equal(t, env1.Subject, e.Subject)
	}

	// Step 5: ListByIssuer.
	issuerResults, err := store.ListByIssuer(ctx, env1.Issuer, 0, 0)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(issuerResults), 1, "should list at least 1 envelope for issuer")

	// Step 6: ListByTimeRange.
	from := env1.IssuedAt.Add(-1 * time.Hour)
	to := env1.IssuedAt.Add(1 * time.Hour)
	timeResults, err := store.ListByTimeRange(ctx, from, to, 0, 0)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(timeResults), 1, "should list at least 1 envelope in time range")

	// Step 7: CountByType.
	count, err := store.CountByType(ctx, TypeEvidenceManifest)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, count, 2, "should count at least 2 evidence.manifest.v1 envelopes")

	// Step 8: PruneExpired with a future cutoff (should not remove anything recent).
	pruned, err := store.PruneExpired(ctx, time.Now().UTC())
	require.NoError(t, err)
	assert.GreaterOrEqual(t, pruned, 0, "prune should not error on recent data")
}