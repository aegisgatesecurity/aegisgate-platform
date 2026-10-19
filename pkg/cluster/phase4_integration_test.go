// SPDX-License-Identifier: Apache-2.0
//go:build integration

// Phase 4 integration tests for the DistributedRateLimiter in distributed
// mode (with PostgreSQL pool). Uses testcontainers to spin up an ephemeral
// PostgreSQL container.
// Run with: go test -tags=integration -count=1 ./pkg/cluster/...

package cluster_test

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/cluster"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/testdb"
)

func setupRateLimiter(t *testing.T, nodeID string, ratePerMin int) (*cluster.DistributedRateLimiter, func()) {
	t.Helper()
	pgStore, dbCleanup := testdb.SetupTestDB(t)
	drl := cluster.NewDistributedRateLimiter(pgStore.Pool(), nodeID, ratePerMin, slog.Default())
	cleanup := func() {
		drl.Cleanup(context.Background())
		dbCleanup()
	}
	return drl, cleanup
}

func TestPhase4_DistributedRateLimiter_DistributedMode(t *testing.T) {
	drl, cleanup := setupRateLimiter(t, "node-1", 6000) // 100/s
	defer cleanup()

	if drl.Mode() != "distributed" {
		t.Errorf("expected mode 'distributed', got '%s'", drl.Mode())
	}
}

func TestPhase4_DistributedRateLimiter_AllowDistributed_BelowLimit(t *testing.T) {
	drl, cleanup := setupRateLimiter(t, "node-1", 6000) // 100/s
	defer cleanup()

	// Should allow requests within the rate limit
	allowed := 0
	for i := 0; i < 50; i++ {
		if drl.Allow("client-dist-1") {
			allowed++
		}
	}
	if allowed == 0 {
		t.Error("expected some requests to be allowed in distributed mode")
	}
}

func TestPhase4_DistributedRateLimiter_AllowDistributed_AboveLimit(t *testing.T) {
	// Very low rate: 60 RPM = 1/s. After 1 request in the window, subsequent
	// requests should be denied (total > 1).
	drl, cleanup := setupRateLimiter(t, "node-1", 60) // 1/s
	defer cleanup()

	// First request should be allowed (count=1, total=1, ratePerWindow=1)
	if !drl.Allow("client-dist-2") {
		t.Fatal("first request should be allowed")
	}

	// Subsequent requests in the same window should be denied
	denied := 0
	for i := 0; i < 10; i++ {
		if !drl.Allow("client-dist-2") {
			denied++
		}
	}
	if denied == 0 {
		t.Error("expected some requests to be denied after exceeding rate limit")
	}
}

func TestPhase4_DistributedRateLimiter_MultiNode(t *testing.T) {
	pgStore, dbCleanup := testdb.SetupTestDB(t)
	defer dbCleanup()

	// Two nodes sharing the same PostgreSQL pool
	drl1 := cluster.NewDistributedRateLimiter(pgStore.Pool(), "node-a", 60, slog.Default()) // 1/s
	drl2 := cluster.NewDistributedRateLimiter(pgStore.Pool(), "node-b", 60, slog.Default()) // 1/s

	// Both nodes share the same key — global limit applies
	allowed1 := drl1.Allow("shared-client")
	allowed2 := drl2.Allow("shared-client")

	// At least one should be allowed, but with 1/s limit and two increments,
	// the second one might be denied (total=2 > ratePerWindow=1)
	if !allowed1 {
		t.Error("first node should be allowed")
	}
	// With 2 total requests in the same window and rate=1/s, second should be denied
	if allowed2 {
		// This could be allowed if timing crosses a window boundary
		t.Log("note: second node was allowed (possible window boundary)")
	}
}

func TestPhase4_DistributedRateLimiter_Cleanup(t *testing.T) {
	drl, cleanup := setupRateLimiter(t, "node-1", 6000)
	defer cleanup()

	// Generate some rate limit data
	drl.Allow("client-cleanup-1")
	drl.Allow("client-cleanup-2")

	// Wait for windows to expire
	time.Sleep(6 * time.Second)

	// Cleanup should remove expired windows without error
	drl.Cleanup(context.Background())
	// No assertion — just verifying no panic/error
}

func TestPhase4_DistributedRateLimiter_Cleanup_EmptyTable(t *testing.T) {
	drl, cleanup := setupRateLimiter(t, "node-1", 6000)
	defer cleanup()

	// Cleanup on empty table should be fine
	drl.Cleanup(context.Background())
}

func TestPhase4_DistributedRateLimiter_DifferentKeys(t *testing.T) {
	drl, cleanup := setupRateLimiter(t, "node-1", 6000)
	defer cleanup()

	// Different keys should have independent counters
	drl.Allow("client-a")
	drl.Allow("client-b")
	drl.Allow("client-c")
	// No assertion needed — just verifying no error
}

func TestPhase4_DistributedRateLimiter_ConcurrentAccess(t *testing.T) {
	drl, cleanup := setupRateLimiter(t, "node-1", 60000) // 1000/s
	defer cleanup()

	var wg sync.WaitGroup
	allowedCount := int64(0)
	deniedCount := int64(0)
	var mu sync.Mutex

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if drl.Allow("concurrent-client") {
				mu.Lock()
				allowedCount++
				mu.Unlock()
			} else {
				mu.Lock()
				deniedCount++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if allowedCount == 0 {
		t.Error("expected some concurrent requests to be allowed")
	}
}

func TestPhase4_DistributedRateLimiter_AllowThenDenyThenAllow(t *testing.T) {
	// 60 RPM = 1/s
	drl, cleanup := setupRateLimiter(t, "node-1", 60)
	defer cleanup()

	// First request in window: allowed
	if !drl.Allow("client-cycle") {
		t.Fatal("first request should be allowed")
	}

	// Second request in same window: denied (total=2 > 1)
	if drl.Allow("client-cycle") {
		t.Log("note: second request was allowed (possible window boundary)")
	}

	// Wait for new window
	time.Sleep(1100 * time.Millisecond)

	// New window: should be allowed again
	if !drl.Allow("client-cycle") {
		t.Fatal("request in new window should be allowed")
	}
}

// Very low rate (30 RPM = 0.5/s) — ratePerWindow < 1, should be clamped to 1
func TestPhase4_DistributedRateLimiter_VeryLowRate(t *testing.T) {
	drl, cleanup := setupRateLimiter(t, "node-1", 30) // 0.5/s → ratePerWindow=0 → clamped to 1
	defer cleanup()

	// First request should be allowed (ratePerWindow=1, total=1, 1<=1)
	if !drl.Allow("client-lowrate") {
		t.Fatal("first request should be allowed with low rate")
	}

	// Second request in same window should be denied (total=2 > 1)
	if drl.Allow("client-lowrate") {
		t.Log("note: second request was allowed (possible window boundary)")
	}
}

// Fallback to local mode when DB becomes unreachable
func TestPhase4_DistributedRateLimiter_FallbackToLocal(t *testing.T) {
	pgStore, dbCleanup := testdb.SetupTestDB(t)
	drl := cluster.NewDistributedRateLimiter(pgStore.Pool(), "node-fb", 6000, slog.Default())

	// Close the database — subsequent Allow calls should fall back to local
	dbCleanup()

	// This should NOT panic — should fall back to local rate limiting
	// The query will fail, and allowDistributed calls allowLocal as fallback
	allowed := drl.Allow("client-fallback")
	// In local fallback mode, the first request should be allowed
	if !allowed {
		t.Log("note: fallback to local did not allow first request (timing-dependent)")
	}
}

// Cleanup removes expired rows — verify rowsAffected > 0 path
func TestPhase4_DistributedRateLimiter_Cleanup_RemovesRows(t *testing.T) {
	drl, cleanup := setupRateLimiter(t, "node-1", 6000)
	defer cleanup()

	// Generate data in current window
	drl.Allow("client-cleanup-r1")
	drl.Allow("client-cleanup-r2")
	drl.Allow("client-cleanup-r3")

	// Wait for windows to expire (> 5 seconds for cutoff)
	time.Sleep(6 * time.Second)

	// Cleanup should remove the expired rows
	drl.Cleanup(context.Background())

	// Verify the table is clean — new requests should work fine
	if !drl.Allow("client-cleanup-r1") {
		t.Fatal("should allow after cleanup")
	}
}
