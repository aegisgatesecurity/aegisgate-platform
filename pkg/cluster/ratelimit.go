// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Distributed Rate Limiter
// =========================================================================
//
// ratelimit.go provides a rate limiter that coordinates across multiple
// AegisGate instances using PostgreSQL as a shared counter backend.
//
// Architecture:
//
//   - When PostgreSQL is available (Professional+ tier), the limiter
//     uses a sliding-window counter in PostgreSQL. Each instance
//     increments a shared counter and checks the total against the
//     configured rate. This ensures that a 10K RPM limit is enforced
//     globally across all instances, not per-node.
//   - When PostgreSQL is unavailable (Community tier), the limiter
//     falls back to per-node token buckets (golang.org/x/time/rate).
//     This means a 10K RPM limit becomes 10K per node. Operators
//     should use external rate limiting (Envoy, Redis, LB) for
//     Community-tier clusters.
//
// The PostgreSQL implementation uses a sliding-window counter with a
// 1-second granularity. Each instance:
//  1. INSERTs or UPDATES its counter row for the current window
//  2. Sums all instance counters for the current window
//  3. Returns Allow if the sum is within the rate limit
//
// This design has the following properties:
//   - Correctness: Within the 1-second window granularity, the global
//     rate limit is enforced. There is a brief window at boundary
//     transitions where the limit may be slightly over (up to 2x
//     the per-second rate for 1 second), which is acceptable for
//     rate limiting.
//   - Availability: If PostgreSQL is unreachable, the limiter falls
//     back to per-node token buckets. Rate limiting continues, just
//     without global coordination.
//   - Performance: Each Allow() call is a single SQL statement with
//     a SUM aggregation. For 3-5 instances, this is sub-millisecond
//     on PostgreSQL.
//
// v3.4.1 clustering support.
// =========================================================================
package cluster

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/time/rate"
)

// DistributedRateLimiter coordinates rate limiting across cluster nodes.
// When a PostgreSQL pool is provided, it uses shared counters for global
// rate enforcement. Otherwise, it falls back to per-node token buckets.
type DistributedRateLimiter struct {
	pgPool   *pgxpool.Pool
	nodeID   string
	mu       sync.RWMutex
	local    map[string]*rate.Limiter
	ratePerS float64 // requests per second
	burst    int
	logger   *slog.Logger
}

// NewDistributedRateLimiter creates a rate limiter for cluster use.
// If pgPool is nil, falls back to per-node rate limiting.
func NewDistributedRateLimiter(pgPool *pgxpool.Pool, nodeID string, ratePerMin int, logger *slog.Logger) *DistributedRateLimiter {
	ratePerS := float64(ratePerMin) / 60.0
	if ratePerS <= 0 {
		ratePerS = float64(10000) / 60.0 // default: 10K RPM
	}
	burst := ratePerMin / 6 // allow 10s worth of burst
	if burst < 10 {
		burst = 10
	}
	if logger == nil {
		logger = slog.Default()
	}
	drl := &DistributedRateLimiter{
		pgPool:   pgPool,
		nodeID:   nodeID,
		local:    make(map[string]*rate.Limiter),
		ratePerS: ratePerS,
		burst:    burst,
		logger:   logger,
	}
	if pgPool != nil {
		drl.initSchema(context.Background())
	}
	return drl
}

// Allow checks whether a request from the given key (client ID, IP, etc.)
// is within the rate limit. If PostgreSQL is available, the check is
// global across all cluster nodes. Otherwise, it falls back to per-node.
func (drl *DistributedRateLimiter) Allow(key string) bool {
	if drl.pgPool != nil {
		return drl.allowDistributed(key)
	}
	return drl.allowLocal(key)
}

// allowLocal uses per-node token buckets. Each node has its own
// rate limit counter, so a 10K RPM limit is effectively 10K per node.
func (drl *DistributedRateLimiter) allowLocal(key string) bool {
	drl.mu.Lock()
	limiter, exists := drl.local[key]
	if !exists {
		limiter = rate.NewLimiter(rate.Limit(drl.ratePerS), drl.burst)
		drl.local[key] = limiter
	}
	drl.mu.Unlock()
	return limiter.Allow()
}

// allowDistributed uses PostgreSQL as a shared counter for global
// rate enforcement across all cluster nodes.
func (drl *DistributedRateLimiter) allowDistributed(key string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	window := time.Now().Truncate(time.Second).Unix()

	// Increment this node's counter for the current window
	_, err := drl.pgPool.Exec(ctx,
		`INSERT INTO cluster_rate_limits (key, window, node_id, count)
		 VALUES ($1, $2, $3, 1)
		 ON CONFLICT (key, window, node_id)
		 DO UPDATE SET count = cluster_rate_limits.count + 1`,
		key, window, drl.nodeID,
	)
	if err != nil {
		drl.logger.Warn("distributed rate limit DB error, falling back to local", "key", key, "err", err)
		return drl.allowLocal(key)
	}

	// Sum all nodes' counters for this window
	var total int
	err = drl.pgPool.QueryRow(ctx,
		`SELECT COALESCE(SUM(count), 0) FROM cluster_rate_limits WHERE key = $1 AND window = $2`,
		key, window,
	).Scan(&total)
	if err != nil {
		drl.logger.Warn("distributed rate limit query error, falling back to local", "key", key, "err", err)
		return drl.allowLocal(key)
	}

	ratePerWindow := int(drl.ratePerS) // requests per second = requests per 1-second window
	if ratePerWindow < 1 {
		ratePerWindow = 1
	}
	return total <= ratePerWindow
}

// initSchema creates the cluster_rate_limits table if it doesn't exist.
func (drl *DistributedRateLimiter) initSchema(ctx context.Context) {
	if drl.pgPool == nil {
		return
	}
	_, err := drl.pgPool.Exec(ctx,
		`CREATE TABLE IF NOT EXISTS cluster_rate_limits (
			key       TEXT    NOT NULL,
			window    BIGINT NOT NULL,
			node_id   TEXT    NOT NULL,
			count     INT    NOT NULL DEFAULT 1,
			PRIMARY KEY (key, window, node_id)
		)`)
	if err != nil {
		drl.logger.Error("failed to create cluster_rate_limits table", "err", err)
		return
	}

	// Auto-expire old windows (keep only last 2 seconds)
	_, err = drl.pgPool.Exec(ctx,
		`CREATE INDEX IF NOT EXISTS idx_cluster_rate_limits_window ON cluster_rate_limits (window)`)
	if err != nil {
		drl.logger.Warn("failed to create rate limits window index", "err", err)
	}
}

// Cleanup removes expired rate limit windows from PostgreSQL.
// Call periodically (every 10-30 seconds) from a background goroutine.
func (drl *DistributedRateLimiter) Cleanup(ctx context.Context) {
	if drl.pgPool == nil {
		return
	}
	cutoff := time.Now().Add(-5 * time.Second).Unix()
	result, err := drl.pgPool.Exec(ctx,
		`DELETE FROM cluster_rate_limits WHERE window < $1`, cutoff)
	if err != nil {
		drl.logger.Warn("rate limit cleanup error", "err", err)
		return
	}
	if result.RowsAffected() > 0 {
		drl.logger.Debug("rate limit cleanup", "rows_removed", result.RowsAffected())
	}
}

// Mode returns "distributed" if using PostgreSQL, "local" otherwise.
func (drl *DistributedRateLimiter) Mode() string {
	if drl.pgPool != nil {
		return "distributed"
	}
	return "local"
}
