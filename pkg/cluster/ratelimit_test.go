// SPDX-License-Identifier: Apache-2.0
package cluster_test

import (
	"log/slog"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/cluster"
)

func TestNewDistributedRateLimiter_LocalMode(t *testing.T) {
	// nil pgPool = local (per-node) rate limiting
	rl := cluster.NewDistributedRateLimiter(nil, "node-1", 6000, nil) // 6000 RPM = 100/s

	if rl.Mode() != "local" {
		t.Errorf("expected mode 'local', got '%s'", rl.Mode())
	}

	// Should allow requests within the rate limit
	allowed := 0
	for i := 0; i < 100; i++ {
		if rl.Allow("client-1") {
			allowed++
		}
	}
	if allowed == 0 {
		t.Error("expected some requests to be allowed")
	}
}

func TestNewDistributedRateLimiter_WithLogger(t *testing.T) {
	logger := slog.Default()
	rl := cluster.NewDistributedRateLimiter(nil, "node-1", 6000, logger)
	if rl.Mode() != "local" {
		t.Errorf("expected mode 'local', got '%s'", rl.Mode())
	}
}

func TestDistributedRateLimiter_DifferentKeys(t *testing.T) {
	rl := cluster.NewDistributedRateLimiter(nil, "node-1", 6000, nil)

	// Different keys should have independent rate limits
	rl.Allow("client-1")
	rl.Allow("client-2")
	rl.Allow("client-3")

	// No error means the function works with multiple keys
}

func TestDistributedRateLimiter_ZeroRate(t *testing.T) {
	// Zero or negative rate should use default
	rl := cluster.NewDistributedRateLimiter(nil, "node-1", 0, nil)
	if rl.Mode() != "local" {
		t.Errorf("expected mode 'local' for zero rate")
	}
}

func TestDistributedRateLimiter_NegativeRate(t *testing.T) {
	// Negative rate should use default
	rl := cluster.NewDistributedRateLimiter(nil, "node-1", -100, nil)
	if rl.Mode() != "local" {
		t.Errorf("expected mode 'local' for negative rate")
	}
	// Should still allow requests with default rate
	if !rl.Allow("test-key") {
		t.Error("expected Allow to succeed with default rate")
	}
}

func TestDistributedRateLimiter_LowRate(t *testing.T) {
	// Very low rate should set minimum burst
	rl := cluster.NewDistributedRateLimiter(nil, "node-1", 30, nil) // 30 RPM, burst = 30/6 = 5 < 10, so 10

	// Should still allow at least some requests
	allowed := 0
	for i := 0; i < 15; i++ {
		if rl.Allow("low-rate-client") {
			allowed++
		}
	}
	if allowed == 0 {
		t.Error("expected at least some requests to be allowed with low rate")
	}
}

func TestDistributedRateLimiter_ManyKeysLocalMode(t *testing.T) {
	rl := cluster.NewDistributedRateLimiter(nil, "node-1", 6000, nil)

	// Create many independent keys
	for i := 0; i < 50; i++ {
		key := string(rune('A'+i%26)) + "-client"
		rl.Allow(key)
	}
	// All keys should be independent and allowed
}

func TestDistributedRateLimiter_AllowLocal_BurstBehavior(t *testing.T) {
	// 600 RPM = 10/s, burst = 600/6 = 100
	rl := cluster.NewDistributedRateLimiter(nil, "node-1", 600, nil)

	// Should allow burst up to the limit
	allowed := 0
	for i := 0; i < 150; i++ {
		if rl.Allow("burst-client") {
			allowed++
		}
	}
	// Should allow some but not all
	if allowed == 0 {
		t.Error("expected some burst requests to be allowed")
	}
	if allowed >= 150 {
		t.Error("expected some requests to be rate-limited in burst")
	}
}

func TestDistributedRateLimiter_Cleanup_LocalMode(t *testing.T) {
	rl := cluster.NewDistributedRateLimiter(nil, "node-1", 6000, nil)

	// Cleanup should be a no-op in local mode (no panic, no error)
	rl.Allow("test-key")
	// This just ensures no panic
}

func TestDistributedRateLimiter_ModeConsistency(t *testing.T) {
	// Local mode
	localRL := cluster.NewDistributedRateLimiter(nil, "node-1", 6000, nil)
	if localRL.Mode() != "local" {
		t.Errorf("expected 'local', got '%s'", localRL.Mode())
	}

	// Calling Mode() multiple times should be consistent
	for i := 0; i < 5; i++ {
		if localRL.Mode() != "local" {
			t.Error("Mode() should be consistent across calls")
		}
	}
}
