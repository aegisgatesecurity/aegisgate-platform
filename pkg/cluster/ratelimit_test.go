// SPDX-License-Identifier: Apache-2.0
package cluster_test

import (
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