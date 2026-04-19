package ratelimit

import (
	"context"
	"testing"
	"time"
)

func TestNewLimiter(t *testing.T) {
	limiter := NewLimiter()
	if limiter == nil {
		t.Fatal("NewLimiter() returned nil")
	}
	if limiter.buckets == nil {
		t.Error("buckets map not initialized")
	}
	if limiter.config == nil {
		t.Error("config not initialized")
	}
}

func TestNewLimiterWithConfig(t *testing.T) {
	cfg := &Config{
		RequestsPerSecond: 5,
		BurstSize:         10,
	}
	limiter := NewLimiterWithConfig(cfg)
	if limiter.config.RequestsPerSecond != 5 {
		t.Errorf("RequestsPerSecond = %v, want 5", limiter.config.RequestsPerSecond)
	}
	if limiter.config.BurstSize != 10 {
		t.Errorf("BurstSize = %v, want 10", limiter.config.BurstSize)
	}
}

func TestLimiterAllow(t *testing.T) {
	limiter := NewLimiter()

	decision := limiter.Allow(context.Background(), "test-key")
	if !decision.Allowed {
		t.Error("First request should be allowed")
	}
	if decision.Remaining == 0 {
		t.Error("Should have remaining tokens")
	}
}

func TestLimiterExceedsLimit(t *testing.T) {
	cfg := &Config{
		RequestsPerSecond: 1000, // Very fast refill for testing
		BurstSize:         2,    // Only 2 requests
	}
	limiter := NewLimiterWithConfig(cfg)

	// First two should succeed
	d1 := limiter.Allow(context.Background(), "burst-key")
	d2 := limiter.Allow(context.Background(), "burst-key")

	if !d1.Allowed || !d2.Allowed {
		t.Error("First 2 requests should be allowed")
	}

	// Third should fail
	d3 := limiter.Allow(context.Background(), "burst-key")
	if d3.Allowed {
		t.Error("Third request should be denied (burst exceeded)")
	}
	if d3.RetryAfter <= 0 {
		t.Error("Should have retry after time")
	}
}

func TestLimiterReset(t *testing.T) {
	limiter := NewLimiter()

	limiter.Allow(context.Background(), "reset-key")
	limiter.Allow(context.Background(), "reset-key")

	limiter.Reset(context.Background(), "reset-key")

	decision := limiter.Allow(context.Background(), "reset-key")
	if !decision.Allowed {
		t.Error("After reset, request should be allowed")
	}
}

func TestLimiterGetRemaining(t *testing.T) {
	limiter := NewLimiter()

	limiter.Allow(context.Background(), "key1")
	limiter.Allow(context.Background(), "key1")

	remaining := limiter.GetRemaining("key1")
	t.Logf("Remaining tokens: %d", remaining)
	if remaining < 0 {
		t.Error("Remaining should not be negative")
	}
}

func TestLimiterGetRemainingEmpty(t *testing.T) {
	limiter := NewLimiter()

	remaining := limiter.GetRemaining("nonexistent")
	if remaining == 0 {
		t.Error("Should return burst size for unknown key")
	}
}

func TestLimiterHasKey(t *testing.T) {
	limiter := NewLimiter()

	if limiter.HasKey("test") {
		t.Error("Key should not exist initially")
	}

	limiter.Allow(context.Background(), "test")

	if !limiter.HasKey("test") {
		t.Error("Key should exist after Allow()")
	}
}

func TestLimiterKeys(t *testing.T) {
	limiter := NewLimiter()

	limiter.Allow(context.Background(), "key1")
	limiter.Allow(context.Background(), "key2")
	limiter.Allow(context.Background(), "key3")

	keys := limiter.Keys()
	if len(keys) != 3 {
		t.Errorf("Keys() count = %d, want 3", len(keys))
	}
}

func TestLimiterAllowN(t *testing.T) {
	limiter := NewLimiter()

	// Try to reserve 5 tokens
	decision := limiter.AllowN(context.Background(), "bulk-key", 5)
	t.Logf("AllowN(5): allowed=%v, remaining=%d", decision.Allowed, decision.Remaining)
}

func TestLimiterAllowWithBurst(t *testing.T) {
	limiter := NewLimiter()

	decision := limiter.AllowWithBurst(context.Background(), "burst-test", 50)
	if !decision.Allowed {
		t.Error("Request should be allowed")
	}
}

func TestLimiterResetAll(t *testing.T) {
	limiter := NewLimiter()

	limiter.Allow(context.Background(), "key1")
	limiter.Allow(context.Background(), "key2")

	limiter.ResetAll(context.Background())

	if len(limiter.Keys()) != 0 {
		t.Error("ResetAll() should clear all keys")
	}
}

func TestTokenBucketRemaining(t *testing.T) {
	cfg := &Config{
		RequestsPerSecond: 10,
		BurstSize:         5,
	}
	limiter := NewLimiterWithConfig(cfg)

	limiter.Allow(context.Background(), "remaining-test")
	limiter.Allow(context.Background(), "remaining-test")

	remaining := limiter.GetRemaining("remaining-test")
	t.Logf("Remaining after 2 requests: %d", remaining)
}

func TestTokenBucketWaitTime(t *testing.T) {
	cfg := &Config{
		RequestsPerSecond: 1, // 1 token per second
		BurstSize:         1,
	}
	limiter := NewLimiterWithConfig(cfg)

	// Exhaust the bucket
	limiter.Allow(context.Background(), "wait-test")

	waitTime := limiter.GetWaitTime("wait-test")
	t.Logf("Wait time: %v", waitTime)
	if waitTime <= 0 {
		t.Error("Wait time should be > 0 after exhausting")
	}
}

func TestTokenBucketWaitTimeEmpty(t *testing.T) {
	limiter := NewLimiter()

	waitTime := limiter.GetWaitTime("nonexistent")
	if waitTime != 0 {
		t.Error("Wait time for unknown key should be 0")
	}
}

func TestSlidingWindowLimiter(t *testing.T) {
	cfg := &Config{
		RequestsPerSecond: 100,
		BurstSize:         3,
		Window:            time.Second,
	}
	limiter := NewSlidingWindowLimiter(cfg)

	d1 := limiter.Allow(context.Background(), "sliding-key")
	d2 := limiter.Allow(context.Background(), "sliding-key")
	d3 := limiter.Allow(context.Background(), "sliding-key")

	if !d1.Allowed || !d2.Allowed || !d3.Allowed {
		t.Error("First 3 requests should be allowed")
	}

	d4 := limiter.Allow(context.Background(), "sliding-key")
	if d4.Allowed {
		t.Error("4th request should be denied")
	}
}

func TestSlidingWindowLimiterReset(t *testing.T) {
	cfg := &Config{
		Window:    time.Second,
		BurstSize: 2,
	}
	limiter := NewSlidingWindowLimiter(cfg)

	limiter.Allow(context.Background(), "sw-reset")
	limiter.Allow(context.Background(), "sw-reset")

	limiter.Reset(context.Background(), "sw-reset")

	d := limiter.Allow(context.Background(), "sw-reset")
	if !d.Allowed {
		t.Error("After reset, request should be allowed")
	}
}

func TestSlidingWindowLimiterTimeBased(t *testing.T) {
	cfg := &Config{
		Window:    100 * time.Millisecond,
		BurstSize: 2,
	}
	limiter := NewSlidingWindowLimiter(cfg)

	limiter.Allow(context.Background(), "time-key")
	limiter.Allow(context.Background(), "time-key")

	// Wait for window to pass
	time.Sleep(150 * time.Millisecond)

	d := limiter.Allow(context.Background(), "time-key")
	if !d.Allowed {
		t.Error("After window expiry, request should be allowed")
	}
}

func TestRateLimitError(t *testing.T) {
	err := &RateLimitError{"rate limit exceeded"}
	if err.Error() != "rate limit exceeded" {
		t.Errorf("Error() = %s, want 'rate limit exceeded'", err.Error())
	}
}

func TestLimiterConcurrent(t *testing.T) {
	limiter := NewLimiter()
	done := make(chan bool, 50)

	for i := 0; i < 50; i++ {
		go func() {
			limiter.Allow(context.Background(), "concurrent-key")
			done <- true
		}()
	}

	for i := 0; i < 50; i++ {
		<-done
	}

	t.Log("Completed 50 concurrent requests without deadlock")
}

func TestLimiterMultipleKeys(t *testing.T) {
	limiter := NewLimiter()

	// Each key should have independent limits
	d1 := limiter.Allow(context.Background(), "key1")
	d2 := limiter.Allow(context.Background(), "key2")
	d3 := limiter.Allow(context.Background(), "key3")

	if !d1.Allowed || !d2.Allowed || !d3.Allowed {
		t.Error("Different keys should have independent limits")
	}
}
