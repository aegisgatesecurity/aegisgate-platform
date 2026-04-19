// Package ratelimit - Rate limiting for AI agent operations
// Provides token bucket and sliding window rate limiting
package ratelimit

import (
	"context"
	"sync"
	"time"
)

// Limiter provides rate limiting functionality
type Limiter struct {
	mu      sync.RWMutex
	buckets map[string]*TokenBucket
	config  *Config
}

// TokenBucket implements token bucket algorithm
type TokenBucket struct {
	tokens     float64
	maxTokens  float64
	refillRate float64 // tokens per second
	lastRefill time.Time
	mu         sync.Mutex
}

// Config holds rate limiter configuration
type Config struct {
	RequestsPerSecond float64       // Tokens added per second
	BurstSize         int           // Maximum burst capacity
	Window            time.Duration // For sliding window mode
}

// Decision represents the result of a rate limit check
type Decision struct {
	Allowed    bool
	Remaining  int
	RetryAfter time.Duration
}

// Stats holds rate limiter statistics
type Stats struct {
	TotalRequests   int64
	AllowedRequests int64
	DeniedRequests  int64
}

// NewLimiter creates a new rate limiter with default config
func NewLimiter() *Limiter {
	return NewLimiterWithConfig(&Config{
		RequestsPerSecond: 10,
		BurstSize:         20,
	})
}

// NewLimiterWithConfig creates a rate limiter with custom config
func NewLimiterWithConfig(cfg *Config) *Limiter {
	if cfg.RequestsPerSecond == 0 {
		cfg.RequestsPerSecond = 10
	}
	if cfg.BurstSize == 0 {
		cfg.BurstSize = 20
	}
	return &Limiter{
		buckets: make(map[string]*TokenBucket),
		config:  cfg,
	}
}

// Allow checks if a request should be allowed
func (l *Limiter) Allow(ctx context.Context, key string) Decision {
	l.mu.Lock()
	defer l.mu.Unlock()

	bucket, exists := l.buckets[key]
	if !exists {
		bucket = newTokenBucket(l.config)
		l.buckets[key] = bucket
	}

	return bucket.Allow(ctx)
}

// AllowN checks if N requests should be allowed
func (l *Limiter) AllowN(ctx context.Context, key string, n int) Decision {
	l.mu.Lock()
	defer l.mu.Unlock()

	bucket, exists := l.buckets[key]
	if !exists {
		bucket = newTokenBucket(l.config)
		l.buckets[key] = bucket
	}

	return bucket.AllowN(ctx, n)
}

// AllowWithBurst allows requests with burst handling
func (l *Limiter) AllowWithBurst(ctx context.Context, key string, burst int) Decision {
	l.mu.Lock()
	defer l.mu.Unlock()

	bucket, exists := l.buckets[key]
	if !exists {
		bucket = newTokenBucketWithBurst(l.config, burst)
		l.buckets[key] = bucket
	}

	return bucket.Allow(ctx)
}

// Reset clears the rate limit for a key
func (l *Limiter) Reset(ctx context.Context, key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.buckets, key)
}

// ResetAll clears all rate limits
func (l *Limiter) ResetAll(ctx context.Context) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buckets = make(map[string]*TokenBucket)
}

// GetRemaining returns remaining tokens for a key
func (l *Limiter) GetRemaining(key string) int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if bucket, ok := l.buckets[key]; ok {
		return bucket.Remaining()
	}
	return l.config.BurstSize
}

// GetWaitTime returns how long to wait before retry
func (l *Limiter) GetWaitTime(key string) time.Duration {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if bucket, ok := l.buckets[key]; ok {
		return bucket.WaitTime()
	}
	return 0
}

// HasKey checks if a key has any rate limit history
func (l *Limiter) HasKey(key string) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	_, exists := l.buckets[key]
	return exists
}

// Keys returns all tracked rate limit keys
func (l *Limiter) Keys() []string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	keys := make([]string, 0, len(l.buckets))
	for k := range l.buckets {
		keys = append(keys, k)
	}
	return keys
}

// TokenBucket methods

// Allow checks if one request can proceed
func (b *TokenBucket) Allow(ctx context.Context) Decision {
	return b.AllowN(ctx, 1)
}

// AllowN checks if N requests can proceed
func (b *TokenBucket) AllowN(ctx context.Context, n int) Decision {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(b.lastRefill).Seconds()
	b.tokens += elapsed * b.refillRate
	if b.tokens > b.maxTokens {
		b.tokens = b.maxTokens
	}
	b.lastRefill = now

	if b.tokens >= float64(n) {
		b.tokens -= float64(n)
		return Decision{
			Allowed:   true,
			Remaining: int(b.tokens),
		}
	}

	retryAfter := time.Duration((float64(n) - b.tokens) / b.refillRate * float64(time.Second))
	return Decision{
		Allowed:    false,
		Remaining:  0,
		RetryAfter: retryAfter,
	}
}

// Remaining returns available tokens
func (b *TokenBucket) Remaining() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(b.lastRefill).Seconds()
	tokens := b.tokens + elapsed*b.refillRate
	if tokens > b.maxTokens {
		tokens = b.maxTokens
	}
	return int(tokens)
}

// WaitTime returns time to wait for one token
func (b *TokenBucket) WaitTime() time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.tokens >= 1 {
		return 0
	}
	return time.Duration((1 - b.tokens) / b.refillRate * float64(time.Second))
}

// newTokenBucket creates a new bucket with config
func newTokenBucket(cfg *Config) *TokenBucket {
	return &TokenBucket{
		tokens:     float64(cfg.BurstSize),
		maxTokens:  float64(cfg.BurstSize),
		refillRate: cfg.RequestsPerSecond,
		lastRefill: time.Now(),
	}
}

// newTokenBucketWithBurst creates a bucket with custom burst
func newTokenBucketWithBurst(cfg *Config, burst int) *TokenBucket {
	if burst <= 0 {
		burst = cfg.BurstSize
	}
	return &TokenBucket{
		tokens:     float64(burst),
		maxTokens:  float64(burst),
		refillRate: cfg.RequestsPerSecond,
		lastRefill: time.Now(),
	}
}

// SlidingWindowLimiter provides sliding window rate limiting
type SlidingWindowLimiter struct {
	mu       sync.RWMutex
	requests map[string][]time.Time
	config   *Config
}

// NewSlidingWindowLimiter creates a sliding window rate limiter
func NewSlidingWindowLimiter(cfg *Config) *SlidingWindowLimiter {
	if cfg.Window == 0 {
		cfg.Window = time.Minute
	}
	return &SlidingWindowLimiter{
		requests: make(map[string][]time.Time),
		config:   cfg,
	}
}

// Allow checks if request is allowed under sliding window
func (sw *SlidingWindowLimiter) Allow(ctx context.Context, key string) Decision {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-sw.config.Window)

	// Clean old requests
	requests := sw.requests[key]
	valid := make([]time.Time, 0, len(requests))
	for _, t := range requests {
		if t.After(windowStart) {
			valid = append(valid, t)
		}
	}

	allowed := len(valid) < sw.config.BurstSize
	if allowed {
		valid = append(valid, now)
	}
	sw.requests[key] = valid

	remaining := sw.config.BurstSize - len(valid)
	if remaining < 0 {
		remaining = 0
	}

	return Decision{
		Allowed:   allowed,
		Remaining: remaining,
	}
}

// Reset clears rate limit for a key
func (sw *SlidingWindowLimiter) Reset(ctx context.Context, key string) {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	delete(sw.requests, key)
}

// Errors
var (
	ErrRateLimited  = &RateLimitError{"rate limit exceeded"}
	ErrInvalidLimit = &RateLimitError{"invalid rate limit configuration"}
)

// RateLimitError represents a rate limit error
type RateLimitError struct {
	message string
}

func (e *RateLimitError) Error() string {
	return e.message
}
