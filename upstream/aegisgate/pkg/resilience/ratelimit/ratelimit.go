// Package ratelimit provides rate limiting functionality for AegisGate
package ratelimit

import (
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimiter implements token bucket rate limiting
type RateLimiter struct {
	mu     sync.RWMutex
	limits map[string]*rate.Limiter
	config *Config
}

// Config holds rate limiter configuration
type Config struct {
	RequestsPerSecond float64       `yaml:"requests_per_second"`
	BurstSize         int           `yaml:"burst_size"`
	BlockDuration     time.Duration `yaml:"block_duration"`
}

// New creates a new RateLimiter
func New(cfg *Config) *RateLimiter {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &RateLimiter{
		limits: make(map[string]*rate.Limiter),
		config: cfg,
	}
}

// DefaultConfig returns default configuration
func DefaultConfig() *Config {
	return &Config{
		RequestsPerSecond: 100.0,
		BurstSize:         200,
		BlockDuration:     5 * time.Minute,
	}
}

// Allow checks if a request should be allowed
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.RLock()
	limiter, exists := rl.limits[key]
	rl.mu.RUnlock()

	if !exists {
		rl.mu.Lock()
		if limiter, exists = rl.limits[key]; !exists {
			limiter = rate.NewLimiter(rate.Limit(rl.config.RequestsPerSecond), rl.config.BurstSize)
			rl.limits[key] = limiter
		}
		rl.mu.Unlock()
	}

	return limiter.Allow()
}

// Middleware returns HTTP middleware for rate limiting
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.RemoteAddr
		if tenant := r.Header.Get("X-Tenant-ID"); tenant != "" {
			key = tenant + ":" + key
		}

		if !rl.Allow(key) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}
