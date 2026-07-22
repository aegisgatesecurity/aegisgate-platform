// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - Trust Portal: 60s in-memory cache
// =========================================================================
//
// The trust portal's 3 JSON endpoints (/trust/api/posture, /frameworks,
// /uptime) are polled by the public HTML page every 60 seconds. To
// avoid re-running the underlying checks on every poll, each endpoint
// caches its result for a configurable TTL (default 60s for posture
// and frameworks, 1h for uptime).
//
// The cache is intentionally simple: a struct with mu, value, and
// expiresAt. No external dependencies (no LRU, no TTL library). The
// page polls every 60s and the cache serves the same data to all
// pollers, so we expect ~1 cache miss per 60s per endpoint under
// normal load.
//
// Thread-safety: all access is guarded by sync.RWMutex. The page
// may be polled by many concurrent browsers; the underlying checks
// (posture, compliance scan) are read-only so concurrent reads are
// safe.
// =========================================================================

package trustportal

import (
	"sync"
	"time"
)

// Cache is a generic TTL cache. Zero value is NOT ready to use; call
// NewCache. The cache holds a single value at a time (no keying) - the
// trust portal endpoints each get their own Cache instance.
type Cache[T any] struct {
	mu        sync.RWMutex
	value     T
	expiresAt time.Time
	hasValue  bool
	ttl       time.Duration
	// now is the time function. Defaults to time.Now. Injectable
	// for deterministic tests.
	now func() time.Time
}

// NewCache creates a Cache with the given TTL. ttl must be > 0; values
// <= 0 are treated as 60s (the default for the trust portal's posture
// and framework endpoints).
func NewCache[T any](ttl time.Duration) *Cache[T] {
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	return &Cache[T]{
		ttl: ttl,
		now: time.Now,
	}
}

// Get returns the cached value if it's still fresh. If the value
// has expired or no value has been set, returns the zero value of T
// and ok=false. Callers should check ok and call Set with a freshly
// computed value if ok is false.
func (c *Cache[T]) Get() (T, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.hasValue || c.now().After(c.expiresAt) {
		var zero T
		return zero, false
	}
	return c.value, true
}

// Set stores the value with the configured TTL. The expiresAt time
// is computed as now() + ttl. If the same value is set twice, the
// second Set wins (last-write-wins, no de-duplication).
func (c *Cache[T]) Set(value T) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.value = value
	c.expiresAt = c.now().Add(c.ttl)
	c.hasValue = true
}

// Invalidate clears the cache. The next Get returns the zero value
// and ok=false. Useful for forcing a refresh after a configuration
// change or in tests.
func (c *Cache[T]) Invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.hasValue = false
	c.value = *new(T)
	c.expiresAt = time.Time{}
}

// setNow is exported within the package for tests that want to
// inject a deterministic clock. Not part of the public API.
func (c *Cache[T]) setNow(now func() time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = now
}
