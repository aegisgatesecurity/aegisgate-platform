// Package contextisolator provides memory isolation for agent sessions
package contextisolator

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// MemoryStore provides isolated memory storage per session
type MemoryStore struct {
	mu       sync.RWMutex
	memory   map[string]map[string]interface{}
	config   *MemoryConfig
	stats    *MemoryStats
}

// MemoryConfig holds memory store configuration
type MemoryConfig struct {
	MaxMemoryPerSession int64  // Maximum bytes per session
	MaxKeysPerSession   int    // Maximum keys per session
	EnableSwap          bool   // Enable swap to disk for overflow
}

// MemoryStats holds memory store statistics
type MemoryStats struct {
	TotalSessions   int64
	TotalKeys      int64
	TotalBytesUsed int64
	hits           int64
	misses         int64
}

// NewMemoryStore creates a new memory store with default configuration
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		memory: make(map[string]map[string]interface{}),
		config: &MemoryConfig{
			MaxMemoryPerSession: 100 * 1024 * 1024, // 100MB default
			MaxKeysPerSession:   10000,
			EnableSwap:          false,
		},
		stats: &MemoryStats{},
	}
}

// NewMemoryStoreWithConfig creates a memory store with custom configuration
func NewMemoryStoreWithConfig(config *MemoryConfig) *MemoryStore {
	if config.MaxMemoryPerSession == 0 {
		config.MaxMemoryPerSession = 100 * 1024 * 1024
	}
	if config.MaxKeysPerSession == 0 {
		config.MaxKeysPerSession = 10000
	}
	return &MemoryStore{
		memory: make(map[string]map[string]interface{}),
		config: config,
		stats:  &MemoryStats{},
	}
}

// Set stores a value in session memory with memory limit enforcement
func (ms *MemoryStore) Set(ctx context.Context, sessionID, key string, value interface{}) error {
	if sessionID == "" {
		return ErrInvalidSessionID
	}
	if key == "" {
		return ErrInvalidKey
	}

	ms.mu.Lock()
	defer ms.mu.Unlock()

	// Get or create session memory map
	sessionMem, exists := ms.memory[sessionID]
	if !exists {
		sessionMem = make(map[string]interface{})
		ms.memory[sessionID] = sessionMem
		atomic.AddInt64(&ms.stats.TotalSessions, 1)
	}

	// Check key limit
	if len(sessionMem) >= ms.config.MaxKeysPerSession {
		return ErrMaxKeysReached
	}

	// Calculate new memory usage
	oldValue := sessionMem[key]
	oldSize := estimateSize(oldValue)
	newSize := estimateSize(value)
	currentUsage := ms.getSessionUsageLocked(sessionID)

	// Check memory limit (only for new/changed values)
	if oldSize == 0 { // New key
		if currentUsage+newSize > ms.config.MaxMemoryPerSession {
			return ErrMemoryLimitExceeded
		}
	}

	// Store the value
	sessionMem[key] = value

	// Update stats
	atomic.AddInt64(&ms.stats.TotalBytesUsed, int64(newSize-oldSize))
	if oldSize == 0 {
		atomic.AddInt64(&ms.stats.TotalKeys, 1)
	}

	return nil
}

// Get retrieves a value from session memory
func (ms *MemoryStore) Get(ctx context.Context, sessionID, key string) (interface{}, bool, error) {
	if sessionID == "" {
		return nil, false, ErrInvalidSessionID
	}
	if key == "" {
		return nil, false, ErrInvalidKey
	}

	ms.mu.RLock()
	defer ms.mu.RUnlock()

	sessionMem, exists := ms.memory[sessionID]
	if !exists {
		atomic.AddInt64(&ms.stats.misses, 1)
		return nil, false, nil
	}

	value, found := sessionMem[key]
	if found {
		atomic.AddInt64(&ms.stats.hits, 1)
		return value, true, nil
	}

	atomic.AddInt64(&ms.stats.misses, 1)
	return nil, false, nil
}

// Delete removes a value from session memory
func (ms *MemoryStore) Delete(ctx context.Context, sessionID, key string) error {
	if sessionID == "" {
		return ErrInvalidSessionID
	}
	if key == "" {
		return ErrInvalidKey
	}

	ms.mu.Lock()
	defer ms.mu.Unlock()

	sessionMem, exists := ms.memory[sessionID]
	if !exists {
		return nil // Deleting non-existent key is no-op
	}

	value := sessionMem[key]
	delete(sessionMem, key)
	atomic.AddInt64(&ms.stats.TotalKeys, -1)
	atomic.AddInt64(&ms.stats.TotalBytesUsed, -estimateSize(value))

	return nil
}

// GetAll returns all memory values for a session
func (ms *MemoryStore) GetAll(ctx context.Context, sessionID string) (map[string]interface{}, error) {
	if sessionID == "" {
		return nil, ErrInvalidSessionID
	}

	ms.mu.RLock()
	defer ms.mu.RUnlock()

	sessionMem, exists := ms.memory[sessionID]
	if !exists {
		return make(map[string]interface{}), nil
	}

	// Return a copy to prevent external modification
	result := make(map[string]interface{}, len(sessionMem))
	for k, v := range sessionMem {
		result[k] = v
	}

	return result, nil
}

// Clear removes all memory for a session
func (ms *MemoryStore) Clear(ctx context.Context, sessionID string) error {
	if sessionID == "" {
		return ErrInvalidSessionID
	}

	ms.mu.Lock()
	defer ms.mu.Unlock()

	sessionMem, exists := ms.memory[sessionID]
	if !exists {
		return nil
	}

	// Update stats
	atomic.AddInt64(&ms.stats.TotalKeys, -int64(len(sessionMem)))
	for _, v := range sessionMem {
		atomic.AddInt64(&ms.stats.TotalBytesUsed, -estimateSize(v))
	}
	atomic.AddInt64(&ms.stats.TotalSessions, -1)

	delete(ms.memory, sessionID)
	return nil
}

// ClearAll removes all memory from all sessions (admin function)
func (ms *MemoryStore) ClearAll(ctx context.Context) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	ms.memory = make(map[string]map[string]interface{})
	atomic.StoreInt64(&ms.stats.TotalKeys, 0)
	atomic.StoreInt64(&ms.stats.TotalBytesUsed, 0)
	atomic.StoreInt64(&ms.stats.TotalSessions, 0)

	return nil
}

// GetMemoryUsage returns memory usage statistics for a session
func (ms *MemoryStore) GetMemoryUsage(sessionID string) *MemoryUsage {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	usage := &MemoryUsage{
		SessionID: sessionID,
		Limit:     ms.config.MaxMemoryPerSession,
	}

	if sessionMem, exists := ms.memory[sessionID]; exists {
		usage.Keys = len(sessionMem)
		usage.Used = ms.getSessionUsageLocked(sessionID)
	}

	return usage
}

// GetAllMemoryUsage returns memory usage for all sessions
func (ms *MemoryStore) GetAllMemoryUsage() map[string]*MemoryUsage {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	result := make(map[string]*MemoryUsage, len(ms.memory))
	for sessionID := range ms.memory {
		result[sessionID] = ms.getMemoryUsageLocked(sessionID)
	}

	return result
}

// GetStats returns global memory store statistics
func (ms *MemoryStore) GetStats() *MemoryStats {
	return &MemoryStats{
		TotalSessions:   atomic.LoadInt64(&ms.stats.TotalSessions),
		TotalKeys:       atomic.LoadInt64(&ms.stats.TotalKeys),
		TotalBytesUsed:  atomic.LoadInt64(&ms.stats.TotalBytesUsed),
		hits:            atomic.LoadInt64(&ms.stats.hits),
		misses:          atomic.LoadInt64(&ms.stats.misses),
	}
}

// GetHitRate returns the cache hit rate
func (ms *MemoryStore) GetHitRate() float64 {
	hits := atomic.LoadInt64(&ms.stats.hits)
	misses := atomic.LoadInt64(&ms.stats.misses)
	total := hits + misses
	if total == 0 {
		return 0
	}
	return float64(hits) / float64(total)
}

// CheckCrossContamination checks if sessions might be contaminated
// Returns true if there's evidence of data leakage between sessions
func (ms *MemoryStore) CheckCrossContamination(ctx context.Context, sessionID1, sessionID2 string) (bool, error) {
	if sessionID1 == "" || sessionID2 == "" {
		return false, ErrInvalidSessionID
	}

	if sessionID1 == sessionID2 {
		return false, nil // Same session, not contamination
	}

	ms.mu.RLock()
	defer ms.mu.RUnlock()

	mem1, exists1 := ms.memory[sessionID1]
	mem2, exists2 := ms.memory[sessionID2]

	if !exists1 || !exists2 {
		return false, nil // One or both sessions don't exist
	}

	// Check for shared references (pointer equality)
	for key1, val1 := range mem1 {
		if val2, exists := mem2[key1]; exists {
			// Same key exists in both sessions
			// Check if they reference the same underlying object
			if areIdentical(val1, val2) {
				return true, nil // Potential contamination detected
			}
		}
	}

	return false, nil
}

// SetWithExpiry stores a value with automatic expiration
func (ms *MemoryStore) SetWithExpiry(ctx context.Context, sessionID, key string, value interface{}, ttl time.Duration) error {
	if err := ms.Set(ctx, sessionID, key, value); err != nil {
		return err
	}

	// Wrap value with expiry metadata
	ms.mu.Lock()
	defer ms.mu.Unlock()

	if sessionMem, exists := ms.memory[sessionID]; exists {
		sessionMem[key] = &ExpiringValue{
			Value:     value,
			ExpiresAt: time.Now().Add(ttl),
		}
	}

	return nil
}

// GetWithExpiry retrieves a value and checks expiration
func (ms *MemoryStore) GetWithExpiry(ctx context.Context, sessionID, key string) (interface{}, bool, error) {
	ms.mu.RLock()
	sessionMem, exists := ms.memory[sessionID]
	ms.mu.RUnlock()

	if !exists {
		return nil, false, nil
	}

	ms.mu.RLock()
	val, found := sessionMem[key]
	ms.mu.RUnlock()

	if !found {
		return nil, false, nil
	}

	// Check if it's an expiring value
	if expVal, ok := val.(*ExpiringValue); ok {
		if time.Now().After(expVal.ExpiresAt) {
			// Value expired, clean up
			go ms.Delete(ctx, sessionID, key)
			return nil, false, nil
		}
		return expVal.Value, true, nil
	}

	return val, true, nil
}

// ListKeys returns all keys for a session
func (ms *MemoryStore) ListKeys(sessionID string) ([]string, error) {
	if sessionID == "" {
		return nil, ErrInvalidSessionID
	}

	ms.mu.RLock()
	defer ms.mu.RUnlock()

	sessionMem, exists := ms.memory[sessionID]
	if !exists {
		return []string{}, nil
	}

	keys := make([]string, 0, len(sessionMem))
	for k := range sessionMem {
		keys = append(keys, k)
	}

	return keys, nil
}

// CleanupExpired removes all expired values
func (ms *MemoryStore) CleanupExpired(ctx context.Context) (int, error) {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	now := time.Now()
	cleaned := 0

	for sessionID, sessionMem := range ms.memory {
		for key, val := range sessionMem {
			if expVal, ok := val.(*ExpiringValue); ok {
				if now.After(expVal.ExpiresAt) {
					delete(sessionMem, key)
					atomic.AddInt64(&ms.stats.TotalKeys, -1)
					atomic.AddInt64(&ms.stats.TotalBytesUsed, -estimateSize(expVal.Value))
					cleaned++
				}
			}
		}

		// If session is now empty, clean up the session
		if len(sessionMem) == 0 {
			delete(ms.memory, sessionID)
			atomic.AddInt64(&ms.stats.TotalSessions, -1)
		}
	}

	return cleaned, nil
}

// SessionExists checks if a session has any stored memory
func (ms *MemoryStore) SessionExists(sessionID string) bool {
	ms.mu.RLock()
	defer ms.mu.RUnlock()
	_, exists := ms.memory[sessionID]
	return exists
}

// HasKey checks if a specific key exists in a session
func (ms *MemoryStore) HasKey(sessionID, key string) bool {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	if sessionMem, exists := ms.memory[sessionID]; exists {
		_, found := sessionMem[key]
		return found
	}
	return false
}

// helper functions

// getSessionUsageLocked calculates memory usage for a session (must hold lock)
func (ms *MemoryStore) getSessionUsageLocked(sessionID string) int64 {
	if sessionMem, exists := ms.memory[sessionID]; exists {
		var total int64
		for _, v := range sessionMem {
			total += estimateSize(v)
		}
		return total
	}
	return 0
}

// getMemoryUsageLocked returns usage for a session (must hold lock)
func (ms *MemoryStore) getMemoryUsageLocked(sessionID string) *MemoryUsage {
	usage := &MemoryUsage{
		SessionID: sessionID,
		Limit:     ms.config.MaxMemoryPerSession,
	}

	if sessionMem, exists := ms.memory[sessionID]; exists {
		usage.Keys = len(sessionMem)
		usage.Used = ms.getSessionUsageLocked(sessionID)
	}

	return usage
}

// estimateSize estimates the memory size of a value
func estimateSize(value interface{}) int64 {
	if value == nil {
		return 0
	}

	switch v := value.(type) {
	case string:
		return int64(len(v))
	case []byte:
		return int64(len(v))
	case int:
		return 8
	case int64:
		return 8
	case float64:
		return 8
	case bool:
		return 1
	case *ExpiringValue:
		return estimateSize(v.Value) + 16 // overhead for expiry metadata
	default:
		// For complex types, serialize to JSON and measure
		data, err := json.Marshal(v)
		if err != nil {
			return 256 // Conservative default for unknown types
		}
		return int64(len(data))
	}
}

// areIdentical checks if two values are identical (deep equality for primitives, pointer equality for complex)
func areIdentical(a, b interface{}) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}

	// For primitives, compare values
	switch av := a.(type) {
	case string:
		if bv, ok := b.(string); ok {
			return av == bv
		}
	case int:
		if bv, ok := b.(int); ok {
			return av == bv
		}
	case int64:
		if bv, ok := b.(int64); ok {
			return av == bv
		}
	case float64:
		if bv, ok := b.(float64); ok {
			return av == bv
		}
	case bool:
		if bv, ok := b.(bool); ok {
			return av == bv
		}
	}

	// For complex types, check pointer equality
	// This is what we want for contamination detection
	return fmt.Sprintf("%p", a) == fmt.Sprintf("%p", b)
}

// ExpiringValue wraps a value with expiration time
type ExpiringValue struct {
	Value     interface{}
	ExpiresAt time.Time
}

// MemoryUsage represents memory usage statistics
type MemoryUsage struct {
	SessionID string
	Used      int64
	Limit     int64
	Keys      int
}

// Errors
var (
	ErrInvalidSessionID    = &MemoryError{"invalid session ID"}
	ErrInvalidKey          = &MemoryError{"invalid key"}
	ErrMaxKeysReached      = &MemoryError{"maximum keys per session reached"}
	ErrMemoryLimitExceeded = &MemoryError{"memory limit exceeded for session"}
	ErrKeyNotFound        = &MemoryError{"key not found"}
)

// MemoryError represents a memory store error
type MemoryError struct {
	message string
}

func (e *MemoryError) Error() string {
	return e.message
}
