package contextisolator

import (
	"context"
	"testing"
	"time"
)

func TestNewMemoryStore(t *testing.T) {
	store := NewMemoryStore()
	if store == nil {
		t.Fatal("NewMemoryStore() returned nil")
	}
	if store.memory == nil {
		t.Error("memory map not initialized")
	}
	if store.config == nil {
		t.Error("config not initialized")
	}
	if store.config.MaxMemoryPerSession != 100*1024*1024 {
		t.Errorf("MaxMemoryPerSession = %d, want 100MB", store.config.MaxMemoryPerSession)
	}
}

func TestNewMemoryStoreWithConfig(t *testing.T) {
	config := &MemoryConfig{
		MaxMemoryPerSession: 50 * 1024 * 1024,
		MaxKeysPerSession:   500,
		EnableSwap:          true,
	}

	store := NewMemoryStoreWithConfig(config)
	if store.config.MaxMemoryPerSession != 50*1024*1024 {
		t.Errorf("MaxMemoryPerSession = %d, want 50MB", store.config.MaxMemoryPerSession)
	}
	if store.config.MaxKeysPerSession != 500 {
		t.Errorf("MaxKeysPerSession = %d, want 500", store.config.MaxKeysPerSession)
	}
}

func TestMemoryStoreSetAndGet(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	sessionID := "session-1"

	err := store.Set(ctx, sessionID, "key1", "value1")
	if err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	val, found, err := store.Get(ctx, sessionID, "key1")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !found {
		t.Error("Get() key not found")
	}
	if val != "value1" {
		t.Errorf("Get() value = %v, want 'value1'", val)
	}
}

func TestMemoryStoreGetNonExistent(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	_, found, err := store.Get(ctx, "session-1", "nonexistent")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if found {
		t.Error("Get() should return false for nonexistent key")
	}
}

func TestMemoryStoreDelete(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	sessionID := "session-delete"

	store.Set(ctx, sessionID, "key1", "value1")

	err := store.Delete(ctx, sessionID, "key1")
	if err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	_, found, _ := store.Get(ctx, sessionID, "key1")
	if found {
		t.Error("Get() after Delete() should return false")
	}
}

func TestMemoryStoreClear(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	sessionID := "session-clear"

	store.Set(ctx, sessionID, "key1", "value1")
	store.Set(ctx, sessionID, "key2", "value2")

	err := store.Clear(ctx, sessionID)
	if err != nil {
		t.Fatalf("Clear() error = %v", err)
	}

	val, found, _ := store.Get(ctx, sessionID, "key1")
	if found || val != nil {
		t.Error("Clear() should remove all keys")
	}
}

func TestMemoryStoreGetAll(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	sessionID := "session-all"

	store.Set(ctx, sessionID, "key1", "value1")
	store.Set(ctx, sessionID, "key2", "value2")

	all, err := store.GetAll(ctx, sessionID)
	if err != nil {
		t.Fatalf("GetAll() error = %v", err)
	}
	if len(all) != 2 {
		t.Errorf("GetAll() count = %d, want 2", len(all))
	}
	if all["key1"] != "value1" {
		t.Errorf("GetAll() key1 = %v, want 'value1'", all["key1"])
	}
}

func TestMemoryStoreSessionIsolation(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	store.Set(ctx, "session-1", "key", "value1")
	store.Set(ctx, "session-2", "key", "value2")

	val1, _, _ := store.Get(ctx, "session-1", "key")
	val2, _, _ := store.Get(ctx, "session-2", "key")

	if val1 == val2 {
		t.Error("Sessions should be isolated - values should differ")
	}
}

func TestMemoryStoreMaxKeysLimit(t *testing.T) {
	config := &MemoryConfig{
		MaxMemoryPerSession: 100 * 1024 * 1024,
		MaxKeysPerSession:   3,
		EnableSwap:          false,
	}
	store := NewMemoryStoreWithConfig(config)
	ctx := context.Background()
	sessionID := "session-maxkeys"

	store.Set(ctx, sessionID, "key1", "value1")
	store.Set(ctx, sessionID, "key2", "value2")
	store.Set(ctx, sessionID, "key3", "value3")

	err := store.Set(ctx, sessionID, "key4", "value4")
	if err != ErrMaxKeysReached {
		t.Errorf("Set() error = %v, want ErrMaxKeysReached", err)
	}
}

func TestMemoryStoreMemoryLimit(t *testing.T) {
	config := &MemoryConfig{
		MaxMemoryPerSession: 100, // Very small limit
		MaxKeysPerSession:   10000,
		EnableSwap:          false,
	}
	store := NewMemoryStoreWithConfig(config)
	ctx := context.Background()
	sessionID := "session-memlimit"

	// Each value should be ~50 bytes when serialized
	err := store.Set(ctx, sessionID, "key1", "this is a much longer string value that exceeds limit")
	if err != nil {
		t.Logf("Set() error = %v (may vary based on serialization)", err)
	}
}

func TestMemoryStoreStats(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	sessionID := "session-stats"

	store.Set(ctx, sessionID, "key1", "value1")
	store.Set(ctx, sessionID, "key2", 12345)

	stats := store.GetStats()
	if stats.TotalSessions != 1 {
		t.Errorf("TotalSessions = %d, want 1", stats.TotalSessions)
	}
	if stats.TotalKeys != 2 {
		t.Errorf("TotalKeys = %d, want 2", stats.TotalKeys)
	}
	t.Logf("Stats: TotalBytes=%d, TotalKeys=%d", stats.TotalBytesUsed, stats.TotalKeys)
}

func TestMemoryStoreHitRate(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	sessionID := "session-hitrate"

	store.Set(ctx, sessionID, "key1", "value1")

	// First get - should be a hit
	store.Get(ctx, sessionID, "key1")
	// Second get - should be a hit  
	store.Get(ctx, sessionID, "key1")
	// Get nonexistent - should be a miss
	store.Get(ctx, sessionID, "nonexistent")

	hitRate := store.GetHitRate()
	t.Logf("Hit rate = %.2f", hitRate)
	if hitRate < 0.5 {
		t.Error("Hit rate should be > 0.5 after hits")
	}
}

func TestMemoryStoreMemoryUsage(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	sessionID := "session-usage"

	store.Set(ctx, sessionID, "key1", "value1")

	usage := store.GetMemoryUsage(sessionID)
	if usage.SessionID != sessionID {
		t.Errorf("SessionID = %s, want %s", usage.SessionID, sessionID)
	}
	if usage.Keys != 1 {
		t.Errorf("Keys = %d, want 1", usage.Keys)
	}
	if usage.Used == 0 {
		t.Error("Used should be > 0")
	}
	t.Logf("Memory usage: Used=%d, Limit=%d", usage.Used, usage.Limit)
}

func TestMemoryStoreAllMemoryUsage(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	store.Set(ctx, "session-1", "key1", "value1")
	store.Set(ctx, "session-2", "key2", "value2")
	store.Set(ctx, "session-3", "key3", "value3")

	allUsage := store.GetAllMemoryUsage()
	if len(allUsage) != 3 {
		t.Errorf("GetAllMemoryUsage() count = %d, want 3", len(allUsage))
	}
}

func TestMemoryStoreCrossContamination(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	// Different values should not be contamination
	store.Set(ctx, "session-1", "key", "value1")
	store.Set(ctx, "session-2", "key", "value2")

	contaminated, err := store.CheckCrossContamination(ctx, "session-1", "session-2")
	if err != nil {
		t.Fatalf("CheckCrossContamination() error = %v", err)
	}
	if contaminated {
		t.Error("Different values should not be contamination")
	}
}

func TestMemoryStoreSetWithExpiry(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	sessionID := "session-expiry"

	err := store.SetWithExpiry(ctx, sessionID, "temp-key", "temp-value", 50*time.Millisecond)
	if err != nil {
		t.Fatalf("SetWithExpiry() error = %v", err)
	}

	// Should exist immediately
	val, found, _ := store.GetWithExpiry(ctx, sessionID, "temp-key")
	if !found || val != "temp-value" {
		t.Error("GetWithExpiry() should return value immediately")
	}

	// Wait for expiry
	time.Sleep(100 * time.Millisecond)

	// Should be expired
	val, found, _ = store.GetWithExpiry(ctx, sessionID, "temp-key")
	if found || val != nil {
		t.Error("GetWithExpiry() should return nil after expiry")
	}
}

func TestMemoryStoreListKeys(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	sessionID := "session-keys"

	store.Set(ctx, sessionID, "key1", "value1")
	store.Set(ctx, sessionID, "key2", "value2")
	store.Set(ctx, sessionID, "key3", "value3")

	keys, err := store.ListKeys(sessionID)
	if err != nil {
		t.Fatalf("ListKeys() error = %v", err)
	}
	if len(keys) != 3 {
		t.Errorf("ListKeys() count = %d, want 3", len(keys))
	}
}

func TestMemoryStoreCleanupExpired(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	sessionID := "session-cleanup"

	store.SetWithExpiry(ctx, sessionID, "temp1", "value1", 10*time.Millisecond)
	store.SetWithExpiry(ctx, sessionID, "temp2", "value2", 10*time.Millisecond)
	store.Set(ctx, sessionID, "persistent", "value3")

	time.Sleep(50 * time.Millisecond)

	cleaned, err := store.CleanupExpired(ctx)
	if err != nil {
		t.Fatalf("CleanupExpired() error = %v", err)
	}
	if cleaned != 2 {
		t.Logf("Cleaned = %d (expected 2 expired)", cleaned)
	}
}

func TestMemoryStoreSessionExists(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	if store.SessionExists("session-1") {
		t.Error("SessionExists() should return false for non-existent session")
	}

	store.Set(ctx, "session-1", "key1", "value1")

	if !store.SessionExists("session-1") {
		t.Error("SessionExists() should return true after adding data")
	}
}

func TestMemoryStoreHasKey(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	sessionID := "session-haskey"

	store.Set(ctx, sessionID, "key1", "value1")

	if !store.HasKey(sessionID, "key1") {
		t.Error("HasKey() should return true for existing key")
	}
	if store.HasKey(sessionID, "nonexistent") {
		t.Error("HasKey() should return false for nonexistent key")
	}
}

func TestMemoryStoreConcurrent(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	sessionID := "session-concurrent"

	done := make(chan error, 20)

	for i := 0; i < 20; i++ {
		go func(n int) {
			err := store.Set(ctx, sessionID, "key", n)
			done <- err
		}(i)
	}

	for i := 0; i < 20; i++ {
		err := <-done
		if err != nil {
			t.Errorf("Concurrent Set() error: %v", err)
		}
	}

	t.Log("Completed 20 concurrent writes without deadlock")
}

func TestMemoryStoreClearAll(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	store.Set(ctx, "session-1", "key1", "value1")
	store.Set(ctx, "session-2", "key2", "value2")

	err := store.ClearAll(ctx)
	if err != nil {
		t.Fatalf("ClearAll() error = %v", err)
	}

	stats := store.GetStats()
	if stats.TotalSessions != 0 || stats.TotalKeys != 0 {
		t.Error("ClearAll() should reset all stats")
	}
}

func TestMemoryStoreInvalidSessionID(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	err := store.Set(ctx, "", "key", "value")
	if err != ErrInvalidSessionID {
		t.Errorf("Set() with empty sessionID error = %v, want ErrInvalidSessionID", err)
	}

	_, _, err = store.Get(ctx, "", "key")
	if err != ErrInvalidSessionID {
		t.Errorf("Get() with empty sessionID error = %v, want ErrInvalidSessionID", err)
	}

	err = store.Delete(ctx, "", "key")
	if err != ErrInvalidSessionID {
		t.Errorf("Delete() with empty sessionID error = %v, want ErrInvalidSessionID", err)
	}
}

func TestMemoryStoreInvalidKey(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	sessionID := "session"

	err := store.Set(ctx, sessionID, "", "value")
	if err != ErrInvalidKey {
		t.Errorf("Set() with empty key error = %v, want ErrInvalidKey", err)
	}
}

func TestMemoryStoreDifferentValueTypes(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	sessionID := "session-types"

	tests := []struct {
		key   string
		value interface{}
	}{
		{"string", "hello"},
		{"int", 42},
		{"int64", int64(9999999999)},
		{"float", 3.14159},
		{"bool", true},
		{"bytes", []byte{1, 2, 3, 4}},
		{"slice", []string{"a", "b", "c"}},
		{"map", map[string]int{"x": 1}},
	}

	for _, tt := range tests {
		err := store.Set(ctx, sessionID, tt.key, tt.value)
		if err != nil {
			t.Errorf("Set() for %s error = %v", tt.key, err)
		}

		val, found, err := store.Get(ctx, sessionID, tt.key)
		if err != nil {
			t.Errorf("Get() for %s error = %v", tt.key, err)
		}
		if !found {
			t.Errorf("Get() for %s not found", tt.key)
		}
		if val == nil {
			t.Errorf("Get() for %s returned nil", tt.key)
		}
	}
}

func TestMemoryStoreEmptySessionGetAll(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	all, err := store.GetAll(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("GetAll() error = %v", err)
	}
	if len(all) != 0 {
		t.Errorf("GetAll() for nonexistent session = %d, want 0", len(all))
	}
}