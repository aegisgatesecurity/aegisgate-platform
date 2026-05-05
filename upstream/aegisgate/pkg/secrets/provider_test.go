package secrets

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestNewManager(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name:    "default config",
			config:  nil,
			wantErr: false,
		},
		{
			name: "env backend",
			config: &Config{
				Backend:      "env",
				CacheEnabled: false,
			},
			wantErr: false,
		},
		{
			name: "file backend",
			config: &Config{
				Backend:      "file",
				CacheEnabled: false,
			},
			wantErr: false,
		},
		{
			name: "unknown backend",
			config: &Config{
				Backend:      "unknown",
				CacheEnabled: false,
			},
			wantErr: true,
		},
		{
			name: "with cache enabled",
			config: &Config{
				Backend:      "env",
				CacheEnabled: true,
				CacheTTL:     5 * time.Minute,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, err := NewManager(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewManager() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				defer manager.Close()
			}
		})
	}
}

func TestManager_Get_Set(t *testing.T) {
	config := &Config{
		Backend:      "env",
		CacheEnabled: false,
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer manager.Close()

	ctx := context.Background()

	// Test getting non-existent secret
	_, err = manager.Get(ctx, "nonexistent")
	if err == nil {
		t.Error("Get() should return error for non-existent key")
	}

	// Test setting a secret
	secret := Secret{
		Value:    "testvalue",
		Metadata: map[string]string{"key": "value"},
	}

	// Note: EnvProvider is read-only, so Set should fail
	err = manager.Set(ctx, "testkey", secret)
	if err == nil {
		t.Error("Set() with env backend should fail")
	}
}

func TestManager_GetString(t *testing.T) {
	config := &Config{
		Backend:      "env",
		CacheEnabled: false,
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer manager.Close()

	ctx := context.Background()

	// Test getting non-existent secret
	_, err = manager.GetString(ctx, "nonexistent")
	if err == nil {
		t.Error("GetString() should return error for non-existent key")
	}
}

func TestManager_List(t *testing.T) {
	config := &Config{
		Backend:      "env",
		CacheEnabled: false,
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer manager.Close()

	ctx := context.Background()

	keys, err := manager.List(ctx)
	if err != nil {
		t.Errorf("List() error = %v", err)
	}

	// List should return env vars (might be empty in test)
	if keys == nil {
		t.Error("List() returned nil instead of empty slice")
	}
}

func TestManager_Concurrent(t *testing.T) {
	config := &Config{
		Backend:      "env",
		CacheEnabled: true,
		CacheTTL:     1 * time.Minute,
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer manager.Close()

	ctx := context.Background()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			key := "TEST_KEY"

			// Try to get
			_, _ = manager.Get(ctx, key)

			// Try to list
			_, _ = manager.List(ctx)
		}(i)
	}

	wg.Wait()
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.Backend != "env" {
		t.Errorf("DefaultConfig().Backend = %s, want env", config.Backend)
	}

	if !config.CacheEnabled {
		t.Error("DefaultConfig().CacheEnabled should be true")
	}

	if config.CacheTTL != 5*time.Minute {
		t.Errorf("DefaultConfig().CacheTTL = %v, want 5m", config.CacheTTL)
	}
}

func TestSecretCache(t *testing.T) {
	cache := &secretCache{
		items: make(map[string]cacheEntry),
		ttl:   100 * time.Millisecond,
	}

	secret := Secret{
		Value:     "test",
		UpdatedAt: time.Now(),
	}

	// Test set and get
	cache.set("key1", secret)

	got, ok := cache.get("key1")
	if !ok {
		t.Error("cache.get() returned false for existing key")
	}
	if got.Value != "test" {
		t.Errorf("cache.get() Value = %v, want test", got.Value)
	}

	// Test delete
	cache.delete("key1")
	_, ok = cache.get("key1")
	if ok {
		t.Error("cache.get() returned true after delete")
	}

	// Test expiration
	cache.set("key2", secret)
	time.Sleep(150 * time.Millisecond)
	_, ok = cache.get("key2")
	if ok {
		t.Error("cache.get() returned true for expired key")
	}
}

func TestGetManager_Singleton(t *testing.T) {
	// Reset for test
	managerInstance = nil
	managerOnce = sync.Once{}
	managerErr = nil

	config1 := DefaultConfig()
	m1, err := GetManager(config1)
	if err != nil {
		t.Fatalf("GetManager() error = %v", err)
	}

	config2 := &Config{Backend: "file"}
	m2, err := GetManager(config2)
	if err != nil {
		t.Fatalf("GetManager() error = %v", err)
	}

	// Should return same instance
	if m1 != m2 {
		t.Error("GetManager() should return singleton instance")
	}
}

func TestSecret_Struct(t *testing.T) {
	now := time.Now()
	secret := Secret{
		Value:     "test",
		Version:   "1.0",
		CreatedAt: now,
		UpdatedAt: now,
		Metadata:  map[string]string{"key": "value"},
		Tags:      map[string]string{"env": "test"},
	}

	if secret.Value != "test" {
		t.Errorf("Secret.Value = %v", secret.Value)
	}
	if secret.Version != "1.0" {
		t.Errorf("Secret.Version = %v", secret.Version)
	}
}
