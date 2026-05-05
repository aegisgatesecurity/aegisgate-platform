// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// =========================================================================
//
// =========================================================================

// Package secrets provides secret management backends
package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Provider defines the interface for secret management backends
type Provider interface {
	Get(ctx context.Context, key string) (Secret, error)
	Set(ctx context.Context, key string, value Secret) error
	Delete(ctx context.Context, key string) error
	List(ctx context.Context) ([]string, error)
	Exists(ctx context.Context, key string) bool
	Close() error
	Health(ctx context.Context) error
	Name() string
}

// Secret represents a secret with metadata
type Secret struct {
	Value     interface{}       `json:"value"`
	Version   string            `json:"version,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	Tags      map[string]string `json:"tags,omitempty"`
}

// Config holds configuration for secrets manager
type Config struct {
	Backend      string
	CacheEnabled bool
	CacheTTL     time.Duration
}

// Manager provides unified access to secrets with caching
type Manager struct {
	provider Provider
	config   *Config
	cache    *secretCache
	logger   *slog.Logger
}

type secretCache struct {
	mu    sync.RWMutex
	items map[string]cacheEntry
	ttl   time.Duration
}

type cacheEntry struct {
	value     Secret
	expiresAt time.Time
}

var (
	managerInstance *Manager
	managerOnce     sync.Once
	managerErr      error
)

// GetManager returns the singleton secrets manager
func GetManager(config *Config) (*Manager, error) {
	managerOnce.Do(func() {
		managerInstance, managerErr = NewManager(config)
	})
	return managerInstance, managerErr
}

// NewManager creates a new secrets manager
func NewManager(config *Config) (*Manager, error) {
	if config == nil {
		config = DefaultConfig()
	}

	var provider Provider
	var err error

	switch config.Backend {
	case "env", "":
		provider = NewEnvProvider()
	case "file":
		provider, err = NewFileProvider(&FileConfig{Path: ".secrets"})
	default:
		return nil, fmt.Errorf("unknown backend: %s", config.Backend)
	}

	if err != nil {
		return nil, err
	}

	m := &Manager{
		provider: provider,
		config:   config,
		logger:   slog.Default().WithGroup("secrets"),
	}

	if config.CacheEnabled {
		if config.CacheTTL == 0 {
			config.CacheTTL = 5 * time.Minute
		}
		m.cache = &secretCache{
			items: make(map[string]cacheEntry),
			ttl:   config.CacheTTL,
		}
	}

	return m, nil
}

// Get retrieves a secret
func (m *Manager) Get(ctx context.Context, key string) (Secret, error) {
	if m.cache != nil {
		if entry, ok := m.cache.get(key); ok {
			return entry, nil
		}
	}

	secret, err := m.provider.Get(ctx, key)
	if err != nil {
		return Secret{}, err
	}

	if m.cache != nil {
		m.cache.set(key, secret)
	}

	return secret, nil
}

// GetString retrieves a secret as string
func (m *Manager) GetString(ctx context.Context, key string) (string, error) {
	secret, err := m.Get(ctx, key)
	if err != nil {
		return "", err
	}

	switch v := secret.Value.(type) {
	case string:
		return v, nil
	case []byte:
		return string(v), nil
	default:
		return fmt.Sprintf("%v", v), nil
	}
}

// GetJSON retrieves and unmarshals a secret
func (m *Manager) GetJSON(ctx context.Context, key string, target interface{}) error {
	secret, err := m.Get(ctx, key)
	if err != nil {
		return err
	}

	var data []byte
	switch v := secret.Value.(type) {
	case string:
		data = []byte(v)
	case []byte:
		data = v
	default:
		data, err = json.Marshal(v)
		if err != nil {
			return err
		}
	}
	return json.Unmarshal(data, target)
}

// Set stores a secret
func (m *Manager) Set(ctx context.Context, key string, value Secret) error {
	err := m.provider.Set(ctx, key, value)
	if err == nil && m.cache != nil {
		m.cache.delete(key)
	}
	return err
}

// Delete removes a secret
func (m *Manager) Delete(ctx context.Context, key string) error {
	err := m.provider.Delete(ctx, key)
	if err == nil && m.cache != nil {
		m.cache.delete(key)
	}
	return err
}

// List returns all secret keys
func (m *Manager) List(ctx context.Context) ([]string, error) {
	return m.provider.List(ctx)
}

// Close releases resources
func (m *Manager) Close() error {
	return m.provider.Close()
}

// Cache methods
func (c *secretCache) get(key string) (Secret, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.items[key]
	if !ok || time.Now().After(entry.expiresAt) {
		return Secret{}, false
	}
	return entry.value, true
}

func (c *secretCache) set(key string, value Secret) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[key] = cacheEntry{
		value:     value,
		expiresAt: time.Now().Add(c.ttl),
	}
}

func (c *secretCache) delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.items, key)
}

// DefaultConfig returns default configuration
func DefaultConfig() *Config {
	return &Config{
		Backend:      "env",
		CacheEnabled: true,
		CacheTTL:     5 * time.Minute,
	}
}
