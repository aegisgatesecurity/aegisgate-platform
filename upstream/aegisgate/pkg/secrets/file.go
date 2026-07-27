// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// =========================================================================
//
// =========================================================================

package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// FileConfig for file-based storage
type FileConfig struct {
	Path      string
	MasterKey string // For encryption (future)
}

// FileProvider stores secrets in a JSON file
type FileProvider struct {
	path string
	mu   sync.RWMutex
	data map[string]Secret
}

// NewFileProvider creates a file-based provider
func NewFileProvider(config *FileConfig) (*FileProvider, error) {
	fp := &FileProvider{
		path: config.Path,
		data: make(map[string]Secret),
	}

	// Load existing data
	if err := fp.load(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	return fp, nil
}

func (f *FileProvider) Get(ctx context.Context, key string) (Secret, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	secret, ok := f.data[key]
	if !ok {
		return Secret{}, fmt.Errorf("secret not found: %s", key)
	}
	return secret, nil
}

func (f *FileProvider) Set(ctx context.Context, key string, value Secret) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	value.UpdatedAt = time.Now().UTC()
	if existing, ok := f.data[key]; ok {
		value.CreatedAt = existing.CreatedAt
	} else {
		value.CreatedAt = time.Now().UTC()
	}

	f.data[key] = value
	return f.save()
}

func (f *FileProvider) Delete(ctx context.Context, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	delete(f.data, key)
	return f.save()
}

func (f *FileProvider) List(ctx context.Context) ([]string, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	keys := make([]string, 0, len(f.data))
	for k := range f.data {
		keys = append(keys, k)
	}
	return keys, nil
}

func (f *FileProvider) Exists(ctx context.Context, key string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	_, ok := f.data[key]
	return ok
}

func (f *FileProvider) Close() error {
	return nil
}

func (f *FileProvider) Health(ctx context.Context) error {
	// Check if directory is writable
	dir := filepath.Dir(f.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("directory not writable: %w", err)
	}
	return nil
}

func (f *FileProvider) Name() string {
	return "file"
}

func (f *FileProvider) load() error {
	data, err := os.ReadFile(f.path)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, &f.data)
}

func (f *FileProvider) save() error {
	// Ensure directory exists
	dir := filepath.Dir(f.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	// Write with restrictive permissions
	data, err := json.MarshalIndent(f.data, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(f.path, data, 0600)
}
