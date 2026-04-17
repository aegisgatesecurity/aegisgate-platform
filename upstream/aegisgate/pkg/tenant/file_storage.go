package tenant

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// FileStorage stores tenant data in JSON files
type FileStorage struct {
	basePath string
	manager  *Manager
	mu       sync.RWMutex
}

// NewFileStorage creates a new file-based tenant storage
func NewFileStorage(basePath string) (*FileStorage, error) {
	if err := os.MkdirAll(basePath, 0750); err != nil {
		return nil, fmt.Errorf("failed to create storage directory: %w", err)
	}

	fs := &FileStorage{
		basePath: basePath,
		manager:  NewManager(),
	}

	// Load existing tenants
	if err := fs.loadAll(); err != nil {
		return nil, fmt.Errorf("failed to load tenants: %w", err)
	}

	return fs, nil
}

// loadAll loads all tenants from disk
func (fs *FileStorage) loadAll() error {
	entries, err := os.ReadDir(fs.basePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		if filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		data, err := os.ReadFile(filepath.Join(fs.basePath, entry.Name()))
		if err != nil {
			continue
		}

		var t Tenant
		if err := json.Unmarshal(data, &t); err != nil {
			continue
		}

		fs.manager.tenants[t.ID] = &t
	}

	return nil
}

// save saves a tenant to disk
func (fs *FileStorage) save(t *Tenant) error {
	data, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return err
	}

	filename := filepath.Join(fs.basePath, fmt.Sprintf("%s.json", t.ID))
	return os.WriteFile(filename, data, 0640)
}

// CreateTenant creates a new tenant
func (fs *FileStorage) CreateTenant(id, name, domain string, storagePath string) (*Tenant, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	// Check if exists
	if _, exists := fs.manager.tenants[id]; exists {
		return nil, fmt.Errorf("tenant %s already exists", id)
	}

	// Create tenant
	t := NewTenant(id, name, domain)
	_ = t.InitializeTenantResources(storagePath)

	// Save to disk
	if err := fs.save(t); err != nil {
		return nil, err
	}

	fs.manager.tenants[id] = t
	return t, nil
}

// GetTenant retrieves a tenant
func (fs *FileStorage) GetTenant(id string) (*Tenant, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	t, exists := fs.manager.tenants[id]
	if !exists {
		return nil, fmt.Errorf("tenant %s not found", id)
	}

	return t, nil
}

// ListTenants returns all tenants
func (fs *FileStorage) ListTenants() []*Tenant {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	tenants := make([]*Tenant, 0, len(fs.manager.tenants))
	for _, t := range fs.manager.tenants {
		tenants = append(tenants, t)
	}

	return tenants
}

// UpdateTenant updates a tenant
func (fs *FileStorage) UpdateTenant(id, name, domain string) (*Tenant, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	t, exists := fs.manager.tenants[id]
	if !exists {
		return nil, fmt.Errorf("tenant %s not found", id)
	}

	if name != "" {
		t.Name = name
	}
	if domain != "" {
		t.Domain = domain
	}
	t.UpdatedAt = time.Now()

	if err := fs.save(t); err != nil {
		return nil, err
	}

	return t, nil
}

// DeleteTenant deletes a tenant
func (fs *FileStorage) DeleteTenant(id string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if _, exists := fs.manager.tenants[id]; !exists {
		return fmt.Errorf("tenant %s not found", id)
	}

	// Remove from memory
	delete(fs.manager.tenants, id)

	// Remove file
	filename := filepath.Join(fs.basePath, fmt.Sprintf("%s.json", id))
	if err := os.Remove(filename); err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}

// Manager returns the underlying manager
func (fs *FileStorage) Manager() *Manager {
	return fs.manager
}

// Close closes the storage
func (fs *FileStorage) Close() error {
	return nil
}

// SearchTenants searches tenants by query
func (fs *FileStorage) SearchTenants(query string) []*Tenant {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	query = fmt.Sprintf("%%%s%%", query)
	var results []*Tenant

	for _, t := range fs.manager.tenants {
		if strings.Contains(strings.ToLower(t.Name), strings.ToLower(query)) ||
			strings.Contains(strings.ToLower(t.Domain), strings.ToLower(query)) {
			results = append(results, t)
		}
	}

	return results
}

// GetTenantsByStatus returns tenants filtered by status
func (fs *FileStorage) GetTenantsByStatus(status TenantStatus) []*Tenant {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	var results []*Tenant
	for _, t := range fs.manager.tenants {
		if t.Status == status {
			results = append(results, t)
		}
	}

	return results
}

// Count returns the total number of tenants
func (fs *FileStorage) Count() int {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	return len(fs.manager.tenants)
}
