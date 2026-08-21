// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform — Tenant Management
// =========================================================================
//
// manager.go provides a CRUD API for multi-tenant management. It stores
// tenant metadata in an in-memory map (default) or PostgreSQL (production).
// Tenants are identified by a unique tenant_id string.
//
// This package provides the management layer that was missing from the
// data-layer tenant isolation (pkg/ioc, pkg/rbac, pkg/license). With this
// API, MSP/MSSP operators can create, list, update, and delete tenants
// via REST endpoints.
//
// =========================================================================

package tenant

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// Tenant represents a managed tenant in the platform.
type Tenant struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	DisplayName string    `json:"displayName"`
	Email       string    `json:"email,omitempty"`
	LicenseTier string    `json:"licenseTier,omitempty"`
	MaxUsers    int       `json:"maxUsers,omitempty"`
	MaxAgents   int       `json:"maxAgents,omitempty"`
	Active      bool      `json:"active"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

// Manager manages tenant CRUD operations.
type Manager struct {
	mu      sync.RWMutex
	tenants map[string]*Tenant
}

// NewManager creates a new in-memory tenant manager.
func NewManager() *Manager {
	return &Manager{
		tenants: make(map[string]*Tenant),
	}
}

// Create creates a new tenant. If id is empty, a random ID is generated.
func (m *Manager) Create(name, displayName, email, licenseTier string, maxUsers, maxAgents int) (*Tenant, error) {
	if name == "" {
		return nil, fmt.Errorf("tenant name is required")
	}
	id := generateTenantID()
	tenant := &Tenant{
		ID:          id,
		Name:        name,
		DisplayName: displayName,
		Email:       email,
		LicenseTier: licenseTier,
		MaxUsers:    maxUsers,
		MaxAgents:   maxAgents,
		Active:      true,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	m.mu.Lock()
	m.tenants[id] = tenant
	m.mu.Unlock()
	return tenant, nil
}

// Get retrieves a tenant by ID.
func (m *Manager) Get(id string) (*Tenant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.tenants[id]
	if !ok {
		return nil, fmt.Errorf("tenant %q not found", id)
	}
	return t, nil
}

// List returns all tenants.
func (m *Manager) List() []*Tenant {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]*Tenant, 0, len(m.tenants))
	for _, t := range m.tenants {
		result = append(result, t)
	}
	return result
}

// Update updates tenant fields.
func (m *Manager) Update(id string, updates map[string]interface{}) (*Tenant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tenants[id]
	if !ok {
		return nil, fmt.Errorf("tenant %q not found", id)
	}
	if name, ok := updates["name"].(string); ok && name != "" {
		t.Name = name
	}
	if dn, ok := updates["displayName"].(string); ok {
		t.DisplayName = dn
	}
	if email, ok := updates["email"].(string); ok {
		t.Email = email
	}
	if lt, ok := updates["licenseTier"].(string); ok {
		t.LicenseTier = lt
	}
	if mu, ok := updates["maxUsers"].(float64); ok {
		t.MaxUsers = int(mu)
	}
	if ma, ok := updates["maxAgents"].(float64); ok {
		t.MaxAgents = int(ma)
	}
	if active, ok := updates["active"].(bool); ok {
		t.Active = active
	}
	t.UpdatedAt = time.Now()
	return t, nil
}

// Delete removes a tenant. The tenant's data (IOCs, agents, etc.) is NOT
// deleted — only the tenant metadata. Data cleanup must be handled
// separately by the operator.
func (m *Manager) Delete(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.tenants[id]; !ok {
		return fmt.Errorf("tenant %q not found", id)
	}
	delete(m.tenants, id)
	return nil
}

// Count returns the total number of tenants.
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.tenants)
}

// generateTenantID creates a random 16-character hex tenant ID.
func generateTenantID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "tnt_" + hex.EncodeToString(b)
}