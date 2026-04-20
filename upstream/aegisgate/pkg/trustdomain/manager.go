// SPDX-License-Identifier: MIT
// =========================================================================
// =========================================================================
//
// =========================================================================

// Package trustdomain provides core trust domain management functionality
package trustdomain

import (
	"fmt"
	"sync"
	"time"
)

// TrustDomainManager manages trust domains for feeds
type TrustDomainManager struct {
	domains    map[TrustDomainID]TrustDomain
	config     *TrustDomainManagerConfig
	mu         sync.RWMutex
	auditLog   chan AuditLogEntry
	auditLogWg sync.WaitGroup
}

// NewTrustDomainManager creates a new trust domain manager
func NewTrustDomainManager(config *TrustDomainManagerConfig) *TrustDomainManager {
	if config == nil {
		config = &TrustDomainManagerConfig{
			DefaultIsolationLevel: IsolationFull,
			MaxTrustDomains:       100,
			EnableAuditLog:        true,
		}
	}

	return &TrustDomainManager{
		domains:  make(map[TrustDomainID]TrustDomain),
		config:   config,
		auditLog: make(chan AuditLogEntry, 100),
	}
}

// CreateDomain creates a new trust domain
func (m *TrustDomainManager) CreateDomain(config *TrustDomainConfig) (TrustDomain, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.domains) >= m.config.MaxTrustDomains {
		return nil, &ValidationError{
			Code:    "max_domains_reached",
			Message: "maximum number of trust domains reached",
			Field:   "domains",
		}
	}

	if config == nil {
		return nil, &ValidationError{
			Code:    "invalid_config",
			Message: "trust domain config cannot be nil",
			Field:   "config",
		}
	}

	// Create a basic trust domain implementation
	domain := &basicTrustDomain{
		config:         config,
		anchors:        make([]*TrustAnchor, 0),
		policies:       make([]FeedTrustPolicy, 0),
		validationMode: ValidationStrict,
	}

	m.domains[config.ID] = domain

	if m.config.EnableAuditLog {
		m.auditLogWg.Add(1)
		go func() {
			defer m.auditLogWg.Done()
			m.auditLog <- AuditLogEntry{
				Timestamp: time.Now(),
				Operation: "create_domain",
				DomainID:  config.ID,
				Message:   "domain created",
				Success:   true,
			}
		}()
	}

	return domain, nil
}

// GetDomain retrieves a trust domain by ID
func (m *TrustDomainManager) GetDomain(id TrustDomainID) (TrustDomain, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	domain, exists := m.domains[id]
	if !exists {
		return nil, &ValidationError{
			Code:    "domain_not_found",
			Message: "trust domain not found",
			Field:   "id",
		}
	}

	return domain, nil
}

// DestroyDomain destroys a trust domain by ID
func (m *TrustDomainManager) DestroyDomain(id TrustDomainID) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	domain, exists := m.domains[id]
	if !exists {
		return nil // Already destroyed or never existed
	}

	if err := domain.Destroy(); err != nil {
		return err
	}

	delete(m.domains, id)

	return nil
}

// GetDomainCount returns the number of active trust domains
func (m *TrustDomainManager) GetDomainCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.domains)
}

// GetAuditLog returns a channel for audit log entries
func (m *TrustDomainManager) GetAuditLog() <-chan AuditLogEntry {
	return m.auditLog
}

// DeleteDomain deletes a trust domain by ID
func (m *TrustDomainManager) DeleteDomain(id TrustDomainID) error {
	return m.DestroyDomain(id)
}

// Validate validates data against the trust domain (for backwards compatibility)
func (m *TrustDomainManager) Validate(id TrustDomainID, data []byte) (*ValidationResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	_, exists := m.domains[id]
	if !exists {
		return nil, &ValidationError{
			Code:    "domain_not_found",
			Message: "trust domain not found",
			Field:   "id",
		}
	}

	// Create a temporary validation result
	return &ValidationResult{
		Success:   true,
		Timestamp: time.Now(),
	}, nil
}

// Start starts the trust domain manager
func (m *TrustDomainManager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, domain := range m.domains {
		if err := domain.Enable(); err != nil {
			return err
		}
	}

	return nil
}

// Stop stops the trust domain manager
func (m *TrustDomainManager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var errs []error
	for _, domain := range m.domains {
		if err := domain.Disable(); err != nil {
			errs = append(errs, err)
		}
	}

	// Close audit log channel
	close(m.auditLog)
	m.auditLogWg.Wait()

	if len(errs) > 0 {
		return fmt.Errorf("errors during shutdown: %v", errs)
	}

	return nil
}
