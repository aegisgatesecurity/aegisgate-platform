// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

package sandbox

import (
	"sync"
	"time"
)

// SandboxManager manages sandbox lifecycles
type SandboxManager interface {
	Create(id SandboxID, policy SandboxPolicy) (*Sandbox, error)
	Get(id SandboxID) (*Sandbox, error)
	Start(id SandboxID) error
	Stop(id SandboxID) error
	Destroy(id SandboxID) error
	List() ([]Sandbox, error)
	Stats() ([]SandboxStats, error)
}

type sandboxManagerImpl struct {
	sandboxes map[SandboxID]*Sandbox
	config    *SandboxManagerConfig
	mu        sync.RWMutex
}

func newDefaultManager(config *SandboxManagerConfig) SandboxManager {
	return &sandboxManagerImpl{
		sandboxes: make(map[SandboxID]*Sandbox),
		config:    config,
	}
}

// SandboxManagerConfig holds configuration for the sandbox manager
type SandboxManagerConfig struct {
	DefaultIsolation IsolationLevel
	DefaultQuota     ResourceQuota
	EnableAudit      bool
	MaxSandboxes     int
}

// ValidationError represents a validation error with context
type ValidationError struct {
	Code      string
	Message   string
	Field     string
	Details   map[string]interface{}
	Timestamp time.Time
	FeedID    string
	DomainID  string
}

func (e *ValidationError) Error() string {
	if e.Message == "" {
		return "validation error: " + e.Code
	}
	return e.Message
}

// AuditLogEntry represents an audit log entry for sandbox operations
type AuditLogEntry struct {
	Timestamp time.Time
	Action    string
	SandboxID SandboxID
	Status    string
	User      string
	Message   string
	Details   map[string]interface{}
}

// Sandbox represents an isolated execution environment
type Sandbox struct {
	ID            SandboxID
	Policy        SandboxPolicy
	Status        SandboxStatus
	CreatedAt     time.Time
	StartedAt     time.Time
	StoppedAt     time.Time
	ResourceUsage ResourceUsage
}

// SandboxStats provides sandbox statistics
type SandboxStats struct {
	SandboxID     SandboxID
	Status        SandboxStatus
	ResourceUsage ResourceUsage
	Uptime        time.Duration
}

// Create creates a new sandbox
func (m *sandboxManagerImpl) Create(id SandboxID, policy SandboxPolicy) (*Sandbox, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	sandbox := &Sandbox{
		ID:            id,
		Policy:        policy,
		Status:        SandboxStatusCreated,
		CreatedAt:     time.Now(),
		ResourceUsage: ResourceUsage{},
	}

	m.sandboxes[id] = sandbox
	return sandbox, nil
}

// Get retrieves a sandbox by ID
func (m *sandboxManagerImpl) Get(id SandboxID) (*Sandbox, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sandbox, exists := m.sandboxes[id]
	if !exists {
		return nil, &ValidationError{
			Code:    "sandbox_not_found",
			Message: "sandbox not found",
			Field:   "id",
		}
	}

	return sandbox, nil
}

// Start starts a sandbox
func (m *sandboxManagerImpl) Start(id SandboxID) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	sandbox, exists := m.sandboxes[id]
	if !exists {
		return &ValidationError{
			Code:    "sandbox_not_found",
			Message: "sandbox not found",
			Field:   "id",
		}
	}

	sandbox.Status = SandboxStatusRunning
	sandbox.StartedAt = time.Now()
	return nil
}

// Stop stops a sandbox
func (m *sandboxManagerImpl) Stop(id SandboxID) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	sandbox, exists := m.sandboxes[id]
	if !exists {
		return &ValidationError{
			Code:    "sandbox_not_found",
			Message: "sandbox not found",
			Field:   "id",
		}
	}

	sandbox.Status = SandboxStatusStopped
	sandbox.StoppedAt = time.Now()
	return nil
}

// Destroy destroys a sandbox
func (m *sandboxManagerImpl) Destroy(id SandboxID) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.sandboxes, id)
	return nil
}

// List lists all sandboxes
func (m *sandboxManagerImpl) List() ([]Sandbox, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sandboxes := make([]Sandbox, 0, len(m.sandboxes))
	for _, sandbox := range m.sandboxes {
		sandboxes = append(sandboxes, *sandbox)
	}
	return sandboxes, nil
}

// Stats returns statistics for all sandboxes
func (m *sandboxManagerImpl) Stats() ([]SandboxStats, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := make([]SandboxStats, 0, len(m.sandboxes))
	for _, sandbox := range m.sandboxes {
		uptime := time.Duration(0)
		if !sandbox.StartedAt.IsZero() {
			uptime = time.Since(sandbox.StartedAt)
		}

		stats = append(stats, SandboxStats{
			SandboxID:     sandbox.ID,
			Status:        sandbox.Status,
			ResourceUsage: sandbox.ResourceUsage,
			Uptime:        uptime,
		})
	}
	return stats, nil
}
