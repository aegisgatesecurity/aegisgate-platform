// SPDX-FileCopyrightText: Copyright (C) 2025 AegisGuard Security
// SPDX-License-Identifier: Apache-2.0

// Package sandbox provides secure code execution sandbox for AI agent operations.
// This is a simplified version adapted from AegisGate for Go-based code execution.
package sandbox

import (
	"sync"
	"time"
)

// ============================================================================
// Types
// ============================================================================

// SandboxID represents a unique sandbox identifier
type SandboxID string

// SandboxStatus represents the current status of a sandbox
type SandboxStatus string

const (
	SandboxStatusCreated   SandboxStatus = "created"
	SandboxStatusRunning   SandboxStatus = "running"
	SandboxStatusStopped   SandboxStatus = "stopped"
	SandboxStatusErrored   SandboxStatus = "errored"
	SandboxStatusDestroyed SandboxStatus = "destroyed"
)

// ResourceQuota defines resource limits for a sandbox
type ResourceQuota struct {
	Timeout     time.Duration // Maximum execution time
	MemoryLimit int64         // Memory limit in bytes
	DiskLimit   int64         // Disk limit in bytes
	MaxOutput   int           // Maximum output size in bytes
	MaxProcs    int           // Maximum concurrent processes
}

// DefaultResourceQuota returns sensible defaults for code execution
func DefaultResourceQuota() ResourceQuota {
	return ResourceQuota{
		Timeout:     30 * time.Second,
		MemoryLimit: 512 << 20, // 512MB
		DiskLimit:   100 << 20, // 100MB
		MaxOutput:   1 << 20,   // 1MB
		MaxProcs:    4,
	}
}

// ExecutionResult represents the result of sandboxed code execution
type ExecutionResult struct {
	SandboxID SandboxID
	Status    SandboxStatus
	ExitCode  int
	Stdout    string
	Stderr    string
	Duration  time.Duration
	Error     string
}

// ExecutionPolicy defines what a sandboxed execution can do
type ExecutionPolicy struct {
	AllowedLanguages []string
	AllowedImports   []string // Package whitelist (e.g., "fmt", "os")
	BlockedImports   []string // Package blacklist
	AllowNetwork     bool
	AllowFilesystem  bool
	AllowedPaths     []string // File access whitelist
	BlockedPaths     []string // File access blacklist
	Timeout          time.Duration
	Quota            ResourceQuota
}

// DefaultExecutionPolicy returns a restrictive default policy
func DefaultExecutionPolicy() ExecutionPolicy {
	return ExecutionPolicy{
		AllowedLanguages: []string{"go", "python", "javascript"},
		AllowedImports:   []string{"fmt", "os", "strconv", "strings", "math", "time", "json"},
		AllowNetwork:     false,
		AllowFilesystem:  false,
		Timeout:          30 * time.Second,
		Quota:            DefaultResourceQuota(),
	}
}

// Sandbox represents an isolated code execution environment
type Sandbox struct {
	ID        SandboxID
	Policy    ExecutionPolicy
	Status    SandboxStatus
	CreatedAt time.Time
	ActiveAt  time.Time
	mu        sync.RWMutex
}

// SandboxManager manages sandbox lifecycles
type SandboxManager struct {
	sandboxes    map[SandboxID]*Sandbox
	policy       *ExecutionPolicy
	mu           sync.RWMutex
	maxSandboxes int
}

// NewSandboxManager creates a new sandbox manager
func NewSandboxManager(policy *ExecutionPolicy, maxSandboxes int) *SandboxManager {
	if maxSandboxes <= 0 {
		maxSandboxes = 10
	}
	return &SandboxManager{
		sandboxes:    make(map[SandboxID]*Sandbox),
		policy:       policy,
		maxSandboxes: maxSandboxes,
	}
}

// ============================================================================
// Sandbox Operations
// ============================================================================

// Create creates a new sandbox
func (m *SandboxManager) Create(id SandboxID) (*Sandbox, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.sandboxes[id]; exists {
		return nil, &ValidationError{Code: "sandbox_exists", Message: "sandbox already exists"}
	}

	if len(m.sandboxes) >= m.maxSandboxes {
		return nil, &ValidationError{Code: "max_sandboxes", Message: "maximum sandboxes reached"}
	}

	sandbox := &Sandbox{
		ID:        id,
		Policy:    *m.policy,
		Status:    SandboxStatusCreated,
		CreatedAt: time.Now(),
		ActiveAt:  time.Now(),
	}

	m.sandboxes[id] = sandbox
	return sandbox, nil
}

// Get retrieves a sandbox by ID
func (m *SandboxManager) Get(id SandboxID) (*Sandbox, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sandbox, exists := m.sandboxes[id]
	if !exists {
		return nil, &ValidationError{Code: "not_found", Message: "sandbox not found"}
	}
	return sandbox, nil
}

// Destroy destroys a sandbox
func (m *SandboxManager) Destroy(id SandboxID) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.sandboxes[id]; !exists {
		return &ValidationError{Code: "not_found", Message: "sandbox not found"}
	}

	delete(m.sandboxes, id)
	return nil
}

// List returns all sandboxes
func (m *SandboxManager) List() []*Sandbox {
	m.mu.RLock()
	defer m.mu.RUnlock()

	list := make([]*Sandbox, 0, len(m.sandboxes))
	for _, s := range m.sandboxes {
		list = append(list, s)
	}
	return list
}

// Count returns the number of active sandboxes
func (m *SandboxManager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sandboxes)
}

// Cleanup removes idle sandboxes
func (m *SandboxManager) Cleanup(idleDuration time.Duration) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	threshold := time.Now().Add(-idleDuration)
	removed := 0

	for id, s := range m.sandboxes {
		if s.Status == SandboxStatusStopped && s.ActiveAt.Before(threshold) {
			delete(m.sandboxes, id)
			removed++
		}
	}

	return removed
}

// ============================================================================
// Execution Validation
// ============================================================================

// ValidateLanguage checks if a language is allowed
func (p *ExecutionPolicy) ValidateLanguage(lang string) error {
	for _, allowed := range p.AllowedLanguages {
		if lang == allowed {
			return nil
		}
	}
	return &ValidationError{
		Code:    "language_not_allowed",
		Message: "language not allowed: " + lang,
	}
}

// ValidationError represents a validation error
type ValidationError struct {
	Code    string
	Message string
}

func (e *ValidationError) Error() string {
	if e.Message == "" {
		return "validation error: " + e.Code
	}
	return e.Message
}

// ============================================================================
// Code Execution (Go-specific)
// ============================================================================

// GoExecutionResult represents the result of Go code execution
type GoExecutionResult struct {
	SandboxID SandboxID
	Status    SandboxStatus
	ExitCode  int
	Output    string
	Error     string
	Duration  time.Duration
	StartTime time.Time
}

// ValidateGoCode performs static analysis on Go code before execution
func ValidateGoCode(code string, policy *ExecutionPolicy) error {
	// Check for forbidden patterns
	forbidden := []string{
		"os.Exit",
		"syscall.",
		"exec.Command",
		"net.Dial",
		"http.Get", // unless network allowed
	}

	for _, pattern := range forbidden {
		if contains(code, pattern) {
			if pattern == "http.Get" && policy.AllowNetwork {
				continue
			}
			return &ValidationError{
				Code:    "forbidden_pattern",
				Message: "forbidden pattern: " + pattern,
			}
		}
	}

	return nil
}

// contains checks if s contains substr
func contains(s, substr string) bool {
	return len(s) >= len(substr) && findSubstring(s, substr)
}

// findSubstring is a simple substring search
func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
