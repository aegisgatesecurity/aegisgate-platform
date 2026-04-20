// SPDX-License-Identifier: MIT
// =========================================================================
// =========================================================================
//
// =========================================================================

// Package core provides a feature flag system for modular feature control.
package core

import (
	"sync"
)

// FeatureFlag represents a feature that can be enabled or disabled.
type FeatureFlag struct {
	ID          string
	Name        string
	Description string
	ModuleID    string // Owner module
	Enabled     bool
	Requires    []string // Other feature IDs that must be enabled
}

// FeatureRegistry manages feature flags across all modules.
type FeatureRegistry struct {
	mu       sync.RWMutex
	flags    map[string]*FeatureFlag
	registry *Registry
}

// NewFeatureRegistry creates a new feature registry.
func NewFeatureRegistry(registry *Registry) *FeatureRegistry {
	return &FeatureRegistry{
		flags:    make(map[string]*FeatureFlag),
		registry: registry,
	}
}

// Register registers a new feature flag.
func (fr *FeatureRegistry) Register(flag FeatureFlag) error {
	fr.mu.Lock()
	defer fr.mu.Unlock()

	if _, exists := fr.flags[flag.ID]; exists {
		return ErrFeatureAlreadyExists{ID: flag.ID}
	}

	fr.flags[flag.ID] = &flag
	return nil
}

// Unregister removes a feature flag.
func (fr *FeatureRegistry) Unregister(id string) {
	fr.mu.Lock()
	defer fr.mu.Unlock()
	delete(fr.flags, id)
}

// IsEnabled checks if a feature is enabled.
func (fr *FeatureRegistry) IsEnabled(id string) bool {
	fr.mu.RLock()
	defer fr.mu.RUnlock()

	flag, exists := fr.flags[id]
	if !exists {
		return false
	}

	// Check if all requirements are met
	for _, reqID := range flag.Requires {
		if !fr.isEnabledInternal(reqID) {
			return false
		}
	}

	// Check if the owner module is active
	if flag.ModuleID != "" && fr.registry != nil {
		if fr.registry.GetStatus(flag.ModuleID) != StatusActive {
			return false
		}
	}

	return flag.Enabled
}

// isEnabledInternal checks without locks (for internal use).
func (fr *FeatureRegistry) isEnabledInternal(id string) bool {
	flag, exists := fr.flags[id]
	if !exists {
		return false
	}
	return flag.Enabled
}

// Enable enables a feature flag.
func (fr *FeatureRegistry) Enable(id string) error {
	fr.mu.Lock()
	defer fr.mu.Unlock()

	flag, exists := fr.flags[id]
	if !exists {
		return ErrFeatureNotFound{ID: id}
	}

	flag.Enabled = true
	return nil
}

// Disable disables a feature flag.
func (fr *FeatureRegistry) Disable(id string) error {
	fr.mu.Lock()
	defer fr.mu.Unlock()

	flag, exists := fr.flags[id]
	if !exists {
		return ErrFeatureNotFound{ID: id}
	}

	flag.Enabled = false
	return nil
}

// Get returns a feature flag by ID.
func (fr *FeatureRegistry) Get(id string) (*FeatureFlag, bool) {
	fr.mu.RLock()
	defer fr.mu.RUnlock()
	flag, exists := fr.flags[id]
	return flag, exists
}

// List returns all registered feature flags.
func (fr *FeatureRegistry) List() []*FeatureFlag {
	fr.mu.RLock()
	defer fr.mu.RUnlock()

	flags := make([]*FeatureFlag, 0, len(fr.flags))
	for _, flag := range fr.flags {
		flags = append(flags, flag)
	}
	return flags
}

// ListByModule returns feature flags for a specific module.
func (fr *FeatureRegistry) ListByModule(moduleID string) []*FeatureFlag {
	fr.mu.RLock()
	defer fr.mu.RUnlock()

	flags := make([]*FeatureFlag, 0)
	for _, flag := range fr.flags {
		if flag.ModuleID == moduleID {
			flags = append(flags, flag)
		}
	}
	return flags
}

// EnableAllForModule enables all features for a module.
func (fr *FeatureRegistry) EnableAllForModule(moduleID string) {
	fr.mu.Lock()
	defer fr.mu.Unlock()

	for _, flag := range fr.flags {
		if flag.ModuleID == moduleID {
			flag.Enabled = true
		}
	}
}

// DisableAllForModule disables all features for a module.
func (fr *FeatureRegistry) DisableAllForModule(moduleID string) {
	fr.mu.Lock()
	defer fr.mu.Unlock()

	for _, flag := range fr.flags {
		if flag.ModuleID == moduleID {
			flag.Enabled = false
		}
	}
}

// Error types
type ErrFeatureAlreadyExists struct {
	ID string
}

func (e ErrFeatureAlreadyExists) Error() string {
	return "feature already exists: " + e.ID
}

type ErrFeatureNotFound struct {
	ID string
}

func (e ErrFeatureNotFound) Error() string {
	return "feature not found: " + e.ID
}
