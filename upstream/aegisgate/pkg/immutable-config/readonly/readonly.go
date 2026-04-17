// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

package readonly

import (
	"fmt"
	"sync"
	"time"

	immutableconfig "github.com/aegisgatesecurity/aegisgate/pkg/immutable-config"
)

// ReadOnlyProvider wraps a Provider with read-only enforcement
type ReadOnlyProvider struct {
	mu            sync.RWMutex
	provider      immutableconfig.Provider
	sealed        bool
	sealedAt      time.Time
	modified      bool
	modifications []Modification
}

// Modification tracks attempted modifications
type Modification struct {
	Timestamp time.Time
	Operation string
	Version   string
	Blocked   bool
}

// ReadOnlyOptions for configuring the read-only provider
type ReadOnlyOptions struct {
	AutoSeal        bool
	SealAfterWrites int
}

// DefaultReadOnlyOptions returns default read-only options
func DefaultReadOnlyOptions() *ReadOnlyOptions {
	return &ReadOnlyOptions{
		AutoSeal:        false,
		SealAfterWrites: 0,
	}
}

// NewReadOnlyProvider creates a new read-only provider wrapper
func NewReadOnlyProvider(provider immutableconfig.Provider, opts *ReadOnlyOptions) *ReadOnlyProvider {
	// Options are used for future configuration; defaults applied implicitly
	return &ReadOnlyProvider{
		provider:      provider,
		modifications: make([]Modification, 0),
		sealed:        false,
	}
}

// Initialize initializes the underlying provider
func (rop *ReadOnlyProvider) Initialize() error {
	return rop.provider.Initialize()
}

// Load loads a configuration (allowed in read-only mode)
func (rop *ReadOnlyProvider) Load(version string) (*immutableconfig.ConfigData, error) {
	rop.mu.RLock()
	defer rop.mu.RUnlock()

	return rop.provider.Load(version)
}

// Save attempts to save a configuration (blocked if sealed)
func (rop *ReadOnlyProvider) Save(config *immutableconfig.ConfigData) (*immutableconfig.ConfigVersion, error) {
	rop.mu.Lock()
	defer rop.mu.Unlock()

	// Record the modification attempt
	mod := Modification{
		Timestamp: time.Now().UTC(),
		Operation: "save",
		Version:   config.Version,
		Blocked:   rop.sealed,
	}
	rop.modifications = append(rop.modifications, mod)

	if rop.sealed {
		return nil, fmt.Errorf("filesystem is sealed: modifications are not allowed")
	}

	rop.modified = true
	return rop.provider.Save(config)
}

// ListVersions lists all versions (allowed in read-only mode)
func (rop *ReadOnlyProvider) ListVersions() ([]*immutableconfig.ConfigVersion, error) {
	return rop.provider.ListVersions()
}

// Close closes the underlying provider
func (rop *ReadOnlyProvider) Close() error {
	return rop.provider.Close()
}

// Seal seals the filesystem, preventing all future modifications
func (rop *ReadOnlyProvider) Seal() error {
	rop.mu.Lock()
	defer rop.mu.Unlock()

	if rop.sealed {
		return fmt.Errorf("filesystem is already sealed")
	}

	rop.sealed = true
	rop.sealedAt = time.Now().UTC()
	return nil
}

// Unseal unseals the filesystem, allowing modifications (admin operation)
func (rop *ReadOnlyProvider) Unseal() error {
	rop.mu.Lock()
	defer rop.mu.Unlock()

	rop.sealed = false
	rop.sealedAt = time.Time{}
	return nil
}

// IsSealed returns whether the filesystem is sealed
func (rop *ReadOnlyProvider) IsSealed() bool {
	rop.mu.RLock()
	defer rop.mu.RUnlock()
	return rop.sealed
}

// SealedAt returns when the filesystem was sealed
func (rop *ReadOnlyProvider) SealedAt() time.Time {
	rop.mu.RLock()
	defer rop.mu.RUnlock()
	return rop.sealedAt
}

// GetModificationHistory returns the history of modification attempts
func (rop *ReadOnlyProvider) GetModificationHistory() []Modification {
	rop.mu.RLock()
	defer rop.mu.RUnlock()

	history := make([]Modification, len(rop.modifications))
	copy(history, rop.modifications)
	return history
}

// GetBlockedModifications returns only blocked modification attempts
func (rop *ReadOnlyProvider) GetBlockedModifications() []Modification {
	rop.mu.RLock()
	defer rop.mu.RUnlock()

	var blocked []Modification
	for _, mod := range rop.modifications {
		if mod.Blocked {
			blocked = append(blocked, mod)
		}
	}
	return blocked
}

// ClearModificationHistory clears the modification history
func (rop *ReadOnlyProvider) ClearModificationHistory() {
	rop.mu.Lock()
	defer rop.mu.Unlock()
	rop.modifications = make([]Modification, 0)
}

// IsModified returns whether modifications have been made since sealing
func (rop *ReadOnlyProvider) IsModified() bool {
	rop.mu.RLock()
	defer rop.mu.RUnlock()
	return rop.modified
}

// ResetModified resets the modified flag
func (rop *ReadOnlyProvider) ResetModified() {
	rop.mu.Lock()
	defer rop.mu.Unlock()
	rop.modified = false
}

// ReadOnlyLayer provides an additional abstraction layer for read-only access
type ReadOnlyLayer struct {
	provider *ReadOnlyProvider
	sealed   bool
}

// NewReadOnlyLayer creates a new read-only layer
func NewReadOnlyLayer(provider *ReadOnlyProvider) *ReadOnlyLayer {
	return &ReadOnlyLayer{
		provider: provider,
		sealed:   provider.IsSealed(),
	}
}

// Get retrieves configuration data without allowing modifications
func (rol *ReadOnlyLayer) Get(version string) (*immutableconfig.ConfigData, error) {
	return rol.provider.Load(version)
}

// GetLatest retrieves the latest configuration
func (rol *ReadOnlyLayer) GetLatest() (*immutableconfig.ConfigData, error) {
	versions, err := rol.provider.ListVersions()
	if err != nil {
		return nil, err
	}

	if len(versions) == 0 {
		return nil, fmt.Errorf("no configurations available")
	}

	// Find the latest version
	var latestVersion string
	var latestTime string
	for _, v := range versions {
		if v.Timestamp > latestTime {
			latestTime = v.Timestamp
			latestVersion = v.Version
		}
	}

	return rol.provider.Load(latestVersion)
}

// ListVersions lists all available versions
func (rol *ReadOnlyLayer) ListVersions() ([]*immutableconfig.ConfigVersion, error) {
	return rol.provider.ListVersions()
}

// IsSealed returns whether the layer is sealed
func (rol *ReadOnlyLayer) IsSealed() bool {
	return rol.sealed
}
