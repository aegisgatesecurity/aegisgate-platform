// SPDX-License-Identifier: MIT
// =========================================================================
// =========================================================================
//
// =========================================================================

// Package core provides the foundational module system for AegisGate.
// It defines the Module interface, module registry, and license management
// for the modular plugin architecture.
package core

import (
	"context"
	"encoding/json"
	"time"
)

// ModuleStatus represents the current state of a module.
type ModuleStatus int

const (
	// StatusUnregistered indicates the module is not registered with the system.
	StatusUnregistered ModuleStatus = iota
	// StatusRegistered indicates the module is registered but not initialized.
	StatusRegistered
	// StatusInitialized indicates the module has been initialized.
	StatusInitialized
	// StatusActive indicates the module is fully active and operational.
	StatusActive
	// StatusDisabled indicates the module is temporarily disabled.
	StatusDisabled
	// StatusError indicates the module encountered an error.
	StatusError
)

func (s ModuleStatus) String() string {
	switch s {
	case StatusUnregistered:
		return "unregistered"
	case StatusRegistered:
		return "registered"
	case StatusInitialized:
		return "initialized"
	case StatusActive:
		return "active"
	case StatusDisabled:
		return "disabled"
	case StatusError:
		return "error"
	default:
		return "unknown"
	}
}

// Tier represents the licensing tier for a module.
// Updated to 4-tier system: Community -> Developer -> Professional -> Enterprise
type Tier int

const (
	TierCommunity    Tier = iota // Community tier (free, open source)
	TierDeveloper                // Developer tier
	TierProfessional             // Professional tier
	TierEnterprise               // Enterprise tier
)

func (t Tier) String() string {
	switch t {
	case TierCommunity:
		return "Community"
	case TierDeveloper:
		return "Developer"
	case TierProfessional:
		return "Professional"
	case TierEnterprise:
		return "Enterprise"
	default:
		return "Unknown"
	}
}

// GetTierByName returns Tier from string name (case insensitive)
func GetTierByName(name string) Tier {
	switch name {
	case "community":
		return TierCommunity
	case "developer":
		return TierDeveloper
	case "professional":
		return TierProfessional
	case "enterprise":
		return TierEnterprise
	default:
		return TierCommunity
	}
}

// MarshalJSON implements json.Marshaler for Tier.
func (t Tier) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

// UnmarshalJSON implements json.Unmarshaler for Tier.
func (t *Tier) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	*t = GetTierByName(s)
	return nil
}

// ModuleCategory groups modules by functionality.
type ModuleCategory string

const (
	CategoryCore       ModuleCategory = "core"
	CategoryProxy      ModuleCategory = "proxy"
	CategorySecurity   ModuleCategory = "security"
	CategoryAuth       ModuleCategory = "auth"
	CategoryUI         ModuleCategory = "ui"
	CategoryCompliance ModuleCategory = "compliance"
	CategoryAnalytics  ModuleCategory = "analytics"
	CategoryAI         ModuleCategory = "ai"
)

// ModuleMetadata contains descriptive information about a module.
type ModuleMetadata struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Version     string                 `json:"version"`
	Description string                 `json:"description"`
	Author      string                 `json:"author"`
	Category    ModuleCategory         `json:"category"`
	Tier        Tier                   `json:"tier"`
	Tags        []string               `json:"tags,omitempty"`
	Website     string                 `json:"website,omitempty"`
	Repository  string                 `json:"repository,omitempty"`
	License     string                 `json:"license,omitempty"`
	Config      map[string]interface{} `json:"config,omitempty"`
}

// ModuleConfig contains runtime configuration for a module.
type ModuleConfig struct {
	Enabled    bool                   `json:"enabled"`
	Priority   int                    `json:"priority"`
	Settings   map[string]interface{} `json:"settings,omitempty"`
	LicenseKey string                 `json:"license_key,omitempty"`
}

// HealthStatus represents the health check result of a module.
type HealthStatus struct {
	Healthy   bool                   `json:"healthy"`
	Message   string                 `json:"message,omitempty"`
	LastCheck time.Time              `json:"last_check"`
	Metrics   map[string]interface{} `json:"metrics,omitempty"`
}

// Module defines the interface that all AegisGate modules must implement.
type Module interface {
	// Metadata returns the module's descriptive information.
	Metadata() ModuleMetadata

	// Initialize prepares the module for operation.
	// Called once during application startup.
	Initialize(ctx context.Context, config ModuleConfig) error

	// Start begins the module's operation.
	// Called after all dependencies are initialized.
	Start(ctx context.Context) error

	// Stop gracefully shuts down the module.
	Stop(ctx context.Context) error

	// Status returns the current operational status.
	Status() ModuleStatus

	// Health returns the module's health status.
	Health(ctx context.Context) HealthStatus

	// Dependencies returns the IDs of modules this module depends on.
	Dependencies() []string

	// OptionalDependencies returns IDs of modules that enhance functionality.
	OptionalDependencies() []string

	// Provides returns what capabilities this module provides.
	Provides() []string

	// SetRegistry allows the module to access other modules.
	SetRegistry(registry *Registry)
}

// ModuleLifecycle represents lifecycle event callbacks.
type ModuleLifecycle struct {
	OnBeforeStart func(ctx context.Context) error
	OnAfterStart  func(ctx context.Context) error
	OnBeforeStop  func(ctx context.Context) error
	OnAfterStop   func(ctx context.Context) error
	OnError       func(ctx context.Context, err error)
}

// ModuleWithLifecycle is an optional interface for modules with lifecycle hooks.
type ModuleWithLifecycle interface {
	Module
	Lifecycle() *ModuleLifecycle
}

// ModuleWithConfig is an optional interface for modules with custom config validation.
type ModuleWithConfig interface {
	Module
	ValidateConfig(config ModuleConfig) error
	DefaultConfig() ModuleConfig
}

// ModuleWithMetrics is an optional interface for modules that expose metrics.
type ModuleWithMetrics interface {
	Module
	Metrics() map[string]interface{}
}

// ModuleWithRoutes is an optional interface for modules that register HTTP routes.
type ModuleWithRoutes interface {
	Module
	RegisterRoutes(router interface{}) error
}

// Capability represents a named capability provided by modules.
type Capability struct {
	ID          string
	Name        string
	Description string
	ProviderID  string // Module ID that provides this capability
	Version     string
}
