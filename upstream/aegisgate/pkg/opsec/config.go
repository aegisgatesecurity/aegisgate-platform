// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

package opsec

import (
	"errors"
	"time"
)

// OPSECConfig contains all configuration options for the OPSEC module
type OPSECConfig struct {
	// Audit configuration
	AuditEnabled    bool `json:"audit_enabled"`
	AuditMaxEntries int  `json:"audit_max_entries"`
	LogIntegrity    bool `json:"log_integrity"`

	// Secret rotation configuration
	RotationEnabled bool          `json:"rotation_enabled"`
	RotationPeriod  time.Duration `json:"rotation_period"`
	SecretLength    int           `json:"secret_length"`

	// Memory scrubbing configuration
	MemoryScrubbing bool `json:"memory_scrubbing"`

	// Runtime hardening configuration
	RuntimeHardening bool `json:"runtime_hardening"`
	DropCapabilities bool `json:"drop_capabilities"`

	// Threat modeling configuration
	ThreatModeling bool `json:"threat_modeling"`
}

// DefaultOPSECConfig returns a configuration with secure defaults
func DefaultOPSECConfig() OPSECConfig {
	return OPSECConfig{
		AuditEnabled:     true,
		AuditMaxEntries:  10000,
		LogIntegrity:     true,
		RotationEnabled:  true,
		RotationPeriod:   24 * time.Hour,
		SecretLength:     32,
		MemoryScrubbing:  true,
		RuntimeHardening: true,
		DropCapabilities: true,
		ThreatModeling:   true,
	}
}

// Validate checks that the configuration is valid
func (c *OPSECConfig) Validate() error {
	if c.SecretLength < 16 {
		return errors.New("secret length must be at least 16 bytes")
	}
	if c.SecretLength > 4096 {
		return errors.New("secret length cannot exceed 4096 bytes")
	}
	if c.RotationPeriod < time.Hour {
		return errors.New("rotation period must be at least 1 hour")
	}
	if c.RotationPeriod > 365*24*time.Hour {
		return errors.New("rotation period cannot exceed 1 year")
	}
	if c.AuditMaxEntries < 100 {
		return errors.New("audit max entries must be at least 100")
	}
	if c.AuditMaxEntries > 100000 {
		return errors.New("audit max entries cannot exceed 100000")
	}
	return nil
}

// ValidateWithDefaults validates the config and applies defaults where needed
func (c *OPSECConfig) ValidateWithDefaults() error {
	// Apply defaults for zero values
	if c.SecretLength == 0 {
		c.SecretLength = 32
	}
	if c.RotationPeriod == 0 {
		c.RotationPeriod = 24 * time.Hour
	}
	if c.AuditMaxEntries == 0 {
		c.AuditMaxEntries = 10000
	}

	return c.Validate()
}

// IsAuditEnabled returns whether audit logging is enabled
func (c *OPSECConfig) IsAuditEnabled() bool {
	return c.AuditEnabled
}

// IsRotationEnabled returns whether secret rotation is enabled
func (c *OPSECConfig) IsRotationEnabled() bool {
	return c.RotationEnabled
}

// IsMemoryScrubbingEnabled returns whether memory scrubbing is enabled
func (c *OPSECConfig) IsMemoryScrubbingEnabled() bool {
	return c.MemoryScrubbing
}

// IsRuntimeHardeningEnabled returns whether runtime hardening is enabled
func (c *OPSECConfig) IsRuntimeHardeningEnabled() bool {
	return c.RuntimeHardening
}

// IsThreatModelingEnabled returns whether threat modeling is enabled
func (c *OPSECConfig) IsThreatModelingEnabled() bool {
	return c.ThreatModeling
}

// GetRotationPeriodDuration returns the rotation period as a time.Duration
func (c *OPSECConfig) GetRotationPeriodDuration() time.Duration {
	return c.RotationPeriod
}

// NewConfig creates a new configuration with all features enabled
func NewConfig() OPSECConfig {
	return DefaultOPSECConfig()
}

// MinimalConfig creates a configuration with minimal security features
// (useful for development/testing only)
func MinimalConfig() OPSECConfig {
	return OPSECConfig{
		AuditEnabled:     false,
		RotationEnabled:  false,
		MemoryScrubbing:  true,
		RuntimeHardening: false,
		ThreatModeling:   false,
	}
}

// HighSecurityConfig creates a configuration with maximum security
// (may have performance impact)
func HighSecurityConfig() OPSECConfig {
	return OPSECConfig{
		AuditEnabled:     true,
		AuditMaxEntries:  50000,
		LogIntegrity:     true,
		RotationEnabled:  true,
		RotationPeriod:   1 * time.Hour,
		SecretLength:     64,
		MemoryScrubbing:  true,
		RuntimeHardening: true,
		DropCapabilities: true,
		ThreatModeling:   true,
	}
}
