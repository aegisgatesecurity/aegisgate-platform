// Copyright 2024 AegisGate
// FIPS Configuration Support
//
// This module provides FIPS configuration options for the AegisGate config.

package config

import (
	"fmt"
)

// FIPSConfig represents FIPS compliance configuration
type FIPSConfig struct {
	// Enable FIPS mode
	Enabled bool `json:"enabled" yaml:"enabled" env:"AEGISGATE_FIPS_ENABLED"`

	// FIPS compliance level: "140-2" or "140-3"
	Level string `json:"level" yaml:"level" env:"AEGISGATE_FIPS_LEVEL"`

	// Enable cryptographic audit logging
	AuditLogging bool `json:"audit_logging" yaml:"audit_logging" env:"AEGISGATE_FIPS_AUDIT_LOGGING"`

	// Require FIPS-approved algorithms only
	ApprovedAlgorithmsOnly bool `json:"approved_algorithms_only" yaml:"approved_algorithms_only" env:"AEGISGATE_FIPS_APPROVED_ONLY"`

	// Minimum RSA key size (bits)
	MinRSAKeySize int `json:"min_rsa_key_size" yaml:"min_rsa_key_size" env:"AEGISGATE_FIPS_MIN_RSA_KEY_SIZE"`

	// Minimum TLS version
	MinTLSVersion string `json:"min_tls_version" yaml:"min_tls_version" env:"AEGISGATE_FIPS_MIN_TLS_VERSION"`

	// Allow deprecated algorithms (for backward compatibility)
	AllowDeprecated bool `json:"allow_deprecated" yaml:"allow_deprecated" env:"AEGISGATE_FIPS_ALLOW_DEPRECATED"`
}

// DefaultFIPSConfig returns the default FIPS configuration
func DefaultFIPSConfig() FIPSConfig {
	return FIPSConfig{
		Enabled:                false,
		Level:                  "140-2",
		AuditLogging:           true,
		ApprovedAlgorithmsOnly: true,
		MinRSAKeySize:          2048,
		MinTLSVersion:          "1.2",
		AllowDeprecated:        false,
	}
}

// Validate validates the FIPS configuration
func (c FIPSConfig) Validate() error {
	// Validate level
	if c.Level != "140-2" && c.Level != "140-3" {
		return fmt.Errorf("invalid FIPS level: %s (must be 140-2 or 140-3)", c.Level)
	}

	// Validate minimum key size
	if c.MinRSAKeySize < 2048 {
		return fmt.Errorf("minimum RSA key size must be at least 2048 bits, got %d", c.MinRSAKeySize)
	}

	// Validate TLS version
	if c.MinTLSVersion != "1.2" && c.MinTLSVersion != "1.3" {
		return fmt.Errorf("invalid minimum TLS version: %s (must be 1.2 or 1.3)", c.MinTLSVersion)
	}

	return nil
}

// IsTLS12Required returns true if TLS 1.2 is required
func (c FIPSConfig) IsTLS12Required() bool {
	return c.Enabled || c.MinTLSVersion == "1.2"
}

// IsTLS13Required returns true if TLS 1.3 is required
func (c FIPSConfig) IsTLS13Required() bool {
	return c.MinTLSVersion == "1.3"
}
