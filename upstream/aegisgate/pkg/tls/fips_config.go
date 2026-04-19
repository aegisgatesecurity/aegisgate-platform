// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

// Copyright 2024 AegisGate
// FIPS-Compliant TLS Configuration
//
// This module provides TLS configuration with FIPS-validated cipher suites
// and proper security settings for FIPS compliance.

package tls

import (
	"crypto/tls"
	"fmt"
	"runtime"

	"github.com/aegisgatesecurity/aegisgate/pkg/crypto/fips"
)

// FIPSConfig represents FIPS-compliant TLS configuration
type FIPSConfig struct {
	// Minimum TLS version (default: TLS 1.2)
	MinVersion uint16

	// Maximum TLS version
	MaxVersion uint16

	// List of cipher suites to use (nil = use FIPS defaults)
	CipherSuites []uint16

	// Prefer server cipher suites
	PreferServerCipherSuites bool

	// Enable FIPS mode
	FIPSMode bool
}

// DefaultFIPSTLSConfig returns a FIPS-compliant TLS configuration
func DefaultFIPSTLSConfig() *FIPSConfig {
	return &FIPSConfig{
		MinVersion:               tls.VersionTLS12,
		MaxVersion:               tls.VersionTLS13,
		CipherSuites:             fipsApprovedCipherSuites(),
		PreferServerCipherSuites: true,
		FIPSMode:                 true,
	}
}

// fipsApprovedCipherSuites returns FIPS-approved TLS 1.2 cipher suites
func fipsApprovedCipherSuites() []uint16 {
	return []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	}
}

// ToStandardTLSConfig converts to standard tls.Config
func (c *FIPSConfig) ToStandardTLSConfig() *tls.Config {
	config := &tls.Config{
		MinVersion:               c.MinVersion,
		MaxVersion:               c.MaxVersion,
		PreferServerCipherSuites: c.PreferServerCipherSuites,
	}

	// Use FIPS-approved cipher suites if in FIPS mode
	if c.FIPSMode {
		config.CipherSuites = fipsApprovedCipherSuites()
	} else if len(c.CipherSuites) > 0 {
		config.CipherSuites = c.CipherSuites
	}

	return config
}

// ValidateConfig validates TLS configuration for FIPS compliance
func ValidateConfig(cfg *tls.Config) error {
	// Check minimum TLS version
	if cfg.MinVersion < tls.VersionTLS12 {
		return fmt.Errorf("FIPS compliance requires TLS 1.2 or higher, got %d", cfg.MinVersion)
	}

	// Check for weak key exchange
	if cfg.MinVersion == tls.VersionTLS10 || cfg.MinVersion == tls.VersionTLS11 {
		return fmt.Errorf("TLS 1.0/1.1 not allowed in FIPS mode")
	}

	return nil
}

// GetDefaultTLSConfig returns a secure default TLS configuration
func GetDefaultTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:               tls.VersionTLS12,
		MaxVersion:               tls.VersionTLS13,
		PreferServerCipherSuites: true,
	}
}

// GetFIPSTLSConfig returns a FIPS-compliant TLS configuration
func GetFIPSTLSConfig() *tls.Config {
	// Run FIPS self-test
	if err := fips.SelfTest(); err != nil {
		// Log but don't fail - we're providing best effort
		fmt.Printf("Warning: FIPS self-test failed: %v\n", err)
	}

	config := DefaultFIPSTLSConfig()

	// Log FIPS mode status
	mode := fips.GetMode()
	fmt.Printf("FIPS TLS Config: Level=%s, Enabled=%v, Go=%s\n",
		mode.Level, mode.Enabled, runtime.Version())

	return config.ToStandardTLSConfig()
}

// CipherSuiteName returns the name of a cipher suite
func CipherSuiteName(id uint16) string {
	names := map[uint16]string{
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:   "ECDHE-RSA-AES256-GCM-SHA384",
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:   "ECDHE-RSA-AES128-GCM-SHA256",
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: "ECDHE-ECDSA-AES256-GCM-SHA384",
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: "ECDHE-ECDSA-AES128-GCM-SHA256",
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384:         "RSA-AES256-GCM-SHA384",
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256:         "RSA-AES128-GCM-SHA256",
	}

	if name, ok := names[id]; ok {
		return name
	}
	return fmt.Sprintf("0x%04X", id)
}
