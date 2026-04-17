// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

package immutableconfig

import (
	"github.com/aegisgatesecurity/aegisgate/pkg/immutable-config/integrity"
	"github.com/aegisgatesecurity/aegisgate/pkg/immutable-config/logging"
	"github.com/aegisgatesecurity/aegisgate/pkg/immutable-config/rollback"
)

// ConfigOptions for configuring the immutable config system
type ConfigOptions struct {
	Provider        Provider
	MaxVersions     int
	EnableRollback  bool
	MaxAuditEntries int
	EnableIntegrity bool
	EnableSignature bool
}

// DefaultOptions returns default configuration options
func DefaultOptions() *ConfigOptions {
	return &ConfigOptions{
		MaxVersions:     10,
		EnableRollback:  true,
		MaxAuditEntries: 1000,
		EnableIntegrity: true,
	}
}

// NewConfigOptions creates new options with default values
func NewConfigOptions() *ConfigOptions {
	return DefaultOptions()
}

// Option is a function that configures options
type Option func(*ConfigOptions)

// WithProvider sets the storage provider
func WithProvider(p Provider) Option {
	return func(opts *ConfigOptions) {
		opts.Provider = p
	}
}

// WithMaxVersions sets the maximum number of versions to keep
func WithMaxVersions(max int) Option {
	return func(opts *ConfigOptions) {
		opts.MaxVersions = max
	}
}

// WithRollback enables/disables rollback functionality
func WithRollback(enabled bool) Option {
	return func(opts *ConfigOptions) {
		opts.EnableRollback = enabled
	}
}

// WithMaxAuditEntries sets the maximum audit log entries
func WithMaxAuditEntries(max int) Option {
	return func(opts *ConfigOptions) {
		opts.MaxAuditEntries = max
	}
}

// WithIntegrity enables/disables integrity checking
func WithIntegrity(enabled bool) Option {
	return func(opts *ConfigOptions) {
		opts.EnableIntegrity = enabled
	}
}

// WithSignature enables/disables signature verification
func WithSignature(enabled bool) Option {
	return func(opts *ConfigOptions) {
		opts.EnableSignature = enabled
	}
}

// NewWithOptions creates a new ConfigManager with custom options
func NewWithOptions(options *ConfigOptions) *ConfigManager {
	if options.Provider == nil {
		options.Provider = NewInMemoryProvider()
	}

	if options.MaxVersions <= 0 {
		options.MaxVersions = 10
	}

	if options.MaxAuditEntries <= 0 {
		options.MaxAuditEntries = 1000
	}

	manager := &ConfigManager{
		provider:    options.Provider,
		integrity:   integrity.NewIntegrityChecker(),
		auditLogger: logging.NewAuditLogger(options.MaxAuditEntries),
		rollbackMgr: rollback.NewRollbackManager(options.MaxVersions, options.EnableRollback),
	}

	return manager
}
