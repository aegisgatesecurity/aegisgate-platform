// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security

// =========================================================================
//
// Compliance Manager
// High-level API for compliance operations in AegisGuard
// =========================================================================

package compliance

import (
	"context"
	"time"

	"github.com/aegisguardsecurity/aegisguard/pkg/compliance/common"
	"github.com/aegisguardsecurity/aegisguard/pkg/compliance/factory"
	"github.com/aegisguardsecurity/aegisguard/pkg/compliance/registry"
)

// Manager provides a high-level API for compliance operations
type Manager struct {
	registry *registry.Registry
	factory  *factory.FrameworkFactory
	tier     string
}

// Config configures the compliance manager
type Config struct {
	Tier       string
	AutoEnable bool
}

// NewManager creates a new compliance manager
func NewManager(config *Config) (*Manager, error) {
	if config == nil {
		config = &Config{Tier: "community", AutoEnable: true}
	}

	f := factory.NewFrameworkFactory()
	reg, err := f.CreateForTier(config.Tier)
	if err != nil {
		return nil, err
	}

	return &Manager{
		registry: reg,
		factory:  f,
		tier:     config.Tier,
	}, nil
}

// GetRegistry returns the underlying registry
func (m *Manager) GetRegistry() *registry.Registry {
	return m.registry
}

// Check performs compliance checks on the given input
func (m *Manager) Check(ctx context.Context, input common.CheckInput) (*registry.AggregateResult, error) {
	return m.registry.CheckAll(ctx, input)
}

// CheckRequest performs compliance checks on an HTTP request
func (m *Manager) CheckRequest(ctx context.Context, req *common.HTTPRequest) (*registry.AggregateResult, error) {
	return m.registry.CheckAllRequests(ctx, req)
}

// CheckResponse performs compliance checks on an HTTP response
func (m *Manager) CheckResponse(ctx context.Context, resp *common.HTTPResponse) (*registry.AggregateResult, error) {
	return m.registry.CheckAllResponses(ctx, resp)
}

// CheckByFrameworks performs compliance checks using specific frameworks
func (m *Manager) CheckByFrameworks(ctx context.Context, frameworkIDs []string, input common.CheckInput) (*registry.AggregateResult, error) {
	return m.registry.CheckByFrameworks(ctx, frameworkIDs, input)
}

// GetStats returns compliance statistics
func (m *Manager) GetStats() *ComplianceStats {
	stats := m.registry.GetStats()
	return &ComplianceStats{
		TotalFrameworks:      stats.TotalFrameworks,
		EnabledFrameworks:    stats.EnabledCount,
		RegisteredFrameworks: m.getRegisteredIDs(),
	}
}

// ComplianceStats holds compliance statistics
type ComplianceStats struct {
	TotalFrameworks      int
	EnabledFrameworks    int
	LastCheckTime        time.Time
	RegisteredFrameworks []string
}

// getRegisteredIDs returns IDs of all registered frameworks
func (m *Manager) getRegisteredIDs() []string {
	ids := make([]string, 0)
	for _, f := range m.registry.List() {
		ids = append(ids, f.GetFrameworkID())
	}
	return ids
}

// ValidateConfiguration validates the current configuration
func (m *Manager) ValidateConfiguration() error {
	// Check that all required frameworks are registered
	frameworks := m.registry.List()
	if len(frameworks) == 0 {
		return ErrNoFrameworksRegistered
	}

	// Check that at least one framework is enabled
	enabled := false
	for _, f := range frameworks {
		if f.IsEnabled() {
			enabled = true
			break
		}
	}
	if !enabled {
		return ErrNoFrameworksEnabled
	}

	return nil
}

// Errors
var (
	ErrNoFrameworksRegistered = &ComplianceError{"no frameworks registered"}
	ErrNoFrameworksEnabled    = &ComplianceError{"no frameworks enabled"}
)

// ComplianceError represents a compliance-specific error
type ComplianceError struct {
	message string
}

func (e *ComplianceError) Error() string {
	return e.message
}
