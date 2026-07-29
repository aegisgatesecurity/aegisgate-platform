// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform — SIEM Integration Package
// =========================================================================
//
// Package siem provides the platform-level SIEM integration for AegisGate.
// It wraps the upstream SIEM manager (github.com/aegisgatesecurity/aegisgate/pkg/siem)
// with platform-specific configuration, lifecycle management, and a public
// API surface suitable for direct use by operators and integrators.
//
// The package provides:
//   - Manager: A platform-level SIEM manager that wraps the upstream manager
//     with platform config bridging and lifecycle hooks.
//   - ConfigFromPlatform: Converts PlatformSIEMConfig into upstream
//     siem.Config for seamless integration with cmd/aegisgate-platform.
//   - HealthCheck: Returns the SIEM dispatcher's operational status for
//     health endpoints and gRPC CoreService.GetHealth().
//   - Stats: Returns live SIEM statistics for the gRPC SIEMService and
//     dashboard endpoints.
//
// Wire target:
//   - cmd/aegisgate-platform/main.go (SIEM dispatcher initialization)
//   - pkg/grpc (SIEMService backend)
//   - /api/v1/siem/* (HTTP endpoints)
//   - /api/v1/health (SIEM component health)
//
// =========================================================================
package siem

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/siem"
)

// Manager wraps the upstream SIEM manager with platform-level
// configuration bridging, health checking, and statistics.
type Manager struct {
	upstream  *siem.Manager
	logger    *slog.Logger
	started   bool
	startTime time.Time
}

// NewManager creates a platform-level SIEM manager wrapping the upstream.
// Returns a manager ready to start; call Start() to begin event processing.
func NewManager(upstream *siem.Manager, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}
	return &Manager{
		upstream: upstream,
		logger:   logger,
	}
}

// Start begins SIEM event processing. This delegates to the upstream
// manager's Start() method and records the start time for uptime tracking.
func (m *Manager) Start() {
	if m.upstream != nil {
		m.upstream.Start()
	}
	m.started = true
	m.startTime = time.Now()
	m.logger.Info("SIEM manager started")
}

// Stop gracefully shuts down the SIEM manager, flushing buffered events.
func (m *Manager) Stop() {
	if m.upstream != nil {
		m.upstream.Stop()
	}
	m.started = false
	m.logger.Info("SIEM manager stopped")
}

// Send sends a single event to all configured SIEM platforms.
func (m *Manager) Send(ctx context.Context, event *siem.Event) error {
	if m.upstream == nil {
		return fmt.Errorf("siem: manager not initialized")
	}
	return m.upstream.Send(event)
}

// SendBatch sends a batch of events to all configured SIEM platforms.
func (m *Manager) SendBatch(ctx context.Context, events []*siem.Event) error {
	if m.upstream == nil {
		return fmt.Errorf("siem: manager not initialized")
	}
	return m.upstream.SendBatch(events)
}

// Stats returns live SIEM statistics.
func (m *Manager) Stats() *siem.ManagerStats {
	if m.upstream == nil {
		return &siem.ManagerStats{}
	}
	return m.upstream.Stats()
}

// IsStarted returns whether the SIEM manager is currently running.
func (m *Manager) IsStarted() bool {
	return m.started
}

// Uptime returns the duration since the SIEM manager was started.
func (m *Manager) Uptime() time.Duration {
	if !m.started {
		return 0
	}
	return time.Since(m.startTime)
}

// HealthStatus represents the SIEM component's health for reporting.
type HealthStatus struct {
	Started   bool          `json:"started"`
	Uptime    time.Duration `json:"uptime"`
	Platforms int           `json:"platforms"`
}

// HealthCheck returns the SIEM manager's health status.
func (m *Manager) HealthCheck() *HealthStatus {
	stats := m.Stats()
	return &HealthStatus{
		Started:   m.started,
		Uptime:    m.Uptime(),
		Platforms: len(stats.PlatformStats),
	}
}

// ConfigFromPlatform converts a PlatformSIEMConfig into an upstream siem.Config.
// This bridges the platform's YAML configuration into the format the upstream
// SIEM manager expects.
func ConfigFromPlatform(cfg PlatformSIEMConfig) siem.Config {
	siemCfg := siem.Config{
		Global: siem.GlobalConfig{
			AppName:     cfg.Source,
			Environment: cfg.Environment,
		},
	}

	for _, pc := range cfg.Platforms {
		auth := siem.AuthConfig{}
		if pc.APIKey != "" {
			auth.Type = "api_key"
			auth.APIKey = pc.APIKey
		}

		siemCfg.Platforms = append(siemCfg.Platforms, siem.PlatformConfig{
			Platform: siem.Platform(pc.Type),
			Enabled:  pc.Enabled,
			Endpoint: pc.Endpoint,
			Format:   siem.Format(pc.Format),
			Auth:     auth,
			Settings: pc.Settings,
		})
	}

	return siemCfg
}

// PlatformSIEMConfig represents the platform-level SIEM configuration
// as loaded from platformconfig.yaml. This is separate from the upstream
// siem.Config to allow platform-specific extensions.
type PlatformSIEMConfig struct {
	Source      string               `yaml:"source" json:"source"`
	Environment string               `yaml:"environment" json:"environment"`
	Enabled     bool                 `yaml:"enabled" json:"enabled"`
	Platforms   []PlatformSIEMTarget `yaml:"platforms" json:"platforms"`
}

// PlatformSIEMTarget represents a single SIEM platform configuration target.
type PlatformSIEMTarget struct {
	Type     string                 `yaml:"type" json:"type"`
	Enabled  bool                   `yaml:"enabled" json:"enabled"`
	Endpoint string                 `yaml:"endpoint" json:"endpoint"`
	APIKey   string                 `yaml:"api_key" json:"api_key"`
	Format   string                 `yaml:"format" json:"format"`
	Settings map[string]interface{} `yaml:"settings" json:"settings"`
}
