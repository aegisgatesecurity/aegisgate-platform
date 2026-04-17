// SPDX-License-Identifier: MIT
// =========================================================================
// AegisGate Security Platform - Bridge Package
// =========================================================================
//
// The bridge package provides unified LLM security coverage by routing
// agent LLM API calls through AegisGate for additional security scanning,
// while maintaining transparent integration with AegisGuard's MCP architecture.
//
// This package re-exports the AegisGuard bridge types and adds platform-level
// convenience constructors that wire the bridge to AegisGate's proxy.
//
// Architecture:
//
//	AI Agent -> AegisGuard (MCP) -> Bridge -> AegisGate (HTTP Proxy) -> LLM Provider
//
// Import path: Uses real upstream module github.com/aegisguardsecurity/aegisguard/pkg/bridge
// via go.mod replace directive.
// =========================================================================

package bridge

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	// Import canonical bridge types from AegisGuard source
	guardbridge "github.com/aegisguardsecurity/aegisguard/pkg/bridge"
)

// ============================================================================
// Re-exports: Canonical types from AegisGuard's bridge package
// ============================================================================
//
// We re-export all types so consumers only need to import one package:
//   github.com/aegisgatesecurity/aegisgate-platform/pkg/bridge
//
// This avoids import confusion and provides a single integration point.

// Config is the bridge configuration (re-exported from AegisGuard)
type Config = guardbridge.Config

// LLMRequest is an LLM API request from an agent (re-exported)
type LLMRequest = guardbridge.LLMRequest

// LLMResponse is an LLM API response (re-exported)
type LLMResponse = guardbridge.LLMResponse

// ScanResult contains AegisGate's security scan results (re-exported)
type ScanResult = guardbridge.ScanResult

// Threat represents a detected security threat (re-exported)
type Threat = guardbridge.Threat

// ThreatSeverity levels (re-exported)
type ThreatSeverity = guardbridge.ThreatSeverity

// ComplianceViolation represents a compliance framework violation (re-exported)
type ComplianceViolation = guardbridge.ComplianceViolation

// Stats holds bridge statistics (re-exported)
type Stats = guardbridge.Stats

// LLMToolContext contains context for an LLM tool call (re-exported)
type LLMToolContext = guardbridge.LLMToolContext

// Severity constants (re-exported)
const (
	SeverityInfo     = guardbridge.SeverityInfo
	SeverityLow      = guardbridge.SeverityLow
	SeverityMedium   = guardbridge.SeverityMedium
	SeverityHigh     = guardbridge.SeverityHigh
	SeverityCritical = guardbridge.SeverityCritical
)

// DefaultConfig returns default bridge configuration targeting AegisGate proxy (re-exported)
var DefaultConfig = guardbridge.DefaultConfig

// ============================================================================
// Platform Bridge: Unified entry point for the consolidated platform
// ============================================================================

// PlatformBridge is the unified bridge for the AegisGate Security Platform.
// It wraps AegisGuard's Gateway with platform-level lifecycle management.
type PlatformBridge struct {
	gateway  *guardbridge.Gateway
	config   *Config
	logger   *slog.Logger
	mu       sync.RWMutex
	enabled  bool
	stats    *Stats
}

// NewPlatformBridge creates a new bridge that routes LLM calls through
// the AegisGate proxy running in the same platform process.
//
// aegisGateURL should be the internal address of the AegisGate proxy
// (e.g., "http://localhost:8080" when proxy-port is 8080).
func NewPlatformBridge(aegisGateURL string) (*PlatformBridge, error) {
	cfg := guardbridge.DefaultConfig()
	cfg.AegisGateURL = aegisGateURL
	cfg.Enabled = true

	gateway, err := guardbridge.NewGateway(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create bridge gateway: %w", err)
	}

	return &PlatformBridge{
		gateway: gateway,
		config:  cfg,
		logger:  slog.Default(),
		enabled: true,
		stats:   guardbridge.NewStats(),
	}, nil
}

// NewPlatformBridgeWithConfig creates a bridge with custom configuration.
func NewPlatformBridgeWithConfig(cfg *Config) (*PlatformBridge, error) {
	if cfg == nil {
		cfg = guardbridge.DefaultConfig()
	}

	gateway, err := guardbridge.NewGateway(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create bridge gateway: %w", err)
	}

	return &PlatformBridge{
		gateway: gateway,
		config:  cfg,
		logger:  slog.Default(),
		enabled: cfg.Enabled,
		stats:   guardbridge.NewStats(),
	}, nil
}

// RouteLLMCall routes an LLM API call through AegisGate.
// This is the primary method used by AegisGuard's MCP handler to route
// LLM tool calls through AegisGate for defense-in-depth scanning.
func (pb *PlatformBridge) RouteLLMCall(ctx context.Context, req *LLMRequest) (*LLMResponse, error) {
	if !pb.enabled {
		// Bridge disabled — pass through without scanning
		return &LLMResponse{
			RequestID:  req.RequestID,
			StatusCode: 200,
		}, nil
	}

	resp, err := pb.gateway.RouteLLMCall(ctx, req)
	if err != nil {
		pb.logger.Error("bridge routing failed", "error", err, "request_id", req.RequestID)
		return nil, fmt.Errorf("bridge routing failed: %w", err)
	}

	// Log blocked requests
	if resp.ScanResult != nil && !resp.ScanResult.Allowed {
		pb.logger.Warn("AegisGate blocked LLM call",
			"request_id", req.RequestID,
			"agent_id", req.AgentID,
			"reason", resp.ScanResult.BlockReason,
			"threats", len(resp.ScanResult.Threats),
		)
	}

	return resp, nil
}

// IsLLMCall determines if a tool call is an LLM API call using
// AegisGuard's built-in LLM detection heuristics.
func (pb *PlatformBridge) IsLLMCall(toolName string, args map[string]interface{}) bool {
	return guardbridge.DetectLLMTool(toolName, args)
}

// GetStats returns bridge statistics
func (pb *PlatformBridge) GetStats() *Stats {
	return pb.gateway.GetStats()
}

// IsEnabled returns whether the bridge is active
func (pb *PlatformBridge) IsEnabled() bool {
	pb.mu.RLock()
	defer pb.mu.RUnlock()
	return pb.enabled
}

// SetEnabled enables or disables the bridge at runtime
func (pb *PlatformBridge) SetEnabled(enabled bool) {
	pb.mu.Lock()
	defer pb.mu.Unlock()
	pb.enabled = enabled
	pb.logger.Info("bridge enabled state changed", "enabled", enabled)
}

// Close shuts down the bridge and releases resources
func (pb *PlatformBridge) Close() error {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	if pb.gateway != nil {
		return pb.gateway.Close()
	}
	return nil
}

// Gateway returns the underlying AegisGuard gateway for advanced usage
func (pb *PlatformBridge) Gateway() *guardbridge.Gateway {
	return pb.gateway
}