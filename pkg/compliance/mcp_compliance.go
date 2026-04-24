// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - MCP Compliance Adapter
// =========================================================================
//
// Adapts compliance package for integration with MCP server.
// Enables tier-aware compliance checks during MCP sessions.
// =========================================================================

package compliance

import (
	"sync"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
)

// ============================================================================
// MCP Compliance Adapter
// ============================================================================

// MCPTierAwareCompliance wraps the compliance Manager for MCP server integration
// with tier-aware framework enforcement.
type MCPTierAwareCompliance struct {
	manager *Manager
	mu      sync.RWMutex
}

// NewMCPTierAwareCompliance creates a new MCP compliance adapter
func NewMCPTierAwareCompliance(config *Config) (*MCPTierAwareCompliance, error) {
	manager, err := NewManager(config)
	if err != nil {
		return nil, err
	}

	return &MCPTierAwareCompliance{
		manager: manager,
	}, nil
}

// Check performs a tier-aware compliance check
// If content passes the tier's enabled frameworks, it returns a passing result
func (c *MCPTierAwareCompliance) Check(content string, direction string, t tier.Tier) (*Result, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result, err := c.manager.Check(content, direction)
	if err != nil {
		return nil, err
	}

	// Filter findings based on tier restrictions
	result.Findings = c.filterFindingsByTier(result.Findings, t)

	// Update passed status based on filtered findings
	result.Passed = true
	for _, f := range result.Findings {
		if f.Block && f.Severity == SeverityCritical {
			result.Passed = false
			break
		}
	}

	return result, nil
}

// CheckFramework performs a tier-aware check against a specific framework
func (c *MCPTierAwareCompliance) CheckFramework(content string, framework Framework, t tier.Tier) (*Result, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result, err := c.manager.CheckFramework(content, framework)
	if err != nil {
		return nil, err
	}

	// Filter based on tier
	result.Findings = c.filterFindingsByTier(result.Findings, t)

	return result, nil
}

// IsFrameworkEnabledForTier checks if a framework is enabled for a tier
func (c *MCPTierAwareCompliance) IsFrameworkEnabledForTier(framework Framework, t tier.Tier) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Enterprise and Professional tiers have access to all premium frameworks
	if t == tier.TierEnterprise || t == tier.TierProfessional {
		return true
	}

	// Developer tier has limited premium access
	if t == tier.TierDeveloper {
		switch framework {
		case FrameworkSOC2, FrameworkGDPR, FrameworkISO27001, FrameworkISO42001:
			return false // Premium-only
		default:
			return true
		}
	}

	// Community tier - only community-mandated frameworks
	switch framework {
	case FrameworkATLAS, FrameworkNIST1500:
		return true // Mandated for Community
	default:
		return false // Premium frameworks not available
	}
}

// GetActiveFrameworks returns frameworks enabled for a specific tier
func (c *MCPTierAwareCompliance) GetActiveFrameworks(t tier.Tier) []Framework {
	c.mu.RLock()
	defer c.mu.RUnlock()

	all := c.manager.GetActiveFrameworks()
	var enabled []Framework

	for _, f := range all {
		if c.isFrameworkAllowedForTier(f, t) {
			enabled = append(enabled, f)
		}
	}

	return enabled
}

// filterFindingsByTier filters out findings from frameworks not allowed for tier
func (c *MCPTierAwareCompliance) filterFindingsByTier(findings []Finding, t tier.Tier) []Finding {
	var filtered []Finding

	for _, f := range findings {
		if c.isFrameworkAllowedForTier(f.Framework, t) {
			filtered = append(filtered, f)
		}
	}

	return filtered
}

// isFrameworkAllowedForTier checks tier-based access
func (c *MCPTierAwareCompliance) isFrameworkAllowedForTier(framework Framework, t tier.Tier) bool {
	// ATLAS and NIST AI RMF are mandated for ALL tiers (including Community)
	if framework == FrameworkATLAS || framework == FrameworkNIST1500 {
		return true
	}

	// Enterprise and Professional tiers have full access
	if t == tier.TierEnterprise || t == tier.TierProfessional {
		return true
	}

	// Developer tier - limited access
	if t == tier.TierDeveloper {
		switch framework {
		case FrameworkHIPAA, FrameworkPCIDSS:
			return true // Developer can use these with proper license
		case FrameworkSOC2, FrameworkGDPR, FrameworkISO27001, FrameworkISO42001:
			return false // Premium-only
		default:
			return true
		}
	}

	// Community tier - no premium frameworks
	return false
}

// GetStatus returns current compliance status
func (c *MCPTierAwareCompliance) GetStatus() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.manager.GetStatus()
}

// GenerateReport generates a compliance report
func (c *MCPTierAwareCompliance) GenerateReport() (string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.manager.GenerateReport()
}

// ============================================================================
// MCP Compliance Adapter Interface
// ============================================================================

// MCPSessionCompliance provides compliance checks scoped to an MCP session
type MCPSessionCompliance struct {
	adapter *MCPTierAwareCompliance
	session struct {
		ID        string
		Tier      tier.Tier
		StartTime time.Time
	}
	time time.Time
}

// NewMCPSessionCompliance creates a session-scoped compliance checker
func NewMCPSessionCompliance(adapter *MCPTierAwareCompliance, sessionID string, sessionTier tier.Tier) *MCPSessionCompliance {
	s := &MCPSessionCompliance{
		adapter: adapter,
	}
	s.session.ID = sessionID
	s.session.Tier = sessionTier
	s.session.StartTime = time.Now()
	return s
}

// Check performs compliance check for this session's tier
func (s *MCPSessionCompliance) Check(content string, direction string) (*Result, error) {
	return s.adapter.Check(content, direction, s.session.Tier)
}

// GetSessionID returns the session ID
func (s *MCPSessionCompliance) GetSessionID() string {
	return s.session.ID
}

// GetTier returns the session's tier
func (s *MCPSessionCompliance) GetTier() tier.Tier {
	return s.session.Tier
}

// ============================================================================
// Default MCP Compliance Configuration
// ============================================================================

// DefaultMCPComplianceConfig returns the default config for MCP integration
func DefaultMCPComplianceConfig() *Config {
	return &Config{
		EnableAtlas:     true,  // ATLAS is mandated
		EnableNIST1500:  true,  // NIST AI RMF is mandated
		EnableOWASP:     true,  // Security baseline
		EnableGDPR:      false, // Premium - opt-in
		EnableHIPAA:     false, // Premium - opt-in
		EnablePCIDSS:    false, // Premium - opt-in
		EnableSOC2:      false, // Premium - opt-in
		EnableISO42001:  false, // Premium - opt-in
		ContextLines:    3,
		StrictMode:      true, // MCP should be strict
		BlockOnCritical: true, // Block critical findings
	}
}

// ============================================================================
// Tier Restrictions Constants
// ============================================================================

// FrameworkTierRestriction documents which tier can access each framework
var FrameworkTierRestriction = map[Framework]tier.Tier{
	FrameworkATLAS:    tier.TierCommunity,    // Mandated for all
	FrameworkNIST1500: tier.TierCommunity,    // Mandated for all
	FrameworkOWASP:    tier.TierCommunity,    // Security baseline
	FrameworkHIPAA:    tier.TierDeveloper,    // Premium
	FrameworkPCIDSS:   tier.TierDeveloper,    // Premium
	FrameworkSOC2:     tier.TierProfessional, // Premium
	FrameworkGDPR:     tier.TierProfessional, // Premium
	FrameworkISO27001: tier.TierProfessional, // Premium
	FrameworkISO42001: tier.TierEnterprise,   // Premium
}

// IsEnterpriseOnly checks if a framework is Enterprise-only
func IsEnterpriseOnly(framework Framework) bool {
	minTier, ok := FrameworkTierRestriction[framework]
	if !ok {
		return false
	}
	return minTier == tier.TierEnterprise
}
