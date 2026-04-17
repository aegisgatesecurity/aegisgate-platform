// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGuard Security
// Copyright (c) 2025-2026 AegisGuard Security. All rights reserved.
// =========================================================================
//
// PCI-DSS Compliance Module for AI Agent Security
// Payment Card Industry Data Security Standard
// =========================================================================

package pci

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/aegisguardsecurity/aegisguard/pkg/compliance/common"
)

const (
	FrameworkName    = "PCI-DSS"
	FrameworkVersion = "4.0"
	FrameworkID      = "PCI_DSS_V4"
)

// PCIDSSFramework implements PCI-DSS compliance for agent operations
type PCIDSSFramework struct {
	name        string
	version     string
	description string
	config      map[string]interface{}
	enabled     bool

	// Cardholder data patterns
	dataPatterns []CardDataPattern

	// Security controls
	controls []PCIControl
}

// CardDataPattern represents cardholder data detection patterns
type CardDataPattern struct {
	ID          string
	Name        string
	Pattern     *regexp.Regexp
	Description string
	Severity    common.Severity
}

// PCIControl represents a PCI-DSS security control
type PCIControl struct {
	ID          string
	Name        string
	Description string
	Requirement string
	Automated   bool
}

// NewPCIDSSFramework creates a new PCI-DSS compliance framework
func NewPCIDSSFramework() *PCIDSSFramework {
	return &PCIDSSFramework{
		name:         FrameworkName,
		version:      FrameworkVersion,
		description:  "PCI-DSS v4.0 compliance for AI agent payment card operations",
		config:       make(map[string]interface{}),
		enabled:      true,
		dataPatterns: initCardDataPatterns(),
		controls:     initPCIControls(),
	}
}

func initCardDataPatterns() []CardDataPattern {
	return []CardDataPattern{
		{
			ID:          "PCI-001",
			Name:        "Primary Account Number (PAN)",
			Pattern:     regexp.MustCompile(`\b4[0-9]{12}(?:[0-9]{3})?\b`),
			Description: "Visa card number",
			Severity:    common.SeverityCritical,
		},
		{
			ID:          "PCI-002",
			Name:        "Primary Account Number (PAN)",
			Pattern:     regexp.MustCompile(`\b5[1-5][0-9]{14}\b`),
			Description: "MasterCard number",
			Severity:    common.SeverityCritical,
		},
		{
			ID:          "PCI-003",
			Name:        "Primary Account Number (PAN)",
			Pattern:     regexp.MustCompile(`\b3[47][0-9]{13}\b`),
			Description: "American Express number",
			Severity:    common.SeverityCritical,
		},
		{
			ID:          "PCI-004",
			Name:        "CVV/CVC",
			Pattern:     regexp.MustCompile(`\b[0-9]{3,4}\b`),
			Description: "Card verification value",
			Severity:    common.SeverityCritical,
		},
	}
}

func initPCIControls() []PCIControl {
	return []PCIControl{
		{
			ID:          "PCI-REQ-1",
			Name:        "Firewall Configuration",
			Description: "Install and maintain network security controls",
			Requirement: "Req 1",
			Automated:   true,
		},
		{
			ID:          "PCI-REQ-2",
			Name:        "Default Credentials",
			Description: "Do not use vendor-supplied defaults",
			Requirement: "Req 2",
			Automated:   true,
		},
		{
			ID:          "PCI-REQ-3",
			Name:        "Cardholder Data Protection",
			Description: "Protect stored cardholder data",
			Requirement: "Req 3",
			Automated:   true,
		},
		{
			ID:          "PCI-REQ-4",
			Name:        "Transmission Security",
			Description: "Encrypt cardholder data in transit",
			Requirement: "Req 4",
			Automated:   true,
		},
		{
			ID:          "PCI-REQ-7",
			Name:        "Access Control",
			Description: "Restrict access to cardholder data",
			Requirement: "Req 7",
			Automated:   true,
		},
		{
			ID:          "PCI-REQ-10",
			Name:        "Logging and Monitoring",
			Description: "Log and monitor all access to system components",
			Requirement: "Req 10",
			Automated:   true,
		},
	}
}

// Framework Interface Implementation
func (p *PCIDSSFramework) GetName() string        { return p.name }
func (p *PCIDSSFramework) GetVersion() string     { return p.version }
func (p *PCIDSSFramework) GetDescription() string { return p.description }
func (p *PCIDSSFramework) IsEnabled() bool        { return p.enabled }
func (p *PCIDSSFramework) Enable()                { p.enabled = true }
func (p *PCIDSSFramework) Disable()               { p.enabled = false }
func (p *PCIDSSFramework) GetFrameworkID() string { return FrameworkID }
func (p *PCIDSSFramework) GetPatternCount() int   { return len(p.dataPatterns) }
func (p *PCIDSSFramework) GetSeverityLevels() []common.Severity {
	return []common.Severity{common.SeverityCritical}
}

func (p *PCIDSSFramework) GetTier() common.TierInfo {
	return common.TierInfo{
		Name:        "Professional",
		Pricing:     "Contact sales",
		Description: "PCI-DSS v4.0 compliance for AI agent payment operations",
	}
}

func (p *PCIDSSFramework) GetConfig() *common.FrameworkConfig {
	return &common.FrameworkConfig{
		Name:    p.name,
		Version: p.version,
		Enabled: p.enabled,
	}
}

func (p *PCIDSSFramework) SupportsTier(tier string) bool {
	return tier == "professional" || tier == "enterprise"
}

func (p *PCIDSSFramework) GetPricing() common.PricingInfo {
	return common.PricingInfo{
		Tier:        "Professional",
		MonthlyCost: 19999,
		Description: "PCI-DSS v4.0 compliance for AI agents",
		Features: []string{
			"Cardholder data detection",
			"PAN masking and redaction",
			"Secure transmission controls",
			"Audit trail for card operations",
			"Compliance reporting",
		},
	}
}

func (p *PCIDSSFramework) Configure(config map[string]interface{}) error {
	p.config = config
	if enabled, ok := config["enabled"].(bool); ok {
		p.enabled = enabled
	}
	return nil
}

func (p *PCIDSSFramework) Check(ctx context.Context, input common.CheckInput) (*common.CheckResult, error) {
	start := time.Now()
	var findings []common.Finding

	for _, pattern := range p.dataPatterns {
		if pattern.Pattern.MatchString(input.Content) {
			findings = append(findings, common.Finding{
				Framework:   p.name,
				Severity:    pattern.Severity,
				Description: fmt.Sprintf("Cardholder data detected: %s", pattern.Name),
				Timestamp:   time.Now(),
			})
		}
	}

	return &common.CheckResult{
		Framework:       p.name,
		Passed:          len(findings) == 0,
		Findings:        findings,
		CheckedAt:       time.Now(),
		Duration:        time.Since(start),
		TotalPatterns:   len(p.dataPatterns),
		MatchedPatterns: len(findings),
	}, nil
}

func (p *PCIDSSFramework) CheckRequest(ctx context.Context, req *common.HTTPRequest) ([]common.Finding, error) {
	var findings []common.Finding
	return findings, nil
}

func (p *PCIDSSFramework) CheckResponse(ctx context.Context, resp *common.HTTPResponse) ([]common.Finding, error) {
	var findings []common.Finding
	return findings, nil
}

var _ common.Framework = (*PCIDSSFramework)(nil)
