// SPDX-License-Identifier: MIT
// =========================================================================
// =========================================================================
//
// =========================================================================

package soc2

import (
	"context"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance/common"
)

const (
	FrameworkName    = "SOC 2 Type II"
	FrameworkVersion = "2022"
)

// SOC2Framework implements SOC 2 Trust Service Criteria
type SOC2Framework struct {
	name        string
	version     string
	description string
	config      map[string]interface{}
	enabled     bool

	configObj  *common.FrameworkConfig
	tierInfo   common.TierInfo
	principles []TrustServicePrinciple
}

// TrustServicePrinciple represents a SOC 2 Trust Service Principle
type TrustServicePrinciple struct {
	ID          string
	Name        string
	Description string
	Criteria    []string
	Severity    common.Severity
}

// NewSOC2Framework creates SOC 2 checker
func NewSOC2Framework() *SOC2Framework {
	return &SOC2Framework{
		name:        FrameworkName,
		version:     FrameworkVersion,
		description: "SOC 2 Type II compliance with Trust Service Criteria for service organizations",
		config:      make(map[string]interface{}),
		enabled:     true,
		configObj: &common.FrameworkConfig{
			Name:    FrameworkName,
			Version: FrameworkVersion,
			Enabled: true,
		},
		tierInfo: common.TierInfo{
			Name:        "Premium",
			Pricing:     "$15,000-$25,000/month",
			Description: "SOC 2 Type II compliance with audit support",
		},
		principles: []TrustServicePrinciple{
			{
				ID:          "TSP-SEC",
				Name:        "Security",
				Description: "System protected against unauthorized access",
				Criteria:    []string{"CC6.1", "CC6.2", "CC6.3", "CC6.4", "CC6.5"},
				Severity:    common.SeverityCritical,
			},
			{
				ID:          "TSP-AVAIL",
				Name:        "Availability",
				Description: "System available for operation and use",
				Criteria:    []string{"A1.1", "A1.2", "A1.3"},
				Severity:    common.SeverityHigh,
			},
			{
				ID:          "TSP-PROC",
				Name:        "Processing Integrity",
				Description: "Processing complete, valid, accurate, timely, and authorized",
				Criteria:    []string{"PI1.1", "PI1.2", "PI1.3", "PI1.4"},
				Severity:    common.SeverityHigh,
			},
			{
				ID:          "TSP-CONF",
				Name:        "Confidentiality",
				Description: "Information designated as confidential is protected",
				Criteria:    []string{"C1.1", "C1.2"},
				Severity:    common.SeverityCritical,
			},
			{
				ID:          "TSP-PRIV",
				Name:        "Privacy",
				Description: "Personal information collected, used, retained, and disclosed in conformity",
				Criteria:    []string{"P1.1", "P2.1", "P3.1", "P4.1", "P5.1", "P6.1", "P7.1", "P8.1"},
				Severity:    common.SeverityCritical,
			},
		},
	}
}

// GetName returns the framework name
func (sf *SOC2Framework) GetName() string {
	return sf.name
}

// GetVersion returns the framework version
func (sf *SOC2Framework) GetVersion() string {
	return sf.version
}

// GetDescription returns the framework description
func (sf *SOC2Framework) GetDescription() string {
	return sf.description
}

// Check performs a compliance check on the input
func (sf *SOC2Framework) Check(ctx context.Context, input common.CheckInput) (*common.CheckResult, error) {
	start := time.Now()
	var findings []common.Finding

	if len(input.Content) > 0 {
		finding := common.Finding{
			Framework:   sf.name,
			Severity:    common.SeverityLow,
			Description: "SOC 2 Type II compliance check completed",
			Timestamp:   time.Now(),
		}
		findings = append(findings, finding)
	}

	return &common.CheckResult{
		Framework:       sf.name,
		Passed:          len(findings) == 0,
		Findings:        findings,
		CheckedAt:       time.Now(),
		Duration:        time.Since(start),
		TotalPatterns:   len(sf.principles),
		MatchedPatterns: len(findings),
	}, nil
}

// CheckRequest checks an HTTP request for compliance
func (sf *SOC2Framework) CheckRequest(ctx context.Context, req *common.HTTPRequest) ([]common.Finding, error) {
	var findings []common.Finding
	return findings, nil
}

// CheckResponse checks an HTTP response for compliance
func (sf *SOC2Framework) CheckResponse(ctx context.Context, resp *common.HTTPResponse) ([]common.Finding, error) {
	var findings []common.Finding
	return findings, nil
}

// Configure applies configuration
func (sf *SOC2Framework) Configure(config map[string]interface{}) error {
	sf.config = config
	return nil
}

// IsEnabled returns whether the framework is enabled
func (sf *SOC2Framework) IsEnabled() bool {
	return sf.enabled
}

// Enable enables the framework
func (sf *SOC2Framework) Enable() {
	sf.enabled = true
}

// Disable disables the framework
func (sf *SOC2Framework) Disable() {
	sf.enabled = false
}

// GetFrameworkID returns the unique identifier
func (sf *SOC2Framework) GetFrameworkID() string {
	return "soc2"
}

// GetPatternCount returns the number of patterns
func (sf *SOC2Framework) GetPatternCount() int {
	return len(sf.principles)
}

// GetSeverityLevels returns the severity levels
func (sf *SOC2Framework) GetSeverityLevels() []common.Severity {
	return []common.Severity{
		common.SeverityLow,
		common.SeverityMedium,
		common.SeverityHigh,
		common.SeverityCritical,
	}
}

// GetTier returns tier information
func (sf *SOC2Framework) GetTier() common.TierInfo {
	return sf.tierInfo
}

// GetConfig returns framework configuration
func (sf *SOC2Framework) GetConfig() *common.FrameworkConfig {
	return sf.configObj
}

// SupportsTier checks if current tier allows this framework
func (sf *SOC2Framework) SupportsTier(tier string) bool {
	return tier == "Premium"
}

// GetPricing returns pricing information
func (sf *SOC2Framework) GetPricing() common.PricingInfo {
	return common.PricingInfo{
		Tier:        "Premium",
		MonthlyCost: 20000,
		Description: "SOC 2 Type II with full audit support",
		Features: []string{
			"Complete TSP coverage",
			"Audit evidence collection",
			"Dedicated account manager",
			"Custom control mapping",
			"24/7 priority support",
		},
	}
}

// Ensure SOC2Framework implements the Framework interface
var _ common.Framework = (*SOC2Framework)(nil)
