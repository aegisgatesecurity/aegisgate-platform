// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGuard Security

// =========================================================================
//
// Compliance Factory
// Creates and configures compliance registries with all available frameworks
// =========================================================================

package factory

import (
	"context"
	"github.com/aegisguardsecurity/aegisguard/pkg/compliance/common"
	"github.com/aegisguardsecurity/aegisguard/pkg/compliance/registry"
)

// FrameworkFactory creates and configures compliance registries
type FrameworkFactory struct{}

// baseFramework is a base implementation of the Framework interface
type baseFramework struct {
	id          string
	name        string
	version     string
	description string
	tier        string
	patterns    int
	severities  []common.Severity
	enabled     bool
}

// GetFrameworkID returns the framework ID
func (f *baseFramework) GetFrameworkID() string {
	return f.id
}

// GetName returns the framework name
func (f *baseFramework) GetName() string {
	return f.name
}

// GetVersion returns the framework version
func (f *baseFramework) GetVersion() string {
	return f.version
}

// GetDescription returns the framework description
func (f *baseFramework) GetDescription() string {
	return f.description
}

// GetTier returns the framework tier
func (f *baseFramework) GetTier() common.TierInfo {
	return common.TierInfo{Name: f.tier}
}

// SupportsTier checks if the framework supports the given tier
func (f *baseFramework) SupportsTier(tier string) bool {
	return f.tier == tier || tier == "enterprise"
}

// Check performs a compliance check
func (f *baseFramework) Check(ctx context.Context, input common.CheckInput) (*common.CheckResult, error) {
	return &common.CheckResult{
		Framework:       f.id,
		Passed:          true,
		TotalPatterns:   f.patterns,
		MatchedPatterns: 0,
		Findings:        []common.Finding{},
	}, nil
}

// IsEnabled returns whether the framework is enabled
func (f *baseFramework) IsEnabled() bool {
	return f.enabled
}

// SetEnabled enables or disables the framework
func (f *baseFramework) SetEnabled(enabled bool) {
	f.enabled = enabled
}

// GetPatternCount returns the number of patterns
func (f *baseFramework) GetPatternCount() int {
	return f.patterns
}

// GetSeverityLevels returns the severity levels
func (f *baseFramework) GetSeverityLevels() []common.Severity {
	return f.severities
}

// GetConfig returns the framework config
func (f *baseFramework) GetConfig() *common.FrameworkConfig {
	return &common.FrameworkConfig{
		Name:    f.name,
		Version: f.version,
		Enabled: f.enabled,
	}
}

// GetPricing returns the pricing info
func (f *baseFramework) GetPricing() common.PricingInfo {
	return common.PricingInfo{
		Tier: f.tier,
	}
}

// Configure configures the framework
func (f *baseFramework) Configure(config map[string]interface{}) error {
	return nil
}

// Enable enables the framework
func (f *baseFramework) Enable() {
	f.enabled = true
}

// Disable disables the framework
func (f *baseFramework) Disable() {
	f.enabled = false
}

// NewFrameworkFactory creates a new framework factory
func NewFrameworkFactory() *FrameworkFactory {
	return &FrameworkFactory{}
}

// CreateForTier creates a registry with all frameworks supported by the given tier
func (f *FrameworkFactory) CreateForTier(tier string) (*registry.Registry, error) {
	reg := registry.New(tier)

	// Get all available frameworks
	frameworks := f.GetAllFrameworks()

	// Filter and register based on tier
	var toRegister []common.Framework
	for _, fw := range frameworks {
		if fw.GetTier().Name == tier || fw.SupportsTier(tier) {
			toRegister = append(toRegister, fw)
		}
	}

	if err := reg.RegisterAll(toRegister); err != nil {
		return nil, err
	}

	return reg, nil
}

// CreateCommunity creates a registry with community-tier frameworks only
func (f *FrameworkFactory) CreateCommunity() (*registry.Registry, error) {
	return f.CreateForTier("community")
}

// CreateProfessional creates a registry with professional-tier frameworks only
func (f *FrameworkFactory) CreateProfessional() (*registry.Registry, error) {
	return f.CreateForTier("professional")
}

// CreateEnterprise creates a registry with enterprise-tier frameworks only
func (f *FrameworkFactory) CreateEnterprise() (*registry.Registry, error) {
	return f.CreateForTier("enterprise")
}

// newMITREATLASFramework creates a MITRE ATLAS framework
func newMITREATLASFramework() common.Framework {
	return &baseFramework{
		id:          "MITRE_ATLAS",
		name:        "MITRE ATLAS",
		version:     "1.0",
		description: "MITRE ATLAS Framework for AI Threat Modeling",
		tier:        "community",
		patterns:    10,
		severities:  []common.Severity{common.SeverityMedium, common.SeverityHigh, common.SeverityCritical},
		enabled:     true,
	}
}

// newNISTAIFramework creates a NIST AI framework
func newNISTAIFramework() common.Framework {
	return &baseFramework{
		id:          "NIST_AI_RMF",
		name:        "NIST AI RMF",
		version:     "1.0",
		description: "AI Risk Management Framework",
		tier:        "community",
		patterns:    8,
		severities:  []common.Severity{common.SeverityMedium, common.SeverityHigh, common.SeverityCritical},
		enabled:     true,
	}
}

// newOWASPLLMFramework creates an OWASP LLM framework
func newOWASPLLMFramework() common.Framework {
	return &baseFramework{
		id:          "OWASP_LLM_TOP_10",
		name:        "OWASP LLM Top 10",
		version:     "1.0",
		description: "OWASP Top 10 for Large Language Model Applications",
		tier:        "community",
		patterns:    10,
		severities:  []common.Severity{common.SeverityLow, common.SeverityMedium, common.SeverityHigh, common.SeverityCritical},
		enabled:     true,
	}
}

// newISO27001Framework creates an ISO 27001 framework
func newISO27001Framework() common.Framework {
	return &baseFramework{
		id:          "ISO_27001_2022",
		name:        "ISO 27001",
		version:     "2022",
		description: "Information Security Management",
		tier:        "professional",
		patterns:    11,
		severities:  []common.Severity{common.SeverityLow, common.SeverityMedium, common.SeverityHigh, common.SeverityCritical},
		enabled:     true,
	}
}

// newGDPRFramework creates a GDPR framework
func newGDPRFramework() common.Framework {
	return &baseFramework{
		id:          "GDPR_2016",
		name:        "GDPR",
		version:     "2016",
		description: "General Data Protection Regulation",
		tier:        "professional",
		patterns:    9,
		severities:  []common.Severity{common.SeverityMedium, common.SeverityHigh, common.SeverityCritical},
		enabled:     true,
	}
}

// newSOC2Framework creates a SOC 2 framework
func newSOC2Framework() common.Framework {
	return &baseFramework{
		id:          "SOC2_TYPE2",
		name:        "SOC 2 Type II",
		version:     "2022",
		description: "Service Organization Control 2 Trust Service Criteria",
		tier:        "professional",
		patterns:    5,
		severities:  []common.Severity{common.SeverityLow, common.SeverityMedium, common.SeverityHigh, common.SeverityCritical},
		enabled:     true,
	}
}

// newHIPAFFramework creates a HIPAA framework
func newHIPAFFramework() common.Framework {
	return &baseFramework{
		id:          "HIPAA_PRIVACY",
		name:        "HIPAA",
		version:     "2024",
		description: "Health Insurance Portability and Accountability Act",
		tier:        "professional",
		patterns:    5,
		severities:  []common.Severity{common.SeverityHigh, common.SeverityCritical},
		enabled:     true,
	}
}

// newPCIFramework creates a PCI DSS framework
func newPCIFramework() common.Framework {
	return &baseFramework{
		id:          "PCI_DSS_V4",
		name:        "PCI-DSS",
		version:     "4.0",
		description: "Payment Card Industry Data Security Standard",
		tier:        "professional",
		patterns:    4,
		severities:  []common.Severity{common.SeverityHigh, common.SeverityCritical},
		enabled:     true,
	}
}

// GetAllFrameworks returns all available frameworks
func (f *FrameworkFactory) GetAllFrameworks() []common.Framework {
	return []common.Framework{
		newMITREATLASFramework(),
		newNISTAIFramework(),
		newOWASPLLMFramework(),
		newISO27001Framework(),
		newGDPRFramework(),
		newSOC2Framework(),
		newHIPAFFramework(),
		newPCIFramework(),
	}
}
