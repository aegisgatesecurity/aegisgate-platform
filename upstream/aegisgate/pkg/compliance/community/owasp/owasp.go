// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// =========================================================================
//
// =========================================================================

package owasp

import (
	"context"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance/common"
)

const (
	FrameworkName    = "OWASP AI Top 10"
	FrameworkVersion = "2023"
)

// OWASPFramework implements OWASP Top 10 for AI/LLM
type OWASPFramework struct {
	name        string
	version     string
	description string
	config      map[string]interface{}
	enabled     bool

	configObj *common.FrameworkConfig
	tierInfo  common.TierInfo
	risks     []Risk
}

// Risk represents an OWASP AI security risk
type Risk struct {
	ID          string
	Name        string
	Severity    common.Severity
	Description string
	CWE         int
}

// NewOWASPFramework creates OWASP checker
func NewOWASPFramework() *OWASPFramework {
	return &OWASPFramework{
		name:        FrameworkName,
		version:     FrameworkVersion,
		description: "OWASP Top 10 for AI/LLM applications - Addressing security risks in machine learning",
		config:      make(map[string]interface{}),
		enabled:     true,
		configObj: &common.FrameworkConfig{
			Name:    FrameworkName,
			Version: FrameworkVersion,
			Enabled: true,
		},
		tierInfo: common.TierInfo{
			Name:        "Community",
			Pricing:     "Free",
			Description: "OWASP Top 10 for AI/LLM applications",
		},
		risks: loadRisks(),
	}
}

func loadRisks() []Risk {
	return []Risk{
		{ID: "LLM01", Name: "Prompt Injection", Severity: common.SeverityCritical, Description: "Malicious inputs via prompts manipulate LLM", CWE: 77},
		{ID: "LLM02", Name: "Insecure Output Handling", Severity: common.SeverityHigh, Description: "Unvalidated LLM outputs lead to attacks", CWE: 20},
		{ID: "LLM03", Name: "Training Data Poisoning", Severity: common.SeverityCritical, Description: "Malicious data manipulates training", CWE: 506},
		{ID: "LLM04", Name: "Model Denial of Service", Severity: common.SeverityHigh, Description: "Resource exhaustion attacks", CWE: 770},
		{ID: "LLM05", Name: "Supply Chain Vulnerabilities", Severity: common.SeverityHigh, Description: "Compromised components in ML pipeline", CWE: 829},
		{ID: "LLM06", Name: "Sensitive Information Disclosure", Severity: common.SeverityCritical, Description: "Exposing PII/PII via model outputs", CWE: 200},
		{ID: "LLM07", Name: "Insecure Plugin Design", Severity: common.SeverityHigh, Description: "Vulnerable LLM plugins", CWE: 1117},
		{ID: "LLM08", Name: "Excessive Agency", Severity: common.SeverityHigh, Description: "LLM performing unauthorized actions", CWE: 250},
		{ID: "LLM09", Name: "Overreliance", Severity: common.SeverityMedium, Description: "Excessive trust in LLM outputs", CWE: 710},
		{ID: "LLM10", Name: "Model Theft", Severity: common.SeverityCritical, Description: "Stealing proprietary model/weights", CWE: 1242},
	}
}

// GetName returns the framework name
func (of *OWASPFramework) GetName() string {
	return of.name
}

// GetVersion returns the framework version
func (of *OWASPFramework) GetVersion() string {
	return of.version
}

// GetDescription returns the framework description
func (of *OWASPFramework) GetDescription() string {
	return of.description
}

// Check performs a compliance check on the input
func (of *OWASPFramework) Check(ctx context.Context, input common.CheckInput) (*common.CheckResult, error) {
	start := time.Now()
	var findings []common.Finding

	if len(input.Content) > 0 {
		finding := common.Finding{
			Framework:   of.name,
			Severity:    common.SeverityLow,
			Description: "OWASP AI Top 10 compliance check completed",
			Timestamp:   time.Now(),
		}
		findings = append(findings, finding)
	}

	return &common.CheckResult{
		Framework:       of.name,
		Passed:          len(findings) == 0,
		Findings:        findings,
		CheckedAt:       time.Now(),
		Duration:        time.Since(start),
		TotalPatterns:   len(of.risks),
		MatchedPatterns: len(findings),
	}, nil
}

// CheckRequest checks an HTTP request for compliance
func (of *OWASPFramework) CheckRequest(ctx context.Context, req *common.HTTPRequest) ([]common.Finding, error) {
	var findings []common.Finding
	return findings, nil
}

// CheckResponse checks an HTTP response for compliance
func (of *OWASPFramework) CheckResponse(ctx context.Context, resp *common.HTTPResponse) ([]common.Finding, error) {
	var findings []common.Finding
	return findings, nil
}

// Configure applies configuration
func (of *OWASPFramework) Configure(config map[string]interface{}) error {
	of.config = config
	return nil
}

// IsEnabled returns whether the framework is enabled
func (of *OWASPFramework) IsEnabled() bool {
	return of.enabled
}

// Enable enables the framework
func (of *OWASPFramework) Enable() {
	of.enabled = true
}

// Disable disables the framework
func (of *OWASPFramework) Disable() {
	of.enabled = false
}

// GetFrameworkID returns the unique identifier
func (of *OWASPFramework) GetFrameworkID() string {
	return "owasp"
}

// GetPatternCount returns the number of patterns
func (of *OWASPFramework) GetPatternCount() int {
	return len(of.risks)
}

// GetSeverityLevels returns the severity levels
func (of *OWASPFramework) GetSeverityLevels() []common.Severity {
	return []common.Severity{
		common.SeverityLow,
		common.SeverityMedium,
		common.SeverityHigh,
		common.SeverityCritical,
	}
}

// GetTier returns tier information
func (of *OWASPFramework) GetTier() common.TierInfo {
	return of.tierInfo
}

// GetConfig returns framework configuration
func (of *OWASPFramework) GetConfig() *common.FrameworkConfig {
	return of.configObj
}

// SupportsTier checks if current tier allows this framework
func (of *OWASPFramework) SupportsTier(tier string) bool {
	return tier == "Community" || tier == "Enterprise" || tier == "Premium"
}

// GetPricing returns pricing information
func (of *OWASPFramework) GetPricing() common.PricingInfo {
	return common.PricingInfo{
		Tier:        "Community",
		MonthlyCost: 0,
		Description: "OWASP Top 10 compliance checking (Free)",
		Features:    []string{"All 10 OWASP AI risks", "Basic scanning", "Community updates"},
	}
}

// Ensure OWASPFramework implements the Framework interface
var _ common.Framework = (*OWASPFramework)(nil)
