// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// =========================================================================
//
// =========================================================================

package pci

import (
	"context"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance/common"
)

const (
	FrameworkName    = "PCI DSS"
	FrameworkVersion = "4.0"
)

// PCIFramework implements PCI DSS
type PCIFramework struct {
	enabled      bool
	requirements []Requirement
}

type Requirement struct {
	Number      string
	Name        string
	Description string
	Severity    common.Severity
}

func NewPCIFramework() *PCIFramework {
	return &PCIFramework{
		enabled: true,
		requirements: []Requirement{
			{Number: "Req 1", Name: "Secure Network", Description: "Install and maintain a firewall configuration", Severity: common.SeverityCritical},
			{Number: "Req 2", Name: "Default Passwords", Description: "Do not use default passwords", Severity: common.SeverityCritical},
			{Number: "Req 3", Name: "Cardholder Data", Description: "Protect stored cardholder data", Severity: common.SeverityCritical},
			{Number: "Req 4", Name: "Encryption", Description: "Encrypt transmission of cardholder data", Severity: common.SeverityCritical},
			{Number: "Req 5", Name: "Malware Protection", Description: "Use and maintain anti-malware", Severity: common.SeverityHigh},
			{Number: "Req 6", Name: "Secure Development", Description: "Develop and maintain secure systems", Severity: common.SeverityCritical},
			{Number: "Req 7", Name: "Access Control", Description: "Restrict access to cardholder data", Severity: common.SeverityCritical},
			{Number: "Req 8", Name: "Authentication", Description: "Identify and authenticate access", Severity: common.SeverityCritical},
			{Number: "Req 9", Name: "Physical Security", Description: "Restrict physical access to cardholder data", Severity: common.SeverityHigh},
			{Number: "Req 10", Name: "Logging", Description: "Track and monitor all access", Severity: common.SeverityCritical},
			{Number: "Req 11", Name: "Security Testing", Description: "Test security systems regularly", Severity: common.SeverityHigh},
			{Number: "Req 12", Name: "Security Policy", Description: "Maintain information security policy", Severity: common.SeverityHigh},
		},
	}
}

func (pf *PCIFramework) Check(ctx context.Context, input common.CheckInput) (*common.CheckResult, error) {
	startTime := time.Now()
	findings := make([]common.Finding, 0)

	for _, r := range pf.requirements {
		finding := common.Finding{
			ID:          r.Number,
			Framework:   FrameworkName,
			Rule:        r.Name,
			Severity:    r.Severity,
			Description: r.Description,
			Timestamp:   time.Now(),
		}
		findings = append(findings, finding)
	}

	result := &common.CheckResult{
		Framework:       FrameworkName,
		Passed:          len(findings) == 0,
		Findings:        findings,
		CheckedAt:       startTime,
		Duration:        time.Since(startTime),
		TotalPatterns:   len(pf.requirements),
		MatchedPatterns: len(findings),
	}

	return result, nil
}

func (pf *PCIFramework) CheckRequest(ctx context.Context, req *common.HTTPRequest) ([]common.Finding, error) {
	return []common.Finding{}, nil
}

func (pf *PCIFramework) CheckResponse(ctx context.Context, resp *common.HTTPResponse) ([]common.Finding, error) {
	return []common.Finding{}, nil
}

func (pf *PCIFramework) GetName() string    { return FrameworkName }
func (pf *PCIFramework) GetVersion() string { return FrameworkVersion }
func (pf *PCIFramework) GetDescription() string {
	return "PCI DSS 4.0 compliance for payment processing"
}
func (pf *PCIFramework) GetFrameworkID() string { return "pci-dss-4.0" }
func (pf *PCIFramework) GetPatternCount() int   { return len(pf.requirements) }
func (pf *PCIFramework) IsEnabled() bool        { return pf.enabled }
func (pf *PCIFramework) Enable()                { pf.enabled = true }
func (pf *PCIFramework) Disable()               { pf.enabled = false }

func (pf *PCIFramework) Configure(config map[string]interface{}) error {
	return nil
}

func (pf *PCIFramework) GetSeverityLevels() []common.Severity {
	return []common.Severity{
		common.SeverityLow,
		common.SeverityMedium,
		common.SeverityHigh,
		common.SeverityCritical,
	}
}

var _ common.Framework = (*PCIFramework)(nil)
