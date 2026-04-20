// SPDX-License-Identifier: MIT
// =========================================================================
// =========================================================================
//
// =========================================================================

package hipaa

import (
	"context"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance/common"
)

const (
	FrameworkName    = "HIPAA"
	FrameworkVersion = "2023"
)

// HIPAAFramework implements HIPAA compliance
type HIPAAFramework struct {
	enabled    bool
	safeguards []Safeguard
}

type Safeguard struct {
	Section      string
	Name         string
	Category     string
	Requirements []string
	Severity     common.Severity
}

func NewHIPAAFramework() *HIPAAFramework {
	return &HIPAAFramework{
		enabled: true,
		safeguards: []Safeguard{
			{
				Section:  "164.308",
				Name:     "Administrative Safeguards",
				Category: "Security Management",
				Requirements: []string{
					"Security Management Process",
					"Assigned Security Responsibility",
					"Workforce Security",
					"Information Access Management",
				},
				Severity: common.SeverityCritical,
			},
			{
				Section:  "164.310",
				Name:     "Physical Safeguards",
				Category: "Facility Access",
				Requirements: []string{
					"Facility Access Controls",
					"Workstation Use",
					"Workstation Security",
				},
				Severity: common.SeverityCritical,
			},
			{
				Section:  "164.312",
				Name:     "Technical Safeguards",
				Category: "Access Control",
				Requirements: []string{
					"Access Control",
					"Audit Controls",
					"Integrity",
					"Person or Entity Authentication",
					"Transmission Security",
				},
				Severity: common.SeverityCritical,
			},
		},
	}
}

func (hf *HIPAAFramework) Check(ctx context.Context, input common.CheckInput) (*common.CheckResult, error) {
	startTime := time.Now()
	findings := make([]common.Finding, 0)

	for _, s := range hf.safeguards {
		finding := common.Finding{
			ID:          s.Section,
			Framework:   FrameworkName,
			Rule:        s.Name,
			Severity:    s.Severity,
			Description: s.Category + ": " + joinStrings(s.Requirements, ", "),
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
		TotalPatterns:   len(hf.safeguards),
		MatchedPatterns: len(findings),
	}

	return result, nil
}

func joinStrings(strs []string, sep string) string {
	result := ""
	for i, s := range strs {
		if i > 0 {
			result += sep
		}
		result += s
	}
	return result
}

func (hf *HIPAAFramework) CheckRequest(ctx context.Context, req *common.HTTPRequest) ([]common.Finding, error) {
	return []common.Finding{}, nil
}

func (hf *HIPAAFramework) CheckResponse(ctx context.Context, resp *common.HTTPResponse) ([]common.Finding, error) {
	return []common.Finding{}, nil
}

func (hf *HIPAAFramework) GetName() string    { return FrameworkName }
func (hf *HIPAAFramework) GetVersion() string { return FrameworkVersion }
func (hf *HIPAAFramework) GetDescription() string {
	return "HIPAA compliance for healthcare AI systems"
}
func (hf *HIPAAFramework) GetFrameworkID() string { return "hipaa-2023" }
func (hf *HIPAAFramework) GetPatternCount() int   { return len(hf.safeguards) }
func (hf *HIPAAFramework) IsEnabled() bool        { return hf.enabled }
func (hf *HIPAAFramework) Enable()                { hf.enabled = true }
func (hf *HIPAAFramework) Disable()               { hf.enabled = false }

func (hf *HIPAAFramework) Configure(config map[string]interface{}) error {
	return nil
}

func (hf *HIPAAFramework) GetSeverityLevels() []common.Severity {
	return []common.Severity{
		common.SeverityLow,
		common.SeverityMedium,
		common.SeverityHigh,
		common.SeverityCritical,
	}
}

var _ common.Framework = (*HIPAAFramework)(nil)
