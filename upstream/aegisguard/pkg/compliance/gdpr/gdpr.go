// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGuard Security

// =========================================================================
//
// GDPR Compliance Module for AI Agent Security
// General Data Protection Regulation
// =========================================================================

package gdpr

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/aegisguardsecurity/aegisguard/pkg/compliance/common"
)

const (
	FrameworkName    = "GDPR"
	FrameworkVersion = "2016/679"
	FrameworkID      = "GDPR_2016"
)

// GDPRFramework implements GDPR compliance for agent operations
type GDPRFramework struct {
	name        string
	version     string
	description string
	config      map[string]interface{}
	enabled     bool

	// Personal data patterns
	personalDataPatterns []PersonalDataPattern

	// Rights
	dataSubjectRights []DataSubjectRight
}

// PersonalDataPattern represents personal data detection patterns
type PersonalDataPattern struct {
	ID          string
	Name        string
	Pattern     *regexp.Regexp
	Description string
	Severity    common.Severity
}

// DataSubjectRight represents a GDPR data subject right
type DataSubjectRight struct {
	ID          string
	Name        string
	Description string
	Article     string
}

// NewGDPRFramework creates a new GDPR compliance framework
func NewGDPRFramework() *GDPRFramework {
	return &GDPRFramework{
		name:                 FrameworkName,
		version:              FrameworkVersion,
		description:          "GDPR compliance for AI agent operations handling EU personal data",
		config:               make(map[string]interface{}),
		enabled:              true,
		personalDataPatterns: initPersonalDataPatterns(),
		dataSubjectRights:    initDataSubjectRights(),
	}
}

func initPersonalDataPatterns() []PersonalDataPattern {
	return []PersonalDataPattern{
		{
			ID:          "GDPR-001",
			Name:        "Email Address",
			Pattern:     regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`),
			Description: "Email address (Article 4)",
			Severity:    common.SeverityMedium,
		},
		{
			ID:          "GDPR-002",
			Name:        "Phone Number",
			Pattern:     regexp.MustCompile(`\b\+?[0-9]{1,4}?[-.\s]?\(?[0-9]{1,3}?\)?[-.\s]?[0-9]{1,4}[-.\s]?[0-9]{1,9}\b`),
			Description: "Phone number",
			Severity:    common.SeverityMedium,
		},
		{
			ID:          "GDPR-003",
			Name:        "IP Address",
			Pattern:     regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`),
			Description: "IP Address",
			Severity:    common.SeverityMedium,
		},
		{
			ID:          "GDPR-004",
			Name:        "National ID",
			Pattern:     regexp.MustCompile(`\b[A-Z]{2}[0-9]{6,10}\b`),
			Description: "National identification number",
			Severity:    common.SeverityHigh,
		},
	}
}

func initDataSubjectRights() []DataSubjectRight {
	return []DataSubjectRight{
		{
			ID:          "DSR-01",
			Name:        "Right to Access",
			Description: "Data subjects have the right to obtain confirmation of personal data processing",
			Article:     "Article 15",
		},
		{
			ID:          "DSR-02",
			Name:        "Right to Rectification",
			Description: "Data subjects have the right to have inaccurate personal data rectified",
			Article:     "Article 16",
		},
		{
			ID:          "DSR-03",
			Name:        "Right to Erasure",
			Description: "Data subjects have the right to have personal data erased",
			Article:     "Article 17",
		},
		{
			ID:          "DSR-04",
			Name:        "Right to Portability",
			Description: "Data subjects have the right to receive personal data in structured format",
			Article:     "Article 20",
		},
		{
			ID:          "DSR-05",
			Name:        "Right to Object",
			Description: "Data subjects have the right to object to processing",
			Article:     "Article 21",
		},
	}
}

// Framework Interface Implementation
func (g *GDPRFramework) GetName() string        { return g.name }
func (g *GDPRFramework) GetVersion() string     { return g.version }
func (g *GDPRFramework) GetDescription() string { return g.description }
func (g *GDPRFramework) IsEnabled() bool        { return g.enabled }
func (g *GDPRFramework) Enable()                { g.enabled = true }
func (g *GDPRFramework) Disable()               { g.enabled = false }
func (g *GDPRFramework) GetFrameworkID() string { return FrameworkID }
func (g *GDPRFramework) GetPatternCount() int   { return len(g.personalDataPatterns) }
func (g *GDPRFramework) GetSeverityLevels() []common.Severity {
	return []common.Severity{common.SeverityLow, common.SeverityMedium, common.SeverityHigh, common.SeverityCritical}
}

func (g *GDPRFramework) GetTier() common.TierInfo {
	return common.TierInfo{
		Name:        "Community",
		Description: "GDPR compliance for AI agents",
	}
}

func (g *GDPRFramework) GetConfig() *common.FrameworkConfig {
	return &common.FrameworkConfig{
		Name:    g.name,
		Version: g.version,
		Enabled: g.enabled,
	}
}

func (g *GDPRFramework) SupportsTier(tier string) bool {
	// GDPR applies to all tiers
	return true
}

func (g *GDPRFramework) Configure(config map[string]interface{}) error {
	g.config = config
	if enabled, ok := config["enabled"].(bool); ok {
		g.enabled = enabled
	}
	return nil
}

func (g *GDPRFramework) Check(ctx context.Context, input common.CheckInput) (*common.CheckResult, error) {
	start := time.Now()
	var findings []common.Finding

	for _, pattern := range g.personalDataPatterns {
		if pattern.Pattern.MatchString(input.Content) {
			findings = append(findings, common.Finding{
				Framework:   g.name,
				Severity:    pattern.Severity,
				Description: fmt.Sprintf("Personal data detected: %s", pattern.Name),
				Timestamp:   time.Now(),
			})
		}
	}

	return &common.CheckResult{
		Framework:       g.name,
		Passed:          len(findings) == 0,
		Findings:        findings,
		CheckedAt:       time.Now(),
		Duration:        time.Since(start),
		TotalPatterns:   len(g.personalDataPatterns),
		MatchedPatterns: len(findings),
	}, nil
}

func (g *GDPRFramework) CheckRequest(ctx context.Context, req *common.HTTPRequest) ([]common.Finding, error) {
	var findings []common.Finding
	return findings, nil
}

func (g *GDPRFramework) CheckResponse(ctx context.Context, resp *common.HTTPResponse) ([]common.Finding, error) {
	var findings []common.Finding
	return findings, nil
}

// GetDataSubjectRights returns all GDPR data subject rights
func (g *GDPRFramework) GetDataSubjectRights() []DataSubjectRight {
	return g.dataSubjectRights
}

var _ common.Framework = (*GDPRFramework)(nil)
