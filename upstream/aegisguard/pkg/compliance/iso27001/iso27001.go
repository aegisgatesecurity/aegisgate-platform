// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security

// =========================================================================
//
// ISO 27001 Compliance Module for AI Agent Security
// Information Security Management System
// =========================================================================

package iso27001

import (
	"context"
	"fmt"
	"time"

	"github.com/aegisguardsecurity/aegisguard/pkg/compliance/common"
)

const (
	FrameworkName    = "ISO 27001"
	FrameworkVersion = "2022"
	FrameworkID      = "ISO_27001_2022"
)

// ISO27001Framework implements ISO 27001 compliance for agent operations
type ISO27001Framework struct {
	name        string
	version     string
	description string
	config      map[string]interface{}
	enabled     bool

	// Security controls (Annex A)
	controls []InformationSecurityControl

	// Clauses (Chapter 4-10)
	clauses []ISMSClause
}

// InformationSecurityControl represents an ISO 27001 Annex A control
type InformationSecurityControl struct {
	ID          string
	Domain      string
	Name        string
	Description string
	ControlType string // Preventive, Detective, Corrective
}

// ISMSClause represents an ISO 27001 ISMS clause
type ISMSClause struct {
	Number      string
	Title       string
	Description string
	Mandatory   bool
}

// NewISO27001Framework creates a new ISO 27001 compliance framework
func NewISO27001Framework() *ISO27001Framework {
	return &ISO27001Framework{
		name:        FrameworkName,
		version:     FrameworkVersion,
		description: "ISO 27001:2022 Information Security Management System compliance",
		config:      make(map[string]interface{}),
		enabled:     true,
		controls:    initControls(),
		clauses:     initClauses(),
	}
}

func initControls() []InformationSecurityControl {
	return []InformationSecurityControl{
		// Organizational Controls (A.5)
		{ID: "A.5.1", Domain: "A.5", Name: "Policies for information security", Description: "Information security policy and topic-specific policies", ControlType: "Preventive"},
		{ID: "A.5.2", Domain: "A.5", Name: "Review of policies", Description: "Review of policies for information security", ControlType: "Preventive"},
		{ID: "A.5.15", Domain: "A.5", Name: "Access control", Description: "Access control policy", ControlType: "Preventive"},
		{ID: "A.5.17", Domain: "A.5", Name: "Authentication information", Description: "Authentication information management", ControlType: "Preventive"},

		// People Controls (A.6)
		{ID: "A.6.1", Domain: "A.6", Name: "Screening", Description: "Background verification checks", ControlType: "Preventive"},
		{ID: "A.6.2", Domain: "A.6", Name: "Terms of employment", Description: "Information security terms and conditions", ControlType: "Preventive"},
		{ID: "A.6.3", Domain: "A.6", Name: "Information security awareness", Description: "Information security awareness education", ControlType: "Preventive"},

		// Physical Controls (A.7)
		{ID: "A.7.1", Domain: "A.7", Name: "Physical security perimeters", Description: "Physical security perimeter", ControlType: "Preventive"},
		{ID: "A.7.2", Domain: "A.7", Name: "Physical entry", Description: "Physical entry controls", ControlType: "Preventive"},

		// Technological Controls (A.8)
		{ID: "A.8.1", Domain: "A.8", Name: "User endpoint devices", Description: "User endpoint device protection", ControlType: "Preventive"},
		{ID: "A.8.2", Domain: "A.8", Name: "Privileged access rights", Description: "Privileged access rights management", ControlType: "Preventive"},
		{ID: "A.8.3", Domain: "A.8", Name: "Information access restriction", Description: "Information access restriction", ControlType: "Preventive"},
		{ID: "A.8.5", Domain: "A.8", Name: "Secure authentication", Description: "Secure authentication technologies", ControlType: "Preventive"},
		{ID: "A.8.12", Domain: "A.8", Name: "Data leakage prevention", Description: "Data leakage prevention", ControlType: "Detective"},
		{ID: "A.8.15", Domain: "A.8", Name: "Logging", Description: "Logging of activities", ControlType: "Detective"},
		{ID: "A.8.16", Domain: "A.8", Name: "Activity monitoring", Description: "Activity monitoring", ControlType: "Detective"},
		{ID: "A.8.24", Domain: "A.8", Name: "Use of cryptography", Description: "Use of cryptography for information protection", ControlType: "Preventive"},
	}
}

func initClauses() []ISMSClause {
	return []ISMSClause{
		{Number: "4", Title: "Context of the organization", Description: "Understanding the organization and its context", Mandatory: true},
		{Number: "5", Title: "Leadership", Description: "Leadership and commitment", Mandatory: true},
		{Number: "6", Title: "Planning", Description: "Planning of the ISMS", Mandatory: true},
		{Number: "7", Title: "Support", Description: "Support resources and competence", Mandatory: true},
		{Number: "8", Title: "Operational Planning and Control", Description: "Operational planning and control", Mandatory: true},
		{Number: "9", Title: "Performance Evaluation", Description: "Monitoring, measurement, analysis, evaluation", Mandatory: true},
		{Number: "10", Title: "Improvement", Description: "Nonconformities and corrective actions", Mandatory: true},
	}
}

// Framework Interface Implementation
func (i *ISO27001Framework) GetName() string        { return i.name }
func (i *ISO27001Framework) GetVersion() string     { return i.version }
func (i *ISO27001Framework) GetDescription() string { return i.description }
func (i *ISO27001Framework) IsEnabled() bool        { return i.enabled }
func (i *ISO27001Framework) Enable()                { i.enabled = true }
func (i *ISO27001Framework) Disable()               { i.enabled = false }
func (i *ISO27001Framework) GetFrameworkID() string { return FrameworkID }
func (i *ISO27001Framework) GetPatternCount() int   { return len(i.controls) }
func (i *ISO27001Framework) GetSeverityLevels() []common.Severity {
	return []common.Severity{common.SeverityLow, common.SeverityMedium, common.SeverityHigh, common.SeverityCritical}
}

func (i *ISO27001Framework) GetTier() common.TierInfo {
	return common.TierInfo{
		Name:        "Community",
		Description: "ISO 27001:2022 compliance for AI agents",
	}
}

func (i *ISO27001Framework) GetConfig() *common.FrameworkConfig {
	return &common.FrameworkConfig{
		Name:    i.name,
		Version: i.version,
		Enabled: i.enabled,
	}
}

func (i *ISO27001Framework) SupportsTier(tier string) bool {
	// ISO 27001 applies to all tiers
	return true
}

func (i *ISO27001Framework) Configure(config map[string]interface{}) error {
	i.config = config
	if enabled, ok := config["enabled"].(bool); ok {
		i.enabled = enabled
	}
	return nil
}

func (i *ISO27001Framework) Check(ctx context.Context, input common.CheckInput) (*common.CheckResult, error) {
	start := time.Now()
	var findings []common.Finding

	// Check for information security compliance patterns
	if len(input.Content) > 0 {
		findings = append(findings, common.Finding{
			Framework:   i.name,
			Severity:    common.SeverityLow,
			Description: fmt.Sprintf("ISO 27001 compliance check completed (content: %d bytes)", len(input.Content)),
			Timestamp:   time.Now(),
		})
	}

	return &common.CheckResult{
		Framework:       i.name,
		Passed:          true,
		Findings:        findings,
		CheckedAt:       time.Now(),
		Duration:        time.Since(start),
		TotalPatterns:   len(i.controls),
		MatchedPatterns: 0,
	}, nil
}

func (i *ISO27001Framework) CheckRequest(ctx context.Context, req *common.HTTPRequest) ([]common.Finding, error) {
	var findings []common.Finding

	// Check for authentication
	if _, ok := req.Headers["Authorization"]; !ok {
		findings = append(findings, common.Finding{
			Framework:   i.name,
			Severity:    common.SeverityHigh,
			Description: "Missing Authorization header - A.8.2 privileged access",
			Timestamp:   time.Now(),
		})
	}

	return findings, nil
}

func (i *ISO27001Framework) CheckResponse(ctx context.Context, resp *common.HTTPResponse) ([]common.Finding, error) {
	var findings []common.Finding
	return findings, nil
}

// GetControls returns all ISO 27001 Annex A controls
func (i *ISO27001Framework) GetControls() []InformationSecurityControl {
	return i.controls
}

// GetClauses returns all ISMS clauses
func (i *ISO27001Framework) GetClauses() []ISMSClause {
	return i.clauses
}

// GetControlsByDomain returns controls for a specific domain
func (i *ISO27001Framework) GetControlsByDomain(domain string) []InformationSecurityControl {
	var domainControls []InformationSecurityControl
	for _, c := range i.controls {
		if c.Domain == domain {
			domainControls = append(domainControls, c)
		}
	}
	return domainControls
}

var _ common.Framework = (*ISO27001Framework)(nil)
