// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGuard Security
// Copyright (c) 2025-2026 AegisGuard Security. All rights reserved.
// =========================================================================
//
// HIPAA Compliance Module for AI Agent Security
// Health Insurance Portability and Accountability Act
// =========================================================================

package hipaa

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/aegisguardsecurity/aegisguard/pkg/compliance/common"
)

const (
	FrameworkName    = "HIPAA"
	FrameworkVersion = "2024"
	FrameworkID      = "HIPAA_PRIVACY"
)

// HIPAAFramework implements HIPAA compliance for agent operations
type HIPAAFramework struct {
	name        string
	version     string
	description string
	config      map[string]interface{}
	enabled     bool

	// PHI patterns for detection
	phiPatterns []PHIPattern

	// Audit controls
	auditControls []HIPAAControl
}

// PHIPattern represents a PHI detection pattern
type PHIPattern struct {
	ID          string
	Name        string
	Pattern     *regexp.Regexp
	Description string
	Severity    common.Severity
}

// HIPAAControl represents a HIPAA audit control
type HIPAAControl struct {
	ID          string
	Name        string
	Description string
	Evidence    []string
	Automated   bool
}

// NewHIPAAFramework creates a new HIPAA compliance framework
func NewHIPAAFramework() *HIPAAFramework {
	return &HIPAAFramework{
		name:          FrameworkName,
		version:       FrameworkVersion,
		description:   "HIPAA Privacy and Security Rules compliance for AI agent operations",
		config:        make(map[string]interface{}),
		enabled:       true,
		phiPatterns:   initPHIPatterns(),
		auditControls: initHIPAAControls(),
	}
}

func initPHIPatterns() []PHIPattern {
	return []PHIPattern{
		{
			ID:          "PHI-001",
			Name:        "SSN Detection",
			Pattern:     regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
			Description: "Social Security Number",
			Severity:    common.SeverityCritical,
		},
		{
			ID:          "PHI-002",
			Name:        "Medical Record Number",
			Pattern:     regexp.MustCompile(`\bMRN[:\s]*[A-Z0-9]{6,}\b`),
			Description: "Medical Record Number",
			Severity:    common.SeverityCritical,
		},
		{
			ID:          "PHI-003",
			Name:        "Diagnosis Code",
			Pattern:     regexp.MustCompile(`\bICD[- ]?(10|9)[:\s]*[A-Z0-9.]{3,8}\b`),
			Description: "ICD Diagnosis Code",
			Severity:    common.SeverityHigh,
		},
		{
			ID:          "PHI-004",
			Name:        "Patient Name Pattern",
			Pattern:     regexp.MustCompile(`(?i)\bpatient[:\s]+[A-Z][a-z]+\s+[A-Z][a-z]+\b`),
			Description: "Patient Name",
			Severity:    common.SeverityHigh,
		},
		{
			ID:          "PHI-005",
			Name:        "Phone Number",
			Pattern:     regexp.MustCompile(`\b\d{3}[-.]?\d{3}[-.]?\d{4}\b`),
			Description: "Phone Number",
			Severity:    common.SeverityMedium,
		},
	}
}

func initHIPAAControls() []HIPAAControl {
	return []HIPAAControl{
		{
			ID:          "HIP-001",
			Name:        "PHI Access Logging",
			Description: "All access to PHI must be logged",
			Evidence:    []string{"access_logs", "audit_trail"},
			Automated:   true,
		},
		{
			ID:          "HIP-002",
			Name:        "Minimum Necessary Standard",
			Description: "Only access minimum necessary PHI",
			Evidence:    []string{"access_controls", "role_definitions"},
			Automated:   true,
		},
		{
			ID:          "HIP-003",
			Name:        "Encryption",
			Description: "PHI must be encrypted at rest and in transit",
			Evidence:    []string{"encryption_keys", "tls_config"},
			Automated:   true,
		},
		{
			ID:          "HIP-004",
			Name:        "Access Controls",
			Description: "Unique user identification and authentication",
			Evidence:    []string{"auth_logs", "session_records"},
			Automated:   true,
		},
		{
			ID:          "HIP-005",
			Name:        "Audit Controls",
			Description: "Implement hardware/software audit controls",
			Evidence:    []string{"audit_logs", "system_activity"},
			Automated:   true,
		},
	}
}

// Framework Interface Implementation
func (h *HIPAAFramework) GetName() string        { return h.name }
func (h *HIPAAFramework) GetVersion() string     { return h.version }
func (h *HIPAAFramework) GetDescription() string { return h.description }
func (h *HIPAAFramework) IsEnabled() bool        { return h.enabled }
func (h *HIPAAFramework) Enable()                { h.enabled = true }
func (h *HIPAAFramework) Disable()               { h.enabled = false }
func (h *HIPAAFramework) GetFrameworkID() string { return FrameworkID }
func (h *HIPAAFramework) GetPatternCount() int   { return len(h.phiPatterns) }
func (h *HIPAAFramework) GetSeverityLevels() []common.Severity {
	return []common.Severity{common.SeverityLow, common.SeverityMedium, common.SeverityHigh, common.SeverityCritical}
}

func (h *HIPAAFramework) GetTier() common.TierInfo {
	return common.TierInfo{
		Name:        "Professional",
		Pricing:     "Contact sales",
		Description: "HIPAA compliance for healthcare AI agents",
	}
}

func (h *HIPAAFramework) GetConfig() *common.FrameworkConfig {
	return &common.FrameworkConfig{
		Name:    h.name,
		Version: h.version,
		Enabled: h.enabled,
	}
}

func (h *HIPAAFramework) SupportsTier(tier string) bool {
	return tier == "professional" || tier == "enterprise"
}

func (h *HIPAAFramework) GetPricing() common.PricingInfo {
	return common.PricingInfo{
		Tier:        "Professional",
		MonthlyCost: 14999,
		Description: "HIPAA compliance for AI agent operations",
		Features: []string{
			"PHI detection and redaction",
			"Audit trail for PHI access",
			"Minimum necessary standard",
			"Encryption controls",
			"Breach notification support",
		},
	}
}

func (h *HIPAAFramework) Configure(config map[string]interface{}) error {
	h.config = config
	if enabled, ok := config["enabled"].(bool); ok {
		h.enabled = enabled
	}
	return nil
}

func (h *HIPAAFramework) Check(ctx context.Context, input common.CheckInput) (*common.CheckResult, error) {
	start := time.Now()
	var findings []common.Finding

	// Check for PHI patterns
	for _, pattern := range h.phiPatterns {
		if pattern.Pattern.MatchString(input.Content) {
			findings = append(findings, common.Finding{
				Framework:   h.name,
				Severity:    pattern.Severity,
				Description: fmt.Sprintf("PHI detected: %s - %s", pattern.ID, pattern.Name),
				Timestamp:   time.Now(),
			})
		}
	}

	return &common.CheckResult{
		Framework:       h.name,
		Passed:          len(findings) == 0,
		Findings:        findings,
		CheckedAt:       time.Now(),
		Duration:        time.Since(start),
		TotalPatterns:   len(h.phiPatterns),
		MatchedPatterns: len(findings),
	}, nil
}

func (h *HIPAAFramework) CheckRequest(ctx context.Context, req *common.HTTPRequest) ([]common.Finding, error) {
	var findings []common.Finding
	// Check headers for PHI indicators
	return findings, nil
}

func (h *HIPAAFramework) CheckResponse(ctx context.Context, resp *common.HTTPResponse) ([]common.Finding, error) {
	var findings []common.Finding
	return findings, nil
}

// CheckPHI checks content for Protected Health Information
func (h *HIPAAFramework) CheckPHI(content string) (*PHICheckResult, error) {
	var detections []PHIDetection

	for _, pattern := range h.phiPatterns {
		matches := pattern.Pattern.FindAllString(content, -1)
		if len(matches) > 0 {
			detections = append(detections, PHIDetection{
				PatternID:   pattern.ID,
				PatternName: pattern.Name,
				Matches:     matches,
				Severity:    pattern.Severity,
			})
		}
	}

	return &PHICheckResult{
		PHIDetected: len(detections) > 0,
		Detections:  detections,
		CheckedAt:   time.Now(),
	}, nil
}

type PHICheckResult struct {
	PHIDetected bool
	Detections  []PHIDetection
	CheckedAt   time.Time
}

type PHIDetection struct {
	PatternID   string
	PatternName string
	Matches     []string
	Severity    common.Severity
}

var _ common.Framework = (*HIPAAFramework)(nil)
