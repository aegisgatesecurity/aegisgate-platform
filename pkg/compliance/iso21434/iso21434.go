// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - ISO 21434 Compliance Module
// =========================================================================
//
// ISO 21434:2021 (Road Vehicle Cybersecurity) compliance controls as a
// licensed add-on module. Covers cybersecurity management, risk assessment,
// product development, production and operations, distributed activities,
// incident management, and vulnerability management throughout the vehicle
// lifecycle.
//
// Module metadata:
//   - Framework:     "iso21434"
//   - Version:       "2.0"
//   - Required tier: Professional ($499/mo)
//   - Controls:      42 (22 automated, 20 manual)
//   - Categories:    7
//
// Architecture:
//   - iso21434.go:  module wiring, 42 RegisterControl calls,
//                   25 CheckFunc implementations (13 existing + 12 new)
//
// Reference: ISO/SAE 21434:2021 - Road vehicles — Cybersecurity engineering
// =========================================================================

// Package iso21434 provides ISO 21434 automotive cybersecurity compliance controls
// as a licensed add-on module. ISO 21434 defines cybersecurity engineering requirements
// for road vehicle electrical and electronic (E/E) systems throughout their lifecycle.
package iso21434

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate/pkg/core"
)

// ISO21434Module implements ISO 21434 automotive cybersecurity compliance controls.
type ISO21434Module struct {
	*compliance.BaseComplianceModule
	automotivePatterns []*regexp.Regexp
	taraPatterns       []*regexp.Regexp
	csmsPatterns       []*regexp.Regexp
}

// NewISO21434Module creates a new ISO 21434 compliance module.
func NewISO21434Module() *ISO21434Module {
	m := &ISO21434Module{
		BaseComplianceModule: compliance.NewBaseComplianceModule("iso21434", "2.0", core.TierProfessional),
	}

	m.initPatterns()
	m.registerControls()

	return m
}

func (m *ISO21434Module) initPatterns() {
	m.automotivePatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)iso\s*21434`),
		regexp.MustCompile(`(?i)automotive\s*cybersecurity`),
		regexp.MustCompile(`(?i)\bvehicle\b`),
		regexp.MustCompile(`(?i)\becu\b|electronic\s*control\s*unit`),
		regexp.MustCompile(`(?i)\boem\b|original\s*equipment\s*manufacturer`),
		regexp.MustCompile(`(?i)tier[- ]?1\s*supplier`),
	}
	m.taraPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)threat\s*analysis`),
		regexp.MustCompile(`(?i)risk\s*assessment`),
		regexp.MustCompile(`(?i)\btara\b`),
		regexp.MustCompile(`(?i)attack\s*surface`),
	}
	m.csmsPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)cybersecurity\s*management`),
		regexp.MustCompile(`(?i)\bcsms\b`),
		regexp.MustCompile(`(?i)security\s*culture`),
	}
}

func (m *ISO21434Module) registerControls() {
	// ── Cybersecurity Management (CM) — 6 controls, 4 automated, 2 manual ──

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-CM-001",
		Name:        "Cybersecurity Management System (CSMS)",
		Description: "Organization must establish, implement, and maintain a cybersecurity management system",
		Category:    "Cybersecurity Management",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkCSMS,
		References:  []string{"ISO 21434:2021 Clause 5.1", "ISO 21434:2021 Clause 5.4.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-CM-002",
		Name:        "Cybersecurity Culture and Competence",
		Description: "Organization must foster cybersecurity culture and ensure personnel competence",
		Category:    "Cybersecurity Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkCultureCompetence,
		References:  []string{"ISO 21434:2021 Clause 5.2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-CM-003",
		Name:        "Cybersecurity Audit and Management Review",
		Description: "Organization must conduct cybersecurity audits and management reviews at planned intervals",
		Category:    "Cybersecurity Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAuditManagementReview,
		References:  []string{"ISO 21434:2021 Clause 5.4.2", "ISO 21434:2021 Clause 5.4.3"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-CM-004",
		Name:        "Quality Management Integration",
		Description: "Integrate cybersecurity management with the organization's quality management system",
		Category:    "Cybersecurity Management",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"ISO 21434:2021 Clause 5.3"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-CM-005",
		Name:        "Resource Allocation",
		Description: "Allocate adequate resources for cybersecurity activities throughout the lifecycle",
		Category:    "Cybersecurity Management",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"ISO 21434:2021 Clause 5.4.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-CM-006",
		Name:        "Cybersecurity Information Sharing",
		Description: "Participate in cybersecurity information sharing with industry partners and authorities",
		Category:    "Cybersecurity Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkInfoSharing,
		References:  []string{"ISO 21434:2021 Clause 5.5"},
	})

	// ── Risk Assessment (RA) — 8 controls, 5 automated, 3 manual ──

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-RA-001",
		Name:        "Threat Analysis and Risk Assessment (TARA)",
		Description: "TARA must be performed to identify and assess cybersecurity risks to assets",
		Category:    "Risk Assessment",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkTARA,
		References:  []string{"ISO 21434:2021 Clause 8.2", "ISO 21434:2021 Clause 15"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-RA-002",
		Name:        "Asset-based Risk Identification",
		Description: "Assets must be identified and their cybersecurity risks assessed based on damage scenarios",
		Category:    "Risk Assessment",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAssetRiskIdentification,
		References:  []string{"ISO 21434:2021 Clause 9.3"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-RA-003",
		Name:        "Risk Treatment Decision",
		Description: "Risk treatment decisions must be made and documented for each identified risk",
		Category:    "Risk Assessment",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkRiskTreatmentDecision,
		References:  []string{"ISO 21434:2021 Clause 15.7"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-RA-004",
		Name:        "Threat Analysis",
		Description: "Identify and analyze threats to vehicle assets including attack vectors and threat actors",
		Category:    "Risk Assessment",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkThreatAnalysis,
		References:  []string{"ISO 21434:2021 Clause 9.4"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-RA-005",
		Name:        "Vulnerability Analysis",
		Description: "Identify and analyze vulnerabilities in vehicle systems and components",
		Category:    "Risk Assessment",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkVulnerabilityAnalysis,
		References:  []string{"ISO 21434:2021 Clause 9.5"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-RA-006",
		Name:        "Impact Rating",
		Description: "Determine impact rating for identified threat scenarios",
		Category:    "Risk Assessment",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkImpactRating,
		References:  []string{"ISO 21434:2021 Clause 15.5"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-RA-007",
		Name:        "Risk Matrix Definition",
		Description: "Define and document a risk matrix for evaluating cybersecurity risks",
		Category:    "Risk Assessment",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkRiskMatrix,
		References:  []string{"ISO 21434:2021 Clause 15.6"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-RA-008",
		Name:        "Risk Treatment Options",
		Description: "Document available risk treatment options: accepting, avoiding, reducing, or sharing",
		Category:    "Risk Assessment",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkRiskTreatmentOptions,
		References:  []string{"ISO 21434:2021 Clause 15.7"},
	})

	// ── Product Development (PD) — 10 controls, 6 automated, 4 manual ──

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-PD-001",
		Name:        "Cybersecurity Goals and Claims",
		Description: "Cybersecurity goals and claims must be defined based on risk assessment outcomes",
		Category:    "Product Development",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkCybersecurityGoals,
		References:  []string{"ISO 21434:2021 Clause 6.4.2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-PD-002",
		Name:        "Cybersecurity Requirements",
		Description: "Cybersecurity requirements must be derived from goals and allocated to system components",
		Category:    "Product Development",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkCybersecurityRequirements,
		References:  []string{"ISO 21434:2021 Clause 10.4"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-PD-003",
		Name:        "Architectural Design Security",
		Description: "System architecture must incorporate security design principles and mitigate identified threats",
		Category:    "Product Development",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkArchitecturalDesignSecurity,
		References:  []string{"ISO 21434:2021 Clause 10.5"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-PD-004",
		Name:        "Integration and Verification",
		Description: "Cybersecurity verification must be performed during integration and testing phases",
		Category:    "Product Development",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkIntegrationVerification,
		References:  []string{"ISO 21434:2021 Clause 11"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-PD-005",
		Name:        "Component Cybersecurity Specification",
		Description: "Define cybersecurity specifications for each component including interfaces and dependencies",
		Category:    "Product Development",
		Severity:    compliance.SeverityCritical,
		Automated:   false,
		References:  []string{"ISO 21434:2021 Clause 10.6"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-PD-006",
		Name:        "Security Architecture Review",
		Description: "Review security architecture against identified risks and requirements",
		Category:    "Product Development",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSecurityArchReview,
		References:  []string{"ISO 21434:2021 Clause 10.5"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-PD-007",
		Name:        "Secure Coding Standards",
		Description: "Implement secure coding standards for vehicle software development",
		Category:    "Product Development",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkSecureCoding,
		References:  []string{"ISO 21434:2021 Clause 10.8"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-PD-008",
		Name:        "Third-Party Component Assessment",
		Description: "Assess cybersecurity of third-party and supplier-provided components",
		Category:    "Product Development",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"ISO 21434:2021 Clause 10.9"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-PD-009",
		Name:        "Cybersecurity Testing",
		Description: "Perform cybersecurity testing including penetration testing and fuzzing",
		Category:    "Product Development",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkCyberTesting,
		References:  []string{"ISO 21434:2021 Clause 10.10"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-PD-010",
		Name:        "Security Update Readiness",
		Description: "Ensure components are designed to support cybersecurity updates throughout lifecycle",
		Category:    "Product Development",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSecurityUpdateReadiness,
		References:  []string{"ISO 21434:2021 Clause 10.11"},
	})

	// ── Production and Operations (PO) — 7 controls, 3 automated, 4 manual ──

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-PO-001",
		Name:        "Production Cybersecurity Controls",
		Description: "Cybersecurity controls must be validated during production and manufacturing processes",
		Category:    "Production and Operations",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkProductionControls,
		References:  []string{"ISO 21434:2021 Clause 12.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-PO-002",
		Name:        "Incident Response and Monitoring",
		Description: "Organization must monitor for cybersecurity incidents and maintain an incident response plan",
		Category:    "Production and Operations",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkIncidentResponse,
		References:  []string{"ISO 21434:2021 Clause 8.4"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-PO-003",
		Name:        "Vulnerability Management and OTA Updates",
		Description: "Vulnerabilities must be managed and remediated, including via over-the-air (OTA) updates",
		Category:    "Production and Operations",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkVulnerabilityManagement,
		References:  []string{"ISO 21434:2021 Clause 8.3", "ISO 21434:2021 Clause 13.3"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-PO-004",
		Name:        "Configuration Management",
		Description: "Maintain configuration management for vehicle cybersecurity throughout production",
		Category:    "Production and Operations",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkConfigManagement,
		References:  []string{"ISO 21434:2021 Clause 12.2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-PO-005",
		Name:        "Production Process Security",
		Description: "Ensure production processes maintain cybersecurity integrity of components",
		Category:    "Production and Operations",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"ISO 21434:2021 Clause 12.3"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-PO-006",
		Name:        "Vehicle Configuration Documentation",
		Description: "Document cybersecurity-relevant configurations for each vehicle produced",
		Category:    "Production and Operations",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"ISO 21434:2021 Clause 12.4"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-PO-007",
		Name:        "Maintenance and Repair Security",
		Description: "Ensure maintenance and repair activities maintain vehicle cybersecurity",
		Category:    "Production and Operations",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"ISO 21434:2021 Clause 13.2"},
	})

	// ── Distributed Activities (DP) — 4 controls, 1 automated, 3 manual ──

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-DP-001",
		Name:        "Supplier Cybersecurity Requirements",
		Description: "Define and communicate cybersecurity requirements for suppliers and partners",
		Category:    "Distributed Activities",
		Severity:    compliance.SeverityCritical,
		Automated:   false,
		References:  []string{"ISO 21434:2021 Clause 7.4"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-DP-002",
		Name:        "Supplier Assessment",
		Description: "Assess supplier cybersecurity capabilities and compliance",
		Category:    "Distributed Activities",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSupplierAssessment,
		References:  []string{"ISO 21434:2021 Clause 7.5"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-DP-003",
		Name:        "Contractual Security Obligations",
		Description: "Include cybersecurity obligations in supplier and partner contracts",
		Category:    "Distributed Activities",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"ISO 21434:2021 Clause 7.6"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-DP-004",
		Name:        "Supply Chain Risk Management",
		Description: "Manage cybersecurity risks in the supply chain including software bill of materials",
		Category:    "Distributed Activities",
		Severity:    compliance.SeverityCritical,
		Automated:   false,
		References:  []string{"ISO 21434:2021 Clause 7.4", "ISO 21434:2021 Clause 7.5"},
	})

	// ── Incident Management (IM) — 4 controls, 2 automated, 2 manual ──

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-IM-001",
		Name:        "Incident Detection and Monitoring",
		Description: "Monitor for cybersecurity incidents affecting vehicles in the field",
		Category:    "Incident Management",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkIncidentDetection,
		References:  []string{"ISO 21434:2021 Clause 8.4.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-IM-002",
		Name:        "Incident Classification",
		Description: "Classify cybersecurity incidents by severity and impact",
		Category:    "Incident Management",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"ISO 21434:2021 Clause 8.4.2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-IM-003",
		Name:        "Incident Response Plan",
		Description: "Maintain and test incident response plans for vehicle cybersecurity incidents",
		Category:    "Incident Management",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkIncidentResponsePlan,
		References:  []string{"ISO 21434:2021 Clause 8.4.3"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-IM-004",
		Name:        "Incident Communication",
		Description: "Establish communication procedures for cybersecurity incidents with stakeholders and authorities",
		Category:    "Incident Management",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"ISO 21434:2021 Clause 8.4.4"},
	})

	// ── Vulnerability Management (VM) — 3 controls, 2 automated, 1 manual ──

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-VM-001",
		Name:        "Vulnerability Disclosure Program",
		Description: "Establish a vulnerability disclosure program for receiving and addressing vulnerability reports",
		Category:    "Vulnerability Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkVulnDisclosure,
		References:  []string{"ISO 21434:2021 Clause 8.3.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-VM-002",
		Name:        "Vulnerability Assessment Schedule",
		Description: "Establish schedules for periodic vulnerability assessments of vehicle systems",
		Category:    "Vulnerability Management",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"ISO 21434:2021 Clause 8.3.2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO21434-VM-003",
		Name:        "Patch and Update Management",
		Description: "Implement processes for deploying security patches and updates to vehicle systems",
		Category:    "Vulnerability Management",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkPatchManagement,
		References:  []string{"ISO 21434:2021 Clause 8.3.3", "ISO 21434:2021 Clause 13.3"},
	})
}

// =========================================================================
// CheckFunc implementations — each returns *compliance.ControlCheckResult.
// =========================================================================

// ── Existing 13 CheckFuncs (preserved) ──

func (m *ISO21434Module) checkCSMS(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := string(input)
	for _, p := range m.csmsPatterns {
		if p.MatchString(content) {
			return &compliance.ControlCheckResult{
				ControlID: "ISO21434-CM-001",
				Status:    compliance.StatusNonCompliant,
				Severity:  compliance.SeverityCritical,
				Message:   "Cybersecurity management system content detected",
				Details:   "ISO 21434 requires establishing, implementing, and maintaining a CSMS",
				Timestamp: time.Now(),
			}, nil
		}
	}
	return &compliance.ControlCheckResult{
		ControlID: "ISO21434-CM-001",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityCritical,
		Message:   "No CSMS patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *ISO21434Module) checkCultureCompetence(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "security culture") || strings.Contains(content, "competence") {
		return &compliance.ControlCheckResult{
			ControlID: "ISO21434-CM-002",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Cybersecurity culture or competence reference detected",
			Details:   "ISO 21434 requires fostering cybersecurity culture and ensuring personnel competence",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "ISO21434-CM-002",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No cybersecurity culture or competence references detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *ISO21434Module) checkAuditManagementReview(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "audit") && (strings.Contains(content, "management review") || strings.Contains(content, "cybersecurity")) {
		return &compliance.ControlCheckResult{
			ControlID: "ISO21434-CM-003",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Cybersecurity audit or management review content detected",
			Details:   "ISO 21434 requires cybersecurity audits and management reviews at planned intervals",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "ISO21434-CM-003",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No cybersecurity audit or management review patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *ISO21434Module) checkTARA(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := string(input)
	for _, p := range m.taraPatterns {
		if p.MatchString(content) {
			return &compliance.ControlCheckResult{
				ControlID: "ISO21434-RA-001",
				Status:    compliance.StatusNonCompliant,
				Severity:  compliance.SeverityCritical,
				Message:   "Threat Analysis and Risk Assessment (TARA) content detected",
				Details:   "ISO 21434 requires TARA to identify and assess cybersecurity risks to assets",
				Timestamp: time.Now(),
			}, nil
		}
	}
	return &compliance.ControlCheckResult{
		ControlID: "ISO21434-RA-001",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityCritical,
		Message:   "No TARA patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *ISO21434Module) checkAssetRiskIdentification(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "asset") && (strings.Contains(content, "risk") || strings.Contains(content, "damage scenario")) {
		return &compliance.ControlCheckResult{
			ControlID: "ISO21434-RA-002",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Asset-based risk identification content detected",
			Details:   "ISO 21434 requires identifying assets and assessing cybersecurity risks based on damage scenarios",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "ISO21434-RA-002",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No asset-based risk identification patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *ISO21434Module) checkRiskTreatmentDecision(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "risk treatment") || (strings.Contains(content, "risk") && strings.Contains(content, "decision")) {
		return &compliance.ControlCheckResult{
			ControlID: "ISO21434-RA-003",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Risk treatment decision content detected",
			Details:   "ISO 21434 requires risk treatment decisions to be made and documented for each identified risk",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "ISO21434-RA-003",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No risk treatment decision references detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *ISO21434Module) checkCybersecurityGoals(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "cybersecurity goal") || strings.Contains(content, "cybersecurity claim") {
		return &compliance.ControlCheckResult{
			ControlID: "ISO21434-PD-001",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Cybersecurity goals or claims reference detected",
			Details:   "ISO 21434 requires cybersecurity goals and claims to be defined based on risk assessment outcomes",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "ISO21434-PD-001",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No cybersecurity goals or claims references detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *ISO21434Module) checkCybersecurityRequirements(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "cybersecurity requirement") || strings.Contains(content, "security requirement") {
		return &compliance.ControlCheckResult{
			ControlID: "ISO21434-PD-002",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Cybersecurity requirements content detected",
			Details:   "ISO 21434 requires cybersecurity requirements to be derived from goals and allocated to components",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "ISO21434-PD-002",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No cybersecurity requirements patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *ISO21434Module) checkArchitecturalDesignSecurity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "architecture") && (strings.Contains(content, "security") || strings.Contains(content, "threat")) {
		return &compliance.ControlCheckResult{
			ControlID: "ISO21434-PD-003",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityCritical,
			Message:   "Architectural design security content detected",
			Details:   "ISO 21434 requires the system architecture to incorporate security design principles and mitigate threats",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "ISO21434-PD-003",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityCritical,
		Message:   "No architectural design security patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *ISO21434Module) checkIntegrationVerification(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if (strings.Contains(content, "integration") || strings.Contains(content, "verification")) && strings.Contains(content, "cybersecurity") {
		return &compliance.ControlCheckResult{
			ControlID: "ISO21434-PD-004",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Integration and verification content detected",
			Details:   "ISO 21434 requires cybersecurity verification during integration and testing phases",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "ISO21434-PD-004",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No integration and verification patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *ISO21434Module) checkProductionControls(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "production") && (strings.Contains(content, "cybersecurity") || strings.Contains(content, "security control")) {
		return &compliance.ControlCheckResult{
			ControlID: "ISO21434-PO-001",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Production cybersecurity controls content detected",
			Details:   "ISO 21434 requires cybersecurity controls to be validated during production and manufacturing",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "ISO21434-PO-001",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No production cybersecurity control patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *ISO21434Module) checkIncidentResponse(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "incident response") || (strings.Contains(content, "monitoring") && strings.Contains(content, "cybersecurity")) {
		return &compliance.ControlCheckResult{
			ControlID: "ISO21434-PO-002",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityCritical,
			Message:   "Incident response or monitoring content detected",
			Details:   "ISO 21434 requires monitoring for cybersecurity incidents and maintaining an incident response plan",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "ISO21434-PO-002",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityCritical,
		Message:   "No incident response or monitoring patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *ISO21434Module) checkVulnerabilityManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "vulnerability") || strings.Contains(content, "ota") || strings.Contains(content, "over-the-air") {
		return &compliance.ControlCheckResult{
			ControlID: "ISO21434-PO-003",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Vulnerability management or OTA update content detected",
			Details:   "ISO 21434 requires vulnerabilities to be managed and remediated, including via OTA updates",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "ISO21434-PO-003",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No vulnerability management or OTA update patterns detected",
		Timestamp: time.Now(),
	}, nil
}

// ── 12 new CheckFuncs ──

func (m *ISO21434Module) checkInfoSharing(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasInfoSharing := strings.Contains(inputStr, "info_sharing") ||
		strings.Contains(inputStr, "threat_sharing") ||
		strings.Contains(inputStr, "auto_isac")

	if hasInfoSharing {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO21434-CM-006",
			ControlName: "Cybersecurity Information Sharing",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Cybersecurity information sharing program detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "ISO21434-CM-006",
		ControlName: "Cybersecurity Information Sharing",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Cybersecurity information sharing program not detected",
		Timestamp:   time.Now(),
		Remediation: "Establish a cybersecurity information sharing program with industry partners and authorities per ISO 21434 Clause 5.5",
	}, nil
}

func (m *ISO21434Module) checkThreatAnalysis(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasThreatAnalysis := strings.Contains(inputStr, "threat_analysis") ||
		strings.Contains(inputStr, "attack_vector") ||
		strings.Contains(inputStr, "threat_actor")

	if hasThreatAnalysis {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO21434-RA-004",
			ControlName: "Threat Analysis",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Threat analysis with attack vectors and threat actors detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "ISO21434-RA-004",
		ControlName: "Threat Analysis",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Threat analysis not detected",
		Timestamp:   time.Now(),
		Remediation: "Identify and analyze threats to vehicle assets including attack vectors and threat actors per ISO 21434 Clause 9.4",
	}, nil
}

func (m *ISO21434Module) checkVulnerabilityAnalysis(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasVulnAnalysis := strings.Contains(inputStr, "vulnerability_analysis") ||
		strings.Contains(inputStr, "vuln_scan") ||
		strings.Contains(inputStr, "weakness")

	if hasVulnAnalysis {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO21434-RA-005",
			ControlName: "Vulnerability Analysis",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Vulnerability analysis for vehicle systems detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "ISO21434-RA-005",
		ControlName: "Vulnerability Analysis",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Vulnerability analysis not detected",
		Timestamp:   time.Now(),
		Remediation: "Identify and analyze vulnerabilities in vehicle systems and components per ISO 21434 Clause 9.5",
	}, nil
}

func (m *ISO21434Module) checkSecurityArchReview(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasArchReview := strings.Contains(inputStr, "architecture_review") ||
		strings.Contains(inputStr, "security_review") ||
		strings.Contains(inputStr, "design_review")

	if hasArchReview {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO21434-PD-006",
			ControlName: "Security Architecture Review",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Security architecture review detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "ISO21434-PD-006",
		ControlName: "Security Architecture Review",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Security architecture review not detected",
		Timestamp:   time.Now(),
		Remediation: "Review security architecture against identified risks and requirements per ISO 21434 Clause 10.5",
	}, nil
}

func (m *ISO21434Module) checkSecureCoding(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasSecureCoding := strings.Contains(inputStr, "secure_coding") ||
		strings.Contains(inputStr, "coding_standard") ||
		strings.Contains(inputStr, "misra")

	if hasSecureCoding {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO21434-PD-007",
			ControlName: "Secure Coding Standards",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Secure coding standards detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "ISO21434-PD-007",
		ControlName: "Secure Coding Standards",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Secure coding standards not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement secure coding standards for vehicle software development per ISO 21434 Clause 10.8",
	}, nil
}

func (m *ISO21434Module) checkCyberTesting(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasCyberTesting := strings.Contains(inputStr, "penetration_test") ||
		strings.Contains(inputStr, "fuzzing") ||
		strings.Contains(inputStr, "cybersecurity_test")

	if hasCyberTesting {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO21434-PD-009",
			ControlName: "Cybersecurity Testing",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Cybersecurity testing including penetration testing and fuzzing detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "ISO21434-PD-009",
		ControlName: "Cybersecurity Testing",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Cybersecurity testing not detected",
		Timestamp:   time.Now(),
		Remediation: "Perform cybersecurity testing including penetration testing and fuzzing per ISO 21434 Clause 10.10",
	}, nil
}

func (m *ISO21434Module) checkConfigManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasConfigMgmt := strings.Contains(inputStr, "configuration_management") ||
		strings.Contains(inputStr, "baseline") ||
		strings.Contains(inputStr, "version_control")

	if hasConfigMgmt {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO21434-PO-004",
			ControlName: "Configuration Management",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Configuration management for vehicle cybersecurity detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "ISO21434-PO-004",
		ControlName: "Configuration Management",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Configuration management not detected",
		Timestamp:   time.Now(),
		Remediation: "Maintain configuration management for vehicle cybersecurity throughout production per ISO 21434 Clause 12.2",
	}, nil
}

func (m *ISO21434Module) checkSupplierAssessment(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasSupplierAssessment := strings.Contains(inputStr, "supplier_assessment") ||
		strings.Contains(inputStr, "vendor_audit") ||
		strings.Contains(inputStr, "supplier_score")

	if hasSupplierAssessment {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO21434-DP-002",
			ControlName: "Supplier Assessment",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Supplier cybersecurity assessment detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "ISO21434-DP-002",
		ControlName: "Supplier Assessment",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Supplier cybersecurity assessment not detected",
		Timestamp:   time.Now(),
		Remediation: "Assess supplier cybersecurity capabilities and compliance per ISO 21434 Clause 7.5",
	}, nil
}

func (m *ISO21434Module) checkIncidentDetection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasIncidentDetection := strings.Contains(inputStr, "incident_detection") ||
		strings.Contains(inputStr, "vehicle_monitoring") ||
		strings.Contains(inputStr, "anomaly_detection")

	if hasIncidentDetection {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO21434-IM-001",
			ControlName: "Incident Detection and Monitoring",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Incident detection and vehicle monitoring detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "ISO21434-IM-001",
		ControlName: "Incident Detection and Monitoring",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Incident detection and monitoring not detected",
		Timestamp:   time.Now(),
		Remediation: "Monitor for cybersecurity incidents affecting vehicles in the field per ISO 21434 Clause 8.4.1",
	}, nil
}

func (m *ISO21434Module) checkIncidentResponsePlan(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasIRPlan := strings.Contains(inputStr, "incident_response_plan") ||
		strings.Contains(inputStr, "ir_plan") ||
		strings.Contains(inputStr, "response_procedure")

	if hasIRPlan {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO21434-IM-003",
			ControlName: "Incident Response Plan",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Incident response plan detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "ISO21434-IM-003",
		ControlName: "Incident Response Plan",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Incident response plan not detected",
		Timestamp:   time.Now(),
		Remediation: "Maintain and test incident response plans for vehicle cybersecurity incidents per ISO 21434 Clause 8.4.3",
	}, nil
}

func (m *ISO21434Module) checkVulnDisclosure(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasVulnDisclosure := strings.Contains(inputStr, "vulnerability_disclosure") ||
		strings.Contains(inputStr, "bug_bounty") ||
		strings.Contains(inputStr, "security_researcher")

	if hasVulnDisclosure {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO21434-VM-001",
			ControlName: "Vulnerability Disclosure Program",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Vulnerability disclosure program detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "ISO21434-VM-001",
		ControlName: "Vulnerability Disclosure Program",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Vulnerability disclosure program not detected",
		Timestamp:   time.Now(),
		Remediation: "Establish a vulnerability disclosure program for receiving and addressing vulnerability reports per ISO 21434 Clause 8.3.1",
	}, nil
}

func (m *ISO21434Module) checkPatchManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasPatchMgmt := strings.Contains(inputStr, "patch_management") ||
		strings.Contains(inputStr, "ota_update") ||
		strings.Contains(inputStr, "security_patch")

	if hasPatchMgmt {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO21434-VM-003",
			ControlName: "Patch and Update Management",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Patch and update management for vehicle systems detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "ISO21434-VM-003",
		ControlName: "Patch and Update Management",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Patch and update management not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement processes for deploying security patches and updates to vehicle systems per ISO 21434 Clause 8.3.3",
	}, nil
}

// GetPatterns returns the detection patterns for this module.
func (m *ISO21434Module) GetPatterns() []*regexp.Regexp {
	var all []*regexp.Regexp
	all = append(all, m.automotivePatterns...)
	all = append(all, m.taraPatterns...)
	all = append(all, m.csmsPatterns...)
	return all
}

// LastUpdated returns the last update time.
func (m *ISO21434Module) LastUpdated() time.Time {
	return time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
}

// String returns a string representation.
func (m *ISO21434Module) String() string {
	return fmt.Sprintf("ISO 21434 Module (v%s, %d controls)", m.Version(), len(m.Controls()))
}

// Dependencies returns required modules.
func (m *ISO21434Module) Dependencies() []string {
	return []string{"scanner"}
}

// ============================================================================
// Promoted CheckFunc implementations — P4 Compliance Automation Expansion
// ============================================================================

func (m *ISO21434Module) checkImpactRating(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasRating := strings.Contains(inputStr, "impact_rating") || strings.Contains(inputStr, "impact_assessment") || strings.Contains(inputStr, "severity_rating")
	if hasRating {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "ISO21434-RA-006", ControlName: "Impact Rating", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Impact rating detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "ISO21434-RA-006", ControlName: "Impact Rating", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium, Message: "Impact rating not detected", Timestamp: time.Now(), Remediation: "Implement impact rating methodology"}, nil
}

func (m *ISO21434Module) checkRiskMatrix(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasMatrix := strings.Contains(inputStr, "risk_matrix") || strings.Contains(inputStr, "risk_matrix_definition") || strings.Contains(inputStr, "risk_scoring")
	if hasMatrix {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "ISO21434-RA-007", ControlName: "Risk Matrix Definition", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Risk matrix definition detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "ISO21434-RA-007", ControlName: "Risk Matrix Definition", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium, Message: "Risk matrix not detected", Timestamp: time.Now(), Remediation: "Define risk matrix"}, nil
}

func (m *ISO21434Module) checkRiskTreatmentOptions(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasOptions := strings.Contains(inputStr, "risk_treatment_options") || strings.Contains(inputStr, "treatment_options") || strings.Contains(inputStr, "risk_mitigation")
	hasDecision := strings.Contains(inputStr, "treatment_decision") || strings.Contains(inputStr, "risk_decision") || strings.Contains(inputStr, "treatment_plan")
	if hasOptions && hasDecision {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "ISO21434-RA-008", ControlName: "Risk Treatment Options", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Risk treatment options detected", Timestamp: time.Now()}, nil
	}
	violations := []string{}
	if !hasOptions {
		violations = append(violations, "treatment options not configured")
	}
	if !hasDecision {
		violations = append(violations, "treatment decisions not configured")
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "ISO21434-RA-008", ControlName: "Risk Treatment Options", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium, Message: "Risk treatment gaps: " + strings.Join(violations, ", "), Timestamp: time.Now(), Remediation: "Implement risk treatment options"}, nil
}

func (m *ISO21434Module) checkSecurityUpdateReadiness(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasReadiness := strings.Contains(inputStr, "security_update_readiness") || strings.Contains(inputStr, "update_readiness") || strings.Contains(inputStr, "patch_readiness")
	hasProcess := strings.Contains(inputStr, "update_process") || strings.Contains(inputStr, "patch_process") || strings.Contains(inputStr, "update_management")
	if hasReadiness && hasProcess {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "ISO21434-PD-010", ControlName: "Security Update Readiness", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Security update readiness detected", Timestamp: time.Now()}, nil
	}
	violations := []string{}
	if !hasReadiness {
		violations = append(violations, "update readiness not configured")
	}
	if !hasProcess {
		violations = append(violations, "update process not configured")
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "ISO21434-PD-010", ControlName: "Security Update Readiness", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium, Message: "Update readiness gaps: " + strings.Join(violations, ", "), Timestamp: time.Now(), Remediation: "Implement security update readiness process"}, nil
}
